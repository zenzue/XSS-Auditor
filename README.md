# XSS Auditor Pro

**Advanced XSS Vulnerability Scanner**  
Author: Aung Myat Thu (w01f)

---

## Overview

XSS Auditor Pro is a powerful Python-based tool designed for ethical penetration testing and security research in controlled environments.  
It can detect Reflected XSS and Form XSS vulnerabilities across multiple domains and subdomains with automatic Telegram reporting.

Built for speed, stealth, and reliability.

---

## Features

- Multi-domain scanning (read from `domains.txt`)
- Automatic subdomain discovery via certificate transparency logs
- Parameter and Form XSS testing
- WAF evasion payloads included
- Fast multi-threaded crawling and scanning
- Sends clean, structured alerts to Telegram on successful hits only
- Minimal and lightweight (no heavy dependencies)

---

## Usage

1. Install requirements:

```bash
pip install -r requirements.txt
```

2. Prepare your domain list:

Create a file named `domains.txt` with one domain per line.

Example:

```
example.com
testphp.vulnweb.com
insecure-website.com
```

3. Configure Telegram Bot:

Edit `xss_auditor_pro.py` and set:

```python
TELEGRAM_BOT_TOKEN = "your_bot_token_here"
TELEGRAM_CHAT_ID = "your_chat_id_here"
```

4. Run the scanner:

```bash
python3 xss_auditor_pro.py
```

---

## Output

When a vulnerability is detected, a message will be sent to your Telegram Bot structured as:

```
XSS Vulnerability Detected!

Domain: target.com
Vulnerability Type: Reflected XSS
Vulnerable URL: https://target.com/vuln.php?search=<payload>
```

Only successful hits will be reported.

---

## Project Structure

```
.
├── xss_auditor_pro.py
├── requirements.txt
├── domains.txt
├── README.md
```

---

## Requirements

- Python 3.8+
- requests
- beautifulsoup4

Install them using:

```bash
pip install -r requirements.txt
```

---

## Legal Disclaimer

This project is made for **educational purposes only**.  
You are responsible for your actions.  
Use it **only on systems you own** or have **explicit permission** to test.

---

## Author

**Aung Myat Thu (w01f)**

---

## License

Free to use for ethical hacking, internal testing, educational, and research purposes.  
Not for illegal use or real-world unauthorized attacks.