
---
layout: post
title: "Ultimate Web Fuzzing CheatSheet Collection"
date: 2026-02-07 19:30:00 +0300
categories: [Web Security, Penetration Testing]
tags: [fuzzing, ffuf, gobuster, feroxbuster, api-security, cheatsheet, bug-bounty]
---


# 🔍 Ultimate Web Fuzzing CheatSheet Collection

In this article, I've compiled the most important commands and techniques for Web Fuzzing. [cite_start]Web fuzzing is a technique used to discover vulnerabilities, hidden resources, and security issues by automatically injecting a large set of input data into an application[cite: 7].

[cite_start]The goal is to identify unexpected behaviors, hidden directories, insecure APIs, and vulnerabilities like SQLi or XSS[cite: 8, 10, 11, 12, 13].

> [cite_start]**Note:** **Fuzzing vs. Brute-Forcing**: Brute-forcing systematically tries all combinations to guess a specific value (like a password), whereas fuzzing injects unexpected data to provoke unexpected application responses[cite: 16].
{: .prompt-info }

---

## 🛠️ Web Fuzzing Tools

### ffuf (Fuzz Faster U Fool)

[cite_start]ffuf is a fast web fuzzer written in Go used to discover directories and files[cite: 37].

```bash
# [cite_start]Basic URL fuzzing [cite: 38]
ffuf -u [http://example.com/FUZZ](http://example.com/FUZZ) -w wordlist.txt

# [cite_start]Fuzz with specific extensions [cite: 38]
ffuf -u [http://example.com/FUZZ](http://example.com/FUZZ) -w wordlist.txt -e .php,.html

# [cite_start]Filter results by status code (e.g., 200) [cite: 38]
ffuf -u [http://example.com/FUZZ](http://example.com/FUZZ) -w wordlist.txt -mc 200

# [cite_start]Filter results by matching a regex pattern [cite: 38]
ffuf -u [http://example.com/FUZZ](http://example.com/FUZZ) -w wordlist.txt -mr "Welcome"

# [cite_start]Ignore comments in wordlist [cite: 38]
ffuf -u [http://example.com/FUZZ](http://example.com/FUZZ) -w wordlist.txt -ic

# [cite_start]Set number of threads (e.g., 50) [cite: 38]
ffuf -u [http://example.com/FUZZ](http://example.com/FUZZ) -w wordlist.txt -t 50

# [cite_start]Use a proxy (e.g., Burp Suite) [cite: 38]
ffuf -u [http://example.com/FUZZ](http://example.com/FUZZ) -w wordlist.txt -x [http://127.0.0.1:8080](http://127.0.0.1:8080)

# [cite_start]Colorize output [cite: 38]
ffuf -u [http://example.com/FUZZ](http://example.com/FUZZ) -w wordlist.txt -c

```

### gobuster

gobuster is used to brute-force URIs (directories/files) and DNS subdomains.

```bash
# [cite_start]Directory fuzzing [cite: 43]
gobuster dir -u [http://example.com](http://example.com) -w wordlist.txt

# [cite_start]Fuzz with specific extensions [cite: 43]
gobuster dir -u [http://example.com](http://example.com) -w wordlist.txt -x .php,.html

# [cite_start]DNS Subdomain fuzzing [cite: 43]
gobuster dns -d example.com -w subdomains.txt

# [cite_start]Show IP addresses of discovered subdomains [cite: 43]
gobuster dns -d example.com -w subdomains.txt -i

# [cite_start]Filter by status code (e.g., 200) [cite: 43]
gobuster dir -u [http://example.com](http://example.com) -w wordlist.txt -s 200

# [cite_start]Save output to file [cite: 43]
gobuster dir -u [http://example.com](http://example.com) -w wordlist.txt -o results.txt

```

### feroxbuster

feroxbuster is designed for recursive content discovery.

```bash
# [cite_start]Basic usage [cite: 53]
feroxbuster -u [http://example.com](http://example.com) -w wordlist.txt

# [cite_start]Follow redirects automatically [cite: 57]
feroxbuster -u [http://example.com](http://example.com) -w wordlist.txt --redirect

# [cite_start]Disable recursion [cite: 53]
feroxbuster -u [http://example.com](http://example.com) -w wordlist.txt --no-recursion

# [cite_start]Set recursion depth (e.g., 3 levels) [cite: 53]
feroxbuster -u [http://example.com](http://example.com) -w wordlist.txt --depth 3

# [cite_start]Exclude specific status codes (e.g., 404) [cite: 53]
feroxbuster -u [http://example.com](http://example.com) -w wordlist.txt -C 404

# [cite_start]Include specific file extensions [cite: 53]
feroxbuster -u [http://example.com](http://example.com) -w wordlist.txt -x .php,.html

```

### wenum (Wfuzz Fork)

wenum is a versatile web application fuzzer fork of wfuzz.

```bash
# [cite_start]Basic fuzzing excluding 404 responses [cite: 47]
wenum -c -w wordlist.txt -hc 404 -u [http://example.com/FUZZ](http://example.com/FUZZ)

# [cite_start]Fuzz POST data [cite: 47]
wenum -c -w wordlist.txt -d 'username=FUZZ&password=secret' -u [http://example.com/login](http://example.com/login)

# [cite_start]Fuzz using specific HTTP method (e.g., PUT) [cite: 50]
wenum -c -w wordlist.txt -X PUT -u [http://example.com/FUZZ](http://example.com/FUZZ)

# [cite_start]Use specific cookie [cite: 50]
wenum -c -w wordlist.txt -b 'session=12345' -u [http://example.com/FUZZ](http://example.com/FUZZ)

# [cite_start]Add custom header [cite: 50]
wenum -c -w wordlist.txt -H 'User-Agent: Wenum' -u [http://example.com/FUZZ](http://example.com/FUZZ)

# [cite_start]Filter by response size (e.g., 50 bytes) [cite: 50]
wenum -c -w wordlist.txt -hs 50 -u [http://example.com/FUZZ](http://example.com/FUZZ)

```

---

## 📂 Wordlists (SecLists)

SecLists is a collection of wordlists used by security researchers.

| Wordlist Path | Description |
| --- | --- |
| `.../Web-Content/common.txt` | <br>**General-Purpose**: Excellent starting point containing common directory and file names.

 |
| `.../directory-list-2.3-medium.txt` | <br>**Directory-Focused**: Extensive list specifically for directory names.

 |
| `.../raft-large-directories.txt` | <br>**Large Directory**: Massive collection for thorough fuzzing campaigns.

 |
| `.../Web-Content/big.txt` | <br>**Comprehensive**: Massive list containing both files and directories.

 |

> 
> **Tip:** Combine multiple wordlists to increase breadth and customize them based on the target technology stack.
> {: .prompt-tip }
> 
> 

---

## 🔗 API Fuzzing Strategies

### REST API (Representational State Transfer)

Uses standard HTTP methods (GET, POST, PUT, DELETE) and typically JSON.

* 
**Test All Methods:** Vulnerabilities may exist in CRUD operations (GET, POST, PUT, DELETE).


* 
**Validate Inputs:** Fuzz fields with unexpected data types to find validation issues.


* 
**Rate Limits:** Check for throttling controls.


* 
**Payloads:** Use SQLi and XSS payloads in API fields.



### SOAP API (Simple Object Access Protocol)

Uses XML and often requires WSDL files.

* 
**Analyze WSDL:** Use WSDL files to understand operations and inputs.


* 
**XML Injection:** Fuzz XML data to test for injection vulnerabilities.


* 
**SOAP Headers:** Fuzz headers to find security misconfigurations.


* 
**Faults:** Analyze SOAP fault messages for information leakage.



### GraphQL

Allows clients to request specific data structure, typically via a single endpoint.

* 
**Introspection:** Check if introspection is enabled to reveal the schema.


* 
**Complexity:** Test deeply nested queries to check for performance bottlenecks (DoS).


* 
**Mutations:** Fuzz mutations (data changes) for input validation flaws.



---

## 💻 Miscellaneous Commands

Useful commands for setting up your environment or generating data.

```bash
# [cite_start]Add a DNS entry to /etc/hosts [cite: 23]
sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'

# [cite_start]Create a sequence wordlist (1 to 1000) [cite: 23]
for i in $(seq 1 1000); do echo $i >> ids.txt; done

# [cite_start]CURL: Send POST request simulating form submission [cite: 23]
curl [http://admin.academy.htb](http://admin.academy.htb):PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'

```

---

## 🔄 Best Practices

* 
**Monitor Performance:** Large wordlists are resource-intensive; adjust threads to avoid overloading the server.


* 
**Filter Responses:** Use status codes or response sizes to filter noise.


* 
**Community Resources:** Always use community-maintained wordlists for effective strategies.



> **Last update:** February 07, 2026
{: .prompt-info }

**Happy Fuzzing! 🚀**


