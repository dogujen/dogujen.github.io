---
layout: post
title: "Ultimate DFIR CheatSheet Collection"
date: 2025-09-18 14:30:00 +0300
categories: [Digital Forensics, Incident Response]
tags: [dfir, forensics, incident-response, cheatsheet, cybersecurity, investigation, malware-analysis]
---

> This cheatsheet is according to my knowledge. And I'm not that good in DFIR. :) 
{: .prompt-warning } 

# 🔍 Ultimate DFIR CheatSheet Collection

In this article, I've compiled the most important cheatsheets and tools used in Digital Forensics and Incident Response (DFIR). This resource serves as a comprehensive guide for both beginners and experienced analysts.

> **Note:** These cheatsheets are continuously updated. The list will be expanded as new tools and techniques are added.
{: .prompt-tip }

---


## 🧠 Memory Forensics

### Volatility Framework CheatSheet

Volatility is one of the most popular tools for memory dump analysis.

```bash
# Profile detection
volatility -f memory.dmp imageinfo

# Process list
volatility -f memory.dmp --profile=Win7SP1x64 pslist
volatility -f memory.dmp --profile=Win7SP1x64 pstree
volatility -f memory.dmp --profile=Win7SP1x64 psscan

# Network connections
volatility -f memory.dmp --profile=Win7SP1x64 netscan
volatility -f memory.dmp --profile=Win7SP1x64 netstat

# File system
volatility -f memory.dmp --profile=Win7SP1x64 filescan
volatility -f memory.dmp --profile=Win7SP1x64 mftparser

# Registry analysis
volatility -f memory.dmp --profile=Win7SP1x64 hivelist
volatility -f memory.dmp --profile=Win7SP1x64 printkey -K "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Malware detection
volatility -f memory.dmp --profile=Win7SP1x64 malfind
volatility -f memory.dmp --profile=Win7SP1x64 apihooks
```

### Volatility 3 CheatSheet

```bash
# Basic information
vol -f memory.dmp windows.info
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree

# Network analysis
vol -f memory.dmp windows.netscan
vol -f memory.dmp windows.netstat

# File analysis
vol -f memory.dmp windows.filescan
vol -f memory.dmp windows.dumpfiles --pid [PID]

# Registry
vol -f memory.dmp windows.registry.hivelist
vol -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

### Rekall Memory Forensic Framework

```bash
# Start session
rekall -f memory.dmp

# Process analysis
pslist()
pstree()
psaux()

# Network connections
netstat()
netscan()
```

---

## 🌐 Network Forensics

### Wireshark CheatSheet

```bash
# Display filters
http.request.method == "POST"
tcp.port == 80
ip.addr == 192.168.1.1
dns.qry.name contains "malware"
http.request.uri contains "shell"

# Protocol analizi
tcp.stream eq 0
http.request.full_uri
ftp-data
smtp.data.fragment

# Malicious traffic detection
http.user_agent contains "bot"
dns.qry.name matches ".*\.tk$"
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### tshark Command Line

```bash
# Basic usage
tshark -r capture.pcap

# Protocol hierarchy
tshark -r capture.pcap -q -z io,phs

# HTTP requests
tshark -r capture.pcap -Y "http.request" -T fields -e http.request.method -e http.request.uri -e http.user_agent

# DNS queries
tshark -r capture.pcap -Y "dns.qry.type == 1" -T fields -e dns.qry.name

# Extract files
tshark -r capture.pcap --export-objects http,/tmp/http-objects/
```

### NetworkMiner

```bash
# Command line usage
NetworkMiner.exe -r capture.pcap

# Extract files automatically
NetworkMiner.exe -r capture.pcap --export /tmp/extracted/
```

---

## 💾 Disk Forensics

### Autopsy CheatSheet

GUI-based disk analysis tool Autopsy main operations:

- **Case Creation**: Creating new cases
- **Data Source**: Adding disk images
- **Timeline Analysis**: Timeline analysis
- **Keyword Search**: Keyword searching
- **Hash Analysis**: Hash comparison

### The Sleuth Kit (TSK)

```bash
# Disk image analysis
mmls disk.img

# File system analysis
fsstat -t ntfs disk.img

# Inode analysis
istat -t ntfs disk.img 128

# File list
fls -t ntfs disk.img

# File content
icat -t ntfs disk.img 256

# Timeline creation
mactime -b /tmp/bodyfile -d > timeline.csv
```

### FTK Imager

```bash
# Command line imaging
FTKImager.exe /dev/sda1 evidence.E01 --case-number "2025-001" --description "Suspect Drive"

# Hash verification
FTKImager.exe --verify evidence.E01
```

---

## 🪟 Windows Forensics

### Registry Analysis

```bash
# Registry hives locations
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SECURITY
C:\Windows\System32\config\SOFTWARE
C:\Windows\System32\config\SYSTEM
C:\Users\[username]\NTUSER.DAT
C:\Users\[username]\AppData\Local\Microsoft\Windows\UsrClass.dat

# RegRipper usage
rip.pl -r NTUSER.DAT -f ntuser
rip.pl -r SOFTWARE -f software
rip.pl -r SYSTEM -f system
```

### Event Log Analysis

```bash
# Windows Event Logs
C:\Windows\System32\winevt\Logs\

# Important Event IDs
# 4624 - Successful logon
# 4625 - Failed logon
# 4648 - Explicit credential logon
# 4720 - User account created
# 7045 - Service installed

# PowerShell event analysis
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624}
```

### PowerShell Forensics

```powershell
# PowerShell history
Get-Content (Get-PSReadlineOption).HistorySavePath

# PowerShell logs
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational"

# Script block logging
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104}
```

### Prefetch Analysis

```bash
# PECmd usage (Eric Zimmerman tools)
PECmd.exe -f "C:\Windows\Prefetch\CALC.EXE-123456.pf"

# WinPrefetchView
WinPrefetchView.exe /stext prefetch_report.txt
```

---

## 🐧 Linux Forensics

### Linux Artifact Locations

```bash
# User activity
/var/log/auth.log          # Authentication logs
/var/log/syslog           # System logs
/home/*/.bash_history     # Command history
/home/*/.ssh/known_hosts  # SSH connections

# System information
/etc/passwd               # User accounts
/etc/shadow              # Password hashes
/proc/version            # Kernel version
/etc/crontab             # Scheduled tasks

# Network configuration
/etc/hosts               # Host file
/etc/resolv.conf         # DNS configuration
/var/log/messages        # General system messages
```

### Command Line Forensics

```bash
# System information
uname -a
cat /etc/os-release
last -f /var/log/wtmp
lastlog

# Network analysis
netstat -tulpn
ss -tulpn
iptables -L

# Process analysis
ps aux
lsof -i
pstree

# File analysis
find / -name "*.php" -exec grep -l "shell_exec\|system\|exec" {} \;
find / -type f -newer /tmp/timestamp
```

### Log Analysis Tools

```bash
# grep patterns for suspicious activity
grep -i "sudo\|su " /var/log/auth.log
grep -E "Failed password|Invalid user" /var/log/auth.log
grep -i "wget\|curl" /var/log/syslog

# Log correlation
tail -f /var/log/syslog | grep -E "(error|warning|critical)"
```

---

## 📱 Mobile Forensics

### Android Forensics

```bash
# ADB commands
adb devices
adb shell dumpsys
adb shell pm list packages
adb backup -all -apk -shared -nosystem

# Important Android paths
/data/data/               # Application data
/sdcard/Android/data/     # External storage
/data/system/packages.xml # Package information
/data/data/com.android.providers.contacts/databases/contacts2.db
```

### iOS Forensics

```bash
# iTunes backup locations
# macOS: ~/Library/Application Support/MobileSync/Backup/
# Windows: %APPDATA%\Apple Computer\MobileSync\Backup\

# libimobiledevice tools
idevice_id -l
ideviceinfo
idevicebackup2 backup --full /path/to/backup/
```

---

## 🦠 Malware Analysis

### Static Analysis

```bash
# File information
file suspicious.exe
strings suspicious.exe
hexdump -C suspicious.exe | head

# Hash calculation
md5sum suspicious.exe
sha256sum suspicious.exe

# PE analysis (Windows)
objdump -p suspicious.exe
readelf -a suspicious.elf

# YARA rules
yara rules.yar suspicious.exe
```

### Dynamic Analysis

```bash
# Process monitoring (Linux)
strace -o trace.log ./suspicious
ltrace -o ltrace.log ./suspicious

# Network monitoring
netstat -tulpn
tcpdump -i any -w capture.pcap

# File system monitoring
inotifywait -m -r /path/to/monitor
```

### Sandbox Analysis

- **Cuckoo Sandbox**: Automated malware analysis
- **Joe Sandbox**: Cloud-based analysis
- **Any.run**: Interactive online sandbox
- **Hybrid Analysis**: Free automated analysis

---

## 📊 Log Analysis

### Common Log Formats

```bash
# Apache/Nginx access logs
tail -f /var/log/apache2/access.log
grep "POST" /var/log/nginx/access.log

# Common attack patterns
grep -E "(union|select|script|alert)" /var/log/apache2/access.log
grep -E "(\.\./|etc/passwd|cmd\.exe)" /var/log/apache2/access.log

# Windows IIS logs
findstr /i "404" u_ex*.log
findstr /i "POST" u_ex*.log
```

### ELK Stack (Elasticsearch, Logstash, Kibana)

```bash
# Logstash configuration example
input {
  file {
    path => "/var/log/apache2/access.log"
    start_position => "beginning"
  }
}

filter {
  grok {
    match => { "message" => "%{COMBINEDAPACHELOG}" }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
  }
}
```

### Splunk

```bash
# Basic search
index=main source="/var/log/auth.log" "Failed password"

# Time range
index=main earliest=-24h latest=now

# Statistical analysis
index=main | stats count by source_ip
index=main | timechart span=1h count
```

---

## 🔍 Digital Evidence

### Hash Verification

```bash
# MD5
md5sum evidence.dd > evidence.md5
md5sum -c evidence.md5

# SHA256
sha256sum evidence.dd > evidence.sha256
sha256sum -c evidence.sha256

# Multiple hash types
hashdeep -c md5,sha1,sha256 evidence.dd
```

### Evidence Acquisition

```bash
# dd command
dd if=/dev/sda of=evidence.dd bs=4096 conv=noerror,sync

# dcfldd (enhanced dd)
dcfldd if=/dev/sda of=evidence.dd hash=md5,sha256 bs=4096

# ewfacquire (Expert Witness Format)
ewfacquire /dev/sda
```

### Chain of Custody

```markdown
# Evidence documentation template
Case Number: 2025-DFIR-001
Evidence ID: E001
Description: Suspect laptop hard drive
Date/Time: 2025-09-18 14:30:00
Location: Suspect's office
Collected by: [Investigator name]
Hash (MD5): [hash value]
Hash (SHA256): [hash value]
```

---

## 🚨 Incident Response

### NIST Incident Response Framework

1. **Preparation**
   - Incident response plan
   - Tools and training
   - Communication protocols

2. **Detection and Analysis**
   - Log monitoring
   - Threat hunting
   - Incident classification

3. **Containment, Eradication, and Recovery**
   - Isolation procedures
   - Malware removal
   - System restoration

4. **Post-Incident Activity**
   - Lessons learned
   - Process improvement
   - Report generation

### Incident Response Toolkit

```bash
# Network isolation
iptables -I INPUT -j DROP
iptables -I OUTPUT -j DROP

# Memory acquisition
winpmem.exe -o memory.aff4
linpmem -o memory.aff4

# Live response (Windows)
wmic process list full
netstat -anob
tasklist /svc

# Live response (Linux)
ps auxf
netstat -tulpn
lsof -i
```

### Timeline Creation

```bash
# Super timeline with log2timeline
log2timeline.py --storage-file timeline.plaso disk.dd

# Timeline analysis with psort
psort.py -w timeline.csv timeline.plaso

# Manual timeline correlation
sort -k1,1 multiple_timelines.csv > master_timeline.csv
```

---

## 🛠️ Essential DFIR Tools

### Free Tools

- **Volatility**: Memory analysis
- **Autopsy**: Disk forensics
- **Wireshark**: Network analysis
- **YARA**: Malware identification
- **Eric Zimmerman Tools**: Windows artifacts
- **Ghidra**: Reverse engineering
- **TheHive**: Case management

### Commercial Tools

- **EnCase**: Comprehensive forensics
- **FTK**: Forensic toolkit
- **X-Ways**: Disk editor and forensics
- **Cellebrite**: Mobile forensics
- **Magnet AXIOM**: Digital investigation

---

## 📚 Useful Resources

### Documentation and References

- [SANS Digital Forensics](https://www.sans.org/cyber-security-courses/digital-forensics/)
- [NIST Computer Forensics Tool Testing (CFTT)](https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt)
- [Digital Forensics Framework (DFF)](http://www.digital-forensic.org/)

### Online Platforms

- [DFIR Training](https://www.dfir.training/)
- [13Cubed YouTube Channel](https://www.youtube.com/c/13cubed)
- [SANS DFIR Blog](https://www.sans.org/blog/?focus-area=digital-forensics)

---

## 🔄 Regular Updates

This cheatsheet is regularly updated. Content will be expanded as new tools, techniques and CVEs are added.

> **Last update:** September 18, 2025
{: .prompt-info }

---

## 🤝 Contributing

If you want to contribute to the development of this resource, you can contact me for new tools, techniques or corrections.

**Happy DFIR Hunting! 🔍🚀**