---
layout: post
title: "FlagCasino CTF Writeup"
date: 2025-07-21 13:54:00 +0300
categories: [HackTheBox, CTFs]
tags: [cybersecurity, reverse, hackthebox, prolabs,tryout]
---

# 🎰 FlagCasino CTF Writeup

Today I’ll walk you through my process of solving the **FlagCasino** CTF binary. Let's dive in.

---

## 📂 Opening the Zip File

The zip archive contains a single binary named `casino`.

Since the binary is small, I initially tried [dogbolt](https://dogbolt.org) to inspect it (yes, I was feeling lazy). However, I wasn’t happy with the Ghidra output, so I pivoted to using **pwndbg** and **manual reverse engineering**.

---

## 🔎 Initial Observations

At line 89, I found the input block that takes a character and stores it into the variable `v0`:

```c
if (__isoc99_scanf(" %c", &v0) != 1)
    exit(-1);
````

Shortly after, a `for` loop controls how many characters will be read from the user:

```
for (v1 = 0; v1 <= 28; v1 += 1)
```

So it expects **29 characters** in total — this is important!

Each character goes through the following logic:

1. It's used as a seed: `srand(v0);`
2. Then `rand()` is called.
3. The result is compared with `check[v1]`.

If any mismatch occurs, the program prints:

```
[ * INCORRECT * ]
[ *** ACTIVATING SECURITY SYSTEM - PLEASE VACATE *** ]
```

…and exits.

---

## 📍 Reading the Check Array

Using `pwndbg`, I found the address of the `check` array:

```bash
info variables check
```

Which gave:

```
0x0000555555558080  check
```

Then I dumped the values with:

```bash
x/32xw 0x555555558080
```

This gave us the actual expected values for each `rand()` call.

---

## 🧠 Exploiting Predictable `rand()`

The key vulnerability here is that the standard C library’s `rand()` function is **predictable** if you know the seed.

So, I wrote a Python script using `ctypes` to brute-force the correct seed character for each `check[i]`:

```python
from ctypes import CDLL

libc = CDLL("libc.so.6")

check = [
    0x244b28be, 0x0af77805, 0x110dfc17, 0x07afc3a1,
    0x6afec533, 0x4ed659a2, 0x33c5d4b0, 0x286582b8,
    0x43383720, 0x055a14fc, 0x19195f9f, 0x43383720,
    0x63149380, 0x615ab299, 0x6afec533, 0x6c6fcfb8,
    0x43383720, 0x0f3da237, 0x6afec533, 0x615ab299,
    0x286582b8, 0x055a14fc, 0x3ae44994, 0x06d7dfe9,
    0x4ed659a2, 0x0ccd4acd, 0x57d8ed64, 0x615ab299,
    0x22e9bc2a
]

flag = ""
for idx, target in enumerate(check):
    for c in range(0x20, 0x7f):  # printable ASCII
        libc.srand(c)
        if libc.rand() == target:
            print(f"Index {idx}: seed char = {c} ('{chr(c)}')")
            flag += chr(c)
            break

print("\n=== FOUND FLAG ===")
print(flag)
```

---

## ✅ Output

The script printed:

```
HTB{r4nd_1s_v3ry_pr3d1ct4bl3}
```

And that’s the flag! 🎉

---

## 🔐 Takeaways

* `rand()` is not suitable for anything security-related.
* If a program seeds `rand()` with external input (like a user character), and checks the result against a known array, it can be reversed easily.
* Always prefer cryptographically secure RNGs (like `arc4random`, `/dev/urandom`, or `getrandom()` in Linux).

---

## 🧠 Final Thoughts

I really enjoyed this challenge because it’s simple, but also requires you to think about how randomness is implemented and how it can be predicted. Great reminder that security through obscurity doesn't work — and default tools can be a vulnerability if misused.

---

Thanks for reading! 🎰💣
Happy hacking!


