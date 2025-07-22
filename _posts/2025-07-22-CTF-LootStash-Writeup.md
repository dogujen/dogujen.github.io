---
layout: post
title: "LootStash CTF Writeup"
date: 2025-07-22 13:54:00 +0300
categories: [CTFs]
tags: [cybersecurity, reverse, hackthebox, prolabs]
---

# 🎰 LootStash CTF Writeup

Today I’ll walk you through my process of solving the **LootStash** CTF binary. Let's dive in.
Note: This writeup is about importance of prechecks.
---

## 📂 Opening the Zip File

The zip archive contains a single binary named `stash`.

Since the binary is small, I initially tried [dogbolt](https://dogbolt.org) to inspect it (I'm lazy). However, I liked the output of **ghidra**. 
```C
undefined8 main(void)

{
  int iVar1;
  time_t tVar2;
  int local_c;
  
  setvbuf(stdout,(char *)0x0,2,0);
  tVar2 = time((time_t *)0x0); // generate an unix timestamp
  srand((uint)tVar2); // Set the seed as the timestamp
  puts("Diving into the stash - let\'s see what we can find.");
  // 5 dots 0,1,2,3,4,5
  iVar1 = rand(); // Generate random stuff that dependent on the seed.
  printf("\nYou got: \'%s\'. Now run, before anyone tries to steal it!\n",
         *(undefined8 *)(gear + (long)(int)((ulong)(long)iVar1 % 0x7f8 >> 3) * 8));
  return 0;
}
```
---
# Understanding srand() and rand()
srand() is a function for setting up a seed for rand(). Rand function will generate a string that dependent on the seed that set up in srand("seed"). This makes it predictable and reversable.

---

# Finding "gear" list:
In GDB, i can easily dump gear list.
```sh
pwndbg> info variables gear
All variables matching regular expression "gear":

Non-debugging symbols:
0x000055555555b060  gear
```
---

# Making a GDB Script For Counting gear[]
```vb
define count_gear
  set $i = 0
  set $gear_base = 0x55555555b060
  while (*(long *)($gear_base + $i * 8)) != 0
    set $i = $i + 1
  end 
  printf "gear[] count = %d\n", $i
end
```
This will count gear size. And we can predict they store all items in gear.
# The Real Solution :P
---
After that I recognize I just need to find via strings :P
```sh
strings stash | grep HTB
```

Thanks for reading my silly adventure. And don't forget to check flags with strings :P  🎰💣
Happy hacking!
