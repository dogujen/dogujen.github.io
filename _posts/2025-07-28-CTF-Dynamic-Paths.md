---
layout: post
title: "Dynamic Paths CTF Writeup"
date: 2025-07-28 19:22:00 +0300
categories: [HackTheBox, CTFs]
tags: [cybersecurity, coding, hackthebox, prolabs,tryout]
---


# 🎰 Dynamic-Paths CTF Writeup

In this writeup, I’ll walk you through how I solved the **Dynamic Paths** CTF coding challenge. This challenge is great for practicing **pwntools** and dynamic algorithms in python. Let’s jump in!

---
## 🕵️‍♀️ Mission
Coding CTFs have a logic and they tell the algorithm to you.
```md
You will be given a number of t = 100 grids for the different regions you need to pass. For every map you will have the below values:
        1. The dimensions i x j of the map grid where 2 <= i, j <= 100
        2. The numbers n_i,j symbolizing the distances between the blocks where 1 <= n_i,j <= 50
You will start at the top left element, and your goal is to reach the bottom right, while only being allowed to move down or right, minimizing the sum of the numbers you pass. Provide the minimum sum.

Example Question:
        4 3
        2 5 1 9 2 3 9 1 3 11 7 4

This generates the following grid:
         2 5 1
         9 2 3
         9 1 3
        11 7 4

Example Response:
        17
(Optimal route is 2 -> 5 -> 2 -> 1 -> 3 -> 4)

Test 1/100
5 5
8 5 8 8 8 7 1 6 6 2 1 6 2 4 7 3 7 3 9 4 2 2 8 6 1
> 
```
## 📋 Solution
Here's the code.
```py
from pwn import *

def min_path_sum(grid):
    if not grid or not grid[0]:  
        return 0
    
    rows = len(grid)
    cols = len(grid[0])
    
    
    dp = [[0] * cols for _ in range(rows)]
    
    
    dp[0][0] = grid[0][0]
    
    
    for j in range(1, cols):
        dp[0][j] = dp[0][j - 1] + grid[0][j]
    
    
    for i in range(1, rows):
        dp[i][0] = dp[i - 1][0] + grid[i][0]
    
    
    for i in range(1, rows):
        for j in range(1, cols):
            dp[i][j] = min(dp[i - 1][j], dp[i][j - 1]) + grid[i][j]
    
    return dp[rows - 1][cols - 1]


def gridmaker3000(rows, cols, data):
    grid = []
    for i in range(rows):  
        row = list(map(int, data[i * cols:(i + 1) * cols]))
        grid.append(row)
    return grid

def main():
    
    conn = remote('94.237.50.221', 55768)
    
    
    for _ in range(1,101):
        
        
        print(str(_)+". Adım" )
        t= conn.recvuntil(f'Test {_}/100'.encode())
        line = conn.recvuntil(b'>').decode().strip()
        print('LINE: '+str(line))
        if not line:
       	    raise TypeError
            break
        array = line.replace('\n'," ").replace('>','').split(' ')
        del array[-1]
        print(array)
        first = array[0]
        second = array[1]
        del array[0:2]
        myowngrid = gridmaker3000(int(first),int(second),array)
        print(myowngrid)
        print(array)
        damnbro = min_path_sum(myowngrid)
        conn.sendline(str(damnbro).encode())
    
    conn.interactive()

if __name__ == "__main__":
    main()
```