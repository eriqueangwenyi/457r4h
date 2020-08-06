---
author:
  name: "Astrah"
date: 2020-08-05
linktitle: Reverse Engineering part 1
type:
- post 
- posts
categories:
- Reversing
- Ctf
- Hackthebox
tags:
- RE
- Reversing
title: Reverse Engineering part 1
weight: 10
series:
- Rerversing
---

# REVERSE ENGINEERING:UPX PACKED EXECUTABLE
Attached is a binary called good luck. You are expected to reverse engineer it and capture the flag. Alternatively, the binary can be found at https://www.dropbox.com/s/mq70390yokr2l02/goodluck?dl=0 

I have started by checking what kind of a file it is from the terminal

![](/images/RE1.1.png)

There is not much information from that except for the fact that it is a 64bit executable.

The next is trying to execute it to see its behavior

![](/images/RE1.2.png)


screenshot above, shows malloc and strcpy,,malloc is used to allocate memory addresses and returns a pointer to it(mostly vulnerable to heap overflow), strcpy copies string pointed from the source to destination address.


So i went ahead and used strings command which makes it possible to view the human-readable characters within a file, this will help me find any hints of a flag before using a dissasembler.
I have attached just some sections of the screenshot for this because it gave a long list of details.I will capture the main points of interest

![](/images/RE1.3.png)

![](/images/RE1.4.png)


The underlined statement captured my attention.the executable was packed using Upx packer.
Upx packer compresses and packs executables ,the reason for this is to hinder dissasembly of executables or even hide the intent of the program especially for maware authors.
https://tech-zealots.com/reverse-engineering/dissecting-manual-unpacking-of-a-upx-packed-file/

Okaay,,,lets see if i can disassemble the packed executable using gdb...

![](/images/RE1.5.png)


i used intel flavor, 

![](/images/RE1.6.png)


Below you can see that we cant use gdb to disassemble the program cause it is compressed and packed using upx packer a technique used to hinder disassembly.

![](/images/RE1.7.png)


so i searched online on how to unpack upx packed executable . I downloaded upx from their github repo https://github.com/upx/upx/releases/tag/v3.95 and unpacked the executable as below.

![](/images/RE1.8.png)


lets now disassemble using gdb ‘ - ’
NB x64 binaries when disassembled gives rbp,rsp,rdx,rax,rip while x86 binaries gives epb, esp,edx,eax,eip etc....

![](/images/RE1.9.png)

lets analyse the function, as underlined,,,there is a comment #0x6c2070<flag> that looks revealing of the flag, 
The value of the address rip+0x2c0ee5 is loaded or moved into rdx, the square brackets defines the value of the address

![](/images/RE1.10.png)


I put a breakpoint after <+32> so it will on 0x000000000040118b

![](/images/RE1.11.png)


Ran the program and stopped at the breakpoint. I examined the string using x/s,,,,other commands like p/d prints integer or decimal value

![](/images/RE1.12.png)

And hurrah the flag is found "UPX...? sounds like a delivery service"

> Packing executables with upx is not hard to disassemble, the likes of themida and vmprotect are not hard to unpack but visualizing the code is harder.