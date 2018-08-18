---
layout: post
title:  "[PWN] Hackcon 2018 - WarChange - Easy"
date:   2018-08-17
categories: Write-ups
---
  - CTF NAME: [Hackcon 2018](https://hackcon.in/)
  - Category: PWN
  - Binary: [pwn2](http://ring0ot.github.io/binary/hackcon2018-vuln)
  - Difficulty: Easy

This challenge was the third challenge of the pwn category in the [Hackcon CTF 2018](https://hackcon.in/).

Let's open the binary:

```
Hola, So you again this time I am more secure. Lets see what u got

```

It request an input. And this input is managed with the vulnerable **gets()** function.
Using radare we can disassemble the main function:

```code
|	    0x004006bc      488d45b0       lea rax, [local_50h]                                                                         
|           0x004006c0      4889c7         mov rdi, rax                                                                                 
|           0x004006c3      e888feffff     call sym.imp.gets           ;[3] ; char *gets(char *s)                                       
|           0x004006c8      488b05b10420.  mov rax, qword obj.stdin    ; [0x600b80:8]=0x7f7996732a00                                    
|           0x004006cf      4889c7         mov rdi, rax                                                                                 
|           0x004006d2      e889feffff     call sym.imp.fflush         ;[2] ; int fflush(FILE *stream)                                  
|           0x004006d7      817dfcefbead.  cmp dword [local_4h], 0xdeadbeef    ; [0xdeadbeef:4]=-1                                      
|       ,=< 0x004006de      740a           je 0x4006ea                 ;[4]                                                             
|       |   0x004006e0      bf01000000     mov edi, 1                                                                                   
|       |   0x004006e5      e886feffff     call sym.imp.exit           ;[5] ; void exit(int status)                                     
|       `-> 0x004006ea      817df8bebafe.  cmp dword [local_8h], 0xcafebabe    ; [0xcafebabe:4]=-1                                      
|       ,=< 0x004006f1      750f           jne 0x400702                ;[6]                                                             
|       |   0x004006f3      bfeb074000     mov edi, str.cat_flag.txt    ; 0x4007eb ; "cat flag.txt"                                     
|       |   0x004006f8      b800000000     mov eax, 0                                                                                   
|       |   0x004006fd      e82efeffff     call sym.imp.system         ;[7] ; int system(const char *string)                            
|       `-> 0x00400702      488b05670420.  mov rax, qword sym.stdout    ; loc.stdout ; [0x600b70:8]=0x7f7996733760 ; "`7s\x96y\x7f"     
|           0x00400709      4889c7         mov rdi, rax                                                                                 
|           0x0040070c      e84ffeffff     call sym.imp.fflush         ;[2] ; int fflush(FILE *stream)                                  
|           0x00400711      b800000000     mov eax, 0                                                                                   
|           0x00400716      c9             leave                                                                                        
\           0x00400717      c3             ret

```

Now the objective is clear: we have to conduct the flow of the program through the **system()** call. To do that, we have to overflow the local_50h buffer
and overwrite the two local variables at rbp-0x8 (local_8h) and at rbp-0x4 (local_4h) with, respectivly, 0xcafebabe and 0xdeadbeef (N.B in little endian ;) )

Then here is the exploit and the flag:

![placeholder](https://ring0ot.github.io/images/hackcon2018-pwn2-flag.jpg)
