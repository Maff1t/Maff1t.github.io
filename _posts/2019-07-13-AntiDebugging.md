---
layout: post
title:  "Defeating windows anti debugging techniques to analyse a self-debugging and self-modifying program"
date:   2019-07-13
category: blog
---


## Introduction
I've just finished my bachelor degree thesis about the development of a [Panda-re](https://github.com/panda-re/panda) plugin to detect malware evasion's techniques on Windows  (anti-debugging, anti-VM, anti-sandbox and so on...) and I remembered of an old, program that was really difficoult to debug.
So with my newly acquired knowledge, I decided to try again to analyze that program and figure out how to debug it.

It uses a lot of **anti-debugging techniques**, then I manage to do a walk-through about all of those interesting tricks and how to defeat them to finally debug the target program.

You can download the program from [here](http://bho.it)

## Overview of the binary

![](https://i.ibb.co/3RSKQ7t/screenshot.png)

The binary seems to be the classical "CrackMe" style program, where the goal is to find the correct password to unlock it.
The first thing that I do on those windows programs, is open the debugger and look for API calls like "GetDlgItemTextA" that can read the ASCII string from the input box to check if the password is correct and "MessageBoxA" to print the correct or uncorrect message.
Trying to do it and placing breakpoints we notice that those APIs are in the code of the program, but seems to be unreachable while debugging....Something strange happens behind the scenes...


## 1. SetUnhandledExceptionFilter

Trying to decompile the program with **IDA**, in main function, we can immidiatly notice a call to the windows API **SetUnhandledExceptionFilter(lpTopLevelExceptionFilter)**. This API can catch an *unhandled exception* and pass the execution to *lpTopLevelExceptionFilter* (that is a pointer to function). This can be a suspicious behaviour, because if a debugger is attached to the process, any exception is handled by the debugger. 
You see the possible anti-debugging trick?

If in the code we use an *int 3* instruction (otherwise, we raise an exception) and our *lpTopLevelExceptionFilter function is not called, we know that the program is debugged!

In our case, lpTopLevelExceptionFilter  have this strange code (I skipped some parts):

<details>
<summary>Click here to View/Hide the code</summary>
    
    ......
    v3 = ExceptionInfo->ExceptionRecord->ExceptionCode; //get exception code
      
      if ( v3 <= 3221225617 )
      {
        if ( v3 >= 3221225613 )
        {
    LABEL_3:
          v2 = 1;
          goto LABEL_4;
        }
        if ( v3 == 3221225477 )
        {
          v8 = (void (__cdecl *)(signed int))signal(11, 0);
          if ( v8 == (void (__cdecl *)(signed int))1 )
          {
            signal(11, 1);
          }
          else
          {
            if ( !v8 )
              return v1;
            v8(11);
          }
          return -1;
        }
        v6 = v3 == 3221225501;
        .......
</details>

It is not immidiatly clear what this function does, but if we ask IDA to solve the constants like 3221225617, we find that they are:
*EXCEPTION_FLT_OVERFLOW, EXCEPTION_FLT_DENORMAL_OPERAND, EXCEPTION_ACCESS_VIOLATION, EXCEPTION_INT_DIVIDE_BY_ZERO* ........
Nothing interesting, it is only a default exception handler..... sad story.... I talked about it, because when I saw the program for the first time I made this mistake ... Let's go on ...

## 2. Same path check

After a bit of junk code, we find an interesting function that seems to be the ipotetic main function:

<details>
<summary>int __stdcall WinMain(HINSTANCE a1, int a2, int a3, int a4)</summary>
    
      CHAR *v4; // eax
      struct _STARTUPINFOA StartupInfo; // [esp+40h] [ebp-68h]
      DWORD dwParentProcessId; // [esp+9Ch] [ebp-Ch]
    
      hInstance = a1;
      dwParentProcessId = get_parent_PID();
      if ( HasSamePath(dwParentProcessId) )
      {
        CreateThread_and_debug(dwParentProcessId);
      }
      else
      {
        memset(&StartupInfo, 0, 0x44u);
        StartupInfo.cb = 68;
        v4 = GetCommandLineA();
        if ( CreateProcessA(0, v4, 0, 0, 0, 0, 0, 0, &StartupInfo, &ProcessInformation) )
        {
          while ( !dword_405008 )
            Sleep(0x64u);
          while ( (signed int)get_cntThreads() > 1 )
            Sleep(0x1F4u);
        }
      }
      return 0;
    }

</details>

I've already renamed the functions like "get_parent_PID" and "HasSamePath" that were easy functions to reverse. We notice that if the parent process have not the same path of the current process, it creates a new process and exit!
This is a clear anti-debugging behaviour, because, in general, a debuggee process is the child of his debugger process, then it has not the same path of his parent !

## 3. Self-Debugging

Since a debugger is the parent process of a debuggee, and whatever process can have only one parent, it's clear that any process can have at most one debugger attached.
Then, a clear anti-debugging technique that someone can use, is to spawn a child process, that execute something, and debug it to avoid the attachment of an external debugger.
It's exacly what happens in the function that I called "CreateThread_and_debug".

<details>
<summary>BOOL __cdecl CreateThread_and_debug(DWORD dwProcessId)</summary>

      DWORD ThreadId; // [esp+2Ch] [ebp-Ch]
      HANDLE hThread; // [esp+30h] [ebp-8h]
      HANDLE hProcess; // [esp+34h] [ebp-4h]
    
      hProcess = OpenProcess(0x1F0FFFu, 0, dwProcessId);
      if ( !hProcess )
      {
        TerminateProcess(0, 1u);
        return CloseHandle(0);
      }
      if ( !DebugActiveProcess(dwProcessId) )
      {
        TerminateProcess(hProcess, 1u);
        return CloseHandle(hProcess);
      }
      hThread = CreateRemoteThread(hProcess, 0, 0, StartAddress, 0, 0, &ThreadId);
      if ( !hThread )
      {
        TerminateProcess(hProcess, 1u);
        return CloseHandle(hProcess);
      }
</details>

As you can see, the child process create a thread in the parent process (the PID passed to the function is the PPID retrived before) and debugs it. This thread execute the code of the *StartAddress* function, that we will analyse later...
Ok, to recap the flow:

![](https://i.ibb.co/gTDV718/Processes.png)

What can we do to overcome the problem and debug the *StartAddress* function?
It's not difficult, we can prevent the second process to debug the first one . We can simply modify the function to skip the debugging part! Then, if we attach a debugger to the parent process, we see that another process spawn a thread in our process, and we can debug this thread.

It seems easy, but now comes the interesting part of this program.

## 4. Self-modifying code

Let's analyse the second part of the CreateThread_and_debug function's code :

<details>
<summary>Click here to View/Hide the code</summary>

    while ( 1 )
      {
        while ( 1 )
        {
          WaitForDebugEvent(&DebugEvent, 0xFFFFFFFF);
          if ( DebugEvent.dwDebugEventCode == DBG_SINGLESTEP )
            return ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
          if ( DebugEvent.dwThreadId == ThreadId && DebugEvent.dwDebugEventCode == 1 )
            break;
          ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
        }
        if ( DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT )
          break;
    LABEL_13:
        ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
      }
      if ( handle_breakpoint(hProcess, hThread) )
      {
        ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
        goto LABEL_13;
      }
      return TerminateProcess(hProcess, 1u);
    }
</details>

If we look deep in the code that debug the parent process, we can notice that if comes an exception from the thread created in the parent process, and in particular if it is a DEBUG_EXCEPTION, the program call another function that i called **handle_breakpoint**.

This is the function handle_breakpoint:

    BOOL __cdecl handle_breakpoint(HANDLE hProcess, HANDLE hThread)
    {
      char Buffer; // [esp+2Fh] [ebp-2D9h]
      CONTEXT Context; // [esp+30h] [ebp-2D8h]
    
      memset(&Context, 0, 0x2CCu);
      Context.ContextFlags = 65543;
      if ( !GetThreadContext(hThread, &Context) )
        return 0;
      if ( !ReadProcessMemory(hProcess, (LPCVOID)Context.Eip, &Buffer, 1u, 0) )
        return 0;
      Buffer = (Buffer >> 2) & 7;
      Context.Eip += Buffer + 1;
      Context.Eax = __ROL4__(Context.Eax, 1);
      return SetThreadContext(hThread, &Context) != 0;
    }

This function reads a byte in the parent process, at the address pointed by the program counter (EIP register) and puts it in the "Buffer" variable, then modifies two registers: EIP and EAX. Modifying in this way EIP, means moving the program counter of the program "Buffer" bytes ahead
EAX is modified with a rotation left of his 32 bits, in this way (in this image the example is done with 8 bit register):

![](http://www.giobe2000.it/Tutorial/img/istruz/ROL.gif)

Mmm...This may have sense only if the function used by the thread, contains some breakpoints. In this way, each time we execute the breakpoint, the program counter change and go some bytes ahead, modifying the code executed....

Let's examine the thread's function. 
As I said at the beginning, the input is read by the winows API *GetDlgItemTextA*, then I will focus on that part of code (IDA doesn't decompile it then we will see only assembly):

<details>
<summary>Click here to View/Hide the code</summary>

    .text:004013CC                 mov     dword ptr [esp+0Ch], 40h
    .text:004013D4                 mov     dword ptr [esp+8], offset serial
    .text:004013DC                 mov     dword ptr [esp+4], 66h
    .text:004013E4                 mov     eax, [ebp+8]
    .text:004013E7                 mov     [esp], eax
    .text:004013EA                 call    GetDlgItemTextA
    .text:004013EF                 sub     esp, 10h
    .text:004013F2                 mov     dword ptr [esp], offset serial
    .text:004013F9                 call    elab_passw
    .text:004013FE                 test    eax, eax
    .text:00401400                 jz      short loc_401431
    .text:00401402                 mov     dword ptr [esp+0Ch], 0
    .text:0040140A                 mov     dword ptr [esp+8], offset serial
    .text:00401412                 mov     eax, off_403038
    .text:00401417                 add     eax, 8
    .text:0040141A                 mov     eax, [eax]
    .text:0040141C                 mov     [esp+4], eax
    .text:00401420                 mov     dword ptr [esp], 0
    .text:00401427                 call    MessageBoxA
    .text:0040142C                 sub     esp, 10h
    .text:0040142F                 jmp     short loc_401461

</details>

This function take the input, pass it to the function (that I called) *elab_passw*, and check the returned value (in EAX register) to decide which message have to print.
Let's examine *elab_passw* function:

<details>
<summary>Click here to View/Hide the code</summary>

    .text:00401BBC                 push    eax
    .text:00401BBD                 add     eax, ebx
    .text:00401BBF                 shl     eax, 1
    .text:00401BC1                 inc     ebx
    .text:00401BC2                 pop     eax
    .text:00401BC3                 dec     ebx
    .text:00401BC4                 int     3               ; Trap to Debugger
    .text:00401BC5                 and     edx, [ebp-77h]
    .text:00401BC8                 in      eax, 0CCh       ; DMA controller, 8237A-5.
    .text:00401BC8                                         ; clear byte pointer flip-flop.
    .text:00401BCA                 mov     bh, 0AAh
    .text:00401BCC                 inc     eax
    .text:00401BCD                 add     [ebp-3Dh], dl
    .text:00401BD0                 push    ebx
    .text:00401BD1                 lea     ebx, [ebp+8]
    .text:00401BD4                 mov     ebx, [ebx]
    .text:00401BD6                 mov     eax, [ebx]
    .text:00401BD8                 xor     eax, 0CC9B402Ah
    .text:00401BDD                 rol     eax, 1
    .text:00401BDF                 int     3               ; Trap to Debugger
    .text:00401BE0                 wait
    .text:00401BE1                 mov     ebx, 0B4F03E9Ah
    .text:00401BE6                 dec     ecx
    .text:00401BE7                 sub     eax, 0FFBDD1F7h
    .text:00401BEC                 mov     ecx, eax
    .text:00401BEE
    .text:00401BEE loc_401BEE:                             ; CODE XREF: .text:00401BF2?j
    .text:00401BEE                 mov     eax, [ebx+4]
    .text:00401BF1                 int     3               ; Trap to Debugger
    .text:00401BF2                 bnd js short near ptr loc_401BEE+1
    .text:00401BF5                 or      eax, 1C289E3h
    .text:00401BFA                 retn    0C201h
</details>

 The first thing that we can notice, is that **this function has no sense**....BUT we can see a lot of *int 3* instructions (**THOSE ARE OUR BREAKPOINTS**!) Each time the execution reach an *int 3*, the code is "modified" by the debugger process, that intercept the breakpoint, and call the **handle_breakpoint** function! We have to patch this function to understand what is the correct flow.

# Patching the binary


Ok, now that we know, how and where, the code is modified, we can modify the code manually to understand what is truly executed! In the thread's function, when we find an *int 3* instruction, we know that we have to read the next byte, calculate  **(byte >> 2) and 7 + 1** and simply **NOP** (place a No OPeration instruction) the bytes that are not executed, to see the correct code.
We have to remember to also change EAX each time!!!

If we NOP also the *int 3* instruction (1 byte long), we have always a minimum of two bytes in which we can write, because, even if *(byte >> 2) and 7* is 0, we can write one byte on *int 3* and another byte because of the formula ( *(byte >> 2) and  7 **+ 1***). Then instead of nopping, we can insert the instruction *rol eax, 1* that fortunatly is 2 bytes long and is exactly what the debugger process do. 

This is the function *elab_passw* patched (I deleted nop instructions):

<details>
<summary>Click here to View/Hide the code</summary>

    .text:00401BC6                 push    ebp
    .text:00401BC7                 mov     ebp, esp
    .text:00401BC9                 rol     eax, 1
    .text:00401BD0                 push    ebx
    .text:00401BD1                 lea     ebx, [ebp+8] //In ebp+8 we have &password
    .text:00401BD4                 mov     ebx, [ebx]
    .text:00401BD6                 mov     eax, [ebx]
    .text:00401BD8                 xor     eax, 0CC9B402Ah
    .text:00401BDD                 rol     eax, 1
    .text:00401BDF                 rol     eax, 1
    .text:00401BE7                 sub     eax, 0FFBDD1F7h
    .text:00401BEC                 mov     ecx, eax
    .text:00401BEE                 mov     eax, [ebx+4] //Take second part of the password
    .text:00401BF1                 rol     eax, 1
    .text:00401BF7                 mov     edx, eax
    .text:00401BF9                 add     edx, eax
    .text:00401BFB                 add     edx, eax
    .text:00401BFD                 rol     eax, 1
    .text:00401C01                 add     edx, 6363E154h
    .text:00401C07                 xor     eax, eax
    .text:00401C09                 or      edx, ecx
    .text:00401C0B                 jnz     short loc_401C1B
    .text:00401C0D                 rol     eax, 1
    .text:00401C0F                 mov     dx, [ebx+8]
    .text:00401C13                 cmp     dx, 69h
    .text:00401C18                 jnz     short loc_401C1B
    .text:00401C1A                 inc     eax
    .text:00401C1B                 pop     ebx
    .text:00401C1C                 pop     ebp
    .text:00401C1D                 retn

</details>

This small pieace of code, simply means (sorry for the pseudo-code used):

    first_block = u32(passw[:4]) # -> take integer number associated to the first 4 chararacters of the password
    p1 = rol((first_block xor 0xcc9b402a), 2) + 422E09h
    
    second_block = u32(passw[4:8])
    p2 = 3 * rol(second_block, 1) + 0x6363E154

	third_block = passw[8]
		if (p1 | p2 | third_block != 'i') 
			Incorrect password 
		else
			Correct password

Then, first_block and second_block must be equal to zero, and the ninth letter of the password must be "i".
We can easly invert the function to find the correct number to solve the equation, knowing that inverse of xor is xor, and inverse of "rol" is "ror" (rotation right):
	
    rol((first_block xor 0xcc9b402a), 2) + 422E09h = 0 
    => first_block = ror(-422e09h , 2) xor 0xcc9b402a 
    = 57347433 = "W4t3"
    
	3 * rol(second_block, 1) + 0x6363E154 = 0
	=> second_block = ror((-6363E154h / 3), 1) 
	= 725a6f6f = "rZoo"

We find that the correct password is "W4t3rZooi"!

## Conclusions

In the end, to debug this program we had to patch it in two steps. The first one to avoid self-debugging, and the second one to adjust the flow of the program, deleting *int 3* exceptions.

Those tricks are wide-spread in malwares as anti-analysis techniques, and are really funny for reversers.
It was a really interesting program to reverse ;)

Bye, Maff1t