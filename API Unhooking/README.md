# API UNHOOKING - Gazprom ransomware

---

To understand **API Unhooking**, you first have to grasp the mechanics of **API Hooking**. At its core, hooking is a technique used to intercept function calls between a program and the Operating System.

Think of it like a "Man-in-the-Middle" attack, but happening entirely within the computer's memory.

---

## How API Hooking Works

Normally, when an application wants to perform a task like opening a file or connecting to the internet it calls a function from a system library (like `ntdll.dll` or `kernel32.dll` on Windows).

### The Normal Flow

1. The **Application** calls `CreateFile`.
2. The execution jumps directly to the **Address** of `CreateFile` in the system DLL.
3. The **Operating System** executes the request and returns the result.

### The Hooked Flow (Inline Hooking)

Security software (EDRs/Antivirus) or malware will "hook" this process to monitor or block the action. The most common method is **Inline Hooking** (also known as "detouring"):

- **The Overwrite:** The first few bytes of the original function (the "prologue") are overwritten with a `JMP` (jump) instruction.
- **The Interception:** When the application calls the function, the `JMP` redirects the execution to a **Hook Function** controlled by the monitor.
- **The Inspection:** The monitor looks at the arguments (e.g., "Is this program trying to encrypt the entire hard drive?").
- **The Resumption:** If deemed safe, the monitor executes the original instructions it overwrote and jumps back to the rest of the function.

---

## Static Analysis of Gazprom ransomware

### Metadata

| **Property** | **Value** |
| --- | --- |
| **MD5** | `0d0d964d5615bbf7c3576b852b8e30d2` |
| **SHA-1** | `cd455c8bea34b872dc1dcced141bed15b3b8d6c6` |
| **SHA-256** | `32ec301f02dfa21932679726f07e30f9c807391aaf1044278c0e0b2c0dc8ebdf` |
| **Vhash** | `025066655d1555555az44nz15z27z` |
| **Authentihash** | `fa9a08753a8dc988599a505ea9cc236339220d47ce4a44b8cc74f95da4f3563a` |
| **Imphash** | `9cf1d77c3f5524c39deb8820c33fe708` |
| **Rich PE Header Hash** | `f38ecbffd9fdf990024b468bf7130436` |
| **SSDEEP** | `3072:Js3LtgpfC21UaIgeR6nDWUgx+3xkDKPhNKdD/Z6bQpZUa:JC5gn1rIgeYq38hzhNKera` |
| **TLSH** | `T1E5341901F51FCBEAD69303BC4956A602FDB7328167248EEB83844A711D0B1D57AEDFA1` |
| **File Type** | Win32 EXE (executable, windows, win32, pe, peexe) |
| **Magic** | PE32+ executable (GUI) x86-64, for MS Windows |
| **TrID** | Win64 Executable (48.7%), Win16 NE (23.3%), OS/2 (9.3%), Win/DOS (9.2%), DOS (9.2%) |
| **DetectItEasy** | PE64; Compiler: MSVC (19.16.27049); Linker: MS Linker (14.16.27049); Tool: VS 2017 |
| **Magika** | PEBIN |
| **File Size** | 234.50 KB (240,128 bytes) |

---

### PE Section

| **Name** | **Entropy** | **File Ratio** | **Raw Address (Begin)** | **Raw Size** | **Virtual Address** | **Virtual Size** |
| --- | --- | --- | --- | --- | --- | --- |
| **.text** | 6.531 | 74.20% | `0x00000400` | 178,176 B | `0x00001000` | 177,834 B |
| **.rdata** | 4.873 | 17.06% | `0x0002BC00` | 40,960 B | `0x0002D000` | 40,634 B |
| **.data** | 2.790 | 4.69% | `0x00035C00` | 11,264 B | `0x00037000` | 15,796 B |
| **.pdata** | 5.245 | 2.56% | `0x00038800` | 6,144 B | `0x0003B000` | 5,688 B |
| **.rsrc** | 4.718 | 0.21% | `0x0003A000` | 512 B | `0x0003D000` | 480 B |
| **.reloc** | 4.889 | 0.85% | `0x0003A200` | 2,048 B | `0x0003E000` | 1,616 B |

### IMPORTS

| **Category** | **Key Functions** | **Library** |
| --- | --- | --- |
| **File I/O** | `CreateFileW`, `WriteFile`, `SetFilePointerEx`, `FlushFileBuffers` | KERNEL32.dll |
| **Networking** | **`htons`**, `WSAGetLastError` | WS2_32.dll |
| **Anti-Analysis** | `IsDebuggerPresent`, `IsProcessorFeaturePresent` | KERNEL32.dll |
| **Process/Thread** | `GetCurrentProcess`, `TerminateProcess`, `ExitProcess`, `TlsAlloc` | KERNEL32.dll |
| **Memory/Heap** | `HeapAlloc`, `HeapFree`, `GetProcessHeap`, `HeapReAlloc` | KERNEL32.dll |
| **System Info** | `GetSystemTimeAsFileTime`, `GetLocalTime`, `GetCommandLineW` | KERNEL32.dll |
| **Dynamic Loading** | `GetProcAddress`, `LoadLibraryExW`, `FreeLibrary` | KERNEL32.dll |
| **Error/Exception** | `GetLastError`, `UnhandledExceptionFilter`, `RaiseException` | KERNEL32.dll |
| **UI/Strings** | `wsprintfW`, `MultiByteToWideChar`, `WriteConsoleW` | USER32 / KERNEL32 |

Among the many imports there’s a htons

![Screenshot 2026-05-06 at 3.08.58 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_3.08.58_AM.png)

---

This function converts a number in host byte order to network byte order. Malware’s often uses this API to specify a destination port before it communicates across a network. Simply the single argument passed to this api could specify a network port used by this malware during execution.

![Screenshot 2026-05-06 at 3.38.24 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_3.38.24_AM.png)

---

## Patching the Sample

### open the sample in x64dbg.

place a **`breakpoint`** on **`htons` .**

![Screenshot 2026-05-06 at 3.34.21 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_3.34.21_AM.png)

---

A Single argument passed to **`htons`** contained in the **`RCX`** register is `1BD` .

![Screenshot 2026-05-06 at 3.35.19 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_3.35.19_AM.png)

---

**`1BD`** translates to decimal **`445`**

Ransomwares often scan the local network targeting **`445 aka SMB service`** in order to identify file shares. So from defence prespective it’s make sense to hook this api to understand if any such network activity is contained within the malware.

We will hook the htons function. To do so we need to modify this sample.

---

**`Now remove the htons breakpoint and restart the program.`**

We will replace the first instruction:

![Screenshot 2026-05-06 at 3.49.07 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_3.49.07_AM.png)

---

right click —> binary —> edit

### edit the opcode:

FROM:

```c
48 83 EC 28
```

TO:

```c
EB FE 90 90
```

like this:

![Screenshot 2026-05-06 at 3.53.34 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_3.53.34_AM.png)

click ok.

---

Now it will effectively replace the previous instructions with a jmp instruction whose target is this very jmp instruction.

![Screenshot 2026-05-06 at 3.54.09 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_3.54.09_AM.png)

---

This infinite loop will allow me to launch this program using frida-trace and attach to it a debugger, such that i arrive at the entry point. Without make this change the malware might execute and then terminate before attach to it with debugger.

Now save this patch version.

go to file —> patch file —> patch file then save it with .exe

![Screenshot 2026-05-06 at 4.01.56 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_4.01.56_AM.png)

---

![Screenshot 2026-05-06 at 4.03.09 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_4.03.09_AM.png)

---

## Hooking with frida-trace

---

Now we will launch frida-trace specifying the modified version of the sample.

```c
C:\Users\redteam\Desktop\api-unhook>frida-trace -f patched.exe -i htons
Instrumenting...
htons: Auto-generated handler at "C:\Users\redteam\Desktop\api-unhook\handlers\WS2_32.dll\htons.js"
Started tracing 1 function. Web UI available at http://localhost:50679/
```

![Screenshot 2026-05-06 at 4.48.02 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_4.48.02_AM.png)

---

## Attaching to x64dbg

Next launch x64dbg and attach to the patched.exe

go to file —> attach then select modified patched program.                                                                                                                                                                                                                                                                                         

![Screenshot 2026-05-06 at 4.50.44 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_4.50.44_AM.png)

---

The program is running.

![Screenshot 2026-05-06 at 4.52.34 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_4.52.34_AM.png)

---

Because of the infinite loop it cannot proceed passed the instruction. 

I will set breakpoint on this jump.

![Screenshot 2026-05-06 at 4.54.53 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_4.54.53_AM.png)

Now the program is paused at the entry point.

#### While it’s paused let’s take a look at the **`hooked version of htons.`**

ctlr + g to follow expression 

![Screenshot 2026-05-06 at 4.59.43 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_4.59.43_AM.png)

---

**`Notice the first intructions is now a jmp.`** 

![Screenshot 2026-05-06 at 5.00.27 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_5.00.27_AM.png)

Original it was:

![Screenshot 2026-05-06 at 5.02.08 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_5.02.08_AM.png)

---

So if we follow **`jmp 7FFCE6B80308` this will take us to the injected dll associated with frida.**

following **`jmp 7FFCE6B80308`**

![Screenshot 2026-05-06 at 5.05.49 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_5.05.49_AM.png)

Next Following: 

00007FFCE6B8030E | FF25 02000000            | **`jmp qword ptr ds:[7FFCE6B80316]`**         |

leads to this location

![Screenshot 2026-05-06 at 5.07.34 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_5.07.34_AM.png)

scroll down will get another jump or a call.

follow the call instruction.

![Screenshot 2026-05-06 at 5.08.25 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_5.08.25_AM.png)

---

Take look at the top it’s a frida-agent.dll

![Screenshot 2026-05-06 at 5.09.43 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_5.09.43_AM.png)

---

### Back to the topic

How this malware actually identifies a hooked function by inspecting the first bytes of an API

get back to htons:  ctrl + g enter htons.

**`We will set hardware on access breakpoint on htons to observe how this ransomware actually evaluates the initial bytes of the api.`**

![Screenshot 2026-05-06 at 5.22.38 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_5.22.38_AM.png)

to do so right click —> follow in dump —> selected address.

![Screenshot 2026-05-06 at 5.26.22 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_5.26.22_AM.png)

Notice the matching addresses: you can see the hex E9 in the dump correlates with the opcode of jmp instruction.

![Screenshot 2026-05-06 at 5.26.42 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_5.26.42_AM.png)

Set the Hardware access breakpoint:

right click on E9.

![Screenshot 2026-05-06 at 5.30.10 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_5.30.10_AM.png)

---

now before running the program return to the entry point. To do so press **`shift + *` will take back to the entry point.**

![Screenshot 2026-05-06 at 6.01.16 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_6.01.16_AM.png)

You can see the infinite loop is still there, **`now we have to replace these instructions with the original ones.`** 

---

Select first 4 bytes then edit.

![Screenshot 2026-05-06 at 6.03.07 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_6.03.07_AM.png)

now type the original opcode which is

```c
48 83 EC 28
```

![Screenshot 2026-05-06 at 6.05.06 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_6.05.06_AM.png)

---

Now it will look like this.

![Screenshot 2026-05-06 at 6.05.33 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_6.05.33_AM.png)

Let’s continue running the program.

---

Reached the hardware breakpoint.

![Screenshot 2026-05-06 at 6.09.01 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_6.09.01_AM.png)

**`It’s comparing one byte at the beginning of the api with the opcode E9`.**

**`below there’s FF and 25 which actually correlates with another type of jump instructions.`**

<aside>
📌

**Key takeaway:** These 3 comparisons check whether the first bytes of the API are **jump instructions** (e.g., `E9`, `FF 25`). If they are, it can indicate the API has been **hooked** by a security product or analysis tool.

</aside>

Malware that performs these kinds of checks. will often times then attempt to overwrite the hooked API code with the original bytes, from the DLL on the disk.

Effectively removing the hook.

To investigate how the malware achieve this let’s go the function that actually contains these comparison instructions.

Copy the address of the comparison instruction.

![Screenshot 2026-05-06 at 6.26.39 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_6.26.39_AM.png)

 First comparison address:

```c
0000000140001D17
```

---

## Ghidra Analysis

---

Open the find.exe original sample in ghidra and go to the comparison address.

![Screenshot 2026-05-06 at 6.32.57 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_6.32.57_AM.png)

---

Before going any further. **You might be wondering is there another way that you would be drawn to this function besides the debugging efforts we just did?**

And there is with the knowledge that API unhooking often involves, **`looking for opcodes associated with the jmp like hex E9 or FF 25.`** 

What you could do is go to search —> program text in ghidra.

search for the opcode e9.

![Screenshot 2026-05-06 at 6.42.28 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_6.42.28_AM.png)

---

We get around 100 results.

sort it by preview. focus only in those which have comparison instructions. Only where the operand is E9

![Screenshot 2026-05-06 at 6.46.24 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_6.46.24_AM.png)

---

This is yet another way to that you might arrive or identify a function, possibly looking for jumps. Which could indicate that an API has been hooked.

---

### **Back to the Function.**

Scroll up a little you will see a a lot function calls specifying RAX as the target.

In other words these registers are going to contain the address of the function that actually called. There are many cases here where the call instruction calls RAX or the address contained within the RAX.

This is referred to as an indirect call because again the function actually called is specified during the execution.

![Screenshot 2026-05-06 at 6.59.39 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_6.59.39_AM.png)

---

You’ll also notice is prior to each call to RAX there is a call to another function which is **`FUN_1400042d0` . One of the argument that is passed to this function is a hexadecimal value. This is actually an indication that we might be looking at in this function is `API hashing`.**

---

To know what these function calls are actually referencing just continue debugging the program. and see what api’s are referenced by these calls to RAX at runtime.

IF we go back to x64 DBG scroll a bit.

Where i currently reside is a call to RAX.

![Screenshot 2026-05-06 at 7.21.53 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_7.21.53_AM.png)

---

To evaluate the contents of RAX we have to run until selection. select the instruction go to debug then run until selection or press F4.

![Screenshot 2026-05-06 at 7.26.57 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_7.26.57_AM.png)

you can see we haven’t yet reached the particular instruction. At the bottom left it looks like we hit the hardware breakpoint.

So disable the hardware breakpoint. and continue running.

![Screenshot 2026-05-06 at 7.29.33 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_7.29.33_AM.png)

Now we arrive at the **`call to RAX` . and there’s a auto generated comment that say’s VirtualProtect.**

so at the address **`0000000140001D79`** is a **`virtualProtect`** 

```c
0000000140001D79 | FFD0                     | call rax                                | rax:VirtualProtect
```

let’s add comment to ghidra.

![Screenshot 2026-05-06 at 7.33.40 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_7.33.40_AM.png)

---

In order to better understand this function. I could set breakpoints on various calls to RAX. And then comment ghidra with the appropriate API references.

I’ve actually done that to speed of our analysis.

Key API’s called by this function. So you can understand how they work together in order to perform API unhooking.

At the top of the function we get a call.

#### GetModuleFileNameW

This API takes a handle to a dll. That is already loaded in memory and it gets the file name for that dll.

![Screenshot 2026-05-06 at 7.41.01 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_7.41.01_AM.png)

---

#### CreateFileW

The first argument passed to CreateFileW. which specifies the file to actually get access to is the file name returned from the previous call to GetModuleFileNameW.

![Screenshot 2026-05-06 at 7.44.10 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_7.44.10_AM.png)

You might ask why is the program accessing a file from disk that is already loaded in the memory.

Next we have 

#### CreateFileMappingW   followed by MapViewofFile

These two API’s work together to effectively load a module from disk into memory. In this case a DLL.

![Screenshot 2026-05-06 at 7.51.20 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_7.51.20_AM.png)

---

At this point there would be essentially two versions of DLL loaded in memory. One that is loaded as a part of normal execution of find.exe and another loaded using these calls to create filemapping  and map view a file.

---

This function then proceed to effectively iterate to all exported functions from all dll’s loaded in memory in order to identify if any of them are hooked.

Continuing scrolling in ghidra will arrive at the code that contains the compare instructions.

**`E9, FF, 25`**

![Screenshot 2026-05-06 at 8.01.03 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_8.01.03_AM.png)

---

![Screenshot 2026-05-06 at 8.06.20 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_8.06.20_AM.png)

If this function identifies that a hook is in fact in place. It will take this jmp 

```c
140001d30 74 1b           JZ         LAB_140001d4d
```

---

Further down we eventually arrive at VirtualProtect. Which will update the permissons of the hooked API in memory. Such that it will be writable (RWX).

This will allow the malware to overwrite the hooked API.

![Screenshot 2026-05-06 at 8.07.40 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_8.07.40_AM.png)

---

After VirtualProtect the program call’s these **`MOVSD`** instructions.

Which will basically copy over bytes from the original code of the API. Which has now mapped into memory. and overwrite the hooked API.

![Screenshot 2026-05-06 at 8.13.29 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_8.13.29_AM.png)

After that it again called VirtualProtect. but this time with PAGE_EXECUTE_READ permissions. effectively restoring the original permissions of the API

![Screenshot 2026-05-06 at 8.19.05 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_8.19.05_AM.png)

---

All these instructions are located within a loop you can see the condition down here it’s **`JNZ instruction.` It evaluates if the loop should continue iterating and the loop allows malware to evaluate for the presence of API hooks in any dll’s that is loaded by this process.**

![Screenshot 2026-05-06 at 8.26.01 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_8.26.01_AM.png)

---

## Back to x64 DBG

---

currently resides at call to rax which is VirtualProtect. First call to VirtualProtect whic updates the permissions of the code that contain the hooked API.

![Screenshot 2026-05-06 at 8.32.53 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_8.32.53_AM.png)

Executing by hitting F8. Until movsd.

The operand at the right hand side references RBX.

![Screenshot 2026-05-06 at 8.46.04 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_8.46.04_AM.png)

RBX will contain the address of the api code that was manually loaded in the memory. Via call to mapview a file so this would be the original dll code. That resides on disk.

going to RBX at top right click and choose follow in dump.

![Screenshot 2026-05-06 at 8.53.04 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_8.53.04_AM.png)

I’ll rename the DUMP 1 

These are the original bytes of the API  from dll on disk.

![Screenshot 2026-05-06 at 8.55.26 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_8.55.26_AM.png)

---

continue Executing

that’s going to place 64 bits of content from the original API code into **`xmm0` .**

We can view the content of xmm0.

![Screenshot 2026-05-06 at 8.59.24 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_8.59.24_AM.png)

---

Continuing executing

now we arrive at the second movsd instruction.

which placing the content of **`xmm0`** into the address specify by **`RDI` .**

![Screenshot 2026-05-06 at 9.00.35 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_9.00.35_AM.png)

---

We’ll **`dump`** the address within **`RDI` .** 

**Follow in dump 2**

These are the hooked API bytes.

![Screenshot 2026-05-06 at 9.05.51 AM.png](API%20UNHOOKING%20-%20Gazprom%20ransomware/Screenshot_2026-05-06_at_9.05.51_AM.png)

Contine executing.

We’ll keep an eye on RDI-hooked dump.

you will see those bytes changed 



https://github.com/user-attachments/assets/7344b953-336c-416c-b732-4f0ac91f3170




---

If we compare it with the original they are the same.

SO the original bytes are in placed and the hook has been overwritten. Which means Malware has achieved API unhooking.
