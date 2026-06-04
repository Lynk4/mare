# Unpacking Malware - Qakbot

---

Qbot (also known as QakBot or QuackBot) is indeed a, persistent, and highly sophisticated banking trojan that has been consistently packed or packed in a new layer of obfuscation for many years to evade detection by security software

It is considered a "Swiss Army knife" for threat actors, operating not only as a banking trojan to steal credentials but also as a malware loader for ransomware

Sample: https://malshare.com/sample.php?action=detail&hash=112a64190b9a0f356880eebf05e195f4c16407032bf89fa843fd136da6f5d515

---

## File Identification

---

| **Field** | **Value** |
| --- | --- |
| **File Name** | Qakbot |
| **MD5** | `bce0df8721504d50f4497c0a0a2c090d` |
| **SHA-1** | `2c5b190d19f0f58e156bd1b28434701cea09cc23` |
| **SHA-256** | `112a64190b9a0f356880eebf05e195f4c16407032bf89fa843fd136da6f5d515` |
| **Vhash** | `026086551d5c1c1c5c551214z2500927z27z6030028fz` |
| **Authentihash** | `86da2bddaab0b1a3d6546dc35de29d8942856dc3eb8e64bd6be9e3dc097c2294` |
| **Imphash** | `829e83c1d2d988349a749b806aa9cfef` |
| **SSDEEP** | `12288:qlQq2wwLHqpVxTp5WK1QAPPAV/Ykfgn6ggKh:u2wwT45xQwkfg93h` |
| **TLSH** | `T1F9D5CF27B560458BE7054A3684F6C9B026A1FEFD563520461EF0BE1BFBB1A934C11E8F` |
| **File Type** | Win32 EXE (executable, windows, win32, pe, peexe) |
| **Magic** | PE32 executable (GUI) Intel 80386, for MS Windows |
| **TrID** | • Win32 Executable MS Visual C++ (generic) (47.3%)
• Win64 Executable (generic) (15.9%)
• Win32 Dynamic Link Library (generic) (9.9%)
• Win16 NE executable (generic) (7.6%)
• Win32 Executable (generic) (6.8%) |
| **DetectItEasy** | • PE32
• Linker: Polink (2.50*) [GUI32,signed]
• Sign tool: Windows Authenticode (2.0) [PKCS #7] |
| **Magika** | PEBIN |
| **File Size** | 2.63 MB (2,755,088 bytes) |

---

### Sections

---

| **Index** | **Name** | **SHA-256 Hash** | **Entropy** | **File Ratio** | **Raw Size (Bytes)** | **Virtual Size (Bytes)** | **Raw Address (Begin)** | **Virtual Address** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **0** | `.text` | `0917EF1437D686D73C90CE2823E761224AFF706BC2AFCF50FC14070A4AE5AB35` | 5.517 | 2.99 % | 82,432 | 82,058 | `0x00000400` | `0x00001000` |
| **1** | `.rdata` | `CA63C02CAA8C0248F3F6A8291F23B0C2F64A6B933F9E7C99DF7E4B62762A7480` | 3.213 | 0.02 % | 512 | 263 | `0x00014600` | `0x00016000` |
| **2** | `.data` | `126425A525E41E910B9358492365743A2330C7F260247AEA3F906E09B298490F` | 5.580 | 0.41 % | 11,264 | 11,300 | `0x00014800` | `0x00017000` |
| **3** | `a2` | `AF3AB617E13B364CA364C8A8192346E14E55A2271662E409424DBB415B1798B3` | 0.139 | 0.02 % | 512 | 10 | `0x00017400` | `0x0001A000` |
| **4** | `a3` | `0F2F59AFFEEC6B89C23DFF01782CBE898B57D866326E828C5952104BAD4BEB5C` | 1.157 | 89.96 % | 2,478,592 | 2,478,294 | `0x00017600` | `0x0001B000` |
| **5** | `a32` | `60AE7E06BA7EA296D2D0A11FD046BA9098E1673CCBB76B81C7E72752B4100862` | 4.845 | 0.04 % | 1,024 | 1,010 | `0x00274800` | `0x00279000` |
| **6** | `a322` | `B76B11A36D44B4C17175B5AE7E018B975E79F7B02EEB6E44B4F143316343A33A` | 5.474 | 4.61 % | 126,976 | 126,843 | `0x00274C00` | `0x0027A000` |
| **7** | `.rsrc` | `597AB4CED962CE1851893DF4A910C0F2A54D7A0034166CBF1006CA9153966D6C` | 3.632 | 1.88 % | 51,712 | 51,416 | `0x00293C00` | `0x00299000` |

### **Key Observations**

- **Space Efficiency:** The file has a total raw size of approximately **2.63 MB**, of which **2.36 MB** belongs solely to the `a3` section.
- **Entropy Alert:** Section `a3` shows extremely low entropy (**1.157**), indicating it is almost entirely redundant data (null bytes or repetitive padding), effectively "bloating" the file size.
- **Non-Standard PE Layout:** The sequential naming of `a2` through `a322` is a strong indicator of a custom packer or an obfuscation layer designed to make manual analysis more difficult.

---

### Imports

---

| **Library (DLL)** | **Function Name** | **Binding** | **Location (VA)** |
| --- | --- | --- | --- |
| **KERNEL32.dll** | `Sleep` | Implicit | `0x000188F8` |
|  | `GetLastError` | Implicit | `0x00018900` |
|  | `GetModuleHandleW` | Implicit | `0x00018910` |
|  | `LoadLibraryA` | Implicit | `0x00018924` |
|  | `GetProcAddress` | Implicit | `0x00018934` |
|  | `CreateMutexA` | Implicit | `0x00018946` |
|  | `VirtualAlloc` | Implicit | `0x00018A8E` |
|  | `WriteFile` | Implicit | `0x00018AAC` |
|  | `WinExec` | Implicit | `0x000190EE` |
|  | `CreateThread` | Implicit | `0x00018E26` |
| **USER32.dll** | `GetKeyState` | Implicit | `0x000193D4` |
|  | `GetAsyncKeyState` | Implicit | `0x000194B2` |
|  | `BlockInput` | Implicit | `0x00019450` |
|  | `wsprintfW` | Implicit | `0x00019530` |
|  | `SendMessageW` | Implicit | `0x0001953C` |
| **ADVAPI32.dll** | `RegOpenKeyExW` | Implicit | `0x000198E6` |
|  | `RegSetValueExW` | Implicit | `0x000199E0` |
|  | `CryptAcquireContextA` | Implicit | `0x0001994C` |
|  | `CryptGenRandom` | Implicit | `0x0001999A` |
|  | `CryptHashData` | Implicit | `0x00019A68` |
| **GDI32.dll** | `CreateSolidBrush` | Implicit | `0x00019664` |
|  | `DeleteObject` | Implicit | `0x000196F6` |
|  | `GetDeviceCaps` | Implicit | `0x0001985C` |
| **SHELL32.dll** | `ShellExecuteW` | Implicit | `0x00019B28` |
|  | `SHCreateProcessAsUserW` | Implicit | `0x00019AF8` |
| **SHLWAPI.dll** | `PathFindFileNameW` | Implicit | `0x00019B92` |
|  | `PathCombineW` | Implicit | `0x00019BBC` |
| **ole32.dll** | `CoTaskMemFree` | Implicit | `0x00019B66` |

| **Library (DLL)** | **Binding** | **Import Count** | **Description** |
| --- | --- | --- | --- |
| **KERNEL32.dll** | Implicit | 146 | Windows NT BASE API Client |
| **USER32.dll** | Implicit | 40 | Multi-User Windows USER API Client Library |
| **GDI32.dll** | Implicit | 37 | GDI Client Library |
| **ADVAPI32.dll** | Implicit | 33 | Advanced Windows 32 Base API |
| **SHELL32.dll** | Implicit | 6 | Windows Shell Library |
| **SHLWAPI.dll** | Implicit | 3 | Shell Light-weight Utility Library |
| **ole32.dll** | Implicit | 2 | Microsoft OLE for Windows |

### Analysis of Imports

Based on these specific function calls, the file possesses several notable capabilities:

- **Execution & Persistence:** The presence of `WinExec`, `CreateThread`, and `ShellExecuteW` indicates the ability to launch other processes or run code in parallel.
- **System Interference:** `BlockInput` (USER32) is a sensitive function often used by malware or utility tools to prevent the user from using their keyboard or mouse.
- **Cryptography:** The `ADVAPI32` imports (`CryptHashData`, `CryptGenRandom`) show the binary can generate or verify encrypted data and hashes.
- **File/Registry Activity:** Extensive use of `RegOpenKeyExW` and `WriteFile` suggests it can modify system settings and drop files to the disk.
- **Core Logic (KERNEL32):** With 146 imports, the bulk of the program's activity involves low-level system operations like memory management, file I/O, and process handling.
- **User Interface (USER32 & GDI32):** The 77 combined imports from these libraries indicate a graphical component, likely involving window management, drawing, and capturing user input.
- **Privileged Operations (ADVAPI32):** 33 imports here suggest significant interaction with the Windows Registry, service management, or cryptographic providers.
- **Shell Integration:** The inclusion of `SHELL32` and `SHLWAPI` suggests the program interacts with the Windows Explorer shell, likely for path manipulation or executing commands with higher-level shell functions.

---

## X32-DBG

---

load the sample in x32dbg hit f9 to get into user space. `ctrl + g`  go to `VirtualAlloc`

![Screenshot 2026-01-30 at 11.22.20 AM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_11.22.20_AM.png)

![Screenshot 2026-01-30 at 11.24.58 AM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_11.24.58_AM.png)

Set breakpoint, hit f9 until hit this breakpoint.

![Screenshot 2026-01-30 at 11.25.39 AM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_11.25.39_AM.png)

Then `ctrl + f9`   then `f8` to get back to userspcae.

![Screenshot 2026-01-30 at 11.41.19 AM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_11.41.19_AM.png)

In hexdump `ctrl + g`  follow eax.

![Screenshot 2026-01-30 at 11.48.01 AM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_11.48.01_AM.png)

Set breakpoint.

![Screenshot 2026-01-30 at 11.49.54 AM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_11.49.54_AM.png)

hit `f9` we can see first byte `8F` in the memory dump.

![Screenshot 2026-01-30 at 11.51.29 AM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_11.51.29_AM.png)

then hit `f9`  couple of times `7times`  we got this.

![Screenshot 2026-01-30 at 11.54.42 AM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_11.54.42_AM.png)

looks like an api lists.

![Screenshot 2026-01-30 at 11.56.09 AM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_11.56.09_AM.png)

I restarted the program disable VirtualAlloc breakpoint.

![Screenshot 2026-01-30 at 12.00.28 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_12.00.28_PM.png)

**`Inside VirtuallAlloc set Breakpoint, So Kernel32 Virtually calls Kernelbase Alloc`**

![Screenshot 2026-01-30 at 12.02.42 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_12.02.42_PM.png)

`F9`hit the break point

![Screenshot 2026-01-30 at 12.14.08 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_12.14.08_PM.png)

hit `ctrl + F9` and `F8` .

Then in memory dump `ctrl + g` Follow EAX.

![Screenshot 2026-01-30 at 12.15.52 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_12.15.52_PM.png)

Set break point

![Screenshot 2026-01-30 at 12.16.47 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_12.16.47_PM.png)

As before hit `f9` we see first byte `8F`

![Screenshot 2026-01-30 at 12.17.43 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_12.17.43_PM.png)

now hit `F9` until you see clear text in memory dump or a `virtualAlloc`

![Screenshot 2026-01-30 at 12.36.04 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_12.36.04_PM.png)

then `ctrl + f9` then `f8` .

in Memory dump2 Follow EAX set hardware breakpoint. hit f9 we can see the first byte

![Screenshot 2026-01-30 at 12.38.47 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_12.38.47_PM.png)

Continue hitting `f9` four times.

**`We get the MZ header`**

![Screenshot 2026-01-30 at 12.40.53 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_12.40.53_PM.png)

**`scrolling a bit after mz header end of the header the first section starts from 400 hex.`**

![Screenshot 2026-01-30 at 12.47.25 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_12.47.25_PM.png)

**`We can Verify it .text section begins with 400`**

![Screenshot 2026-01-30 at 12.58.49 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_12.58.49_PM.png)

---

### Dump Memory

---

![Screenshot 2026-01-30 at 1.05.49 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_1.05.49_PM.png)

---

### Now Some calculations

---

Open new dump file in any pe analyzer tool. 

![Screenshot 2026-01-30 at 2.39.29 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_2.39.29_PM.png)

---

**`Let’s focus on .reloc end section of the binary.`**

**`Fileoffset + Size`   `35400 + C00 = 36000`**

![Screenshot 2026-01-30 at 2.50.33 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_2.50.33_PM.png)

---

`We can verify offset 36000 it’s point to the end of the file.`

![Screenshot 2026-01-30 at 2.57.38 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-01-30_at_2.57.38_PM.png)

---

So we don’t need any cleanup.

---

## qakbot_023B0000.bin

---

### Basic properties

| **Property** | **Value** |
| --- | --- |
| **MD5** | `58e1c32eeb0130da19625e55ee48cf1e` |
| **SHA-1** | `00ae1c5066f67e5e71285de99bea8d8b67085743` |
| **SHA-256** | `f5ff6dbf5206cc2db098b41f5af14303f6dc43e36c5ec02604a50d5cfecf4790` |
| **Imphash** | `f83b544e96ab46c08e00b6dc80fbb352` |
| **Vhash** | `025056657d15755198z4506033z67z33z4fz` |
| **Rich Header Hash** | `39b9a9743747272230098b3403672606` |
| **SSDEEP** | `3072:4FCXMfyhFPZ8H7kJiIceKozOMeNJwOUJCfUfWcxQvAKChQztvWZZOtyFb8e:lXPFP6HWriMeN2rJCyWVDhM55` |
| **TLSH** | `T11324F1017293E5FBDA4600390A49117726B4EE312C738647F2D077BD69F689FDA35AC2` |
| **File Type** | Win32 EXE (PE32 executable, GUI) |
| **Compiler** | Microsoft Visual C/C++ (16.00.40219) [Visual Studio 2010] |
| **Linker** | Microsoft Linker (10.00) with LTCG (Link Time Code Generation) |
| **File Size** | 216.00 KB (221,184 bytes) |

### PE section

| **Index** | **Name** | **Entropy** | **File Ratio** | **Raw Size** | **Virtual Size** | **Raw Address (Begin)** | **Virtual Address** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **0** | `.text` | 6.386 | 17.82 % | 39,424 | 39,370 | `0x00000400` | `0x00001000` |
| **1** | `.rdata` | 7.515 | 9.26 % | 20,480 | 20,072 | `0x00009E00` | `0x0000B000` |
| **2** | `.data` | 4.390 | 0.69 % | 1,536 | 10,132 | `0x0000EE00` | `0x00010000` |
| **3** | `.rsrc` | 7.863 | 70.37 % | 155,648 | 155,612 | `0x0000F400` | `0x00013000` |
| **4** | `.reloc` | 5.475 | 1.39 % | 3,072 | 2,678 | `0x00035400` | `0x00039000` |

### Key Observations for the Decrypted File

- **Resource Dominance:** The `.rsrc` section now accounts for over **70%** of the file. Its extremely high entropy (**7.863**) suggests it contains compressed data, encrypted payloads, or high-resolution media.
- **Normalized Naming:** Unlike the encrypted version (which used non-standard names like `a2`, `a3`), this file uses standard Microsoft compiler section names (`.text`, `.rdata`, etc.), confirming a successful "unpacking" or "decryption."
- **Data Expansion:** In section `[2]` (`.data`), the virtual size (**10,132 bytes**) is significantly larger than the raw size (**1,536 bytes**). This is typical for uninitialized data or variables that expand in memory once the program is loaded.
- **Code Complexity:** The `.text` section (where the executable code resides) has an entropy of **6.386**, which is standard for a compiled C++ application.

---

### Decrypted Import Address Table Imports

---

| **Library (DLL)** | **Functions** |
| --- | --- |
| **KERNEL32.dll** | `GetLastError`, `GetProcAddress`, `LoadLibraryA`, `lstrcmpiW`, `GetModuleHandleA`, `CloseHandle`, `GetCurrentProcessId`, `GetEnvironmentVariableW`, `lstrlenA`, `WideCharToMultiByte`, `lstrcatA`, `GetEnvironmentVariableA`, `MultiByteToWideChar`, `lstrlenW`, `lstrcatW`, `lstrcpyA`, `HeapAlloc`, `HeapFree`, `HeapCreate`, `VirtualAlloc`, `GetFileSize`, `lstrcmpiA`, `GetModuleFileNameA`, `GetThreadContext`, `GetCurrentProcess`, `CreateEventA`, `LoadLibraryW`, `TerminateProcess`, `DeleteFileW`, `ResumeThread`, `ExpandEnvironmentStringsW`, `GetComputerNameW`, `GetVolumeInformationW`, `ReleaseMutex`, `GetExitCodeProcess`, `GetSystemTimeAsFileTime`, `SetEnvironmentVariableW`, `GetTickCount`, `GetModuleFileNameW`, `GetSystemInfo`, `SetEnvironmentVariableA`, `GetVersionExA`, `GetWindowsDirectoryW`, `SetEvent`, `OpenEventA`, `CopyFileW`, `TerminateThread`, `CreateThread`, `GetFileAttributesA`, `GetFileAttributesW`, `GetCurrentThread`, `LocalAlloc`, `GetLocalTime`, `LocalFree`, `lstrcpyW`, `CreateDirectoryW`, `SleepEx`, `WaitForSingleObject`, `FreeLibrary`, `GetDriveTypeW`, `lstrcmpA`, `GetCommandLineW`, `ExitProcess`, `lstrcpynW`, `Sleep`, `SystemTimeToFileTime`, `GetSystemTime`, `GetModuleHandleW`, `CreateMutexA` |
| **ADVAPI32.dll** | `RegOpenKeyExW`, `RegEnumValueW`, `RegDeleteValueW`, `RegQueryInfoKeyW`, `LookupAccountNameW`, `EqualSid`, `SetServiceStatus`, `RegUnLoadKeyW`, `RegLoadKeyW`, `ConvertSidToStringSidW`, `RegSetValueExW`, `RegQueryValueExW`, `SetSecurityDescriptorDacl`, `InitializeSecurityDescriptor`, `GetTokenInformation`, `RegisterServiceCtrlHandlerA`, `StartServiceCtrlDispatcherA`, `RegCloseKey`, `SetFileSecurityW`, `OpenProcessToken`, `GetSidSubAuthority`, `OpenThreadToken`, `GetSidSubAuthorityCount`, `LookupAccountSidW`, `CreateProcessAsUserW` |
| **USER32.dll** | `CharUpperBuffA`, `MessageBoxA`, `GetClassNameA`, `CharUpperBuffW` |
| **SHELL32.dll** | `SHGetFolderPathW`, `CommandLineToArgvW`, `ShellExecuteW` |
| **ole32.dll** | `CoInitialize`, `CoInitializeEx`, `CoInitializeSecurity`, `CoSetProxyBlanket`, `CoUninitialize`, `CoCreateInstance` |
| **NETAPI32.dll** | `NetApiBufferFree`, `NetUserEnum`, `NetGetDCName` |
| **SETUPAPI.dll** | `SetupDiEnumDeviceInfo`, `SetupDiDestroyDeviceInfoList`, `SetupDiGetClassDevsA`, `SetupDiGetDeviceRegistryPropertyA` |
| **msvcrt.dll** | `_vsnprintf`, `_ltoa`, `_except_handler3`, `memset`, `_vsnwprintf`, `memcpy` |
| **USERENV.dll** | `GetUserProfileDirectoryW` |

### Critical Behavioral Indicators

Analyzing these specific imports reveals the binary's core capabilities:

- **Process Hollowing/Injection:** The combination of `GetThreadContext`, `VirtualAlloc`, and `ResumeThread` is a classic signature for process hollowing, where the binary injects code into a suspended legitimate process.
- **Privilege Escalation & Identity:** Imports like `OpenProcessToken`, `GetTokenInformation`, and `CreateProcessAsUserW` suggest the ability to manipulate user tokens or run tasks with administrative/SYSTEM privileges.
- **Network Enumeration:** `NetUserEnum` and `NetGetDCName` indicate that the file is designed to query domain controllers and list users on a network, common in reconnaissance phases.
- **Persistence:** `StartServiceCtrlDispatcherA` and `SetServiceStatus` show the binary can operate as a Windows Service, allowing it to start automatically with the OS.
- **Hardware Profiling:** The `SETUPAPI.dll` imports suggest it is looking for specific hardware or drivers, possibly for environment keying or anti-VM checks.

---

---

## Sample 2

---

Sample: https://malshare.com/sample.php?action=detail&hash=1042f400ed776bc5d2c68becb386fb2ef3116417f96a67c14e8ca5b421ae7bc9

| **Property** | **Value** |
| --- | --- |
| **MD5** | `ce6d60aefd0bba037a50186818cc23cb` |
| **SHA-1** | `423155bd783bd5209f4ff05c23159fd75e2f4e5d` |
| **SHA-256** | `1042f400ed776bc5d2c68becb386fb2ef3116417f96a67c14e8ca5b421ae7bc9` |
| **Vhash** | `065086755555551d5f5510c1802007900ff6z156z1e0300fffz` |
| **Authentihash** | `1eaac19b0627e9e53c1df7f9671718f5fc161355d78104950abc96bdf8915030` |
| **Imphash** | `09516c081315a6de933d15f22a94d805` |
| **SSDEEP** | `12288:WTZ3ESbJAzTU+HjLI2UxI3JacfhLwVSZR0mjieAqTVc2xrW/f:AfJ8ThHjLZ3JxhL57ueAUVcarW/f` |
| **TLSH** | `T140E4CEB26BE40C26D69ACA7541611E177067FF0D2FC0580B6DC8E63BDA12BD9BCD1E48` |
| **File Type** | Win32 EXE (PE32 executable, GUI) |
| **TrID** | Win32 Executable MS Visual C++ (47.3%), Win64 Executable (15.9%) |
| **DetectItEasy** | PE32; Sign tool: Windows Authenticode (2.0) |
| **File Size** | 648.52 KB (664,080 bytes) |

### PE section

| **Index** | **Name** | **SHA-256 (Full)** | **Entropy** | **File Ratio** | **Raw Size (Bytes)** | **Virtual Size** | **Characteristics** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **0** | `.text` | `4EB5A21D4AA7DE4C2FCF4124FF224378F597DAF0B205E2F2680757BC46D74AA3` | 7.238 | 80.11% | 531,968 | 531,865 | Execute, Read |
| **1** | `.rdata4` | `1E8428ACD7003A0DF93471CE69B1CFD9A4A50D6D148AB95AB5E0E16C0FE14FB7` | 5.903 | 0.08% | 512 | 483 | Read |
| **2** | `.rdata3` | `1E8428ACD7003A0DF93471CE69B1CFD9A4A50D6D148AB95AB5E0E16C0FE14FB7` | 5.903 | 0.08% | 512 | 483 | Read |
| **3** | `.rdata2` | `1E8428ACD7003A0DF93471CE69B1CFD9A4A50D6D148AB95AB5E0E16C0FE14FB7` | 5.903 | 0.08% | 512 | 483 | Read |
| **4** | `.rdata` | `B17141BD9DEB3C6FBA87E5CE806D4CC11A98F8A5A4CB699296D4EBA8E608ADA2` | 3.378 | 0.08% | 512 | 280 | Read |
| **5** | `.data` | `57EA9046FE23666E1C9AA5C428B274D4F340B0D8FE6411D788E0ED570744E5D7` | 5.513 | 18.58% | 123,392 | 123,396 | Read, Write |
| **6** | `.rdata5` | `1E8428ACD7003A0DF93471CE69B1CFD9A4A50D6D148AB95AB5E0E16C0FE14FB7` | 5.903 | 0.08% | 512 | 483 | Read, Write, Exec* |
| **7** | `.rsrc` | `716AEBF3D58674C078A9F93F3A5D020AB0E7D33A072DBCDEC0E43A9C4C2F7ED7` | 5.903 | 0.62% | 4,096 | 3,824 | Read |

### Memory and Execution offsets

| **Item** | **Value** | **Section Association** |
| --- | --- | --- |
| **Entry Point** | `0x00082630` | Falls outside standard `.text` mapping |
| **Base of Code** | `0x00001000` | `.text` |
| **Base of Data** | `0x00083000` | `.rdata4` |
| **Import Directory** | `0x0009F870` | `.data` |
| **Resource Directory** | `0x000A7000` | `.rsrc` |
| **Import Address Table** | `0x000A06D4` | `.data` |
- **Identical Sections:** Sections `.rdata4`, `.rdata3`, `.rdata2`, and `.rdata5` share the **exact same SHA-256 hash**. This indicates these sections are likely duplicates or placeholders filled with the same static data.
- **High Code Entropy:** The `.text` section has an entropy of **7.238**. This is quite high for standard executable code and often suggests the code is either compressed or contains an embedded encrypted payload.
- **Self-Modifying / W+X Flag:** Section **.rdata5** is flagged for **Execute and Write** permissions and is marked as **self-modifying**. This is a significant indicator of a packer or a polymorphic engine.
- **Entry Point Anomaly:** The Entry Point is at `0x00082630`, which places it far beyond the `.text` section's virtual end. This suggests the execution starts in a later section (likely the self-modifying `.rdata5` or a custom tail), a common trait of packed malware.

---

### Imports

| **Library (DLL)** | **Notable Functions** |
| --- | --- |
| **KERNEL32.dll** | `VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`, `ReadProcessMemory`, `CreateProcessW`, `WinExec`, `CreateThread`, `Module32FirstW`, `GetThreadContext`, `SetThreadPriority`, `SleepEx`, `GetTickCount`, `QueryPerformanceFrequency`, `MapViewOfFile`, `CreateFileMappingW` |
| **USER32.dll** | `SetWindowsHookExW`, `GetAsyncKeyState`, `GetKeyState`, `GetForegroundWindow`, `OpenDesktopW`, `AttachThreadInput`, `keybd_event`, `OpenClipboard`, `GetClipboardData`, `EmptyClipboard`, `EnumDisplayMonitors` |
| **ADVAPI32.dll** | `RegCreateKeyExA`, `RegSetValueExA`, `RegDeleteValueA`, `RegDeleteKeyA`, `RegOpenKeyExA`, `RegFlushKey`, `RegQueryInfoKeyA` |
| **GDI32.dll** | `BitBlt`, `StretchBlt`, `CreateCompatibleBitmap`, `SelectObject`, `CreateCompatibleDC`, `GetDeviceCaps`, `DeleteObject` |
| **SHELL32.dll** | `ShellExecuteExW`, `SHCreateProcessAsUserW`, `SHChangeNotify`, `SHGetPathFromIDListW`, `DoEnvironmentSubstA` |
| **COMCTL32.dll** | `ImageList_BeginDrag`, `ImageList_DragMove`, `ImageList_DragEnter`, `ImageList_EndDrag`, `DPA_DeleteAllPtrs` |
| **ole32.dll** | `CoCreateInstance`, `CoInitializeEx`, `CoUninitialize`, `DoDragDrop` |

### MITRE ATT&CK Mapping

| **Tactic** | **Technique** | **ID** | **Indicators (API/Logic)** |
| --- | --- | --- | --- |
| **Persistence** | Boot or Logon Autostart Execution: Registry Run Keys | `T1547.001` | `RegCreateKeyExA`, `RegSetValueExA` |
| **Privilege Escalation** | Process Injection: Process Hollowing | `T1055.012` | `VirtualAllocEx`, `WriteProcessMemory`, `ResumeThread`, `GetThreadContext` |
| **Defense Evasion** | Obfuscated Files or Information: Software Packing | `T1027.002` | High entropy in `.text` (7.238), Self-modifying `.rdata5` section |
|  | Virtualization/Sandbox Evasion: Time-Based Evasion | `T1497.003` | `QueryPerformanceFrequency`, `GetTickCount` |
|  | Indicator Removal: File Deletion | `T1070.004` | `DeleteFileW`, `RemoveDirectoryW` |
| **Discovery** | System Information Discovery | `T1082` | `GetVersionExW`, `GetSystemInfo`, `GlobalMemoryStatusEx` |
|  | Process Discovery | `T1057` | `Module32FirstW` |
| **Collection** | Input Capture: Keylogging | `T1056.001` | `GetAsyncKeyState`, `GetKeyState` |
|  | Screen Capture | `T1113` | `BitBlt`, `StretchBlt`, `CreateCompatibleDC` |
|  | Archive Collected Data: Clipboard Data | `T1115` | `OpenClipboard`, `GetClipboardData` |
| **Execution** | Shared Modules | `T1129` | Extensive use of `LoadLibraryW` and `GetProcAddress` |

### Initial Observations

- **Signature:** Unlike the previous samples, this one explicitly mentions **Windows Authenticode**, indicating the file is (or claims to be) digitally signed.
- **Size:** At **~648 KB**, it is significantly smaller than your first sample's encrypted state but larger than the decrypted payload.
- **Tooling:** TrID suggests a high likelihood of **MS Visual C++** origin.

### Technical Summary:

This binary is a **digitally signed** Win32 executable that exhibits strong characteristics of a **packed surveillance tool** or **Remote Access Trojan (RAT)**.

---

### 1. Delivery & Structure

- **Packing Signature:** The high entropy in `.text` (**7.238**) and the existence of a **self-modifying, executable** section (`.rdata5`) indicate the core logic is encrypted or compressed.
- **Execution Anomaly:** The program starts at an unusual Entry Point (`0x00082630`) located outside the main code section, which is a classic indicator of a packer stub.
- **Size:** At **648 KB**, it is compact enough for quick delivery while containing significant functionality.

### 2. Core Capabilities (via Imports)

- **Code Injection:** It can manipulate other processes using `WriteProcessMemory` and `VirtualProtect`, likely to hide its presence within legitimate system tasks.
- **Information Theft:**
    - **Keylogging:** Monitors background keystrokes (`GetAsyncKeyState`).
    - **Clipboard Stealing:** Accesses and clears user clipboard data (`OpenClipboard`).
    - **Screen Grabbing:** Capable of capturing the desktop via GDI drawing functions.
- **Persistence:** Extensive Registry access (`ADVAPI32.dll`) suggests it modifies system "Run" keys to ensure it starts automatically upon reboot.

### 3. Operational Risk

The combination of **Keylogging**, **Clipboard access**, and **Screen capture** suggests this sample is designed for **credential harvesting** and user monitoring. Its ability to inject code further increases the risk of it evading standard task manager detection.

---

## Unpacking

---

### X32 DBG

Setting breakpoint on VirtuallAlloc

![Screenshot 2026-02-01 at 12.52.08 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_12.52.08_PM.png)

After hitting the breakpoint `ctrl + f9` and `f8`

![Screenshot 2026-02-01 at 12.54.13 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_12.54.13_PM.png)

Follow eax in memory dump.

![Screenshot 2026-02-01 at 12.56.28 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_12.56.28_PM.png)

Setting hardware breakpoints.

![Screenshot 2026-02-01 at 12.57.54 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_12.57.54_PM.png)

Then f9 we can see the first byte A4

![Screenshot 2026-02-01 at 12.59.06 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_12.59.06_PM.png)

hit f9 couple of times. until you see the MZ header decoded.

![Screenshot 2026-02-01 at 1.01.57 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_1.01.57_PM.png)

We can see the .text section starts from 400 hex

![Screenshot 2026-02-01 at 1.03.48 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_1.03.48_PM.png)

We will dump this.

![Screenshot 2026-02-01 at 1.05.36 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_1.05.36_PM.png)

Dump memory to file.

![Screenshot 2026-02-01 at 1.06.40 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_1.06.40_PM.png)

Open the the dumped bin file into pe bear.

last section .reloc

`Raw Addr. + Raw size`  

`0x40800 + 0x1600 = 0x41E00`

![Screenshot 2026-02-01 at 1.27.41 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_1.27.41_PM.png)

now open the file in hxd and go to offset `0x41E00` to verify.

We can see there are bytes after **`41E00`** because this unpacked file didn’t stopped at the end of the heap.

![Screenshot 2026-02-01 at 1.33.15 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_1.33.15_PM.png)

Select and delete everything after **`41E00`  and make surer to save it.**

![Screenshot 2026-02-01 at 1.39.41 PM.png](Unpacking%20Malware%20-%20Qakbot/Screenshot_2026-02-01_at_1.39.41_PM.png)

---

---