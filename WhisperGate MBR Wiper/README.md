# Analyzing WhisperGate MBR Wiper

---

## Executive Summary

**WhisperGate** is a critical destructive wiper deployed by the **Russian GRU (Unit 29155)** against **Ukrainian government and IT infrastructure** in January 2022. While it masquerades as ransomware with a $10,000 Bitcoin demand, its true intent is geopolitical sabotage through permanent system neutralization.

The malware gains administrative access to **`\\.\PhysicalDrive0`** to overwrite the Master Boot Record (MBR) with a malicious 16-bit bootloader and a fake ransom note. Forensic analysis confirms the absence of encryption logic; instead, it intentionally destroys partition tables and enters an infinite disk-read loop using **BIOS Interrupt 13h**. This "False Flag" operation was designed to brick systems and cause widespread operational chaos as a prelude to physical conflict, making data recovery technically impossible.

## File Information: WhisperGate - Stage 1

| **Property** | **Value** |
| --- | --- |
| **MD5** | `5d5c99a08a7d927346ca2dafa7973fc1` |
| **SHA-1** | `189166d382c73c242ba45889d57980548d4ba37e` |
| **SHA-256** | `a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92` |
| **Vhash** | `0240876d55155c0d5d1d1az1502=z` |
| **Authentihash** | `589ac7405e8562a501cd8c13339e58f226ff0448de3569853314bd7bfbc5a244` |
| **Imphash** | `3a2a2de20daa74d8f6921230416ed4e6` |
| **SSDEEP** | `384:hgvApUHEZKu08YtQI4GS1dxRBUHCHCHCHCHCHCHCHCHCHCHCHCHCHCHCHfskp2BD:ivmUHEZ4yVUiiiiiiiiiiiiiii9pd` |
| **TLSH** | `T192C22A89F2494DE9F062C7B514DB9FB2EE62992244116BA3CB2DE3BCCE3B3415D13521` |
| **File Type** | Win32 EXE (executable, windows, win32, pe, peexe) |
| **Magic** | PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows |
| **TrID** | Win32 Executable MS Visual C++ (generic) (39.7%), Microsoft Visual C++ compiled executable (generic) (21%), Win32 Dynamic Link Library (generic) (8.3%), Win64 Executable (generic) (8.3%), Win16 NE executable (generic) (6.4%) |
| **DetectItEasy** | PE32, Compiler: MinGW (GCC: (GNU) 6.3.0), Linker: GNU linker ld (2.28) [GUI32] |
| **Magika** | PEBIN |
| **File Size** | 27.00 KB (27648 bytes) |

### Sections

| **Name** | **Virtual Address** | **Virtual Size** | **Raw Size** | **Entropy** | **MD5 Hash** | **Chi2** |
| --- | --- | --- | --- | --- | --- | --- |
| **.text** | 4096 | 11332 | 11776 | 6.05 | `2036a3ec8d69332516af7a45bd0e95d1` | 136842.94 |
| **.data** | 16384 | 8248 | 8704 | 5.71 | `c347e1c3a12f8e09e1bd14dd6a2508c5` | 70506.57 |
| **.rdata** | 28672 | 760 | 1024 | 4.01 | `2d7762721cd6d861442eeb34045e7b05` | 41907.5 |
| **.eh_fram** | 32768 | 2496 | 2560 | 4.78 | `f3fa60eb8140371a44c211d821bb7032` | 62734.62 |
| **.bss** | 36864 | 112 | 0 | 0.00 | `d41d8cd98f00b204e9800998ecf8427e` | -1 |
| **.idata** | 40960 | 1524 | 1536 | 4.68 | `b9343cdc3e0b143e68a7c8822a9bcd7d` | 52219.48 |
| **.CRT** | 45056 | 24 | 512 | 0.10 | `9613b19b86f9cff884c127d7bedc1359` | 128016.00 |
| **.tls** | 49152 | 32 | 512 | 0.22 | `91bcf9f4179ab79fbfbb4634d5a90f70` | 124501.00 |

### Imports

| **Library** | **Key Functions** | **Potential Capability** |
| --- | --- | --- |
| **KERNEL32.dll** | `CreateFileW`, `WriteFile`, `CloseHandle` | **File Manipulation:** Critical for overwriting the MBR (e.g., targeting `\\.\PhysicalDrive0`) or destroying files. |
|  | `FindFirstFileA`, `FindNextFileA`, `FindClose` | **File Discovery:** Used to scan the drive for specific file extensions to target for destruction. |
|  | `VirtualProtect`, `VirtualQuery` | **Memory Management:** Often used in Stage 2/3 to change memory permissions for code injection or unpacking payloads. |
|  | `LoadLibraryA`, `GetProcAddress` | **Dynamic Loading:** Allows the malware to call other functions at runtime that are not visible in this static import list. |
|  | `SetUnhandledExceptionFilter` | **Anti-Analysis:** Can be used to intercept debugger events or handle crashes during malicious execution. |
| **msvcrt.dll** | `malloc`, `calloc`, `free`, `realloc` | **Memory Allocation:** Standard C-runtime functions for managing buffers during file reading/writing. |
|  | `memcpy`, `strlen`, `tolower` | **Data Processing:** String and buffer manipulation, likely for comparing file extensions or obfuscating paths. |
|  | `_fullpath` | **Path Resolution:** Getting the absolute path of files to ensure they are correctly targeted for deletion/overwriting. |

### Strings

![Screenshot 2026-05-07 at 9.43.16 PM.png](Analyzing%20WhisperGate%20MBR%20Wiper/Screenshot_2026-05-07_at_9.43.16_PM.png)

```c
19	32a8	004040a8	Section(1)['.data']	23	A	Your hard drive has been corrupted.
20	32cd	004040cd	Section(1)['.data']	2b	A	In case you want to recover all hard drives
21	32fa	004040fa	Section(1)['.data']	15	A	of your organization,
22	3311	00404111	Section(1)['.data']	2a	A	You should pay us  $10k via bitcoin wallet
23	333d	0040413d	Section(1)['.data']	37	A	1AVNM68gj6PGPFcJuftKATa4WLnzg8fpfv and send message via
24	3376	00404176	Section(1)['.data']	53	A	tox ID 8BEDC411012A33BA34F49130D0F186993C6A32DAD8976F6A5D82C1ED23054C057ECED5496F65
25	33cb	004041cb	Section(1)['.data']	1c	A	with your organization name.
26	33e9	004041e9	Section(1)['.data']	31	A	We will contact you to give further instructions.
27	34a2	004042a2	Section(1)['.data']	05	A	AAAAA
28	34a8	004042a8	Section(1)['.data']	23	A	Your hard drive has been corrupted.
29	34cd	004042cd	Section(1)['.data']	2b	A	In case you want to recover all hard drives
```

### Malware Profile: WhisperGate Destructive Loader

This **27 KB Win32 PE** executable acts as a destructive bootloader. While it presents itself as ransomware to create operational confusion, its mechanical design is purely for **permanent system sabotage**.

### Technical Breakdown

- **The Ransom Deception (False Flag):**
The `.data` section contains a hardcoded ransom note demanding **$10,000 USD** in Bitcoin to a specific wallet (`1AVNM68...`). Because the malware uses `WriteFile` to overwrite the MBR with this static text rather than an encryption key, the system is rendered unrecoverable. There is no decryption routine; the note is a psychological distraction.
- **Infrastructure & Attribution:**
    - **Payment:** BTC Wallet `1AVNM68gj6PGPFcJuftKATa4WLnzg8fpfv`.
    - **Communication:** Tox ID **`8BEDC411012A33BA34F49130D0F186993C6A32DAD8976F6A5D82C1ED23054C057ECED5496F65`** (An encrypted, peer-to-peer protocol).
    - **Targeting:** The specific phrasing—*"of your organization"*—indicates this was designed for high-impact targeting of corporate or government infrastructures.
- **Execution Mechanism:**
    1. **Privilege Escalation:** Uses `VirtualProtect` to prep memory.
    2. **Device Access:** Opens a handle to the physical drive via `CreateFileW`.
    3. **Wiping:** Executes the destructive payload by writing the ransom strings directly into the drive’s boot sectors.
    4. **System Death:** Once the machine reboots, the legitimate OS loader is gone, replaced by the static strings found in your analysis.

---

## Ghidra Analysis

Following WriteFile

![Screenshot 2026-05-08 at 1.02.53 AM.png](Analyzing%20WhisperGate%20MBR%20Wiper/Screenshot_2026-05-08_at_1.02.53_AM.png)

Which actually reference to the function: **`FUN_00403b60`**

---

```c
/* 
 * WhisperGate Stage 1: MBR Overwrite Routine
 * Function: FUN_00403b60
 * Description: Directly targets the physical drive to replace the 
 * Master Boot Record with a malicious payload.
 */

undefined4 FUN_00403b60(void)
{
  int iVar1;
  uint uVar2;
  HANDLE pvVar3;
  BOOL BVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 local_2020 [2050]; // Main 8KB buffer to hold the destructive payload
  undefined1 *apuStack_18 [2];
  DWORD DStack_4;
  
  // --- Stack Initialization ---
  apuStack_18[1] = &stack0x00000004;
  apuStack_18[0] = (undefined1 *)0x403b7a;
  
  // Dynamic stack adjustment used to obfuscate variable locations
  uVar2 = FUN_00401fe0();
  iVar1 = -uVar2;
  *(undefined4 *)((int)apuStack_18 + iVar1) = 0x403b8c;
  
  // Potential environment check or anti-analysis routine
  FUN_00401990();

  // --- Payload Staging ---
  // Copies the malicious bootloader/fake ransom note from global data (DAT_00404020)
  // 0x800 (2048) bytes are moved into the local stack buffer.
  puVar6 = &DAT_00404020;
  puVar7 = local_2020;
  for (iVar5 = 0x800; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar7 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar7 = puVar7 + 1;
  }

  // --- Parameter Preparation for CreateFileW ---
  // Manually pushing arguments onto the stack for the raw disk handle call
  *(undefined4 *)(&stack0x00000004 + iVar1) = 0;          // hTemplateFile: NULL
  *(undefined4 *)(&stack0x00000000 + iVar1) = 0;          // dwFlagsAndAttributes: 0
  *(undefined4 *)((int)&DStack_4 + iVar1) = 3;            // dwCreationDisposition: OPEN_EXISTING
  *(undefined4 *)(&stack0xfffffff8 + iVar1) = 0;          // lpSecurityAttributes: NULL
  *(undefined4 *)(&stack0xfffffff4 + iVar1) = 3;            // dwShareMode: FILE_SHARE_READ | FILE_SHARE_WRITE
  *(undefined4 *)(&stack0xfffffff0 + iVar1) = 0x10000000; // dwDesiredAccess: GENERIC_ALL (Raw Write Access)
  
  // Target: The raw physical disk device instead of a file
  *(wchar_t **)((int)apuStack_18 + iVar1 + 4) = L"\\\\.\\PhysicalDrive0";

  // --- Obtain Handle to Raw Disk ---
  pvVar3 = CreateFileW(*(LPCWSTR *)((int)apuStack_18 + iVar1 + 4),
                       *(DWORD *)(&stack0xfffffff0 + iVar1),
                       *(DWORD *)(&stack0xfffffff4 + iVar1),
                       *(LPSECURITY_ATTRIBUTES *)(&stack0xfffffff8 + iVar1),
                       *(DWORD *)((int)&DStack_4 + iVar1),
                       *(DWORD *)(&stack0x00000000 + iVar1),
                       *(HANDLE *)(&stack0x00000004 + iVar1));

  // --- Execute the Wipe ---
  *(HANDLE *)((int)apuStack_18 + iVar1 + 4) = pvVar3;     // Handle to disk
  *(undefined4 *)((int)&DStack_4 + iVar1) = 0;            // lpOverlapped: NULL
  *(undefined4 *)(&stack0xfffffff8 + iVar1) = 0;          // lpNumberOfBytesWritten: NULL
  *(undefined4 *)(&stack0xfffffff4 + iVar1) = 0x200;      // nNumberOfBytesToWrite: 512 (MBR Size)
  *(undefined4 **)(&stack0xfffffff0 + iVar1) = local_2020; // Source: malicious buffer

  // Perform the overwrite: Sector 0 is replaced with the fake ransom note
  WriteFile(*(HANDLE *)((int)apuStack_18 + iVar1 + 4),
            *(LPCVOID *)(&stack0xfffffff0 + iVar1),
            *(DWORD *)(&stack0xfffffff4 + iVar1),
            *(LPDWORD *)(&stack0xfffffff8 + iVar1),
            *(LPOVERLAPPED *)((int)&DStack_4 + iVar1));

  // --- Closure ---
  // Commit changes and close the handle. The system is now unbootable.
  *(HANDLE *)((int)apuStack_18 + iVar1 + 4) = pvVar3;
  BVar4 = CloseHandle(*(HANDLE *)((int)apuStack_18 + iVar1 + 4));
  
  return 0;
}
```

### Description

This function, `FUN_00403b60`, is the **primary execution engine** for the WhisperGate wiper. Its sole purpose is to gain low-level access to the machine's primary hard drive and overwrite the **Master Boot Record (MBR)** with a malicious payload, effectively "bricking" the operating system.

### Full Functional Breakdown

1. **Stack and Variable Initialization:**
The function begins by calculating stack offsets and allocating a local buffer, `local_2020`, which is roughly 8KB in size. This buffer is designed to hold the data that will be forcibly written to the hardware.
2. **Payload Staging (The Loop):**
The malware enters a `for` loop that iterates **2,048 times** (`0x800`). It copies data from a global data segment (`DAT_00404020`) which contains the fake ransom note and malicious boot code into the local `local_2020` stack buffer. This ensures the destructive payload is ready in memory.
3. **Hardware Access via `CreateFileW`:**
It attempts to open a handle to `\\.\PhysicalDrive0`. This is a critical "Red Flag" indicator; by targeting the physical drive instead of a specific file, the malware is bypassing the Windows File System (NTFS/FAT32). It requests **Generic Write** permissions (`0x10000000`) and uses a **Share Mode of 3** to ensure it can access the drive even while the OS is running.
4. **The Destructive Write (`WriteFile`):**
Once the handle is acquired, it calls `WriteFile`. It targets the very first sector of the disk by writing exactly **512 bytes** (`0x200`) from its memory buffer. This action destroys the legitimate MBR—which contains the partition table and the boot instructions—and replaces it with the "ransom" note you found earlier.
5. **Finalization:**
The function concludes by calling `CloseHandle` to commit the changes to the disk and then returns.

---

what’s inside `DAT_00404020` 

![Screenshot 2026-05-08 at 1.37.01 AM.png](Analyzing%20WhisperGate%20MBR%20Wiper/Screenshot_2026-05-08_at_1.37.01_AM.png)

---

We can copy the bytes and paste it into Hxd.

now we have the full buffer which is being overwritten by the malware.

![Screenshot 2026-05-08 at 1.42.03 AM.png](Analyzing%20WhisperGate%20MBR%20Wiper/Screenshot_2026-05-08_at_1.42.03_AM.png)

The MBR (Master Boot Record) end signature is a 2-byte sequence, **`0x55AA`**, located at the very end of the first 512-byte sector of a bootable disk (bytes 511 and 512). This signature acts as a "bootable" marker, allowing the BIOS to identify the sector as a valid MBR.

---

We can verify it by saving the file.

![Screenshot 2026-05-08 at 1.46.28 AM.png](Analyzing%20WhisperGate%20MBR%20Wiper/Screenshot_2026-05-08_at_1.46.28_AM.png)

---

## MBR Analysis

Now let’s load our newly saved file in ghidra.

Select Real Mode Language.

![Screenshot 2026-05-08 at 2.14.17 AM.png](Analyzing%20WhisperGate%20MBR%20Wiper/Screenshot_2026-05-08_at_2.14.17_AM.png)

---

#### MBR Entry point is at address **`0x7C00`**

Add this i n ghidra.

![Screenshot 2026-05-08 at 2.19.24 AM.png](Analyzing%20WhisperGate%20MBR%20Wiper/Screenshot_2026-05-08_at_2.19.24_AM.png)

---

Disassemble it .

![Screenshot 2026-05-08 at 2.21.04 AM.png](Analyzing%20WhisperGate%20MBR%20Wiper/Screenshot_2026-05-08_at_2.21.04_AM.png)

---

This snippet reveals a classic, low-level routine commonly found in custom bootloaders or malicious MBR payloads. Since the MBR executes in **Real Mode** before the operating system starts, it relies on BIOS interrupts to interact with hardware.

![Screenshot 2026-05-08 at 2.26.13 AM.png](Analyzing%20WhisperGate%20MBR%20Wiper/Screenshot_2026-05-08_at_2.26.13_AM.png)

This function is a wrapper for a specific BIOS service designed to print text to the screen during the boot process.

| **Instruction** | **Technical Detail** | **Purpose** |
| --- | --- | --- |
| **`MOV AH, 0xe`** | Sets the high byte of the Accumulator register to `0x0E`. | Selects **Teletype Output** mode for the Video Service. |
| **`INT 0x10`** | Triggers BIOS Interrupt `0x10`. | Executes the Video Service to print the character currently stored in the `AL` register. |
| **`RET`** | Near Return. | Returns control to the calling function. |

### Another Interrupt

![Screenshot 2026-05-08 at 2.35.08 AM.png](Analyzing%20WhisperGate%20MBR%20Wiper/Screenshot_2026-05-08_at_2.35.08_AM.png)

It uses **BIOS Interrupt 13h**, which is the low-level service for disk operations.

Specifically, it is calling the **Extended Read** function to load more data from the disk into memory, which likely facilitates the transition from the 512-byte MBR to the larger destructive payload.

| **Instruction** | **Technical Detail** | **Purpose** |
| --- | --- | --- |
| **`MOV AH, 0x43`** | Sets Function ID to `0x43`. | Selects **Extended Read** (LBA mode). This allows the malware to read sectors beyond the standard 8GB limit of older BIOS calls. |
| **`MOV AL, 0x0`** | Clear AL. | Standard initialization for the interrupt call. |
| **`MOV DL, [7c87]`** | Get drive index. | Loads the drive number. `0x80` usually represents the first physical hard drive. |
| **`ADD DL, 0x80`** | Ensure HDD targeting. | Force-adjusts the register to target a physical hard drive rather than a floppy disk. |
| **`MOV SI, 7c72`** | Load DAP pointer. | Points to a **Disk Address Packet (DAP)**. This structure contains the number of sectors to read and the destination memory address. |
| **`INT 0x13`** | Execute Disk Service. | Tells the BIOS to perform the read operation defined in the DAP. |
| **`JC / JNC`** | Jump on Carry flag. | **Error Handling:** If the read fails, the Carry flag is set (`JC`), and it jumps to an error handler. If successful (`JNC`), it continues to the payload execution. |

## **Technical Analysis: WhisperGate Stage 1 (MBR Wiper)**

**1. Attack Mechanism (Host-Level)**
The initial stage of the malware is a 32-bit Windows executable. Its primary function is to gain raw access to the physical storage and overwrite the boot sector.
**Key Code Routine:**
The function `FUN_00403b60` performs the "kill" operation. It prepares a buffer of **2,048 bytes** containing malicious code and a fake ransom note.
• **Target Device:** `\\.\PhysicalDrive0` (Raw disk access)
• **Write Size:** `0x200` (512 bytes)
• **Primary API:** `WriteFile`
• **Impact:** Overwrites **Sector 0 (MBR)**, destroying the partition table and legitimate boot instructions.

**2. Payload Analysis (Pre-Boot Environment)**
Once the system reboots, the BIOS executes the malicious 16-bit code written to the MBR. This code acts as a custom, destructive bootloader.

**A. User Deception (Screen Output)**
The malware uses **BIOS Interrupt 10h** (Video Services) to display a ransom demand. This is a "False Flag" intended to disguise a targeted destruction attack as a criminal ransomware attempt.
• **Routine:** `INT 0x10, AH=0x0E` (Teletype Output)
• **Payload String:** *"Your hard drive has been corrupted..."*
• **Wallet:** `1AVNM68gj6PGPFcJuftKATa4WLnzg8fpfv`

**B. Low-Level Disk Hammering**
After displaying the message, the code enters an infinite loop using **BIOS Interrupt 13h** to repeatedly read distant sectors of the disk.**InstructionHexFunction**`MOV AH, 0x43B4 43`Extended Disk Read (LBA Mode)`INT 0x13CD 13`Triggers the physical read request`ADD [LBA], 0xC781 06 ... C7`Shifts the target sector to hammer the disk

**3. Conclusion and Severity**
This sample is a **high-confidence wiper**.

1. **Irreversibility:** It does not back up the original MBR or encrypt it; it simply overwrites the data with static text and "A" characters (`0x41`).
2. **Bricking:** The deletion of the partition table (`0x55AA` signature remains, but the table itself is gone) means that the Operating System is logically disconnected from the hardware.
3. **Deception:** The ransomware elements are purely cosmetic and provide no functional decryption path.

---

## IOCs: WhisperGate Stage 1

### **File Metadata & Hashes**

| **Type** | **Hash / Value** |
| --- | --- |
| **MD5** | `5d5c99a08a7d927346ca2dafa7973fc1` |
| **SHA-1** | `189166d382c73c242ba45889d57980548d4ba37e` |
| **SHA-256** | `a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92` |
| **Imphash** | `3a2a2de20daa74d8f6921230416ed4e6` |
| **SSDEEP** | `384:hgvApUHEZKu08YtQI4GS1dxRBUHCHCHCHCHCHCHCHCHCHCHCHCHCHCHCHfskp2BD:ivmUHEZ4yVUiiiiiiiiiiiiiii9pd` |

### **Network & Attribution Indicators**

Hardcoded strings found within the malware's data segment, used for the fake ransomware facade.
• **Bitcoin (BTC) Wallet:** `1AVNM68gj6PGPFcJuftKATa4WLnzg8fpfv`
• **Tox ID:** `8BEDC411012A33BA34F49130D0F186993C6A32DAD8976F6A5D82C1ED23054C057ECED5496F65`
• **Note Phrasing:** "Your hard drive has been corrupted. In case you want to recover all hard drives of your organization..."

### **Host-Based & Behavioral Indicators (HBI)**

These patterns indicate active execution or successful infection on an endpoint.
• **Device Access:** Unauthorized processes opening a handle to `\\.\PhysicalDrive0` with `GENERIC_WRITE` permissions.
• **Artifacts:** A 512-byte overwrite of Sector 0 (MBR) that includes the plaintext "Your hard drive has been corrupted" starting at offset `0x7C88` (when loaded in memory).
• **Partition Table Destruction:** The traditional partition table entries (offsets `0x1BE` through `0x1FD` in the MBR) are filled with static bytes, specifically `0x41` ("A").
• **Boot Signature:** Presence of the standard boot signature `55 AA` at the end of a corrupted/malicious MBR.

### **Technical Artifacts (MBR Code)**

Specific 16-bit instructions within the dumped MBR that signal malicious "disk hammering" behavior:
• **Opcode Pattern:** `B4 43 B0 00` (Setup for `INT 0x13, AH=43h` - Extended Read).
• **Interrupt:** `CD 13` (BIOS Disk Service call).
• **LBA Modification:** `81 06 7A 7C C7 00` (Adding `0xC7` to the Logical Block Address to shift the read target).

---