## Challenge Description

(1/24) * (1/60) * (1/60) , flag format:flag{xxxxxxxxxxxxxxxxxxxxxxxxx}

---

Let's start....................


### Basic File check...
```bash
┌──(lockon💀kali)-[~/ctf/pure-luck]
└─$ file pure-luck.out 
pure-luck.out: ELF 32-bit LSB executable, Intel i386, version 1 (GNU/Linux), statically linked, no section header

┌──(lockon💀kali)-[~/ctf/pure-luck]
└─$ checksec --file=pure-luck.out
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   No Symbols        No    0               0pure-luck.out
                
```

---

### Strings

<img width="543" height="246" alt="Screenshot 2025-10-15 at 10 24 47 AM" src="https://github.com/user-attachments/assets/bb03d96e-dc70-4eed-85cb-b9d029bd7fbb" />

---

**found UPX! … It means that it’s packed with upx.**

### Unpack it..

```bash
┌──(lockon💀kali)-[~/ctf/pure-luck]
└─$ upx -d pure-luck.out -o pure-luck
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.4       Markus Oberhumer, Laszlo Molnar & John Reiser    May 9th 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
[WARNING] bad b_info at 0x4312c

[WARNING] ... recovery at 0x43128

    741689 <-    300420   40.50%   linux/i386    pure-luck

Unpacked 1 file.
```

---

### Ghidra 


<img width="1440" height="870" alt="Screenshot 2025-10-15 at 10 43 19 AM" src="https://github.com/user-attachments/assets/045a4697-43c9-4d76-9d9d-29b3165db5c8" />


---

So we find some hexadecimal stuff. let's covert it into char.

```python3
import re

# Your original C code as a string
c_code = """
local_2c = 0x66;
local_2b = 0x6c;
local_2a = 0x61;
local_29 = 0x67;
local_28 = 0x7b;
local_27 = 0x55;
local_26 = 0x50;
local_25 = 0x58;
local_24 = 0x5f;
local_23 = 0x69;
local_22 = 0x73;
local_21 = 0x5f;
local_20 = 0x73;
local_1f = 0x6f;
local_1e = 0x5f;
local_1d = 0x65;
local_1c = 0x61;
local_1b = 0x61;
local_1a = 0x61;
local_19 = 0x61;
local_18 = 0x73;
local_17 = 0x79;
local_16 = 0x79;
local_15 = 0x7d;
"""

# Extract all hex values using regex
hex_pattern = r'0x([0-9a-fA-F]+)'
hex_matches = re.findall(hex_pattern, c_code)

# Convert hex strings to integers and then to characters
hex_values = [int(hex_str, 16) for hex_str in hex_matches]
result = ''.join(chr(x) for x in hex_values)

print(f"Extracted hex values: {hex_matches}")
print(f"Converted string: {result}")

```

---


```bash
┌──(lockon💀kali)-[~/ctf/pure-luck]
└─$ python3 extract-flag.py 
Extracted hex values: ['66', '6c', '61', '67', '7b', '55', '50', '58', '5f', '69', '73', '5f', '73', '6f', '5f', '65', '61', '61', '61', '61', '73', '79', '79', '7d']
Converted string: flag{UPX_is_so_eaaaasyy}
```

---
