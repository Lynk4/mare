# ELF Master

---

### file check:

```bash
┌──(lockon💀kali)-[~/ctf/elf-master]
└─$ file ELF+Master 
ELF+Master: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID[sha1]=d761599d626ef54b1c89efe653b0ff69d94a3140, for GNU/Linux 
3.2.0, stripped
                              
```

---

### Binary Ninja

<img width="1440" height="861" alt="Screenshot 2025-10-15 at 11 30 46 AM" src="https://github.com/user-attachments/assets/3174fb27-1f0e-4b60-97dd-858e395c299b" />

---

XORs the byte with 0x99

### Cyber chef

<img width="1041" height="480" alt="Screenshot 2025-10-15 at 11 34 50 AM" src="https://github.com/user-attachments/assets/9d2bb485-4c2d-4f13-9221-68c9865cf0e9" />

---

### flag: flag{D0_1_L00k_L1k3_4n_3LF_M4st3r}

---
