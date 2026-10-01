const fs = require('fs');
const path = require('path');

const thumbsDir = path.join(__dirname, 'reports', 'assets', 'thumbs');
if (!fs.existsSync(thumbsDir)) {
  fs.mkdirSync(thumbsDir, { recursive: true });
}

// Data definitions for all 30 report thumbnails
const cardSpecs = [
  // macOS Reports
  {
    id: 'digit-stealer',
    title: 'DIGIT STEALER',
    theme: 'blue',
    badgeLeft: 'MACOS 14+',
    badgeRight: 'IN-MEMORY JXA',
    cmd: 'dig +short TXT @8.8.8.8',
    iconType: 'chip-lock'
  },
  {
    id: 'atomic-macos-stealer',
    title: 'ATOMIC STEALER (AMOS)',
    theme: 'blue',
    badgeLeft: 'MACOS ARM64',
    badgeRight: 'XOR DECRYPT',
    cmd: 'xmm0 XOR 0x5A6B7C',
    iconType: 'keychain'
  },
  {
    id: 'kitty-stealer',
    title: 'KITTY STEALER',
    theme: 'cyan',
    badgeLeft: 'MACOS UNIVERSAL',
    badgeRight: 'CREDENTIALS',
    cmd: '~/Library/Keychains/login',
    iconType: 'browser-vault'
  },
  {
    id: 'rustbucket',
    title: 'RUSTBUCKET',
    theme: 'purple',
    badgeLeft: 'APT // LAZARUS',
    badgeRight: 'UNIVERSAL 2',
    cmd: 'BlueNoroff Mach-O Triage',
    iconType: 'reticle'
  },
  {
    id: 'macho-static-analysis',
    title: 'MACHO STATIC ANALYSIS',
    theme: 'cyan',
    badgeLeft: 'MACOS REVERSE',
    badgeRight: 'DYLD HOOK',
    cmd: 'dyld_stub_binder [ARM64]',
    iconType: 'binary-tree'
  },

  // Linux Reports
  {
    id: 'mirai-botnet',
    title: 'MIRAI BOTNET VARIANT',
    theme: 'amber',
    badgeLeft: 'LINUX ARM32',
    badgeRight: 'UPX UNPACK',
    cmd: 'telnet :23 brute-force',
    iconType: 'botnet-swarm'
  },
  {
    id: 'bpfdoor',
    title: 'BPFDOOR BACKDOOR',
    theme: 'purple',
    badgeLeft: 'LINUX ROOTKIT',
    badgeRight: 'RAW SOCKET',
    cmd: 'BPF bytecode packet sniffer',
    iconType: 'packet-filter'
  },

  // Windows Reports - C2 & APT
  {
    id: 'cobalt-strike-beacon',
    title: 'COBALT STRIKE',
    theme: 'blue',
    badgeLeft: 'WIN64 C2',
    badgeRight: 'EARLY BIRD APC',
    cmd: 'QueueUserAPC(pShellcode)',
    iconType: 'beacon-radar'
  },
  {
    id: 'regin-malware',
    title: 'REGIN APT',
    theme: 'purple',
    badgeLeft: 'STATE-SPONSORED',
    badgeRight: 'VFS STAGE 1',
    cmd: 'Modular VFS Ring-0 Driver',
    iconType: 'modular-core'
  },
  {
    id: 'bangladesh-gpca',
    title: 'BANGLADESH GPCA',
    theme: 'purple',
    badgeLeft: 'BANKING ESPIONAGE',
    badgeRight: 'RECONNAISSANCE',
    cmd: 'Recon & Lateral Infiltration',
    iconType: 'reticle'
  },
  {
    id: 'notepad-chrysalis',
    title: 'NOTEPAD++ CHRYSALIS',
    theme: 'amber',
    badgeLeft: 'SUPPLY CHAIN',
    badgeRight: 'DLL HIJACK',
    cmd: 'SciLexer.dll Proxy Hook',
    iconType: 'chain-hijack'
  },

  // Windows Reports - Ransomware & Wipers
  {
    id: 'whispergate',
    title: 'WHISPERGATE WIPER',
    theme: 'red',
    badgeLeft: 'DESTRUCTIVE',
    badgeRight: 'MBR CORRUPT',
    cmd: 'Sector 0x00 Overwrite (Wipe)',
    iconType: 'mbr-skull'
  },
  {
    id: 'wannacry',
    title: 'WANNACRY RANSOMWARE',
    theme: 'red',
    badgeLeft: 'WORM LOCKER',
    badgeRight: 'MS17-010',
    cmd: 'EternalBlue SMBv1 Exploit',
    iconType: 'ransom-vault'
  },
  {
    id: 'notpetya',
    title: 'NOTPETYA WIPER',
    theme: 'red',
    badgeLeft: 'CYBER WEAPON',
    badgeRight: 'SALSA20 CIPHER',
    cmd: 'Disk Sector Zero Overwrite',
    iconType: 'mbr-skull'
  },
  {
    id: 'api-unhooking',
    title: 'API UNHOOKING',
    theme: 'cyan',
    badgeLeft: 'EDR EVASION',
    badgeRight: 'NTDLL RESTORE',
    cmd: 'Syscall Stub Patch Overwrite',
    iconType: 'unhook-trampoline'
  },

  // Windows Reports - Banking & Backdoors
  {
    id: 'etherrat',
    title: 'ETHERRAT',
    theme: 'blue',
    badgeLeft: 'BLOCKCHAIN C2',
    badgeRight: 'SMART CONTRACT',
    cmd: 'Ethereum RPC :8545 Beacon',
    iconType: 'blockchain-c2'
  },
  {
    id: 'zeus-trojan',
    title: 'ZEUS BANKING TROJAN',
    theme: 'amber',
    badgeLeft: 'FINANCIAL THREAT',
    badgeRight: 'WEB INJECT',
    cmd: 'Man-in-the-Browser API Hook',
    iconType: 'browser-vault'
  },
  {
    id: 'agent-tesla',
    title: 'AGENT TESLA',
    theme: 'blue',
    badgeLeft: 'INFOSTEALER',
    badgeRight: 'CVE-2017-11882',
    cmd: 'SMTP / FTP Keystroke Exfil',
    iconType: 'keychain'
  },
  {
    id: 'sillyputty',
    title: 'SILLYPUTTY BACKDOOR',
    theme: 'cyan',
    badgeLeft: 'PERSISTENCE',
    badgeRight: 'REVERSE SHELL',
    cmd: 'PuTTY.exe Trojanized Thread',
    iconType: 'chain-hijack'
  },
  {
    id: 'npm-axios',
    title: 'NPM AXIOS ATTACK',
    theme: 'amber',
    badgeLeft: 'CROSS-PLATFORM',
    badgeRight: 'SUPPLY CHAIN',
    cmd: 'npm postinstall.js RAT Hook',
    iconType: 'chain-hijack'
  },

  // Windows Reports - Reverse Engineering & Unpacking
  {
    id: 'reverse-engineering-packed-trojan',
    title: 'PACKED TROJAN RE',
    theme: 'cyan',
    badgeLeft: 'GHIDRA / X64DBG',
    badgeRight: 'OEP UNPACK',
    cmd: 'JMP [EAX] -> Original Entry',
    iconType: 'binary-tree'
  },
  {
    id: 'payload-extraction-x64dbg',
    title: 'PAYLOAD EXTRACTION',
    theme: 'cyan',
    badgeLeft: 'MEMORY ANALYSIS',
    badgeRight: 'VIRTUALALLOC',
    cmd: 'MEM_COMMIT Page Dump',
    iconType: 'memory-matrix'
  },
  {
    id: 'emotet-deconstructing',
    title: 'DECONSTRUCTING EMOTET',
    theme: 'amber',
    badgeLeft: 'BOTNET LOADER',
    badgeRight: 'POLYMORPHIC',
    cmd: 'In-Memory Decrypted DLL Dump',
    iconType: 'botnet-swarm'
  },
  {
    id: 'qakbot-unpacking',
    title: 'QAKBOT UNPACKING',
    theme: 'blue',
    badgeLeft: 'BANKING / BOT',
    badgeRight: 'HOLLOWING',
    cmd: 'Multi-layer Stage Extraction',
    iconType: 'memory-matrix'
  },
  {
    id: 'malware-binary-diffing',
    title: 'MALWARE BINARY DIFFING',
    theme: 'cyan',
    badgeLeft: 'GHIDRA + BINDIFF',
    badgeRight: 'CFG MATCH',
    cmd: 'Function Match: 98.4% Score',
    iconType: 'diff-graph'
  },
  {
    id: 'dynamic-api-resolution',
    title: 'DYNAMIC API RESOLUTION',
    theme: 'cyan',
    badgeLeft: 'EVASION // PEB',
    badgeRight: 'RESOLVER',
    cmd: 'FS:[0x30] PEB Module Lookup',
    iconType: 'memory-matrix'
  },
  {
    id: 'reversing-hash-api',
    title: 'HASH-BASED API RESOLUTION',
    theme: 'blue',
    badgeLeft: 'API HASHING',
    badgeRight: 'ROR13 / CRC32',
    cmd: 'Hash: 0x6A4ABC5B -> Resolved',
    iconType: 'hash-calc'
  },
  {
    id: 'shellcode-triage',
    title: 'SHELLCODE TRIAGE',
    theme: 'cyan',
    badgeLeft: 'CAPA // TRIAGE',
    badgeRight: 'EMULATION',
    cmd: 'capa rule: check-for-debugger',
    iconType: 'binary-tree'
  },
  {
    id: 'x64dbg-conditional-breakpoints',
    title: 'X64DBG STRING DEOBFUSCATION',
    theme: 'cyan',
    badgeLeft: 'DEBUGGER SCRIPT',
    badgeRight: 'COND BREAKPOINT',
    cmd: 'log [ESP+4] String Decrypt Loop',
    iconType: 'memory-matrix'
  },
  {
    id: 'api-unhooking-gazprom',
    title: 'API UNHOOKING',
    theme: 'cyan',
    badgeLeft: 'EDR EVASION',
    badgeRight: 'NTDLL RESTORE',
    cmd: 'Syscall Stub Patch Overwrite',
    iconType: 'unhook-trampoline'
  },
  {
    id: 'cyber-talents-ctf',
    title: 'CYBER TALENTS CTF',
    theme: 'purple',
    badgeLeft: 'REVERSE CHALLENGE',
    badgeRight: 'ANTI-DEBUG',
    cmd: 'IsDebuggerPresent Bypass',
    iconType: 'reticle'
  },
  {
    id: 'automated-unpacking',
    title: 'AUTOMATED UNPACKING',
    theme: 'cyan',
    badgeLeft: 'WIN32 REVERSE',
    badgeRight: 'MAL_UNPACK',
    cmd: 'Runtime Injected PE Header Dump',
    iconType: 'binary-tree'
  },
  {
    id: 'bypassing-isdebuggerpresent',
    title: 'ISDEBUGGERPRESENT BYPASS',
    theme: 'cyan',
    badgeLeft: 'ANTI-ANALYSIS',
    badgeRight: 'PEB HOOK',
    cmd: 'FS:[30h] + 2 BeingDebugged = 0',
    iconType: 'memory-matrix'
  },
  {
    id: 'dll-malware-emotet',
    title: 'EMOTET DLL MALWARE',
    theme: 'amber',
    badgeLeft: 'BOTNET DLL',
    badgeRight: 'RUNDLL32',
    cmd: 'rundll32.exe sample.dll, #1',
    iconType: 'botnet-swarm'
  },
  {
    id: 'debugging-malware-cobalt-strike',
    title: 'COBALT STRIKE EXTRACTION',
    theme: 'blue',
    badgeLeft: 'WIN64 C2',
    badgeRight: 'VIRTUALALLOC',
    cmd: 'DIE Triage & In-Memory Payload Dump',
    iconType: 'beacon-radar'
  },
  {
    id: 'patching-malware',
    title: 'PATCHING MALWARE',
    theme: 'purple',
    badgeLeft: 'BINARY PATCH',
    badgeRight: 'CONTROL FLOW',
    cmd: 'NOP Sled & JZ->JNZ Byte Flip',
    iconType: 'binary-tree'
  },
  {
    id: 'packed-autoit-malware',
    title: 'PACKED AUTOIT MALWARE',
    theme: 'amber',
    badgeLeft: 'AUTOIT3 DECOMP',
    badgeRight: 'ASLR ANALYSIS',
    cmd: 'Extract Embedded Shellcode Buffers',
    iconType: 'chain-hijack'
  },
  {
    id: 'shellcode-extraction',
    title: 'SHELLCODE EXTRACTION',
    theme: 'cyan',
    badgeLeft: 'MEMORY EXTRACTION',
    badgeRight: 'SCDBG EMULATION',
    cmd: 'Reconstruct Raw x86/x64 Shellcode',
    iconType: 'memory-matrix'
  },
  {
    id: 'unpacking-modified-upx',
    title: 'UNPACKING MODIFIED UPX',
    theme: 'cyan',
    badgeLeft: 'UPX HEADER REPAIR',
    badgeRight: 'OEP RECOVERY',
    cmd: 'Reconstruct Corrupted Section Headers',
    iconType: 'binary-tree'
  },
  {
    id: 'pe32-shellcode-loader',
    title: 'PE32 SHELLCODE LOADER',
    theme: 'purple',
    badgeLeft: 'CROSS-PLATFORM',
    badgeRight: 'STATIC REVERSE',
    cmd: 'MalwareBazaar Dropper Analysis',
    iconType: 'reticle'
  }
];

function getThemeColors(theme) {
  switch (theme) {
    case 'red':
      return {
        glow: '#FF2A2A',
        glowOpacity: '0.35',
        primary: '#FF453A',
        secondary: '#FF9F0A',
        badgeBg: 'rgba(255, 69, 58, 0.15)',
        badgeBorder: 'rgba(255, 69, 58, 0.35)',
        badgeText: '#FF8A80'
      };
    case 'amber':
      return {
        glow: '#FF9F0A',
        glowOpacity: '0.30',
        primary: '#FFB340',
        secondary: '#FF7A00',
        badgeBg: 'rgba(255, 159, 10, 0.15)',
        badgeBorder: 'rgba(255, 159, 10, 0.35)',
        badgeText: '#FFD180'
      };
    case 'purple':
      return {
        glow: '#A855F7',
        glowOpacity: '0.32',
        primary: '#C084FC',
        secondary: '#818CF8',
        badgeBg: 'rgba(168, 85, 247, 0.15)',
        badgeBorder: 'rgba(168, 85, 247, 0.35)',
        badgeText: '#E9D5FF'
      };
    case 'cyan':
      return {
        glow: '#00E5FF',
        glowOpacity: '0.28',
        primary: '#38BDF8',
        secondary: '#0052FF',
        badgeBg: 'rgba(56, 189, 248, 0.15)',
        badgeBorder: 'rgba(56, 189, 248, 0.35)',
        badgeText: '#BAE6FD'
      };
    case 'blue':
    default:
      return {
        glow: '#0052FF',
        glowOpacity: '0.38',
        primary: '#8DCAFE',
        secondary: '#0052FF',
        badgeBg: 'rgba(0, 82, 255, 0.15)',
        badgeBorder: 'rgba(0, 82, 255, 0.35)',
        badgeText: '#8DCAFE'
      };
  }
}

function getCenterEmblem(type, colors) {
  switch (type) {
    case 'chip-lock':
      return `
        <!-- Silicon CPU with Glowing Padlock -->
        <rect x="0" y="0" width="80" height="80" rx="14" fill="#060913" stroke="${colors.primary}" stroke-width="1.6"/>
        <line x1="16" y1="-5" x2="16" y2="0" stroke="${colors.primary}" stroke-width="1.5"/>
        <line x1="40" y1="-5" x2="40" y2="0" stroke="${colors.primary}" stroke-width="1.5"/>
        <line x1="64" y1="-5" x2="64" y2="0" stroke="${colors.primary}" stroke-width="1.5"/>
        <line x1="16" y1="80" x2="16" y2="85" stroke="${colors.primary}" stroke-width="1.5"/>
        <line x1="40" y1="80" x2="40" y2="85" stroke="${colors.primary}" stroke-width="1.5"/>
        <line x1="64" y1="80" x2="64" y2="85" stroke="${colors.primary}" stroke-width="1.5"/>
        <g transform="translate(26, 22)">
          <rect x="0" y="14" width="28" height="22" rx="4" fill="${colors.secondary}" opacity="0.9"/>
          <path d="M 6 14 V 8 A 8 8 0 0 1 22 8 V 14" fill="none" stroke="#FFFFFF" stroke-width="2.5" stroke-linecap="round"/>
          <circle cx="14" cy="24" r="2.5" fill="#FFFFFF"/>
          <line x1="14" y1="26" x2="14" y2="30" stroke="#FFFFFF" stroke-width="2"/>
        </g>
      `;

    case 'mbr-skull':
      return `
        <!-- Hard Drive Cylinder with Warning Hazard -->
        <ellipse cx="40" cy="20" rx="36" ry="12" fill="#0B132B" stroke="${colors.primary}" stroke-width="1.6"/>
        <path d="M 4 20 V 60 A 36 12 0 0 0 76 60 V 20" fill="#060913" stroke="${colors.primary}" stroke-width="1.6"/>
        <ellipse cx="40" cy="40" rx="36" ry="12" fill="none" stroke="${colors.primary}" stroke-width="1" opacity="0.5"/>
        <ellipse cx="40" cy="60" rx="36" ry="12" fill="none" stroke="${colors.primary}" stroke-width="1.4"/>
        <g transform="translate(26, 30)">
          <!-- Skull / Hazard Warning -->
          <path d="M 14 0 L 28 24 L 0 24 Z" fill="${colors.secondary}" opacity="0.9"/>
          <circle cx="14" cy="18" r="1.5" fill="#000000"/>
          <line x1="14" y1="8" x2="14" y2="14" stroke="#000000" stroke-width="2.2" stroke-linecap="round"/>
        </g>
      `;

    case 'ransom-vault':
      return `
        <!-- Cyber Vault / Encryption Cube -->
        <polygon points="40,5 75,25 75,65 40,85 5,65 5,25" fill="#060913" stroke="${colors.primary}" stroke-width="1.8"/>
        <line x1="40" y1="45" x2="75" y2="25" stroke="${colors.primary}" stroke-width="1.2" opacity="0.6"/>
        <line x1="40" y1="45" x2="5" y2="25" stroke="${colors.primary}" stroke-width="1.2" opacity="0.6"/>
        <line x1="40" y1="45" x2="40" y2="85" stroke="${colors.primary}" stroke-width="1.2" opacity="0.6"/>
        <circle cx="40" cy="45" r="10" fill="${colors.secondary}" opacity="0.9"/>
        <path d="M 37 42 L 43 48 M 43 42 L 37 48" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>
      `;

    case 'beacon-radar':
      return `
        <!-- C2 Transmitter & Signal Beacon Waves -->
        <circle cx="40" cy="45" r="34" fill="none" stroke="${colors.primary}" stroke-width="1" stroke-dasharray="3,3" opacity="0.4"/>
        <circle cx="40" cy="45" r="22" fill="none" stroke="${colors.primary}" stroke-width="1.2" opacity="0.7"/>
        <circle cx="40" cy="45" r="10" fill="none" stroke="${colors.primary}" stroke-width="1.6"/>
        <circle cx="40" cy="45" r="4" fill="${colors.secondary}"/>
        <line x1="40" y1="45" x2="68" y2="20" stroke="${colors.primary}" stroke-width="1.8"/>
        <circle cx="68" cy="20" r="3" fill="#FFFFFF"/>
      `;

    case 'botnet-swarm':
      return `
        <!-- Swarm Network Nodes -->
        <circle cx="40" cy="40" r="12" fill="#0A1128" stroke="${colors.primary}" stroke-width="1.8"/>
        <circle cx="40" cy="40" r="4" fill="${colors.secondary}"/>
        <circle cx="15" cy="20" r="6" fill="#060913" stroke="${colors.primary}" stroke-width="1.4"/>
        <circle cx="65" cy="20" r="6" fill="#060913" stroke="${colors.primary}" stroke-width="1.4"/>
        <circle cx="20" cy="65" r="6" fill="#060913" stroke="${colors.primary}" stroke-width="1.4"/>
        <circle cx="60" cy="65" r="6" fill="#060913" stroke="${colors.primary}" stroke-width="1.4"/>
        <line x1="40" y1="40" x2="15" y2="20" stroke="${colors.primary}" stroke-width="1.2" opacity="0.6"/>
        <line x1="40" y1="40" x2="65" y2="20" stroke="${colors.primary}" stroke-width="1.2" opacity="0.6"/>
        <line x1="40" y1="40" x2="20" y2="65" stroke="${colors.primary}" stroke-width="1.2" opacity="0.6"/>
        <line x1="40" y1="40" x2="60" y2="65" stroke="${colors.primary}" stroke-width="1.2" opacity="0.6"/>
      `;

    case 'reticle':
      return `
        <!-- Tactical Military APT Reticle Target -->
        <circle cx="40" cy="40" r="32" fill="none" stroke="${colors.primary}" stroke-width="1.4" opacity="0.5"/>
        <circle cx="40" cy="40" r="20" fill="none" stroke="${colors.primary}" stroke-width="1.8"/>
        <circle cx="40" cy="40" r="6" fill="${colors.secondary}" opacity="0.8"/>
        <line x1="40" y1="4" x2="40" y2="16" stroke="${colors.primary}" stroke-width="1.8"/>
        <line x1="40" y1="64" x2="40" y2="76" stroke="${colors.primary}" stroke-width="1.8"/>
        <line x1="4" y1="40" x2="16" y2="40" stroke="${colors.primary}" stroke-width="1.8"/>
        <line x1="64" y1="40" x2="76" y2="40" stroke="${colors.primary}" stroke-width="1.8"/>
      `;

    case 'binary-tree':
    case 'diff-graph':
      return `
        <!-- Decompiler Control Flow Graph -->
        <rect x="25" y="8" width="30" height="18" rx="4" fill="#060913" stroke="${colors.primary}" stroke-width="1.4"/>
        <rect x="5" y="48" width="28" height="18" rx="4" fill="#060913" stroke="${colors.primary}" stroke-width="1.4"/>
        <rect x="47" y="48" width="28" height="18" rx="4" fill="#060913" stroke="${colors.secondary}" stroke-width="1.4"/>
        <path d="M 40 26 L 40 36 L 19 36 L 19 48" fill="none" stroke="${colors.primary}" stroke-width="1.4"/>
        <path d="M 40 36 L 61 36 L 61 48" fill="none" stroke="${colors.secondary}" stroke-width="1.4"/>
        <circle cx="40" cy="36" r="2.5" fill="#FFFFFF"/>
      `;

    case 'memory-matrix':
    case 'hash-calc':
      return `
        <!-- Memory Matrix & Hex Registers -->
        <rect x="4" y="10" width="72" height="60" rx="8" fill="#060913" stroke="${colors.primary}" stroke-width="1.5"/>
        <line x1="4" y1="28" x2="76" y2="28" stroke="${colors.primary}" stroke-width="1" opacity="0.4"/>
        <line x1="4" y1="46" x2="76" y2="46" stroke="${colors.primary}" stroke-width="1" opacity="0.4"/>
        <line x1="28" y1="10" x2="28" y2="70" stroke="${colors.primary}" stroke-width="1" opacity="0.4"/>
        <line x1="52" y1="10" x2="52" y2="70" stroke="${colors.primary}" stroke-width="1" opacity="0.4"/>
        <rect x="30" y="30" width="20" height="14" rx="2" fill="${colors.secondary}" opacity="0.8"/>
      `;

    case 'packet-filter':
      return `
        <!-- Raw Socket BPF Bytecode Filter -->
        <rect x="8" y="15" width="64" height="50" rx="8" fill="#060913" stroke="${colors.primary}" stroke-width="1.6"/>
        <path d="M 16 32 L 28 32 M 36 32 L 64 32" stroke="${colors.primary}" stroke-width="1.5"/>
        <path d="M 16 48 L 44 48 M 52 48 L 64 48" stroke="${colors.secondary}" stroke-width="1.5"/>
        <polygon points="40,24 48,32 40,40" fill="${colors.primary}"/>
      `;

    case 'chain-hijack':
      return `
        <!-- Chain Links / Supply Chain Injection -->
        <rect x="12" y="18" width="34" height="20" rx="6" fill="none" stroke="${colors.primary}" stroke-width="2.5"/>
        <rect x="34" y="38" width="34" height="20" rx="6" fill="none" stroke="${colors.secondary}" stroke-width="2.5"/>
        <circle cx="40" cy="38" r="3" fill="#FFFFFF"/>
      `;

    case 'blockchain-c2':
      return `
        <!-- Ethereum Decentralized Node -->
        <polygon points="40,10 65,38 40,50 15,38" fill="#0A1128" stroke="${colors.primary}" stroke-width="1.5"/>
        <polygon points="40,53 65,41 40,70 15,41" fill="#060913" stroke="${colors.secondary}" stroke-width="1.5"/>
      `;

    case 'unhook-trampoline':
      return `
        <!-- EDR Hook Bypass / Syscall Trampoline -->
        <rect x="8" y="15" width="28" height="50" rx="6" fill="#060913" stroke="${colors.primary}" stroke-width="1.4"/>
        <rect x="44" y="15" width="28" height="50" rx="6" fill="#060913" stroke="${colors.secondary}" stroke-width="1.4"/>
        <path d="M 22 40 C 22 20, 58 20, 58 40" fill="none" stroke="#FFFFFF" stroke-width="1.8" stroke-dasharray="3,3"/>
        <polygon points="58,40 54,34 62,34" fill="#FFFFFF"/>
      `;

    case 'keychain':
    case 'browser-vault':
    case 'modular-core':
    default:
      return `
        <!-- Generic Shield & Protected Binary -->
        <path d="M 40 8 L 68 20 V 46 C 68 62 40 74 40 74 C 40 74 12 62 12 46 V 20 Z" fill="#060913" stroke="${colors.primary}" stroke-width="1.6"/>
        <path d="M 40 24 L 54 38 L 40 56 L 26 38 Z" fill="${colors.secondary}" opacity="0.8"/>
      `;
  }
}

function buildSvg(spec) {
  const colors = getThemeColors(spec.theme);
  const emblem = getCenterEmblem(spec.iconType, colors);

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 220" width="100%" height="100%">
  <defs>
    <linearGradient id="bgGrad_${spec.id}" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#04060A"/>
      <stop offset="100%" stop-color="#010204"/>
    </linearGradient>
    <radialGradient id="glow_${spec.id}" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="${colors.glow}" stop-opacity="${colors.glowOpacity}"/>
      <stop offset="70%" stop-color="#000000" stop-opacity="0"/>
    </radialGradient>
    <pattern id="grid_${spec.id}" width="16" height="16" patternUnits="userSpaceOnUse">
      <path d="M 16 0 L 0 0 0 16" fill="none" stroke="rgba(255,255,255,0.03)" stroke-width="0.7"/>
    </pattern>
  </defs>

  <!-- Deep Background -->
  <rect width="320" height="220" fill="url(#bgGrad_${spec.id})"/>
  <rect width="320" height="220" fill="url(#grid_${spec.id})"/>
  <circle cx="160" cy="100" r="100" fill="url(#glow_${spec.id})"/>

  <!-- Glass Card Outer Frame -->
  <g transform="translate(20, 14)">
    <rect x="0" y="0" width="280" height="192" rx="12" fill="rgba(8, 12, 22, 0.75)" stroke="rgba(255, 255, 255, 0.08)" stroke-width="1"/>
    
    <!-- Top Pills -->
    <rect x="12" y="10" width="74" height="16" rx="4" fill="${colors.badgeBg}" stroke="${colors.badgeBorder}" stroke-width="0.8"/>
    <text x="49" y="21.5" text-anchor="middle" fill="${colors.badgeText}" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="8" font-weight="700" letter-spacing="0.5">${spec.badgeLeft}</text>

    <rect x="180" y="10" width="88" height="16" rx="4" fill="rgba(255, 255, 255, 0.04)" stroke="rgba(255, 255, 255, 0.1)" stroke-width="0.8"/>
    <text x="224" y="21.5" text-anchor="middle" fill="#C4C9D4" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="8" font-weight="600" letter-spacing="0.5">${spec.badgeRight}</text>

    <!-- Center Emblem Illustration -->
    <g transform="translate(100, 34)">
      ${emblem}
    </g>

    <!-- Monospace Telemetry Strip -->
    <g transform="translate(12, 126)">
      <rect x="0" y="0" width="256" height="22" rx="4" fill="rgba(0, 0, 0, 0.65)" stroke="rgba(255, 255, 255, 0.06)" stroke-width="0.8"/>
      <circle cx="12" cy="11" r="2.5" fill="#3FB950"/>
      <text x="22" y="14.5" fill="#8DCAFE" font-family="'JetBrains Mono', ui-monospace, monospace" font-size="9" letter-spacing="0.2">${spec.cmd}</text>
    </g>

    <!-- Title Label -->
    <text x="140" y="172" text-anchor="middle" fill="#FFFFFF" font-family="'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="800" letter-spacing="1">${spec.title}</text>
  </g>
</svg>`;
}

let count = 0;
for (const spec of cardSpecs) {
  const filePath = path.join(thumbsDir, `${spec.id}.svg`);
  fs.writeFileSync(filePath, buildSvg(spec));
  count++;
}

console.log(`Successfully generated ${count} bespoke SVG thumbnails in ${thumbsDir}!`);
