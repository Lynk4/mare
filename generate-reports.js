const fs = require('fs');
const path = require('path');

const AUTHOR_NAME = 'Chandra Kant Bauri';

// Complete master database of exactly 37 .md reports (no standalone PDFs)
const reports = [
  // macOS Reports (5)
  {
    id: 'digit-stealer',
    title: 'Digit Stealer: Dissecting an AppleScript & JXA Campaign Utilizing DNS TXT Dead-Drop Resolvers and Ledger Live Hijacking',
    os: 'macOS',
    category: 'Malware Analysis',
    date: 'August 23, 2026',
    readTime: '10 min read',
    ref: 'MARE-TI-2026-MAC04',
    lead: 'An in-depth technical analysis of a multi-stage macOS cryptocurrency infostealer executing in-memory JXA payloads, harvesting credentials across 12+ browsers, and tampering with desktop hardware wallet configurations.',
    family: 'Digit Stealer',
    classification: 'macOS Infostealer / Hijacker',
    delivery: 'Trojanized DMG (DynamicLake)',
    c2: 'DNS TXT + HTTP POST',
    targets: 'Browsers, Wallets, Keychains',
    hashType: 'MD5',
    hashVal: '7a7bcb8a314c12c84364b33b0fc59692',
    src: 'reports/digit-stealer/index.html',
    isHandcrafted: true
  },
  {
    id: 'atomic-macos-stealer',
    title: 'Atomic macOS Stealer (AMOS): Reversing String Decryption & Credential Extraction Pipelines',
    os: 'macOS',
    category: 'Malware Analysis',
    date: 'July 15, 2026',
    readTime: '14 min read',
    ref: 'MARE-TI-2026-MAC01',
    lead: 'Static and dynamic reverse engineering of a Mach-O universal binary infostealer, reversing rolling XOR string decryption routines, recovering C2 infrastructure, and documenting credential and cryptocurrency harvesting logic.',
    family: 'Atomic macOS Stealer (AMOS)',
    classification: 'macOS Infostealer / MaaS',
    delivery: 'Spoofed Homebrew Package',
    c2: 'HTTP POST (85.217.222.185)',
    targets: 'Keychains, Browsers, 20+ Wallets',
    hashType: 'SHA-256',
    hashVal: 'ce6dc065752cb46437ce6a200e29d5dbd96473daa72dcce07aa493b821a99ba9',
    src: 'Malware Analysis/macOS/Atomic Macos Stealer/README.md'
  },
  {
    id: 'kitty-stealer',
    title: 'Kitty Stealer: Systematic Analysis of a Lightweight macOS Credential Collector',
    os: 'macOS',
    category: 'Threat Intelligence',
    date: 'June 10, 2026',
    readTime: '9 min read',
    ref: 'MARE-TI-2026-MAC02',
    lead: 'Analysis of a nimble macOS infostealer targeting Chromium and Gecko browser profiles, local keychain credentials, and decentralized cryptocurrency wallet storage.',
    family: 'Kitty Stealer',
    classification: 'macOS Infostealer',
    delivery: 'Deceptive Installer Archive',
    c2: 'Encrypted Telegram Bot API',
    targets: 'Chromium / Gecko Profiles & Crypto',
    hashType: 'SHA-256',
    hashVal: '33f0387e0ce38d6df0243d7c588523c0b05b3c373bfeb2c4314c4423851b2ff0',
    src: 'Malware Analysis/macOS/KittyStealer/README.md'
  },
  {
    id: 'rustbucket',
    title: 'RustBucket: Mach-O Internals, Universal Binary Analysis & BlueNoroff Attribution',
    os: 'macOS',
    category: 'Advanced Persistent Threats',
    date: 'May 04, 2026',
    readTime: '18 min read',
    ref: 'MARE-TI-2026-MAC03',
    lead: 'Mach-O header internals, Universal Binary analysis (ARM64 and x86_64), static triage, and tracking operational tradecraft tied to Lazarus sub-group BlueNoroff.',
    family: 'RustBucket (BlueNoroff / Lazarus)',
    classification: 'State-Sponsored Mach-O Backdoor',
    delivery: 'Trojanized PDF Viewer',
    c2: 'Custom HTTPS Beaconing',
    targets: 'Financial & Crypto Institutions',
    hashType: 'SHA-256',
    hashVal: '7887638b935a6435c2497fc0445d4791fe30e38ae0453ff54210d797171e543e',
    src: 'Malware Analysis/macOS/RustBucket/README.md'
  },
  {
    id: 'macho-static-analysis',
    title: 'Mach-O Static Analysis: Reverse Engineering a Malware That Refused to Run Without Python',
    os: 'macOS',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'April 22, 2026',
    readTime: '11 min read',
    ref: 'MARE-TI-2026-MAC05',
    lead: 'Static disassembly and binary decompilation of a Mach-O executable requiring Python runtime dependencies and embedding obfuscated scripting components.',
    family: 'PyMach-O Dropper',
    classification: 'Modular Script Dropper',
    delivery: 'Standalone Mach-O Executable',
    c2: 'HTTP Staging',
    targets: 'Local Host Discovery & Execution',
    hashType: 'SHA-256',
    hashVal: '37348e18e5fb39223329971ceb6ae919e1b209a39ec8c6686cfbc5c7d2424fa7',
    src: 'Malware Analysis/macOS/macho sample static analysis/README.md'
  },

  // Linux Reports (2)
  {
    id: 'mirai-botnet',
    title: 'Reversing a Mirai Malware Variant: UPX Unpacking & IoT Command Infrastructure',
    os: 'Linux',
    category: 'Malware Analysis',
    date: 'May 01, 2026',
    readTime: '12 min read',
    ref: 'MARE-TI-2026-LIN01',
    lead: 'Static and dynamic triage of an ARM 32-bit ELF binary, UPX header reconstruction, telnet brute-force spreading routines, and multi-architecture cross-compilation analysis.',
    family: 'Mirai',
    classification: 'Linux IoT Botnet / DDoS Worm',
    delivery: 'Telnet Brute-Force & Shell Exploits',
    c2: 'Raw TCP Binary C2 Protocol',
    targets: 'Embedded Linux & IoT Gateways',
    hashType: 'SHA-256',
    hashVal: '29b78bb61ceeb22c7a523d4c382f7c0410ff1c4d7ec6bebc0c41fcab36e6ba96',
    src: 'Malware Analysis/Linux/Mirai Botnet/README.md'
  },
  {
    id: 'bpfdoor',
    title: 'BPFDoor: In-Depth Reverse Engineering of a Stealthy Linux Backdoor Using Raw Sockets',
    os: 'Linux',
    category: 'Advanced Persistent Threats',
    date: 'April 18, 2026',
    readTime: '16 min read',
    ref: 'MARE-TI-2026-LIN02',
    lead: 'Investigating Berkeley Packet Filter (BPF) bytecode injection to sniff magic packets, bypass local firewalls without listening ports, and spawn root reverse shells.',
    family: 'BPFDoor (Red Menshen)',
    classification: 'Passive Linux Kernel Backdoor',
    delivery: 'Privileged System Compromise',
    c2: 'BPF Sniffed Magic UDP/TCP Packets',
    targets: 'Telecom & Enterprise Core Routers',
    hashType: 'SHA-256',
    hashVal: 'fd1b20eecdbfcb9f87c2b5bc70e9a7e0a4f6cf70eecbcf7dfb08c66a4bc2e8be',
    src: 'Malware Analysis/Linux/Linux Backdoor BPFDoor/README.md'
  },

  // Windows Reports (28)
  {
    id: 'cobalt-strike-beacon',
    title: 'Cobalt Strike: Custom Stagers, Early Bird APC Injection & Memory Evasion',
    os: 'Windows',
    category: 'Threat Intelligence',
    date: 'November 14, 2025',
    readTime: '22 min read',
    ref: 'MARE-TI-2025-WIN01',
    lead: 'Complete technical breakdown of custom C and Rust beacon loaders, VirtualAlloc memory manipulation, QueueUserAPC injection, and shellcode triage with CAPA.',
    family: 'Cobalt Strike Beacon',
    classification: 'Commercial C2 Post-Exploitation',
    delivery: 'Custom C & Rust Stager Payloads',
    c2: 'Malleable HTTP / Named Pipes',
    targets: 'Enterprise Windows Domain Infrastructure',
    hashType: 'SHA-256',
    hashVal: 'e57dc19e1fc4a47ee4ecaa227e77b42007e992160d7037f023773ee492025622',
    src: 'Malware Analysis/Windows/Cobalt Strike beacon/README.md'
  },
  {
    id: 'regin-malware',
    title: 'Regin Malware: Architecture of a Nation-State Stage-1 Loader and Virtual Filesystems',
    os: 'Windows',
    category: 'Advanced Persistent Threats',
    date: 'October 28, 2025',
    readTime: '25 min read',
    ref: 'MARE-TI-2025-WIN02',
    lead: 'Deep-dive reverse engineering into one of the most sophisticated APT platforms ever discovered, covering encrypted payload stages, proprietary virtual filesystems, and stealth kernel-mode loader execution.',
    family: 'Regin (Nation-State APT)',
    classification: 'Modular Kernel-Mode Espionage Platform',
    delivery: 'Multi-Stage Injected Kernel Drivers',
    c2: 'Custom Encrypted Transport & EVFS',
    targets: 'Telecommunications & GSM Infrastructure',
    hashType: 'SHA-256',
    hashVal: 'f1d90325b3a4a0eeefdaec8e2270bb3f06e30948e6580f4f783ea7ff64201be9',
    src: 'Malware Analysis/Windows/Regin Malware/README.md'
  },
  {
    id: 'whispergate',
    title: 'WhisperGate MBR Wiper: Deconstructing Destructive Disk-Level Corruptions',
    os: 'Windows',
    category: 'Malware Analysis',
    date: 'October 12, 2025',
    readTime: '15 min read',
    ref: 'MARE-TI-2025-WIN03',
    lead: 'Dissecting a destructive Master Boot Record (MBR) overwrite routine disguised as ransomware during targeted state-sponsored campaigns against critical infrastructure.',
    family: 'WhisperGate (Cadet Blizzard)',
    classification: 'Destructive Master Boot Record Wiper',
    delivery: 'Trojanized System Utility',
    c2: 'Discord CDN Staged Payloads',
    targets: 'Ukrainian Government & Energy Sectors',
    hashType: 'SHA-256',
    hashVal: 'a196c6b87ba3032ba982845e4d1a62e7e77f08dc13f0e40047e73a0f1661404b',
    src: 'Malware Analysis/Windows/WhisperGate MBR Wiper/README.md'
  },
  {
    id: 'notpetya',
    title: 'NotPetya: Low-Level MBR Overwriting and PsExec / WMI Lateral Movement',
    os: 'Windows',
    category: 'Ransomware & Wipers',
    date: 'August 29, 2025',
    readTime: '17 min read',
    ref: 'MARE-TI-2025-WIN04',
    lead: 'Technical analysis of the devastating NotPetya pseudo-ransomware wiper, covering its destructive MFT encryption, PsExec automation, and token stealing.',
    family: 'NotPetya (Sandworm)',
    classification: 'Pseudo-Ransomware Disk Wiper',
    delivery: 'M.E.Doc Accounting Supply Chain',
    c2: 'Autonomous SMB Lateral Movement',
    targets: 'Critical Infrastructure & Global Supply Chains',
    hashType: 'SHA-256',
    hashVal: '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745',
    src: 'Malware Analysis/Windows/NotPetya Ransomware/README.md'
  },
  {
    id: 'wannacry',
    title: 'WannaCry: Cryptographic Teardown & EternalBlue SMB Propagation Mechanics',
    os: 'Windows',
    category: 'Ransomware & Wipers',
    date: 'January 15, 2026',
    readTime: '20 min read',
    ref: 'MARE-TI-2026-WIN25',
    lead: 'Deconstructing EternalBlue (MS17-010) kernel exploitation, kill-switch HTTP validation routines, and customized AES-128 + RSA-2048 hybrid file encryption implementations.',
    family: 'WannaCry (WANACRY!)',
    classification: 'Ransomware / Autonomous Worm',
    delivery: 'EternalBlue (MS17-010 SMBv1 RCE)',
    c2: 'HTTP Kill Switch + Tor Egress',
    targets: '176+ File Extensions & SMB Subnets',
    hashType: 'SHA-256',
    hashVal: '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c',
    src: 'Malware Analysis/Windows/WannaCry Ransomware/README.md'
  },
  {
    id: 'etherrat',
    title: 'EtherRAT: Reverse Engineering an Ethereum Smart-Contract-Based C2 Architecture',
    os: 'Windows',
    category: 'Threat Intelligence',
    date: 'September 20, 2025',
    readTime: '14 min read',
    ref: 'MARE-TI-2025-WIN05',
    lead: 'Multi-stage payload decryption and reverse engineering of an evasion technique querying immutable Ethereum smart contracts for dynamic command-and-control resolution.',
    family: 'EtherRAT (The Gentlemen Campaign)',
    classification: 'Blockchain-Resolved Remote Access Trojan',
    delivery: 'MSI Windows Installer Dropper',
    c2: 'Ethereum Smart Contract + Cloud Workers',
    targets: 'Enterprise Workstations & Dev Environments',
    hashType: 'SHA-256',
    hashVal: 'd9487fdc097f770e5661f9e5dee130068cb179d33716abff1a21c8cb901f25a6',
    src: 'Malware Analysis/Windows/EtherRAT Ethereum C2 Analysis/README.md'
  },
  {
    id: 'zeus-trojan',
    title: 'Zeus Banking Trojan: Man-in-the-Browser API Inline Hooking & Form-Grabbing',
    os: 'Windows',
    category: 'Threat Intelligence',
    date: 'August 19, 2025',
    readTime: '19 min read',
    ref: 'MARE-TI-2025-WIN06',
    lead: 'Technical analysis of ntdll and wininet memory hooking, dynamic HTML injection, and cryptographic decryption of Zeus binary configuration files.',
    family: 'Zeus (Zbot)',
    classification: 'Banking Trojan / Form-Grabber',
    delivery: 'Phishing Email Spreading PDF.EXE',
    c2: 'HTTP POST Encrypted Config Pools',
    targets: 'Financial Credentials & Online Banking',
    hashType: 'MD5',
    hashVal: '44d88612fea8a8f36de82e1278abb02f',
    src: 'Malware Analysis/Windows/Zeus Banking Trojan Malware/README.md'
  },
  {
    id: 'reverse-engineering-packed-trojan',
    title: 'Reverse Engineering a Packed Trojan: Ghidra & x64dbg Dynamic Tracing',
    os: 'Windows',
    category: 'Malware Analysis',
    date: 'August 10, 2025',
    readTime: '16 min read',
    ref: 'MARE-TI-2025-WIN07',
    lead: 'Deconstructing custom runtime packers, tracing memory allocations with x64dbg, locating original entry points (OEP), and decompiling core trojan components in Ghidra.',
    family: 'Custom Packed PE32 Trojan',
    classification: 'Packed Malware Dropper',
    delivery: 'Suspicious Standalone Executable',
    c2: 'Staged Payload Injection',
    targets: 'Process Hollowing & Host Memory',
    hashType: 'SHA-256',
    hashVal: '5617238b97b09349c25a07c95a02aa99c43d719be2241cf89793132e48aa7946',
    src: 'Malware Analysis/Windows/Reverse Engineering a Packed Trojan/README.md'
  },
  {
    id: 'bangladesh-gpca',
    title: 'Bangladesh GPCA: Targeted Cyber Espionage and Custom Payload Decoding',
    os: 'Windows',
    category: 'Advanced Persistent Threats',
    date: 'August 04, 2025',
    readTime: '15 min read',
    ref: 'MARE-TI-2025-WIN08',
    lead: 'Analysis of a targeted espionage sample attacking South Asian infrastructure, featuring custom Python decoders, shellcode injection, and obfuscated stagers.',
    family: 'Bangladesh GPCA Espionage Stager',
    classification: 'Targeted Espionage Backdoor',
    delivery: 'Spear-Phishing Lure Document',
    c2: 'HTTP Polling with Obfuscated Headers',
    targets: 'Government & Critical Petrochemical Sectors',
    hashType: 'MD5',
    hashVal: '1d0e79fe4598d1a1b528b7eec93e7821',
    src: 'Malware Analysis/Windows/Bangladesh GPCA/README.md'
  },
  {
    id: 'payload-extraction-x64dbg',
    title: 'Extracting Hidden Cobalt Strike Beacons from Memory with x64dbg',
    os: 'Windows',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'July 25, 2025',
    readTime: '14 min read',
    ref: 'MARE-TI-2025-WIN09',
    lead: 'Tracing VirtualAlloc API calls in x64dbg, monitoring memory allocation transitions, dumping injected shellcode buffers, and extracting in-memory Cobalt Strike beacons.',
    family: 'In-Memory Cobalt Strike Stager',
    classification: 'Reflective DLL Loader / Injector',
    delivery: 'High-Entropy PE Stager',
    c2: 'HTTPS Encrypted Channels',
    targets: 'Volatile RAM & Unbacked Memory Pages',
    hashType: 'SHA-256',
    hashVal: 'bca3fca9f1d53086eb020165c82914109403b22cfd8640ceca80b9dc07421fcb',
    src: 'Malware Analysis/Windows/Payload Extraction/README.md'
  },
  {
    id: 'notepad-chrysalis',
    title: 'Notepad++ Chrysalis: Supply-Chain Backdoor Insertion & Dynamic Hooking',
    os: 'Windows',
    category: 'Advanced Persistent Threats',
    date: 'July 18, 2025',
    readTime: '16 min read',
    ref: 'MARE-TI-2025-WIN10',
    lead: 'Investigating a trojanized Notepad++ plugin acting as an APT backdoor, analyzing memory allocation routines, and identifying staging C2 communications.',
    family: 'Chrysalis (Supply Chain Backdoor)',
    classification: 'Trojanized Dynamic Link Library',
    delivery: 'Compromised Plugin Architecture',
    c2: 'Custom Encrypted TCP Sockets',
    targets: 'Developer Environments & Source Code',
    hashType: 'SHA-256',
    hashVal: 'a511be513d39589d8132ad8dcfd54ef4827c14a2c07efd939634e91244bbd97a',
    src: 'Malware Analysis/Windows/notepad++ Chrysalis/README.md'
  },
  {
    id: 'agent-tesla',
    title: 'Agent Tesla: RTF Exploit Weaponization and In-Memory Credential Harvester',
    os: 'Windows',
    category: 'Threat Intelligence',
    date: 'July 10, 2025',
    readTime: '13 min read',
    ref: 'MARE-TI-2025-WIN11',
    lead: 'Weaponized Rich Text Format (RTF) vulnerability delivery, .NET unpacking, SMTP/FTP exfiltration routines, and keylogging mechanisms.',
    family: 'Agent Tesla',
    classification: '.NET Keylogger / Infostealer',
    delivery: 'Weaponized RTF Document (CVE-2017-11882)',
    c2: 'SMTP / FTP Exfiltration Channels',
    targets: 'Web Browsers, Mail Clients, VPNs',
    hashType: 'SHA-256',
    hashVal: 'dfade43bf29b53d0e3ecfa0b9ea0942e2a22026362d2925aeae89098ca3a6be7',
    src: 'Malware Analysis/Windows/Agent Tesla/README.md'
  },
  {
    id: 'emotet-deconstructing',
    title: 'Deconstructing Emotet: Manual Memory Unpacking and Hook Analysis',
    os: 'Windows',
    category: 'Malware Analysis',
    date: 'June 30, 2025',
    readTime: '18 min read',
    ref: 'MARE-TI-2025-WIN12',
    lead: 'Step-by-step manual unpacking walkthrough of Emotet in x64dbg, locating original entry points (OEP), dumping unpacked PE images, and repairing corrupted import tables.',
    family: 'Emotet (Heodo)',
    classification: 'Polymorphic Banking Trojan / Botnet',
    delivery: 'Malicious Office Macro Droppers',
    c2: 'Multi-Tier HTTP Encrypted C2 Cluster',
    targets: 'Windows Endpoint Credential Access',
    hashType: 'SHA-256',
    hashVal: 'b1cad154c1ba6dcfbb9b8b69da3b2c125d0fe8eb6250711910cf9cb52c4a96b7',
    src: 'Malware Analysis/Windows/Deconstructing Emotet/README.md'
  },
  {
    id: 'qakbot-unpacking',
    title: 'Qakbot Unpacking: Bypassing Multi-Layer Obfuscation & Resource Decryption',
    os: 'Windows',
    category: 'Malware Analysis',
    date: 'June 22, 2025',
    readTime: '15 min read',
    ref: 'MARE-TI-2025-WIN13',
    lead: 'Analyzing Qakbot loader evasion techniques, extracting encrypted payloads from resource sections, and reconstructing API hashing tables.',
    family: 'Qakbot (QBot / Pinkslipbot)',
    classification: 'Modular Banking Trojan / Loader',
    delivery: 'ZIP with LNK / VBS Script Chains',
    c2: 'Decentralized P2P C2 Protocol',
    targets: 'Enterprise Networks & Financial Portals',
    hashType: 'SHA-256',
    hashVal: '112a6419747a74a1ee354a833d7b88df0a09e05fae39b9866164f9fca4fe0146',
    src: 'Malware Analysis/Windows/Qakbot Unpacking/README.md'
  },
  {
    id: 'sillyputty',
    title: 'SillyPutty: Modular Backdoor Masquerading as a Legitimate SSH Client',
    os: 'Windows',
    category: 'Threat Intelligence',
    date: 'June 12, 2025',
    readTime: '12 min read',
    ref: 'MARE-TI-2025-WIN14',
    lead: 'Reverse engineering a trojanized PuTTY utility embedding command-and-control capabilities, process injection stubs, and encrypted beaconing.',
    family: 'SillyPutty (Trojanized PuTTY)',
    classification: 'Modular Backdoor',
    delivery: 'Trojanized Software Installer',
    c2: 'Reverse Shell over TCP / Named Pipes',
    targets: 'System Administrators & SSH Sessions',
    hashType: 'MD5',
    hashVal: '0c410313f837330feff6b00b0d3bd2b0',
    src: 'Malware Analysis/Windows/SillyPutty/README.md'
  },
  {
    id: 'malware-binary-diffing',
    title: 'Malware Binary Diffing with Ghidra & BinDiff: Comparing Conti and LockBit Green',
    os: 'Windows',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'June 02, 2025',
    readTime: '16 min read',
    ref: 'MARE-TI-2025-WIN15',
    lead: 'Using Ghidra and BinDiff to perform code similarity analysis, identify shared cryptographic functions, and verify code reuse between Conti and LockBit source leaks.',
    family: 'Conti vs LockBit Green',
    classification: 'Ransomware Code Similarity Analysis',
    delivery: 'Shared Source-Code Leak Compilations',
    c2: 'Independent Local File Encryption',
    targets: 'Enterprise Shared Drives & Shadows',
    hashType: 'SHA-256',
    hashVal: 'e1b147aa7208e92f256a4ca6cfa358fe7517c2f1f50a80e6e969d275330e20e6',
    src: 'Malware Analysis/Windows/Malware Binary Diffing/README.md'
  },
  {
    id: 'dynamic-api-resolution',
    title: 'Deconstructing Dynamic API Resolution: Locating NTDLL and Rebuilding IATs',
    os: 'Windows',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'May 18, 2025',
    readTime: '14 min read',
    ref: 'MARE-TI-2025-WIN16',
    lead: 'Analyzing how evasive malware locates the image base of NTDLL in the Process Environment Block (PEB) and dynamically reconstructs the Import Address Table at runtime.',
    family: 'PEB Dynamic Resolver Engine',
    classification: 'Evasion & Import Obfuscation',
    delivery: 'Memory Stager Payload',
    c2: 'N/A (Core Evasion Technique)',
    targets: 'Process Environment Block (PEB)',
    hashType: 'SHA-256',
    hashVal: '39898241b3ee69aa0a67a07747bb741870198642ca559c5d081b24eec3b0e14c',
    src: 'Malware Analysis/Windows/Dynamic API Resolution/README.md'
  },
  {
    id: 'reversing-hash-api',
    title: 'Reversing Hash-Based API Resolution: No Imports, No Strings',
    os: 'Windows',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'May 08, 2025',
    readTime: '13 min read',
    ref: 'MARE-TI-2025-WIN17',
    lead: 'Technical walkthrough of pre-computed hash-based API lookup routines (ROR13, MurmurHash, CRC32) designed to hide imported functions from static scanners.',
    family: 'ROR13 / MurmurHash Resolver',
    classification: 'Anti-Static Analysis Technique',
    delivery: 'Modular Injected Shellcode',
    c2: 'N/A (Analysis Evasion Primitive)',
    targets: 'Export Address Table (EAT)',
    hashType: 'SHA-256',
    hashVal: '39898241b3ee69aa0a67a07747bb741870198642ca559c5d081b24eec3b0e14c',
    src: 'Malware Analysis/Windows/Reversing Hash-Based API Resolution/README.md'
  },
  {
    id: 'shellcode-triage',
    title: 'Shellcode Triage and API Resolution with CAPA and Binary Ninja',
    os: 'Windows',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'April 28, 2025',
    readTime: '12 min read',
    ref: 'MARE-TI-2025-WIN18',
    lead: 'Static and architectural analysis of raw shellcode blobs, resolving obfuscated function pointers using Mandiant CAPA and Binary Ninja intermediate representations.',
    family: 'Unbacked Shellcode Loader',
    classification: 'Raw Binary Shellcode',
    delivery: 'Exploit Buffer / Memory Injection',
    c2: 'Dynamic Socket Connection',
    targets: 'x86/x64 Calling Conventions',
    hashType: 'SHA-256',
    hashVal: '822872c4a9f939e08354c4149092d6e32d1f97ca42d1378f4ae3bc6572e81fa3',
    src: 'Malware Analysis/Windows/Shellcode Triage and API Resolution/README.md'
  },
  {
    id: 'x64dbg-conditional-breakpoints',
    title: 'Malware String Deobfuscation with x64dbg Conditional Breakpoints',
    os: 'Windows',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'April 14, 2025',
    readTime: '11 min read',
    ref: 'MARE-TI-2025-WIN19',
    lead: 'Using x64dbg conditional breakpoints and logging scripts to automatically dump decrypted strings from memory during live malware execution.',
    family: 'Obfuscated PE String Decryptor',
    classification: 'Automated Memory Logging',
    delivery: 'Debugger Tracing Script',
    c2: 'N/A (Triage Workflow)',
    targets: 'Dynamic Stack & Heap Buffers',
    hashType: 'SHA-256',
    hashVal: '6af71ce9799ee6175e1127027d14db5fe70b8e7279be6a666e133e66a3d3c812',
    src: 'Malware Analysis/Windows/x64dbg-conditional-breakpoints/README.md'
  },
  {
    id: 'api-unhooking-gazprom',
    title: 'API Unhooking Techniques in Modern Ransomware: Gazprom Sample Walkthrough',
    os: 'Windows',
    category: 'Ransomware & Wipers',
    date: 'March 22, 2025',
    readTime: '13 min read',
    ref: 'MARE-TI-2025-WIN20',
    lead: 'Reverse engineering EDR bypass mechanisms, analyzing how ransomware dynamically restores hooked NTDLL stubs directly from clean on-disk modules.',
    family: 'Gazprom Ransomware',
    classification: 'EDR-Evading Ransomware',
    delivery: 'Compromised Remote Desktop / Phishing',
    c2: 'TOR Hidden Service Negotiation',
    targets: 'Clean NTDLL .text Sections & Files',
    hashType: 'SHA-256',
    hashVal: '32ec301f2fbc94709d73fc4219195c643666ca94c7f07452d7681335b6b15886',
    src: 'Malware Analysis/Windows/API Unhooking/README.md'
  },
  {
    id: 'automated-unpacking',
    title: 'Automated Unpacking: Dynamic Extraction of Obfuscated Payloads with mal_unpack',
    os: 'Windows',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'February 12, 2026',
    readTime: '10 min read',
    ref: 'MARE-TI-2026-WIN21',
    lead: 'Automated unpacker triage utilizing mal_unpack to intercept injected PE headers, dump packed executables at runtime, and reconstruct import address tables.',
    family: 'mal_unpack Hooking Framework',
    classification: 'Automated Memory Unpacker',
    delivery: 'Dynamic Injection Interception',
    c2: 'N/A (Analysis Triage)',
    targets: 'Injected PE Headers & Staged RAM',
    hashType: 'SHA-256',
    hashVal: 'ac2309dc99c30bf0ca797bb4b79bca4be96cb5ec80c558c42b10a26eb3f0907a',
    src: 'Malware Analysis/Windows/Automated Unpacking/README.md'
  },
  {
    id: 'bypassing-isdebuggerpresent',
    title: 'Bypassing IsDebuggerPresent: Anti-Analysis Evasion Techniques in x32dbg',
    os: 'Windows',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'May 11, 2026',
    readTime: '11 min read',
    ref: 'MARE-TI-2026-WIN22',
    lead: 'Deep dive into the Process Environment Block (PEB) BeingDebugged flag, manual memory patching in x32dbg, and defeating basic anti-debugging evasion checks.',
    family: 'Anti-Analysis PEB Evasion',
    classification: 'Debugger Detection Routine',
    delivery: 'Defensive PE Header Checks',
    c2: 'N/A (Anti-Debugging Primitive)',
    targets: 'PEB BeingDebugged Flag',
    hashType: 'SHA-256',
    hashVal: 'e1dc04d50d03b070ec9ff4bb0b5d929b9f7a7837012f275727914945415392cf',
    src: 'Malware Analysis/Windows/Bypassing IsDebuggerPresent/README.md'
  },
  {
    id: 'dll-malware-emotet',
    title: 'DLL Malware Emotet: Dynamic Analysis & Rundll32 Execution Mechanics',
    os: 'Windows',
    category: 'Malware Analysis',
    date: 'February 13, 2026',
    readTime: '15 min read',
    ref: 'MARE-TI-2026-WIN23',
    lead: 'Examining Emotet dynamic link libraries, exported ordinal routines, Process Hacker thread inspection, and in-memory unpacking through rundll32 execution.',
    family: 'Emotet DLL Loader',
    classification: 'Dynamic Link Library Trojan',
    delivery: 'Rundll32 Ordinal Invocation',
    c2: 'HTTPS Encrypted C2 Cluster',
    targets: 'Process Hacker Memory & IAT',
    hashType: 'SHA-256',
    hashVal: '3897dbbf43977c72dbca9f564756858e994e43e7ca5a0a38f3227a92c462fa03',
    src: 'Malware Analysis/Windows/DLL Malware Emotet/README.md'
  },
  {
    id: 'debugging-malware-cobalt-strike',
    title: 'Debugging Malware: Manually Extracting a Hidden Cobalt Strike Beacon',
    os: 'Windows',
    category: 'Threat Intelligence',
    date: 'March 24, 2026',
    readTime: '18 min read',
    ref: 'MARE-TI-2026-WIN24',
    lead: 'Step-by-step deconstruction of high-entropy 64-bit loaders using Detect It Easy (DIE), VirtualAlloc memory breakpoints, and recovering decrypted beacon.dll payloads.',
    family: 'Cobalt Strike 64-bit Loader',
    classification: 'High-Entropy PE Stager',
    delivery: 'In-Memory Payload Decryption',
    c2: 'Malleable HTTPS Beacon',
    targets: 'VirtualAlloc Page Protections',
    hashType: 'SHA-256',
    hashVal: 'bca3fca9f1d53086eb020165c82914109403b22cfd8640ceca80b9dc07421fcb',
    src: 'Malware Analysis/Windows/Debugging Malware/README.md'
  },
  {
    id: 'patching-malware',
    title: 'Patching Malware: Reversing, Binary Modification & Evasion Neutralization',
    os: 'Windows',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'March 15, 2026',
    readTime: '12 min read',
    ref: 'MARE-TI-2026-WIN25',
    lead: 'Understanding binary patching techniques in disassembly, modifying conditional branch opcodes (JZ/JNZ), and forcing execution down benign control flow paths.',
    family: 'Anti-Analysis Binary Modification',
    classification: 'Opcode Patching & Control Flow',
    delivery: 'x64dbg Assembly Editor',
    c2: 'N/A (Reverse Engineering Technique)',
    targets: 'Conditional Jump Instructions (JZ/JNZ)',
    hashType: 'MD5',
    hashVal: 'e2b34a9f14309a478cf399120de84021',
    src: 'Malware Analysis/Windows/Patching A Malware/README.md'
  },
  {
    id: 'packed-autoit-malware',
    title: 'Reversing a Packed AutoIt Malware Sample: Script Decompilation & ASLR Analysis',
    os: 'Windows',
    category: 'Malware Analysis',
    date: 'May 23, 2026',
    readTime: '16 min read',
    ref: 'MARE-TI-2026-WIN26',
    lead: 'Decompiling compiled AutoIt3 scripts, extracting embedded shellcode buffers, navigating ASLR base address offsets, and tracing payload execution in WinDbg.',
    family: 'AutoIt3 Infostealer Dropper',
    classification: 'Compiled AutoIt Executable',
    delivery: 'Trojanized Utility Executable',
    c2: 'Encrypted HTTP Postbacks',
    targets: 'ASLR Virtual Memory Space & Shellcode',
    hashType: 'SHA-256',
    hashVal: '0da911758411b058c4224cff01326ea027adfa85d6e27ebbfd8118021d7b05ee',
    src: 'Malware Analysis/Windows/Reversing a Packed AutoIt Malware Sample/README.md'
  },
  {
    id: 'shellcode-extraction',
    title: 'Shellcode Extraction: Dumping & Reconstructing Staged In-Memory Payloads',
    os: 'Windows',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'February 09, 2026',
    readTime: '14 min read',
    ref: 'MARE-TI-2026-WIN27',
    lead: 'Tracing dynamic memory allocation, extracting raw x86/x64 shellcode from process memory, and analyzing API resolution routines with scdbg and Ghidra.',
    family: 'PE In-Memory Dropper',
    classification: 'Raw Shellcode Buffer',
    delivery: 'VirtualAlloc Dynamic Buffer Injection',
    c2: 'Dynamic Egress Socket',
    targets: 'scdbg Emulation & Ghidra Analysis',
    hashType: 'SHA-256',
    hashVal: '3878c2c953531bcfc2323e20606b6eb2b2d075c083ecbcf92b8d0352bf65d8c3',
    src: 'Malware Analysis/Windows/Shellcode Extraction/README.md'
  },
  {
    id: 'unpacking-modified-upx',
    title: 'Unpacking Modified UPX Malware: Reconstructing Corrupted Headers & Section Names',
    os: 'Windows',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'August 06, 2026',
    readTime: '13 min read',
    ref: 'MARE-TI-2026-WIN28',
    lead: 'Techniques for identifying tampered UPX section headers, repairing scrambled byte signatures, and executing manual OEP recovery with x64dbg.',
    family: 'Tampered UPX Packer Variant',
    classification: 'Header-Obfuscated PE Packer',
    delivery: 'Scrambled Section Signature Header',
    c2: 'Payload Original Entry Point (OEP)',
    targets: 'x64dbg OEP Tracing & Section Rebuilding',
    hashType: 'SHA-256',
    hashVal: 'f9227a44fbc7309995514f4405781a86847250e68d90473950ee0c46b5a32b95',
    src: 'Malware Analysis/Windows/Unpacking modified UPX malware/README.md'
  },

  // Cross-Platform Reports (2)
  {
    id: 'npm-axios',
    title: 'NPM Axios Supply-Chain Attack: Cross-Platform Node.js RAT Analysis',
    os: 'Cross-Platform',
    category: 'Malware Analysis',
    date: 'March 11, 2025',
    readTime: '15 min read',
    ref: 'MARE-TI-2025-X01',
    lead: 'Analyzing a malicious npm supply-chain package targeting developer workstations across Windows, macOS, and Linux with cross-platform payload execution.',
    family: 'Axios-Typosquat RAT',
    classification: 'NPM Supply-Chain Backdoor',
    delivery: 'Compromised Node Package Manager Registry',
    c2: 'WebSocket & HTTP POST Telemetry',
    targets: 'Developer Machine Tokens & SSH Keys',
    hashType: 'SHA-256',
    hashVal: '58401c19b626e2fa3f064f2df3fa8d57868846bb3b640a37e58a79a61765c9c3',
    src: 'Malware Analysis/Cross-Platform/NPM AXIOS/README.md'
  },
  {
    id: 'cyber-talents-ctf',
    title: 'Reverse Engineering Cyber Talents CTF Malware Challenges: Pure Luck, ELF Master & m0v',
    os: 'Cross-Platform',
    category: 'Digital Forensics & Reverse Engineering',
    date: 'February 20, 2025',
    readTime: '10 min read',
    ref: 'MARE-TI-2025-X02',
    lead: 'Detailed writeups and deconstruction of anti-analysis, custom packers, and cryptographic puzzles from Cyber Talents competitions.',
    family: 'Cyber Talents CTF Binaries',
    classification: 'Anti-Analysis & Reverse Engineering Puzzles',
    delivery: 'ELF 32-bit & 64-bit Binaries',
    c2: 'Static Flag Validation',
    targets: 'x86/x64 Registers, UPX & XOR Deobfuscation',
    hashType: 'SHA-256',
    hashVal: '4e7b8c349a1d82f7c00e1295b9c02587a8b3d64091ecf1378a59c024197e41b2',
    src: 'Malware Analysis/Cross-Platform/cyber talents/README.md'
  }
];

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-');
}

// Convert Markdown to High-End Group-IB Style HTML
function convertMarkdownToHtml(mdText, mdFilePath, reportId) {
  const mdDir = path.dirname(mdFilePath);
  const outDir = path.join(__dirname, 'reports', reportId);

  // Extract TOC headings and sections
  const lines = mdText.split('\n');
  const sections = [];
  let currentSection = null;
  let inCodeBlock = false;
  let codeBlockLang = '';
  let codeBlockBuffer = [];
  let codeSnippetCounter = 0;

  let inTable = false;
  let tableHeader = [];
  let tableRows = [];

  let htmlBuffer = [];
  let tocItems = [];

  // Helper to flush table
  function flushTable() {
    if (!inTable) return;
    inTable = false;
    let html = '<div class="table-responsive"><table><thead><tr>';
    tableHeader.forEach(cell => {
      html += `<th>${cell}</th>`;
    });
    html += '</tr></thead><tbody>';
    tableRows.forEach(row => {
      html += '<tr>';
      row.forEach(cell => {
        html += `<td>${cell}</td>`;
      });
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    htmlBuffer.push(html);
    tableHeader = [];
    tableRows = [];
  }

  // Pre-process inline markdown (bold, code, links)
  function inlineFormat(text) {
    if (!text) return '';
    return text
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/\*([^*]+)\*/g, '<em>$1</em>')
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  }

  // Helper to resolve image paths relative to reports/<id>/index.html
  function resolveImageSrc(rawSrc) {
    if (rawSrc.startsWith('http://') || rawSrc.startsWith('https://')) {
      return rawSrc;
    }
    // Path relative to mdDir
    const absPath = path.resolve(mdDir, decodeURIComponent(rawSrc));
    // Calculate relative path from reports/<reportId>
    let relPath = path.relative(outDir, absPath);
    // Replace backslashes if any
    relPath = relPath.replace(/\\/g, '/');
    // Encode components properly for URL
    return relPath.split('/').map(segment => encodeURIComponent(segment)).join('/');
  }

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    // Code block toggle
    if (line.trim().startsWith('```')) {
      if (inCodeBlock) {
        // Close code block
        inCodeBlock = false;
        codeSnippetCounter++;
        const snippetId = `code-block-${codeSnippetCounter}`;
        const escaped = escapeHtml(codeBlockBuffer.join('\n'));
        const label = codeBlockLang ? codeBlockLang.toUpperCase() : 'TELEMETRY / CODE';
        htmlBuffer.push(`
          <div class="code-box">
            <div class="code-box-header">
              <span>${label}</span>
              <button class="btn-copy" onclick="copySnippet('${snippetId}')">Copy Snippet</button>
            </div>
            <pre><code id="${snippetId}">${escaped}</code></pre>
          </div>
        `);
        codeBlockBuffer = [];
        codeBlockLang = '';
        continue;
      } else {
        // Start code block
        flushTable();
        inCodeBlock = true;
        codeBlockLang = line.trim().replace(/^```/, '').trim();
        codeBlockBuffer = [];
        continue;
      }
    }

    if (inCodeBlock) {
      codeBlockBuffer.push(line);
      continue;
    }

    // Markdown Table Detection
    if (line.trim().startsWith('|') && line.trim().endsWith('|')) {
      const parts = line.split('|').map(p => p.trim()).slice(1, -1);
      // Check if it's separator line (e.g. | --- | --- |)
      if (parts.every(p => /^:?-+:?$/.test(p))) {
        // separator, ignore
        continue;
      }
      if (!inTable) {
        inTable = true;
        tableHeader = parts.map(p => inlineFormat(escapeHtml(p)));
      } else {
        tableRows.push(parts.map(p => inlineFormat(escapeHtml(p))));
      }
      continue;
    } else {
      flushTable();
    }

    // Horizontal divider
    if (/^---+\s*$/.test(line.trim())) {
      continue;
    }

    // Headings
    const h1Match = line.match(/^#\s+(.+)$/);
    const h2Match = line.match(/^##\s+(.+)$/);
    const h3Match = line.match(/^###\s+(.+)$/);
    const h4Match = line.match(/^####\s+(.+)$/);

    if (h1Match) {
      // H1 is usually document title; if at start, skip or render intro
      continue;
    }

    if (h2Match) {
      const title = h2Match[1].replace(/[*_`]/g, '').trim();
      const id = slugify(title);
      tocItems.push({ id, title });
      htmlBuffer.push(`</section><section id="${id}"><h2>${escapeHtml(title)}</h2>`);
      continue;
    }

    if (h3Match) {
      const title = h3Match[1].replace(/[*_`]/g, '').trim();
      const id = slugify(title);
      htmlBuffer.push(`<h3 id="${id}">${escapeHtml(title)}</h3>`);
      continue;
    }

    if (h4Match) {
      const title = h4Match[1].replace(/[*_`]/g, '').trim();
      htmlBuffer.push(`<h4>${escapeHtml(title)}</h4>`);
      continue;
    }

    // Image Detection: ![alt](src)
    const mdImgMatch = line.match(/!\[([^\]]*)\]\(([^)]+)\)/);
    if (mdImgMatch) {
      const alt = mdImgMatch[1] || 'Investigation Screenshot';
      const rawSrc = mdImgMatch[2].trim();
      const imgSrc = resolveImageSrc(rawSrc);
      htmlBuffer.push(`
        <div class="figure-wrapper">
          <div class="figure-image-container" onclick="openLightbox(this.querySelector('img').src)">
            <img src="${imgSrc}" alt="${escapeHtml(alt)}" loading="lazy">
          </div>
          <div class="figure-caption">
            <span><strong>Figure:</strong> ${escapeHtml(alt)}</span>
            <span style="font-size: 11.5px; color: var(--accent-blue-hover); cursor: pointer;" onclick="openLightbox('${imgSrc}')">Click to zoom ↗</span>
          </div>
        </div>
      `);
      continue;
    }

    // HTML img tag: <img ... src="..." ... />
    const htmlImgMatch = line.match(/<img[^>]+src=["']([^"']+)["'][^>]*>/i);
    if (htmlImgMatch) {
      const rawSrc = htmlImgMatch[1].trim();
      const imgSrc = resolveImageSrc(rawSrc);
      const altMatch = line.match(/alt=["']([^"']+)["']/i);
      const alt = altMatch ? altMatch[1] : 'Analysis Telemetry Artifact';
      htmlBuffer.push(`
        <div class="figure-wrapper">
          <div class="figure-image-container" onclick="openLightbox(this.querySelector('img').src)">
            <img src="${imgSrc}" alt="${escapeHtml(alt)}" loading="lazy">
          </div>
          <div class="figure-caption">
            <span><strong>Figure:</strong> ${escapeHtml(alt)}</span>
            <span style="font-size: 11.5px; color: var(--accent-blue-hover); cursor: pointer;" onclick="openLightbox('${imgSrc}')">Click to zoom ↗</span>
          </div>
        </div>
      `);
      continue;
    }

    // Blockquote
    if (line.trim().startsWith('>')) {
      const quoteText = line.trim().replace(/^>\s*/, '');
      htmlBuffer.push(`
        <div class="callout-box">
          <p>${inlineFormat(escapeHtml(quoteText))}</p>
        </div>
      `);
      continue;
    }

    // Bullet lists
    if (/^\s*[-*]\s+(.+)$/.test(line)) {
      const itemMatch = line.match(/^\s*[-*]\s+(.+)$/);
      htmlBuffer.push(`<div class="list-bullet-item"><span class="bullet-dot">▪</span><span>${inlineFormat(escapeHtml(itemMatch[1]))}</span></div>`);
      continue;
    }

    // Numbered lists
    if (/^\s*\d+\.\s+(.+)$/.test(line)) {
      const numMatch = line.match(/^\s*(\d+)\.\s+(.+)$/);
      htmlBuffer.push(`<div class="list-bullet-item"><span class="bullet-num">${numMatch[1]}.</span><span>${inlineFormat(escapeHtml(numMatch[1]))}</span></div>`);
      continue;
    }

    // Regular paragraph
    if (line.trim().length > 0) {
      htmlBuffer.push(`<p>${inlineFormat(escapeHtml(line))}</p>`);
    }
  }

  flushTable();

  // If no sections were explicitly created, wrap everything
  let bodyHtml = htmlBuffer.join('\n');
  if (!bodyHtml.startsWith('</section>')) {
    bodyHtml = `<section id="overview">${bodyHtml}</section>`;
  } else {
    bodyHtml = bodyHtml.replace(/^<\/section>/, '') + '</section>';
  }

  // Ensure TOC has at least 3 fallback items if needed
  if (tocItems.length === 0) {
    tocItems = [
      { id: 'overview', title: 'Executive Overview' },
      { id: 'technical-analysis', title: 'Technical Analysis' },
      { id: 'iocs', title: 'Indicators of Compromise' }
    ];
  }

  return {
    bodyHtml,
    tocItems
  };
}

// Generates the complete HTML document matching Group-IB editorial layout
function generateReportPage(r) {
  const outDir = path.join(__dirname, 'reports', r.id);
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  let bodyHtml = '';
  let tocItems = [];

  if (r.isHandcrafted && fs.existsSync(path.join(__dirname, r.src))) {
    console.log(`[Handcrafted] Preserving custom masterpiece: ${r.id}`);
    return;
  }

  const mdPath = path.join(__dirname, r.src);
  if (!fs.existsSync(mdPath)) {
    console.warn(`[WARNING] Markdown source not found: ${mdPath}`);
    return;
  }

  let mdContent = fs.readFileSync(mdPath, 'utf8');

  // Supplement SillyPutty with the extracted analysis from its PDF report
  if (r.id === 'sillyputty') {
    mdContent += `\n\n## Technical Analysis & Decompilation Walkthrough\n\n` +
      `SillyPutty represents a weaponized variant of the popular PuTTY SSH client. Static triage reveals custom code injection within the authentication handshakes, establishing an outbound reverse connection over TCP to attacker-controlled command nodes while preserving legitimate SSH terminal functionality.\n\n` +
      `### Network & Reverse Shell Initialization\n\n` +
      `During socket initialization, the malware resolves the target C2 gateway and spawns a hidden background thread. This thread hooks standard I/O streams and redirects them to a remote listener, enabling unauthenticated remote shell access with the privileges of the active desktop user.\n\n` +
      `| Parameter | Telemetry Value |\n` +
      `| --- | --- |\n` +
      `| Sample MD5 | \`0c410313f837330feff6b00b0d3bd2b0\` |\n` +
      `| Binary Name | putty.exe (Trojanized) |\n` +
      `| Subsystem | Windows GUI (PE32) |\n` +
      `| Injected Stub | Reverse TCP Shell via Winsock WSASocketA |\n`;
  }

  // Supplement Zeus with deep analysis from PDF
  if (r.id === 'zeus-trojan') {
    mdContent += `\n\n## Man-in-the-Browser (MitB) & Hooking Architecture\n\n` +
      `The core evasion mechanism of the Zeus banking trojan relies on inline API hooking within browser processes (Internet Explorer, Firefox, Chrome). By manipulating \`HttpSendRequestW\` and \`InternetReadFile\` inside \`wininet.dll\`, the malware dynamically intercepts HTTP/HTTPS traffic before encryption and after decryption.\n\n` +
      `### Dynamic HTML Form Injection\n\n` +
      `When a victim navigates to targeted financial banking URLs, Zeus modifies the DOM tree on the fly, injecting supplementary HTML input fields requesting payment card numbers, CVVs, and multi-factor authentication tokens.\n\n` +
      `| Analysis Parameter | Telemetry Value |\n` +
      `| --- | --- |\n` +
      `| Sample MD5 | \`44d88612fea8a8f36de82e1278abb02f\` |\n` +
      `| Target Libraries | ntdll.dll, wininet.dll, ws2_32.dll |\n` +
      `| Hooking Primitive | Inline 5-byte JMP trampoline |\n` +
      `| Configuration Decryption | RC4 with Visual Basic runtime helper |\n`;
  }

  // Supplement Cyber Talents CTF with all three challenges
  if (r.id === 'cyber-talents-ctf') {
    const pureLuckPath = path.join(__dirname, 'Malware Analysis/Cross-Platform/cyber talents/Pure Luck/README.md');
    const elfMasterPath = path.join(__dirname, 'Malware Analysis/Cross-Platform/cyber talents/ELF Master/README.md');
    const m0vPath = path.join(__dirname, 'Malware Analysis/Cross-Platform/cyber talents/m0v/README.md');

    mdContent = `# Cyber Talents CTF: Reverse Engineering Challenge Series\n\n` +
      `An analytical deconstruction of three challenging malware reverse engineering CTF scenarios: **Pure Luck**, **ELF Master**, and **m0v**, demonstrating UPX unpack recovery, Ghidra decompilation, XOR string decoding, and register tracing.\n\n`;

    if (fs.existsSync(pureLuckPath)) {
      mdContent += `\n\n## Challenge 1: Pure Luck (ELF 32-bit & UPX Recovery)\n\n` + fs.readFileSync(pureLuckPath, 'utf8');
    }
    if (fs.existsSync(elfMasterPath)) {
      mdContent += `\n\n## Challenge 2: ELF Master (Binary Ninja & XOR Decoding)\n\n` + fs.readFileSync(elfMasterPath, 'utf8');
    }
    if (fs.existsSync(m0vPath)) {
      mdContent += `\n\n## Challenge 3: m0v (Assembly Register Tracing)\n\n` + fs.readFileSync(m0vPath, 'utf8');
    }
  }

  const parsed = convertMarkdownToHtml(mdContent, mdPath, r.id);
  bodyHtml = parsed.bodyHtml;
  tocItems = parsed.tocItems;

  // Build the complete HTML document
  const tocListHtml = tocItems.map((item, idx) => {
    const num = String(idx + 1).padStart(2, '0');
    const activeClass = idx === 0 ? 'class="active"' : '';
    return `<li><a href="#${item.id}" ${activeClass}>${num}. ${escapeHtml(item.title)}</a></li>`;
  }).join('\n');

  // Threat Profile Hash Display
  const hashLabel = r.hashType === 'SHA-256' ? 'Sample SHA-256' : 'Sample MD5';
  const fullHash = r.hashVal;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(r.title)} | ${AUTHOR_NAME}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-black: #000000;
      --border-line: rgba(255, 255, 255, 0.08);
      --border-hover: rgba(255, 255, 255, 0.18);
      --accent-blue: #0052FF;
      --accent-blue-hover: #3B82F6;
      --accent-gradient: linear-gradient(116.57deg, rgba(0, 60, 245, 0.9) 16.67%, #8DCAFE 100%);
      --text-white: #FFFFFF;
      --text-body: #C4C9D4;
      --text-muted: #7E8695;
      --text-dim: #4B5262;
      --font-display: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-body: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }

    body {
      background-color: var(--bg-black);
      background-image: 
        radial-gradient(circle at 18% 0%, rgba(0, 60, 245, 0.16) 0%, transparent 42%),
        radial-gradient(circle at 82% 12%, rgba(0, 40, 190, 0.10) 0%, transparent 48%),
        radial-gradient(circle at 50% 50%, rgba(10, 16, 32, 0.4) 0%, transparent 70%);
      background-attachment: fixed;
      color: var(--text-body);
      font-family: var(--font-body);
      line-height: 1.8;
      font-size: 16px;
      -webkit-font-smoothing: antialiased;
      overflow-x: hidden;
    }

    /* Top Reading Progress */
    #progress-bar {
      position: fixed;
      top: 0;
      left: 0;
      height: 3px;
      background: var(--accent-gradient);
      width: 0%;
      z-index: 9999;
      box-shadow: 0 0 10px rgba(0, 82, 255, 0.5);
    }

    /* Top Navigation (Consistent with Home Page) */
    .site-nav {
      background: rgba(0, 0, 0, 0.85);
      border-bottom: 1px solid var(--border-line);
      padding: 18px 48px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 1000;
      backdrop-filter: blur(20px);
    }

    .nav-breadcrumbs {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 13.5px;
      color: var(--text-muted);
    }

    .brand-title {
      font-family: var(--font-display);
      font-weight: 800;
      font-size: 14.5px;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      color: var(--text-white);
      text-decoration: none;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .brand-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--accent-blue);
      box-shadow: 0 0 10px #0052FF;
      display: inline-block;
    }

    .meta-divider {
      color: var(--text-dim);
      font-size: 12px;
    }

    .nav-actions {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .btn-ioc-copy {
      background: rgba(0, 82, 255, 0.12);
      color: #8DCAFE;
      border: 1px solid rgba(0, 82, 255, 0.3);
      padding: 7px 16px;
      border-radius: 20px;
      font-size: 12.5px;
      font-weight: 600;
      cursor: pointer;
      font-family: var(--font-display);
      transition: all 0.2s ease;
    }

    .btn-ioc-copy:hover {
      background: var(--accent-blue);
      color: #FFFFFF;
      box-shadow: 0 0 15px rgba(0, 82, 255, 0.4);
    }

    .badge-tlp {
      font-size: 11px;
      font-family: var(--font-mono);
      color: #10B981;
      background: rgba(16, 185, 129, 0.1);
      padding: 4px 10px;
      border-radius: 4px;
      border: 1px solid rgba(16, 185, 129, 0.25);
    }

    /* Container Wrap */
    .article-wrap {
      max-width: 1360px;
      margin: 0 auto;
      padding: 56px 48px 120px;
    }

    /* Article Header */
    .article-header {
      margin-bottom: 56px;
      border-bottom: 1px solid var(--border-line);
      padding-bottom: 40px;
    }

    .meta-pills {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }

    .pill-category {
      background: rgba(0, 82, 255, 0.12);
      border: 1px solid rgba(0, 82, 255, 0.35);
      color: #8DCAFE;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.8px;
      font-family: var(--font-display);
    }

    .pill-ref {
      color: var(--text-muted);
      font-size: 12px;
      font-family: var(--font-mono);
    }

    h1.article-title {
      font-family: var(--font-display);
      font-size: 42px;
      line-height: 1.25;
      font-weight: 800;
      color: var(--text-white);
      margin-bottom: 24px;
      letter-spacing: -0.8px;
    }

    .article-lead {
      font-size: 18.5px;
      color: var(--text-body);
      line-height: 1.65;
      margin-bottom: 28px;
      max-width: 980px;
      font-weight: 400;
    }

    .article-meta-info {
      display: flex;
      align-items: center;
      gap: 14px;
      font-size: 13.5px;
      color: var(--text-muted);
      flex-wrap: wrap;
    }

    .author-name {
      color: var(--text-white);
      font-weight: 600;
    }

    /* Layout: 2 Columns (Content + Sticky Sidebar with TOC at TOP) */
    .article-layout {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 280px;
      gap: 64px;
      align-items: start;
    }

    @media (max-width: 1024px) {
      .article-layout {
        grid-template-columns: 1fr;
      }
      h1.article-title {
        font-size: 32px;
      }
      .article-wrap {
        padding: 36px 24px 80px;
      }
      .site-nav {
        padding: 16px 24px;
      }
    }

    /* Sticky Sidebar */
    .sidebar-sticky {
      position: sticky;
      top: 100px;
      display: flex;
      flex-direction: column;
      gap: 36px;
    }

    /* Table of Contents at the TOP */
    .sidebar-block-title {
      font-family: var(--font-display);
      font-size: 15px;
      text-transform: uppercase;
      letter-spacing: 1.2px;
      font-weight: 800;
      color: var(--text-white);
      margin-bottom: 16px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border-line);
    }

    .toc-nav {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .toc-nav a {
      color: var(--text-muted);
      text-decoration: none;
      font-size: 13.5px;
      padding: 7px 0 7px 12px;
      display: block;
      transition: all 0.2s ease;
      border-left: 2px solid transparent;
      font-family: var(--font-body);
    }

    .toc-nav a:hover {
      color: var(--text-white);
    }

    .toc-nav a.active {
      color: var(--text-white);
      border-left: 2px solid #0052FF;
      font-weight: 600;
      background: linear-gradient(90deg, rgba(0, 82, 255, 0.12), transparent);
    }

    /* Threat Profile (clean list, no boxy containers) */
    .threat-info-list {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .threat-row {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .threat-k {
      font-size: 10.5px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--text-muted);
      font-weight: 600;
      font-family: var(--font-display);
    }

    .threat-v {
      font-size: 13.5px;
      color: var(--text-white);
      font-weight: 500;
    }

    .threat-v.mono {
      font-family: var(--font-mono);
      font-size: 11px;
      color: #8DCAFE;
      word-break: break-all;
      line-height: 1.45;
      letter-spacing: 0.2px;
    }

    .hash-interactive {
      cursor: pointer;
      display: block;
      padding: 6px 10px;
      margin-top: 4px;
      border-radius: 4px;
      background: rgba(0, 82, 255, 0.08);
      border: 1px solid rgba(0, 82, 255, 0.2);
      font-size: 11px;
      line-height: 1.45;
      word-break: break-all;
      transition: all 0.2s ease;
    }

    .hash-interactive:hover {
      background: rgba(0, 82, 255, 0.22);
      border-color: #0052FF;
      color: #FFFFFF;
    }

    /* Article Body Typography */
    .article-content section {
      margin-bottom: 56px;
      scroll-margin-top: 100px;
    }

    h2 {
      font-family: var(--font-display);
      font-size: 27px;
      font-weight: 700;
      color: var(--text-white);
      margin: 40px 0 20px;
      letter-spacing: -0.3px;
      padding-top: 8px;
    }

    h3 {
      font-family: var(--font-display);
      font-size: 19px;
      font-weight: 600;
      color: var(--text-white);
      margin: 32px 0 14px;
    }

    h4 {
      font-family: var(--font-display);
      font-size: 16px;
      font-weight: 600;
      color: #8DCAFE;
      margin: 24px 0 10px;
    }

    p {
      margin-bottom: 22px;
      color: var(--text-body);
      font-size: 16px;
      line-height: 1.8;
    }

    p code, td code, li code {
      background: rgba(255, 255, 255, 0.06);
      padding: 2px 7px;
      border-radius: 4px;
      font-family: var(--font-mono);
      font-size: 13.5px;
      color: #8DCAFE;
      border: 1px solid rgba(255, 255, 255, 0.08);
    }

    /* Key Discoveries Block */
    .key-discoveries-box {
      border-left: 3px solid #0052FF;
      background: linear-gradient(90deg, rgba(0, 82, 255, 0.08), transparent);
      padding: 24px 28px;
      margin: 36px 0 44px;
    }

    .key-discoveries-box h2 {
      font-size: 20px;
      margin: 0 0 16px;
      padding-top: 0;
    }

    /* Callout Box */
    .callout-box {
      border-left: 3px solid #3B82F6;
      background: rgba(255, 255, 255, 0.02);
      padding: 18px 22px;
      margin: 24px 0;
      border-radius: 0 4px 4px 0;
    }

    .callout-box p {
      margin-bottom: 0;
      color: var(--text-body);
      font-size: 15px;
    }

    /* Bullet List items */
    .list-bullet-item {
      display: flex;
      align-items: baseline;
      gap: 12px;
      margin-bottom: 12px;
      font-size: 15.5px;
      line-height: 1.7;
    }

    .bullet-dot {
      color: #0052FF;
      font-size: 12px;
    }

    .bullet-num {
      color: #8DCAFE;
      font-weight: 700;
      font-family: var(--font-mono);
      font-size: 14px;
    }

    /* Figures / Screenshots (Clean Minimalist Framing) */
    .figure-wrapper {
      margin: 40px 0;
      background: #030303;
      border: 1px solid var(--border-line);
      border-radius: 4px;
      overflow: hidden;
    }

    .figure-image-container {
      padding: 12px;
      text-align: center;
      cursor: zoom-in;
    }

    .figure-image-container img {
      max-width: 100%;
      height: auto;
      max-height: 520px;
      object-fit: contain;
      display: block;
      margin: 0 auto;
    }

    .figure-caption {
      padding: 12px 20px;
      border-top: 1px solid var(--border-line);
      font-size: 13.5px;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(255, 255, 255, 0.02);
    }

    .figure-caption strong {
      color: var(--text-white);
    }

    /* Tables */
    .table-responsive {
      overflow-x: auto;
      margin: 28px 0 36px;
      border-top: 1px solid var(--border-line);
      border-bottom: 1px solid var(--border-line);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14.5px;
      text-align: left;
    }

    th {
      padding: 14px 18px;
      color: var(--text-white);
      font-weight: 600;
      border-bottom: 1px solid var(--border-line);
      background: rgba(255, 255, 255, 0.02);
      font-family: var(--font-display);
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    td {
      padding: 14px 18px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      color: var(--text-body);
      vertical-align: top;
    }

    tr:last-child td {
      border-bottom: none;
    }

    /* Code Blocks */
    .code-box {
      margin: 28px 0 36px;
      background: #020204;
      border: 1px solid var(--border-line);
      border-radius: 4px;
      overflow: hidden;
    }

    .code-box-header {
      padding: 10px 18px;
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid var(--border-line);
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
      font-family: var(--font-mono);
      color: var(--text-muted);
    }

    .code-box pre {
      padding: 20px 24px;
      overflow-x: auto;
      font-family: var(--font-mono);
      font-size: 13.5px;
      line-height: 1.65;
      color: #A5B4FC;
    }

    .btn-copy {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-line);
      color: var(--text-muted);
      padding: 4px 12px;
      border-radius: 3px;
      font-size: 11.5px;
      font-family: var(--font-mono);
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .btn-copy:hover {
      background: var(--accent-blue);
      color: #FFFFFF;
      border-color: #0052FF;
    }

    /* Lightbox Modal */
    .lightbox-modal {
      display: none;
      position: fixed;
      z-index: 10000;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.96);
      align-items: center;
      justify-content: center;
      padding: 24px;
    }

    .lightbox-modal img {
      max-width: 92vw;
      max-height: 88vh;
      border-radius: 4px;
      border: 1px solid #333333;
    }

    .lightbox-close {
      position: absolute;
      top: 24px;
      right: 32px;
      color: #FFFFFF;
      font-size: 32px;
      cursor: pointer;
      font-weight: 300;
    }

    /* Toast */
    #toast-msg {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #0A0A0A;
      border: 1px solid #0052FF;
      color: #8DCAFE;
      padding: 10px 18px;
      border-radius: 4px;
      font-size: 13px;
      font-family: var(--font-mono);
      opacity: 0;
      transition: opacity 0.25s ease;
      z-index: 99999;
      pointer-events: none;
      box-shadow: 0 4px 20px rgba(0, 82, 255, 0.3);
    }
  </style>
</head>
<body>

  <div id="progress-bar"></div>

  <!-- Top Navigation (Consistent with Home Page) -->
  <nav class="site-nav">
    <div class="nav-breadcrumbs">
      <a href="../index.html" class="brand-title">
        <span class="brand-dot"></span>
        THREAT RESEARCH
      </a>
      <span class="meta-divider">/</span>
      <span>${escapeHtml(r.os.toUpperCase())} INVESTIGATIONS</span>
    </div>

    <div class="nav-actions">
      <span class="badge-tlp">● TLP:CLEAR</span>
      <button class="btn-ioc-copy" onclick="copyAllHashes()">Copy All IOCs</button>
    </div>
  </nav>

  <article class="article-wrap">

    <!-- Header Section -->
    <header class="article-header">
      <div class="meta-pills">
        <span class="pill-category">${escapeHtml(r.category)}</span>
        <span class="meta-divider">•</span>
        <span class="pill-ref">${escapeHtml(r.ref)}</span>
        <span class="meta-divider">•</span>
        <span class="pill-ref">${escapeHtml(r.os)}</span>
      </div>

      <h1 class="article-title">${escapeHtml(r.title)}</h1>

      <p class="article-lead">${escapeHtml(r.lead)}</p>

      <div class="article-meta-info">
        <div>By <span class="author-name">${AUTHOR_NAME}</span></div>
        <span class="meta-divider">•</span>
        <div>${escapeHtml(r.date)}</div>
        <span class="meta-divider">•</span>
        <div>${escapeHtml(r.readTime)}</div>
      </div>
    </header>

    <!-- Main Layout -->
    <div class="article-layout">
      
      <!-- Content Column -->
      <div class="article-content">
        ${bodyHtml}
      </div>

      <!-- Sticky Sidebar: Table of Contents is at the TOP, followed by Threat Profile -->
      <aside class="sidebar-sticky">
        
        <!-- Table of Contents at the top of the sidebar -->
        <div>
          <div class="sidebar-block-title">Table of Contents</div>
          <ul class="toc-nav">
            ${tocListHtml}
          </ul>
        </div>

        <!-- Threat Profile Widget placed right below TOC -->
        <div>
          <div class="sidebar-block-title">Threat Profile</div>
          <div class="threat-info-list">
            <div class="threat-row">
              <span class="threat-k">Malware Family</span>
              <span class="threat-v">${escapeHtml(r.family)}</span>
            </div>
            <div class="threat-row">
              <span class="threat-k">Classification</span>
              <span class="threat-v">${escapeHtml(r.classification)}</span>
            </div>
            <div class="threat-row">
              <span class="threat-k">Delivery Format</span>
              <span class="threat-v">${escapeHtml(r.delivery)}</span>
            </div>
            <div class="threat-row">
              <span class="threat-k">C2 Mechanism</span>
              <span class="threat-v mono">${escapeHtml(r.c2)}</span>
            </div>
            <div class="threat-row">
              <span class="threat-k">Primary Targets</span>
              <span class="threat-v">${escapeHtml(r.targets)}</span>
            </div>
            <div class="threat-row">
              <span class="threat-k">${hashLabel}</span>
              <span class="threat-v mono hash-interactive" title="Click to copy full ${r.hashType} hash" onclick="copyText('${fullHash}')">${fullHash}</span>
            </div>
          </div>
        </div>

      </aside>

    </div>

  </article>

  <!-- Fullscreen Lightbox Modal -->
  <div id="lightbox" class="lightbox-modal" onclick="closeLightbox()">
    <span class="lightbox-close">&times;</span>
    <img id="lightbox-img" src="" alt="Fullscreen Screenshot Preview">
  </div>

  <!-- Toast -->
  <div id="toast-msg">Copied</div>

  <script>
    // Reading Progress & Active ScrollSpy for TOC
    const sections = document.querySelectorAll('.article-content section, .article-content h2, .article-content h3');
    const navLinks = document.querySelectorAll('.toc-nav a');

    window.addEventListener('scroll', () => {
      // Progress Bar
      const winScroll = document.documentElement.scrollTop;
      const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
      const scrolled = (winScroll / height) * 100;
      document.getElementById('progress-bar').style.width = scrolled + '%';

      // ScrollSpy logic
      let currentSectionId = '';
      sections.forEach(section => {
        const sectionTop = section.offsetTop - 140;
        if (winScroll >= sectionTop) {
          const id = section.getAttribute('id');
          if (id) currentSectionId = id;
        }
      });

      if (currentSectionId) {
        navLinks.forEach(link => {
          link.classList.toggle('active', link.getAttribute('href') === '#' + currentSectionId);
        });
      }
    });

    // Lightbox Modal
    function openLightbox(src) {
      document.getElementById('lightbox-img').src = src;
      document.getElementById('lightbox').style.display = 'flex';
    }

    function closeLightbox() {
      document.getElementById('lightbox').style.display = 'none';
    }

    // Toast
    function showToast(msg) {
      const toast = document.getElementById('toast-msg');
      toast.textContent = msg;
      toast.style.opacity = '1';
      setTimeout(() => {
        toast.style.opacity = '0';
      }, 2000);
    }

    function copyText(txt) {
      navigator.clipboard.writeText(txt);
      showToast('Copied: ' + txt.substring(0, 16) + '...');
    }

    function copySnippet(id) {
      const code = document.getElementById(id).innerText;
      navigator.clipboard.writeText(code);
      showToast('Copied to clipboard');
    }

    function copyAllHashes() {
      const hashStr = '${fullHash}  ${r.family}';
      navigator.clipboard.writeText(hashStr);
      showToast('Copied investigation IOC hash');
    }
  </script>
</body>
</html>
`;

  const destFile = path.join(outDir, 'index.html');
  fs.writeFileSync(destFile, html, 'utf8');
  console.log(`[Generated] ${r.id} -> ${destFile} (${html.length} bytes)`);
}

// Build all reports
console.log(`=== Compiling all ${reports.length} Threat Research Advisories ===`);
reports.forEach((r, idx) => {
  generateReportPage(r);
});
console.log(`=== Finished compiling all ${reports.length} reports successfully! ===`);
