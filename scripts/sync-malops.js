const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT_DIR = path.resolve(__dirname, '..');
const EXTERNAL_DIR = path.join(ROOT_DIR, 'external');
const MALOPS_REPO_DIR = path.join(EXTERNAL_DIR, 'malops');
const ANALYSIS_DIR = path.join(ROOT_DIR, 'Malware Analysis');
const MALOPS_GIT_URL = 'https://github.com/Lynk4/malops.io.git';

// Challenge-specific metadata mappings
const CHALLENGE_METADATA = {
  'Singularity': {
    platform: 'Linux',
    mareCategory: 'Reverse Engineering Techniques',
    difficulty: 'Easy',
    tools: 'IDA Pro',
    date: 'February 17, 2026',
    family: 'Singularity Rootkit',
    title: 'Singularity: Linux Kernel Rootkit Reverse Engineering',
    classification: 'Linux Kernel Rootkit / MalOps Challenge',
    delivery: 'Privileged Kernel Module Injection',
    c2: 'ICMP-Triggered Covert Reverse Shell',
    targets: 'Linux Kernel Space & Hidden PIDs/Sockets',
    hashType: 'SHA-256',
    hashVal: '0b8ecdaccf492000f3143fa209481eb9db8c0a29da2b79ff5b7f6e84bb3ac7c8',
    challengeUrl: 'https://malops.io/challenges/singularity',
    navTitle: 'Singularity (Linux Rootkit)',
    subtitle: 'Deconstruct a sophisticated Linux kernel rootkit that hides PIDs and network sockets, hook kernel tables, and establishes an ICMP-triggered covert reverse shell.'
  },
  'Kernel Shield': {
    platform: 'Windows',
    mareCategory: 'Reverse Engineering Techniques',
    difficulty: 'Easy',
    tools: 'IDA Pro',
    date: 'February 24, 2026',
    family: 'Kernel Shield EDR Killer',
    title: 'Kernel Shield: Windows EDR Killer Driver Analysis',
    classification: 'Malicious Kernel Driver / EDR Bypass',
    delivery: 'Bypass / BYOVD Privilege Escalation',
    c2: 'Local IOCTL Communication Loop',
    targets: 'EDR Handle Table & Process Rights',
    hashType: 'SHA-256',
    hashVal: '9bbd99ccbaaeeb95bcf608c02a4bf732ae49e7552ea64e16d445cbf23d1cb539',
    challengeUrl: 'https://malops.io/challenges/kernel-shield',
    navTitle: 'Kernel Shield (EDR Killer)',
    subtitle: 'Analyze a malicious Windows kernel driver that strips handle access rights and force-terminates EDR sensor processes prior to ransomware execution.'
  },
  'EquationDrug': {
    platform: 'Windows',
    mareCategory: 'Threat Intelligence & APTs',
    difficulty: 'Hard',
    tools: 'IDA Pro, x64dbg',
    date: 'February 19, 2026',
    family: 'EquationDrug (Equation Group)',
    title: 'EquationDrug: Kernel-Mode Implant & APC Injection Analysis',
    classification: 'Nation-State Kernel-Mode APT Implant',
    delivery: 'Staged Driver / Kernel Loader',
    c2: 'Raw Kernel Packet Sniffer Protocol',
    targets: 'System Processes & Kernel APC Dispatcher',
    hashType: 'SHA-256',
    hashVal: '980954a2440122da5840b31af7e032e8a25b0ce43e071ceb023cca21cedb2c43',
    challengeUrl: 'https://malops.io/challenges/equationdrug',
    navTitle: 'EquationDrug (Kernel APC)',
    subtitle: 'Investigate the EquationDrug nation-state kernel implant, analyzing memory-only driver execution and kernel APC injection into privileged system processes.'
  },
  'Katz Stealer': {
    platform: 'Windows',
    mareCategory: 'Malware Family Analysis',
    difficulty: 'Medium',
    tools: 'IDA Pro, x64dbg',
    date: 'February 28, 2026',
    family: 'Katz Stealer',
    title: 'Katz Stealer: Dissecting an In-Memory Credential Harvester',
    classification: 'Windows Infostealer / Memory Harvester',
    delivery: 'Trojanized Dropper / Fake Software',
    c2: 'Raw TCP Socket Exfiltration',
    targets: 'Browsers, Crypto Wallets & Desktop Vaults',
    hashType: 'SHA-256',
    hashVal: 'fa72cb8384f671c69992ad81b5314a51e6ba68ce46ee887340f6b3e94472c64b',
    challengeUrl: 'https://malops.io/challenges/katz-stealer',
    navTitle: 'Katz Stealer (Harvester)',
    subtitle: 'Reverse engineer Katz Stealer to uncover broad browser, cryptocurrency wallet, and application credential harvesting routines exfiltrated over raw TCP sockets.'
  },
  'RokRat Loader': {
    platform: 'Windows',
    mareCategory: 'Threat Intelligence & APTs',
    difficulty: 'Medium',
    tools: 'IDA Pro, x64dbg',
    date: 'March 02, 2026',
    family: 'RokRat (Lazarus / APT37)',
    title: 'RokRat Loader: Lazarus APT Shellcode Decryption & PEB Hashing',
    classification: 'State-Sponsored Shellcode Loader',
    delivery: 'Malicious PDF LNK Job Application',
    c2: 'Cloud Storage API Beaconing',
    targets: 'Aerospace & Defense Research Workstations',
    hashType: 'MD5',
    hashVal: 'cf28ef5ceda2aa7d7c149864723e5890',
    challengeUrl: 'https://malops.io/challenges/rokrat-loader',
    navTitle: 'RokRat Loader (Lazarus)',
    subtitle: 'Trace the Lazarus APT RokRat shellcode loader utilizing self-referencing get-EIP routines, XOR payload decryption, and PEB-walk API hashing.'
  },
  'Simda': {
    platform: 'Windows',
    mareCategory: 'Malware Family Analysis',
    difficulty: 'Hard',
    tools: 'IDA Pro, x64dbg',
    date: 'March 04, 2026',
    family: 'Simda Botnet',
    title: 'Simda: Multi-Stage Packer, Anti-Debugging & Dynamic C2 Resolution',
    classification: 'Multi-Stage Botnet / Loader',
    delivery: 'Exploit Kit / Compromised Web Egress',
    c2: 'Dynamic DGA / Registry Config Egress',
    targets: 'Windows Hosts & Corporate Subnets',
    hashType: 'SHA-256',
    hashVal: '75f3a0937c87c9d96850bbdb8e42f61ad61ce5cb3f7076a086bc7920dcbc3e7a',
    challengeUrl: 'https://malops.io/challenges/simda',
    navTitle: 'Simda (Multi-Stage Packer)',
    subtitle: 'Deconstruct the multi-stage Simda loader botnet, detailing XOR payload decryption, memory dumping, debugger detection traps, and RunOnce registry persistence.'
  },
  'carbanak': {
    platform: 'Windows',
    mareCategory: 'Malware Family Analysis',
    difficulty: 'Medium',
    tools: 'IDA Pro, x64dbg',
    date: 'March 06, 2026',
    family: 'Carbanak (FIN7)',
    title: 'Carbanak: Banking Trojan Reverse Engineering & API Hashing Teardown',
    classification: 'Financial Banking Trojan / Backdoor',
    delivery: 'Targeted Spearphishing DOC / CPL Loader',
    c2: 'Custom Encrypted TCP Communications',
    targets: 'Financial Institutions & ATM Controllers',
    hashType: 'SHA-256',
    hashVal: '001b0c11131d161001031f0d0815171e1c0b1a0e0a12140402050609190f0718',
    challengeUrl: 'https://malops.io/challenges/carbanak',
    navTitle: 'Carbanak (Banking Trojan)',
    subtitle: 'Teardown the notorious Carbanak banking trojan, analyzing custom API hashing tables, in-memory process injection, encrypted configurations, and stealthy C2 protocols.'
  },
  'AuraWiper': {
    platform: 'Windows',
    mareCategory: 'Ransomware & Wipers',
    difficulty: 'Easy',
    tools: 'IDA Pro, x64dbg',
    date: 'March 08, 2026',
    family: 'AuraWiper',
    title: 'AuraWiper: Destructive MBR Wiper & Forced BSOD Corruption',
    classification: 'Destructive Wiper / Disk Overwriter',
    delivery: 'Compromised Logistics Endpoint Stager',
    c2: 'N/A (Autonomous Destruction)',
    targets: 'MBR, Windows Boot Loaders & Shadow Copies',
    hashType: 'SHA-256',
    hashVal: '521e714bdc7fdbdc9789aaac1beec6ca63b936e613bc606e2c341d1d8ced64d0',
    challengeUrl: 'https://malops.io/challenges/aurawiper',
    navTitle: 'AuraWiper (MBR Wiper)',
    subtitle: 'Deconstruct the AuraWiper malware to examine destructive MBR overwriting, deletion of critical EFI boot files, Volume Shadow Copy destruction, and forced BSOD via NtRaiseHardError.'
  },
  'ShinySpider': {
    platform: 'Windows',
    mareCategory: 'Ransomware & Wipers',
    difficulty: 'Hard',
    tools: 'IDA Pro, x64dbg',
    date: 'March 10, 2026',
    family: 'ShinySpider Ransomware',
    title: 'ShinySpider: Go-Based Ransomware, ETW Evasion & Hybrid File Encryption',
    classification: 'Enterprise Ransomware / Lateral Movement',
    delivery: 'Lateral Spread via SMB & WMI Tokens',
    c2: 'Local Mutex & Hardcoded Ransom Portal',
    targets: 'Local Drives, Shared Shares & Shadow Copies',
    hashType: 'SHA-256',
    hashVal: 'e41dd341f317cb674ff12c83a17365e5c5aa3240d912ab3801ff4cf09a00ccb2',
    challengeUrl: 'https://malops.io/challenges/shinyspider',
    navTitle: 'ShinySpider (Go Ransomware)',
    subtitle: 'Analyze ShinySpider, a Go-based ransomware featuring ETW evasion, API hashing, mutex-based execution locks, shadow copy purging, and hybrid RSA-OAEP + AES file encryption.'
  },
  'ValleyRAT': {
    platform: 'Windows',
    mareCategory: 'Malware Family Analysis',
    difficulty: 'Medium',
    tools: 'IDA Pro, x64dbg',
    date: 'March 12, 2026',
    family: 'ValleyRAT',
    title: 'ValleyRAT: Go RAT In-Memory PE Loading & Security Patching',
    classification: 'Modular Remote Access Trojan',
    delivery: 'Multi-Stage Dropper Archive',
    c2: 'Multi-Port TCP Socket Beaconing',
    targets: 'Manufacturing Endpoints & In-Memory Secrets',
    hashType: 'SHA-256',
    hashVal: '034e45d82054238e8ec4344d18ec0e9bcba33c56efcb655ea7e26fc49f57fa9e',
    challengeUrl: 'https://malops.io/challenges/valleyrat',
    navTitle: 'ValleyRAT (In-Memory PE)',
    subtitle: 'Reverse engineer ValleyRAT to inspect Run-key persistence, AES-encrypted payload stages, in-memory PE loading, AMSI/ETW security patching, and MiniDumpWriteDump memory dumps.'
  }
};

function copyDirRecursive(src, dest) {
  if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirRecursive(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

async function syncMalOps() {
  console.log('=== Starting MalOps.io Repository Sync ===');

  // 1. Ensure external directory exists
  if (!fs.existsSync(EXTERNAL_DIR)) {
    fs.mkdirSync(EXTERNAL_DIR, { recursive: true });
  }

  // 2. Clone or pull malops.io
  if (!fs.existsSync(MALOPS_REPO_DIR)) {
    console.log(`Cloning ${MALOPS_GIT_URL} into ${MALOPS_REPO_DIR}...`);
    try {
      execSync(`git clone --depth 1 "${MALOPS_GIT_URL}" "${MALOPS_REPO_DIR}"`, { stdio: 'inherit' });
    } catch (e) {
      console.error('Failed to clone malops.io repository:', e.message);
      // Fallback check if /tmp/malops-repo exists
      if (fs.existsSync('/tmp/malops-repo')) {
        console.log('Using /tmp/malops-repo as fallback...');
        copyDirRecursive('/tmp/malops-repo', MALOPS_REPO_DIR);
      } else {
        process.exit(1);
      }
    }
  } else {
    console.log('Updating existing malops.io cache...');
    try {
      execSync(`git -C "${MALOPS_REPO_DIR}" pull`, { stdio: 'inherit' });
    } catch (e) {
      console.warn('[Notice] Could not pull latest changes (offline or clean); continuing with cached files:', e.message);
    }
  }

  // 3. Process each challenge
  const challengeDirs = fs.readdirSync(MALOPS_REPO_DIR).filter(d => 
    !d.startsWith('.') && fs.statSync(path.join(MALOPS_REPO_DIR, d)).isDirectory()
  );

  console.log(`Discovered ${challengeDirs.length} challenge directories in malops.io.`);
  let syncedCount = 0;

  for (const dirName of challengeDirs) {
    const srcDir = path.join(MALOPS_REPO_DIR, dirName);
    const mdPath = path.join(srcDir, 'README.md');
    if (!fs.existsSync(mdPath)) continue;

    // Look up metadata or determine default
    const meta = CHALLENGE_METADATA[dirName] || {
      platform: dirName === 'Singularity' ? 'Linux' : 'Windows',
      mareCategory: 'Reverse Engineering Techniques',
      difficulty: 'Medium',
      tools: 'IDA Pro, x64dbg',
      date: 'March 01, 2026',
      family: dirName,
      title: `${dirName}: Reverse Engineering MalOps Challenge`,
      classification: `${dirName} / MalOps Challenge`,
      delivery: 'Staged Executable / Artifact',
      c2: 'Dynamic Protocol / Telemetry',
      targets: 'Memory & System Artefacts',
      challengeUrl: `https://malops.io/challenges/${dirName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
      navTitle: dirName
    };

    const targetPlatformDir = path.join(ANALYSIS_DIR, meta.platform);
    const targetDir = path.join(targetPlatformDir, dirName);

    console.log(`- Ingesting [${meta.platform}] ${dirName} -> ${path.relative(ROOT_DIR, targetDir)}`);
    copyDirRecursive(srcDir, targetDir);

    // Write enhanced meta.json
    const metaPayload = {
      title: meta.title,
      subtitle: meta.subtitle,
      lead: meta.subtitle,
      category: meta.mareCategory,
      source: 'malops',
      difficulty: meta.difficulty,
      tools: meta.tools,
      challengeUrl: meta.challengeUrl,
      platform: meta.platform,
      date: meta.date,
      family: meta.family,
      classification: meta.classification,
      delivery: meta.delivery,
      c2: meta.c2,
      targets: meta.targets,
      hashType: meta.hashType || 'N/A',
      hashVal: meta.hashVal || '',
      navTitle: meta.navTitle,
      readTime: '15 min read'
    };

    fs.writeFileSync(path.join(targetDir, 'meta.json'), JSON.stringify(metaPayload, null, 2), 'utf8');
    syncedCount++;
  }

  console.log(`\nSuccessfully ingested ${syncedCount} MalOps challenges into Malware Analysis/!`);
  console.log('Run `npm run build` to compile the portal.');
}

syncMalOps().catch(err => {
  console.error('Sync failed:', err);
  process.exit(1);
});
