const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const AUTHOR_NAME = 'Chandra Kant Bauri';
const ROOT_DIR = path.resolve(__dirname, '..');
const BASE_ANALYSIS_DIR = path.join(ROOT_DIR, 'Malware Analysis');
const REPORTS_DIR = path.join(ROOT_DIR, 'reports');
const CACHE_DIR = path.join(ROOT_DIR, '.cache');
const CACHE_FILE = path.join(CACHE_DIR, 'build-manifest.json');

function loadBuildCache() {
  if (process.argv.includes('--force') || process.env.FORCE_BUILD === '1') {
    return {};
  }
  try {
    if (fs.existsSync(CACHE_FILE)) {
      return JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    }
  } catch (e) {}
  return {};
}

function saveBuildCache(cache) {
  try {
    if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2), 'utf8');
  } catch (e) {}
}

const BUILD_GENERATOR_VERSION = 'v2.7-mitre-badges';

function computeReportSourceHash(r) {
  const hash = crypto.createHash('sha256');
  hash.update(BUILD_GENERATOR_VERSION);
  if (fs.existsSync(r.mdPath)) {
    hash.update(fs.readFileSync(r.mdPath));
  }
  const metaPath = path.join(r.srcDir, 'meta.json');
  if (fs.existsSync(metaPath)) {
    hash.update(fs.readFileSync(metaPath));
  }
  try {
    const files = fs.readdirSync(r.srcDir);
    files.forEach(f => {
      const p = path.join(r.srcDir, f);
      const stat = fs.statSync(p);
      if (stat.isDirectory()) {
        const sub = fs.readdirSync(p);
        sub.forEach(sf => {
          hash.update(sf + fs.statSync(path.join(p, sf)).mtimeMs);
        });
      } else {
        hash.update(f + stat.mtimeMs);
      }
    });
  } catch (e) {}
  return hash.digest('hex');
}

// Canonical authentic dates when reports were added to repository
const CANONICAL_REPORT_DATES = {
  'dissecting-avenger-stealer': 'November 09, 2026',
  'hvnc-implant': 'October 17, 2026',
  'rustbucket-2': 'October 02, 2026',
  'rustbucket': 'September 06, 2026',
  'digit-stealer': 'August 23, 2026',
  'unpacking-modified-upx-malware': 'August 06, 2026',
  'atomic-macos-stealer': 'July 15, 2026',
  'kittystealer': 'June 10, 2026',
  'reversing-a-packed-autoit-malware-sample': 'May 23, 2026',
  'bypassing-isdebuggerpresent': 'May 11, 2026',
  'mirai-botnet': 'May 01, 2026',
  'macho-static-analysis': 'April 22, 2026',
  'bpfdoor': 'April 18, 2026',
  'debugging-malware': 'March 24, 2026',
  'patching-a-malware': 'March 15, 2026',
  'dll-malware-emotet': 'February 13, 2026',
  'automated-unpacking': 'February 12, 2026',
  'shellcode-extraction': 'February 09, 2026',
  'wannacry': 'January 15, 2026',
  'cobalt-strike-beacon': 'November 14, 2025',
  'regin-malware': 'October 28, 2025',
  'whispergate-mbr-wiper': 'October 12, 2025',
  'etherrat': 'September 20, 2025',
  'notpetya-ransomware': 'August 29, 2025',
  'reverse-engineering-a-packed-trojan': 'August 10, 2025',
  'bangladesh-gpca': 'August 04, 2025',
  'payload-extraction': 'July 25, 2025',
  'notepad-chrysalis': 'July 18, 2025',
  'agent-tesla': 'July 10, 2025',
  'deconstructing-emotet': 'June 30, 2025',
  'qakbot-unpacking': 'June 22, 2025',
  'malware-binary-diffing': 'June 02, 2025',
  'dynamic-api-resolution': 'May 18, 2025',
  'reversing-hash-based-api-resolution': 'May 08, 2025',
  'shellcode-triage-and-api-resolution': 'April 28, 2025',
  'x64dbg-conditional-breakpoints': 'April 14, 2025',
  'api-unhooking': 'March 22, 2025',
  'npm-axios': 'March 11, 2025',
  'cyber-talents-ctf': 'February 20, 2025',
  'singularity': 'February 17, 2026',
  'equationdrug': 'February 19, 2026',
  'kernel-shield': 'February 24, 2026',
  'katz-stealer': 'February 28, 2026',
  'rokrat-loader': 'March 02, 2026',
  'simda': 'March 04, 2026',
  'carbanak': 'March 06, 2026',
  'aurawiper': 'March 08, 2026',
  'shinyspider': 'March 10, 2026',
  'valleyrat': 'March 12, 2026'
};

// Helper to get authentic git added date for a file
function getGitAddedDate(filePath, id) {
  if (id && CANONICAL_REPORT_DATES[id]) {
    return CANONICAL_REPORT_DATES[id];
  }
  try {
    const rel = path.relative(ROOT_DIR, filePath);
    const out = execSync(`git log --diff-filter=A --follow --format="%ad" --date=format:"%B %d, %Y" -- "${rel}"`, { encoding: 'utf8', cwd: ROOT_DIR }).trim();
    if (!out) {
      const out2 = execSync(`git log --reverse --format="%ad" --date=format:"%B %d, %Y" -- "${rel}"`, { encoding: 'utf8', cwd: ROOT_DIR }).trim();
      const lines2 = out2.split('\n').filter(Boolean);
      return lines2[0] || null;
    }
    const lines = out.split('\n').filter(Boolean);
    return lines[lines.length - 1]; // oldest commit where file was added
  } catch (e) {
    return null;
  }
}

// Helper to escape HTML
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

// Minimalist Threat Icons
function getThreatIcon(type) {
  switch (type) {
    case 'stealer':
      return `<svg class="threat-svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-1.5 1.5L16 7l1.5 1.5L16 10l-1.5-1.5L13 10l-1.5-1.5L10 10 3 17v4h4l7-7 1.5 1.5 1.5-1.5-1.5-1.5L17 11l1.5-1.5L20 8l1-1z"/></svg>`;
    case 'wiper':
    case 'ransomware':
      return `<svg class="threat-svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>`;
    case 'apt':
      return `<svg class="threat-svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/><circle cx="12" cy="12" r="2.5"/></svg>`;
    case 'c2':
    case 'botnet':
      return `<svg class="threat-svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4.93 4.93a10 10 0 0 1 14.14 0"/><path d="M7.76 7.76a6 6 0 0 1 8.48 0"/><circle cx="12" cy="12" r="2"/><line x1="12" y1="14" x2="12" y2="21"/></svg>`;
    case 'binary':
    default:
      return `<svg class="threat-svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/><line x1="14" y1="4" x2="10" y2="20"/></svg>`;
  }
}

// Intelligent Content-Aware Code Block Language Classifier
function formatCodeBlockHeader(declared, codeText) {
  const d = (declared || '').trim().toLowerCase();
  const c = (codeText || '').trim();
  const lines = c.split('\n').map(l => l.trim()).filter(Boolean);
  if (!lines.length) return 'TELEMETRY';

  const firstLine = lines[0];
  const sample = lines.slice(0, 15).join('\n');

  // 1. YARA Detection Rules
  if (/\brule\s+[A-Za-z0-9_]+\s*[:{]/.test(c) && /\b(?:strings|condition)\s*:/i.test(c)) {
    return 'YARA RULE';
  }

  // Pre-calculate assembly & disassembly signals
  const arm64Matches = (sample.match(/\b(?:ldr|str|stp|ldp|bl|adr|adrp|cbnz|cbz|w[0-9]{1,2}|x[0-9]{1,2})\b/gi) || []).length;
  const x86Matches = (sample.match(/\b(?:eax|ebx|ecx|edx|rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r[89]|r1[0-5]|qword|dword|byte ptr|syscall)\b/gi) || []).length;
  const genericAsm = (sample.match(/\b(?:mov|push|pop|call|lea|xor|cmp|test|sub|add|jmp|jne|je|ret|nop)\b/gi) || []).length;
  const hasHexOffsets = (sample.match(/^(?:0x[0-9a-fA-F]+|[0-9a-fA-F]{8,16})\b/gm) || []).length;
  const isAsmDisasm = (arm64Matches >= 2 || x86Matches >= 2 || (genericAsm >= 2 && hasHexOffsets >= 1) || (arm64Matches >= 1 && (genericAsm >= 1 || hasHexOffsets >= 1)) || (x86Matches >= 1 && (genericAsm >= 1 || hasHexOffsets >= 1)));

  // 2. Terminal Prompts or CLI Tool Invocations
  const isCliPrompt = /^(?:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+.*?[%#\$>]|┌──\(|PS\s+[A-Z]:\\|[A-Z]:\\[^\n>]*>|\$\s+|#\s+|>\s*)/.test(firstLine);
  const isCliCmd = /^(?:go\s+|python3?\s+-[cm]|codesign\s+|otool\s+|objdump\s+|strings\s+|nm\s+|xxd\s+|hexdump\s+|curl\s+|wget\s+|sudo\s+|chmod\s+|file\s+|grep\s+|find\s+|cat\s+|sysctl\s+|volatility\s+|gcc\s+|g\+\+\s+|make\s+|npm\s+|git\s+|upx\s+|xattr\s+)/.test(firstLine);
  if (isCliCmd || (isCliPrompt && !isAsmDisasm)) {
    return 'TERMINAL / COMMAND';
  }

  // 3. Architecture & ASCII Diagrams
  const boxChars = (c.match(/[┌└├│─┬┴┼▼►▲◄]/g) || []).length;
  if (boxChars >= 6) {
    return 'ARCHITECTURE / DIAGRAM';
  }
  if (/^\+[-+]+\+\s*$/.test(firstLine) && /\|.*\|/.test(sample)) {
    if (!/\b(?:mov|push|pop|call|add|sub)\b/i.test(sample)) {
      return 'ARCHITECTURE / DIAGRAM';
    }
  }

  // 4. Hex Byte Dumps
  if (/^[0-9a-fA-F]{4,8}[:\s]+(?:[0-9a-fA-F]{2}\s+){4,}/m.test(sample)) {
    return 'HEX DUMP';
  }

  // 5. XML / Plist Documents
  if (c.startsWith('<?xml') || c.startsWith('<!DOCTYPE plist') || c.startsWith('<plist') || /<\?xml\b/i.test(firstLine) || /<!DOCTYPE\s+plist/i.test(sample)) {
    if (/<plist\b/i.test(sample) || /com\.apple\./i.test(sample)) {
      return 'XML / PLIST';
    }
    return 'XML';
  }
  if (/^\s*<[a-zA-Z0-9_-]+(\s+[^>]*)?>/i.test(firstLine) && /<\/[a-zA-Z0-9_-]+>\s*$/i.test(lines[lines.length - 1])) {
    if (!/(?:#include|int\s+main|std::)/.test(sample)) {
      if (/<plist\b/i.test(sample)) return 'XML / PLIST';
      if (/<html\b/i.test(sample)) return 'HTML';
      return 'XML';
    }
  }

  // 6. JSON Documents
  if ((c.startsWith('{') && c.endsWith('}')) || (c.startsWith('[') && c.endsWith(']'))) {
    if (/"[a-zA-Z0-9_.-]+"\s*:/i.test(sample)) {
      return 'JSON';
    }
  }

  // 6. Python Scripts & Modules
  if (c.startsWith('#!/usr/bin/env python') || c.startsWith('#!/usr/bin/python')) {
    return 'PYTHON';
  }
  if (/\b(?:import\s+[a-zA-Z0-9_]+|from\s+[a-zA-Z0-9_.]+\s+import)\b/.test(sample)) {
    if (!/(?:#include|using\s+namespace|#define|int\s+main)/.test(sample)) {
      return 'PYTHON';
    }
  }
  if (/\bdef\s+[a-zA-Z0-9_]+\s*\([^)]*\)\s*:/.test(sample)) {
    return 'PYTHON';
  }

  // 7. PowerShell Commands & Scripts
  if (/\b(?:Get-[A-Za-z]+|Set-[A-Za-z]+|Invoke-[A-Za-z]+|Start-Process|Write-Host|\$env:[A-Za-z]+)\b/.test(sample)) {
    return 'POWERSHELL';
  }

  // 8. Assembly & Disassembly (ARM64 vs x86/x64 vs Generic)
  if (arm64Matches >= 2 || (arm64Matches >= 1 && genericAsm >= 1)) {
    if (!/(?:#include|int\s+main|void\s+[a-zA-Z0-9_]+\s*\(|return\s+[^;]+;)/.test(sample)) {
      return 'ARM64 DISASSEMBLY';
    }
  }

  if (x86Matches >= 2 || (x86Matches >= 1 && genericAsm >= 1)) {
    if (!/(?:#include|int\s+main|void\s+[a-zA-Z0-9_]+\s*\(|return\s+[^;]+;)/.test(sample)) {
      return 'X86_64 DISASSEMBLY';
    }
  }

  if (genericAsm >= 3 || (hasHexOffsets >= 2 && genericAsm >= 1)) {
    if (!/(?:#include|int\s+main|void\s+[a-zA-Z0-9_]+\s*\(|return\s+[^;]+;)/.test(sample)) {
      return 'DISASSEMBLY';
    }
  }

  // 9. Native C / C++ / Decompiled Source
  if (/(?:#include\s*<|int\s+main\s*\(|NTSTATUS|PVOID|HANDLE|DWORD|WINAPI|typedef\s+struct|std::|__stdcall|__fastcall|\bvoid\s*\*)/.test(sample)) {
    return 'C / C++';
  }

  // 10. Filter out bogus tags and map valid declared tags
  const bogusTags = new Set(['jsx', 'passw0rd1337', '001a1287', '006813b4', 'mruprac', 'mal', 'malware-report']);
  const cleanDeclared = bogusTags.has(d) ? '' : d;

  if (cleanDeclared === 'nasm' || cleanDeclared === 'asm') {
    if (arm64Matches >= 1 || x86Matches >= 1 || genericAsm >= 1 || hasHexOffsets >= 1) {
      if (arm64Matches >= 2 || (arm64Matches >= 1 && genericAsm >= 1)) return 'ARM64 DISASSEMBLY';
      if (x86Matches >= 2 || (x86Matches >= 1 && genericAsm >= 1)) return 'X86_64 DISASSEMBLY';
      return 'ASSEMBLY (ASM)';
    }
    // No assembly instructions found: plain text, translation, or CLI command
    if (isCliPrompt || isCliCmd || /^(?:go\s|curl\s|python|chmod|git|cat|grep)/i.test(firstLine)) {
      return 'TERMINAL / COMMAND';
    }
    return 'TELEMETRY / OUTPUT';
  }

  if (cleanDeclared === 'xml' || cleanDeclared === 'plist') {
    if (/<plist\b/i.test(sample) || /com\.apple\./i.test(sample) || cleanDeclared === 'plist') {
      return 'XML / PLIST';
    }
    return 'XML';
  }

  const declaredMap = {
    c: 'C',
    cpp: 'C++',
    python: 'PYTHON',
    python3: 'PYTHON',
    py: 'PYTHON',
    bash: 'TERMINAL / BASH',
    sh: 'SHELL',
    zsh: 'SHELL',
    powershell: 'POWERSHELL',
    ps1: 'POWERSHELL',
    json: 'JSON',
    xml: 'XML',
    plist: 'XML / PLIST',
    html: 'HTML',
    yaml: 'YAML',
    yml: 'YAML',
    sql: 'SQL',
    go: 'GO',
    golang: 'GO',
    rust: 'RUST',
    rs: 'RUST',
    js: 'JAVASCRIPT',
    javascript: 'JAVASCRIPT',
    ts: 'TYPESCRIPT',
    typescript: 'TYPESCRIPT',
    toml: 'CONFIG / TOML',
    ini: 'CONFIG / INI',
    diff: 'DIFF / PATCH',
    patch: 'DIFF / PATCH',
    swift: 'SWIFT',
    objectivec: 'OBJECTIVE-C',
    objc: 'OBJECTIVE-C',
    yara: 'YARA RULE',
    text: 'TELEMETRY / OUTPUT',
    txt: 'TELEMETRY / OUTPUT'
  };

  if (cleanDeclared && declaredMap[cleanDeclared]) {
    return declaredMap[cleanDeclared];
  }

  if (isAsmDisasm || genericAsm >= 1 || arm64Matches >= 1 || x86Matches >= 1 || hasHexOffsets >= 1) {
    return 'DISASSEMBLY';
  }

  return 'TELEMETRY / OUTPUT';
}

// Maps code block classification to clean user-facing label and CSS ecosystem class
function getCodeBlockMeta(declared, codeText) {
  const rawLabel = formatCodeBlockHeader(declared, codeText);
  // Guarantee zero raw backticks in user-facing header
  const label = (rawLabel || 'TELEMETRY / OUTPUT').replace(/`+/g, '').trim();

  let langClass = 'lang-generic';
  const u = label.toUpperCase();
  if (u.includes('ARM64') || u.includes('X86') || u.includes('DISASSEMBLY') || u.includes('ASSEMBLY') || u.includes('NASM')) {
    langClass = 'lang-disasm';
  } else if (u.includes('TERMINAL') || u.includes('COMMAND') || u.includes('BASH') || u.includes('SHELL')) {
    langClass = 'lang-terminal';
  } else if (u.includes('YARA')) {
    langClass = 'lang-yara';
  } else if (u.includes('XML') || u.includes('PLIST') || u.includes('HTML')) {
    langClass = 'lang-xml';
  } else if (u.includes('PYTHON')) {
    langClass = 'lang-python';
  } else if (u.includes('C / C++') || u.includes('C++') || u === 'C') {
    langClass = 'lang-c';
  } else if (u.includes('POWERSHELL')) {
    langClass = 'lang-powershell';
  } else if (u.includes('HEX')) {
    langClass = 'lang-hex';
  } else if (u.includes('JSON') || u.includes('YAML') || u.includes('CONFIG') || u.includes('TOML') || u.includes('INI')) {
    langClass = 'lang-config';
  } else if (u.includes('GO')) {
    langClass = 'lang-go';
  } else if (u.includes('RUST')) {
    langClass = 'lang-rust';
  } else if (u.includes('SWIFT') || u.includes('OBJECTIVE-C')) {
    langClass = 'lang-swift';
  }

  return { label, langClass };
}

// =============================================================================
// AUTONOMOUS SYNTAX HIGHLIGHTER (Zero Runtime Dependencies)
// =============================================================================

const ASM_OPCODES = new Set([
  'ldr', 'str', 'ldur', 'stur', 'mov', 'movz', 'movk', 'movn', 'add', 'sub', 'adds', 'subs',
  'cmp', 'cmn', 'b', 'bl', 'blr', 'bx', 'cbz', 'cbnz', 'tbz', 'tbnz', 'adr', 'adrp', 'nop',
  'ret', 'svc', 'stp', 'ldp', 'and', 'orr', 'eor', 'mvn', 'lsl', 'lsr', 'asr', 'ror',
  'lea', 'push', 'pop', 'call', 'jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jae',
  'jb', 'jbe', 'jg', 'jge', 'jl', 'jle', 'js', 'jns', 'test', 'xor', 'not', 'shl', 'shr',
  'sar', 'imul', 'idiv', 'mul', 'div', 'inc', 'dec', 'int', 'int3', 'syscall', 'sysenter', 'leave'
]);
const ASM_DIRECTIVES = new Set([
  'section', 'global', 'extern', 'default', 'rel', 'byte', 'word', 'dword', 'qword',
  'ptr', 'db', 'dw', 'dd', 'dq', 'resb', 'resw', 'resd', 'resq', 'align', 'equ'
]);
const ARM_COND = /^(b\.(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le))$/i;
const ASM_REG_REGEX = /^(x[0-9]{1,2}|w[0-9]{1,2}|sp|fp|lr|xzr|wzr|pc|d[0-9]{1,2}|q[0-9]{1,2}|s[0-9]{1,2}|v[0-9]{1,2}|r[a-d]x|r[s|d]i|r[b|s]p|r[8-9][d|w|b]?|r1[0-5][d|w|b]?|e[a-d]x|e[s|d]i|e[b|s]p|[a-d]x|[s|d]i|[b|s]p|[a-d][l|h]|cs|ds|es|fs|gs|ss|cr[0-4]|dr[0-7])$/i;

// Safe replacement helper that HTML-escapes all text outside matched tokens
function replaceWithHtmlEscape(text, regex, replacer) {
  if (!text) return '';
  let lastIndex = 0;
  let out = '';
  let flags = regex.flags || '';
  if (!flags.includes('g')) flags += 'g';
  const re = new RegExp(regex.source, flags);
  let match;
  while ((match = re.exec(text)) !== null) {
    if (match.index > lastIndex) {
      out += escapeHtml(text.slice(lastIndex, match.index));
    }
    const tokenResult = replacer(...match, match.index, text);
    out += (tokenResult !== undefined && tokenResult !== null) ? tokenResult : escapeHtml(match[0]);
    lastIndex = re.lastIndex;
    if (match.index === re.lastIndex) {
      re.lastIndex++;
    }
  }
  if (lastIndex < text.length) {
    out += escapeHtml(text.slice(lastIndex));
  }
  return out;
}

function highlightDisasm(text) {
  const lines = text.split('\n');
  return lines.map(line => {
    const trimmed = line.trim();
    if (!trimmed) return '';
    if (trimmed.startsWith(';') || trimmed.startsWith('//') || /^#(?![+-]?(0x)?[0-9])/.test(trimmed)) {
      return `<span class="tok-cmt">${escapeHtml(line)}</span>`;
    }
    let codePart = line;
    let cmtPart = '';
    const cmtMatch = line.match(/(;\s*.*|\/\/\s*.*|\s+#[a-zA-Z\s].*)$/);
    if (cmtMatch) {
      codePart = line.slice(0, cmtMatch.index);
      cmtPart = cmtMatch[0];
    }
    const tokenRegex = /(#[+-]?0x[0-9a-fA-F]+|#[+-]?[0-9]+|\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{8,16}\b|\b\d+\b)|([a-zA-Z0-9_\.]+|\[|\]|,|!)/g;
    let out = replaceWithHtmlEscape(codePart, tokenRegex, (m, num, word) => {
      if (num) return `<span class="tok-num">${escapeHtml(num)}</span>`;
      if (word) {
        const lower = word.toLowerCase();
        if (ASM_OPCODES.has(lower) || ARM_COND.test(lower)) {
          return `<span class="tok-kw">${escapeHtml(word)}</span>`;
        }
        if (ASM_DIRECTIVES.has(lower)) {
          return `<span class="tok-tag">${escapeHtml(word)}</span>`;
        }
        if (ASM_REG_REGEX.test(lower)) {
          return `<span class="tok-reg">${escapeHtml(word)}</span>`;
        }
        if (word.startsWith('_') || word.includes('.')) {
          return `<span class="tok-fn">${escapeHtml(word)}</span>`;
        }
      }
      return escapeHtml(m);
    });
    if (cmtPart) {
      out += `<span class="tok-cmt">${escapeHtml(cmtPart)}</span>`;
    }
    return out;
  }).join('\n');
}

const C_KEYWORDS = new Set([
  'int', 'char', 'void', 'float', 'double', 'short', 'long', 'unsigned', 'signed',
  'const', 'static', 'volatile', 'struct', 'union', 'enum', 'typedef', 'sizeof',
  'return', 'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'break', 'continue',
  'default', 'goto', 'NULL', 'nullptr', 'true', 'false', 'auto', 'class', 'public',
  'private', 'protected', 'virtual', 'namespace', 'using', 'new', 'delete', 'try',
  'catch', 'throw', 'DWORD', 'HANDLE', 'BOOL', 'LPVOID', 'PVOID', 'HMODULE', 'NTSTATUS',
  'WINAPI', 'CALLBACK', 'BYTE', 'WORD', 'ULONG', 'LONG', 'SIZE_T', 'HINSTANCE',
  'LPCSTR', 'LPWSTR', 'LPCWSTR', 'LPBYTE', 'FARPROC'
]);

function highlightC(code) {
  const regex = /(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(^#[a-zA-Z_]+[^\n]*)|(\b0x[0-9a-fA-F]+[uUlL]*\b|\b\d+(?:\.\d+)?[fFlL]?\b)|(\b[a-zA-Z_][a-zA-Z0-9_]*\b)/gm;
  return replaceWithHtmlEscape(code, regex, (m, cmt, str, prep, num, ident) => {
    if (cmt) return `<span class="tok-cmt">${escapeHtml(cmt)}</span>`;
    if (str) return `<span class="tok-str">${escapeHtml(str)}</span>`;
    if (prep) return `<span class="tok-tag">${escapeHtml(prep)}</span>`;
    if (num) return `<span class="tok-num">${escapeHtml(num)}</span>`;
    if (ident) {
      if (C_KEYWORDS.has(ident)) return `<span class="tok-kw">${escapeHtml(ident)}</span>`;
      return `<span class="tok-fn">${escapeHtml(ident)}</span>`;
    }
    return escapeHtml(m);
  });
}

const PY_KEYWORDS = new Set([
  'def', 'class', 'import', 'from', 'as', 'return', 'if', 'elif', 'else', 'while',
  'for', 'in', 'try', 'except', 'finally', 'raise', 'with', 'pass', 'break', 'continue',
  'lambda', 'yield', 'global', 'nonlocal', 'assert', 'async', 'await', 'True', 'False',
  'None', 'and', 'or', 'not', 'is'
]);
const PY_BUILTINS = new Set([
  'print', 'len', 'range', 'open', 'str', 'int', 'bytes', 'bytearray', 'list', 'dict',
  'set', 'tuple', 'enumerate', 'zip', 'isinstance', 'type', 'hex', 'chr', 'ord', 'map', 'filter'
]);

function highlightPython(code) {
  const regex = /(#[^\n]*)|("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(\b0x[0-9a-fA-F]+\b|\b\d+(?:\.\d+)?\b)|(\b[a-zA-Z_][a-zA-Z0-9_]*\b)/gm;
  return replaceWithHtmlEscape(code, regex, (m, cmt, str, num, ident) => {
    if (cmt) return `<span class="tok-cmt">${escapeHtml(cmt)}</span>`;
    if (str) return `<span class="tok-str">${escapeHtml(str)}</span>`;
    if (num) return `<span class="tok-num">${escapeHtml(num)}</span>`;
    if (ident) {
      if (PY_KEYWORDS.has(ident)) return `<span class="tok-kw">${escapeHtml(ident)}</span>`;
      if (PY_BUILTINS.has(ident)) return `<span class="tok-fn">${escapeHtml(ident)}</span>`;
      return escapeHtml(ident);
    }
    return escapeHtml(m);
  });
}

function highlightTerminal(text) {
  const lines = text.split('\n');
  return lines.map(line => {
    const trimmed = line.trim();
    if (!trimmed) return '';
    const promptMatch = line.match(/^(\s*)([\$#➜%]|PS\s+[^>]+>)\s+(.*)$/);
    if (promptMatch) {
      const indent = promptMatch[1];
      const prompt = promptMatch[2];
      const cmdRest = promptMatch[3];
      const highlightedRest = replaceWithHtmlEscape(cmdRest, /(#[^\n]*)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(-{1,2}[a-zA-Z0-9_\-]+)|(^[a-zA-Z0-9_\.\-]+|\s+[a-zA-Z0-9_\.\-]+)/g, (m, cmt, str, flag, cmd) => {
        if (cmt) return `<span class="tok-cmt">${escapeHtml(cmt)}</span>`;
        if (str) return `<span class="tok-str">${escapeHtml(str)}</span>`;
        if (flag) return `<span class="tok-kw">${escapeHtml(flag)}</span>`;
        if (cmd) return `<span class="tok-fn">${escapeHtml(cmd)}</span>`;
        return escapeHtml(m);
      });
      return `${indent}<span class="tok-prompt">${escapeHtml(prompt)} </span>${highlightedRest}`;
    }
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) {
      return `<span class="tok-cmt">${escapeHtml(line)}</span>`;
    }
    return replaceWithHtmlEscape(line, /(\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{32,64}\b)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|([a-zA-Z0-9_-]+=[^\s]+)/g, (m, hex, str, kv) => {
      if (hex) return `<span class="tok-num">${escapeHtml(hex)}</span>`;
      if (str) return `<span class="tok-str">${escapeHtml(str)}</span>`;
      if (kv) {
        const eqIdx = kv.indexOf('=');
        return `<span class="tok-reg">${escapeHtml(kv.slice(0, eqIdx))}</span>=${escapeHtml(kv.slice(eqIdx + 1))}`;
      }
      return escapeHtml(m);
    });
  }).join('\n');
}

const YARA_KEYWORDS = new Set([
  'rule', 'meta', 'strings', 'condition', 'all', 'any', 'of', 'them', 'and', 'or', 'not',
  'in', 'contains', 'matches', 'nocase', 'wide', 'ascii', 'fullword', 'xor', 'base64',
  'filesize', 'entrypoint', 'uint8', 'uint16', 'uint32', 'int8', 'int16', 'int32'
]);

function highlightYara(code) {
  const regex = /(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\])*")|(\$[a-zA-Z0-9_]+)|\b(0x[0-9a-fA-F]+|\d+)\b|(\{[\s0-9a-fA-F\?\(\)\|]+\})|(\b[a-zA-Z_][a-zA-Z0-9_]*:?)/g;
  return replaceWithHtmlEscape(code, regex, (m, cmt, str, varId, num, hexBytes, word) => {
    if (cmt) return `<span class="tok-cmt">${escapeHtml(cmt)}</span>`;
    if (str) return `<span class="tok-str">${escapeHtml(str)}</span>`;
    if (varId) return `<span class="tok-reg">${escapeHtml(varId)}</span>`;
    if (num) return `<span class="tok-num">${escapeHtml(num)}</span>`;
    if (hexBytes) return `<span class="tok-str">${escapeHtml(hexBytes)}</span>`;
    if (word) {
      const clean = word.replace(/:$/, '').toLowerCase();
      if (YARA_KEYWORDS.has(clean) || word.endsWith(':')) {
        return `<span class="tok-tag">${escapeHtml(word)}</span>`;
      }
      return escapeHtml(word);
    }
    return escapeHtml(m);
  });
}

function highlightXml(code) {
  const regex = /(<!--[\s\S]*?-->)|(<\?[^>]*\?>|<!DOCTYPE[^>]*>)|(<\/?)([a-zA-Z0-9_\-:]+)([^>]*?)(\/?>)/g;
  return replaceWithHtmlEscape(code, regex, (m, cmt, decl, openTag, tagName, attrs, closeTag) => {
    if (cmt) return `<span class="tok-cmt">${escapeHtml(cmt)}</span>`;
    if (decl) return `<span class="tok-tag">${escapeHtml(decl)}</span>`;
    if (openTag) {
      let attrHtml = replaceWithHtmlEscape(attrs || '', /([a-zA-Z0-9_\-]+)(=)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/g, (am, aName, eq, aVal) => {
        return `<span class="tok-reg">${escapeHtml(aName)}</span>=<span class="tok-str">${escapeHtml(aVal)}</span>`;
      });
      return `${escapeHtml(openTag)}<span class="tok-fn">${escapeHtml(tagName)}</span>${attrHtml}${escapeHtml(closeTag)}`;
    }
    return escapeHtml(m);
  });
}

const GO_KEYWORDS = new Set([
  'package', 'import', 'func', 'var', 'const', 'type', 'struct', 'interface', 'map',
  'chan', 'return', 'if', 'else', 'for', 'range', 'switch', 'case', 'default', 'select',
  'go', 'defer', 'break', 'continue', 'fallthrough', 'nil', 'true', 'false'
]);
const GO_TYPES = new Set([
  'string', 'int', 'int8', 'int16', 'int32', 'int64', 'uint', 'uint8', 'uint16',
  'uint32', 'uint64', 'byte', 'rune', 'float32', 'float64', 'bool', 'error', 'any'
]);
function highlightGo(code) {
  const regex = /(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|(`(?:\\.|[^`\\])*`|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(\b0x[0-9a-fA-F]+\b|\b\d+(?:\.\d+)?\b)|(\b[a-zA-Z_][a-zA-Z0-9_]*\b)/gm;
  return replaceWithHtmlEscape(code, regex, (m, cmt, str, num, ident) => {
    if (cmt) return `<span class="tok-cmt">${escapeHtml(cmt)}</span>`;
    if (str) return `<span class="tok-str">${escapeHtml(str)}</span>`;
    if (num) return `<span class="tok-num">${escapeHtml(num)}</span>`;
    if (ident) {
      if (GO_KEYWORDS.has(ident)) return `<span class="tok-kw">${escapeHtml(ident)}</span>`;
      if (GO_TYPES.has(ident)) return `<span class="tok-tag">${escapeHtml(ident)}</span>`;
      return `<span class="tok-fn">${escapeHtml(ident)}</span>`;
    }
    return escapeHtml(m);
  });
}

function highlightPowerShell(code) {
  const regex = /(#[^\n]*|<#[\s\S]*?#>)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(\$[a-zA-Z0-9_:]+)|(\b[a-zA-Z]+-[a-zA-Z0-9]+\b)|(-[a-zA-Z0-9]+)|(\b0x[0-9a-fA-F]+\b|\b\d+\b)/gm;
  return replaceWithHtmlEscape(code, regex, (m, cmt, str, varId, cmdlet, param, num) => {
    if (cmt) return `<span class="tok-cmt">${escapeHtml(cmt)}</span>`;
    if (str) return `<span class="tok-str">${escapeHtml(str)}</span>`;
    if (varId) return `<span class="tok-reg">${escapeHtml(varId)}</span>`;
    if (cmdlet) return `<span class="tok-fn">${escapeHtml(cmdlet)}</span>`;
    if (param) return `<span class="tok-kw">${escapeHtml(param)}</span>`;
    if (num) return `<span class="tok-num">${escapeHtml(num)}</span>`;
    return escapeHtml(m);
  });
}

function highlightHex(code) {
  const lines = code.split('\n');
  return lines.map(line => {
    const trimmed = line.trim();
    if (!trimmed) return '';
    return replaceWithHtmlEscape(line, /^(\s*[0-9a-fA-F]{4,8}:?)|(\|[^\|]*\|)$/g, (m, addr, ascii) => {
      if (addr) return `<span class="tok-num">${escapeHtml(addr)}</span>`;
      if (ascii) return `<span class="tok-str">${escapeHtml(ascii)}</span>`;
      return escapeHtml(m);
    });
  }).join('\n');
}

function highlightConfig(code) {
  const regex = /(#[^\n]*|\/\/[^\n]*)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(\b0x[0-9a-fA-F]+\b|\b\d+(?:\.\d+)?\b)|(\b(?:true|false|null)\b)|([a-zA-Z0-9_\-]+(?=\s*[:=]))/gm;
  return replaceWithHtmlEscape(code, regex, (m, cmt, str, num, boolVal, key) => {
    if (cmt) return `<span class="tok-cmt">${escapeHtml(cmt)}</span>`;
    if (str) return `<span class="tok-str">${escapeHtml(str)}</span>`;
    if (num) return `<span class="tok-num">${escapeHtml(num)}</span>`;
    if (boolVal) return `<span class="tok-kw">${escapeHtml(boolVal)}</span>`;
    if (key) return `<span class="tok-reg">${escapeHtml(key)}</span>`;
    return escapeHtml(m);
  });
}

function highlightGeneric(code) {
  const regex = /(#[^\n]*|\/\/[^\n]*)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{32,64}\b|\b\d+(?:\.\d+)?\b)|(https?:\/\/[^\s"'>]+)/gm;
  return replaceWithHtmlEscape(code, regex, (m, cmt, str, num, url) => {
    if (cmt) return `<span class="tok-cmt">${escapeHtml(cmt)}</span>`;
    if (str) return `<span class="tok-str">${escapeHtml(str)}</span>`;
    if (num) return `<span class="tok-num">${escapeHtml(num)}</span>`;
    if (url) return `<span class="tok-str">${escapeHtml(url)}</span>`;
    return escapeHtml(m);
  });
}

function highlightCode(rawCode, langClass, label) {
  if (!rawCode) return '';
  switch (langClass) {
    case 'lang-disasm':
      return highlightDisasm(rawCode);
    case 'lang-c':
    case 'lang-swift':
    case 'lang-rust':
      return highlightC(rawCode);
    case 'lang-python':
      return highlightPython(rawCode);
    case 'lang-terminal':
      return highlightTerminal(rawCode);
    case 'lang-yara':
      return highlightYara(rawCode);
    case 'lang-powershell':
      return highlightPowerShell(rawCode);
    case 'lang-xml':
      return highlightXml(rawCode);
    case 'lang-go':
      return highlightGo(rawCode);
    case 'lang-hex':
      return highlightHex(rawCode);
    case 'lang-config':
      return highlightConfig(rawCode);
    case 'lang-generic':
    default:
      return highlightGeneric(rawCode);
  }
}

// 1. DISCOVER ALL REPORTS FROM DISK DYNAMICALLY
function discoverReports() {
  const discovered = [];
  const platforms = ['macOS', 'Linux', 'Windows', 'Cross-Platform'];

  platforms.forEach(os => {
    const osPath = path.join(BASE_ANALYSIS_DIR, os);
    if (!fs.existsSync(osPath)) return;

    const dirs = fs.readdirSync(osPath).filter(d => !d.startsWith('.') && fs.statSync(path.join(osPath, d)).isDirectory());

    dirs.forEach(dirName => {
      const fullDir = path.join(osPath, dirName);
      const mdPath = path.join(fullDir, 'README.md');

      // Only consider folders with README.md (no standalone non-investigation folders)
      if (!fs.existsSync(mdPath)) return;

      const rawContent = fs.readFileSync(mdPath, 'utf8');

      // Support optional standard YAML frontmatter (--- ... ---) in README.md
      const fmMatch = rawContent.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);
      const frontmatter = {};
      const cleanContent = fmMatch ? rawContent.slice(fmMatch[0].length) : rawContent;
      if (fmMatch) {
        fmMatch[1].split('\n').forEach(line => {
          const colonIdx = line.indexOf(':');
          if (colonIdx > 0) {
            const k = line.slice(0, colonIdx).trim();
            const v = line.slice(colonIdx + 1).trim().replace(/^['"]|['"]$/g, '');
            if (k && v) frontmatter[k] = v;
          }
        });
      }

      // Generate consistent ID slug
      let id = slugify(dirName);
      if (dirName === 'Cobalt Strike beacon') id = 'cobalt-strike-beacon';
      if (dirName === 'EtherRAT Ethereum C2 Analysis') id = 'etherrat';
      if (dirName === 'notepad++ Chrysalis') id = 'notepad-chrysalis';
      if (dirName === 'WannaCry Ransomware') id = 'wannacry';
      if (dirName === 'cyber talents') id = 'cyber-talents-ctf';
      if (dirName === 'NPM AXIOS') id = 'npm-axios';
      if (dirName === 'macho sample static analysis') id = 'macho-static-analysis';
      if (dirName === 'Atomic Macos Stealer') id = 'atomic-macos-stealer';
      if (dirName === 'Digit Stealer') id = 'digit-stealer';
      if (dirName === 'Linux Backdoor BPFDoor') id = 'bpfdoor';
      if (dirName === 'Hvnc Implant') id = 'hvnc-implant';
      if (dirName === 'macOS Malware Analysis The __c5cfg Enigma') id = 'c5-enigma';

      // 100% AUTOMATIC EXTRACTION FROM CONTENT
      // A. Extract Title from first # Heading
      const titleMatch = cleanContent.match(/^#\s+(.+)$/m);
      let title = titleMatch ? titleMatch[1].replace(/[*_`]/g, '').trim() : dirName;

      // Clean up common repetitive title prefixes
      title = title.replace(/\.\.\.+$/, '').trim();

      // B. Extract Hashes (SHA-256 and MD5)
      const sha256Match = cleanContent.match(/\b([a-fA-F0-9]{64})\b/);
      const md5Match = cleanContent.match(/\b([a-fA-F0-9]{32})\b/);

      let hashType = sha256Match ? 'SHA-256' : (md5Match ? 'MD5' : 'N/A');
      let hashVal = sha256Match ? sha256Match[1] : (md5Match ? md5Match[1] : 'Analysis Telemetry Artifact');

      // C. Extract Lead / Executive Summary
      let lead = '';
      const execMatch = cleanContent.match(/##\s+Executive Summary[\s\S]*?\n\n([^\n#]+)/i);
      if (execMatch) {
        lead = execMatch[1].replace(/[*_`]/g, '').trim();
      } else {
        const firstP = cleanContent.split('\n\n').find(p => p.trim() && !p.trim().startsWith('#') && !p.trim().startsWith('---') && !p.trim().startsWith('|'));
        if (firstP) lead = firstP.replace(/[*_`]/g, '').trim();
      }
      if (!lead || lead.length < 20) {
        lead = `Technical reverse engineering and static analysis report for ${dirName}.`;
      }
      if (lead.length > 280) {
        lead = lead.substring(0, 277) + '...';
      }

      // D. Determine Category & Threat Family
      let category = 'Malware Family Analysis';
      let iconType = 'binary';
      const textLower = (cleanContent + ' ' + dirName).toLowerCase();

      if (textLower.includes('ransomware') || textLower.includes('wiper') || textLower.includes('notpetya') || textLower.includes('wannacry') || textLower.includes('whispergate') || textLower.includes('gazprom')) {
        category = 'Ransomware & Wipers';
        iconType = 'wiper';
      } else if (textLower.includes('apt') || textLower.includes('lazarus') || textLower.includes('red menshen') || textLower.includes('regin') || textLower.includes('espionage') || textLower.includes('chrysalis') || textLower.includes('supply-chain') || textLower.includes('supply chain') || textLower.includes('nation-state')) {
        category = 'Threat Intelligence & APTs';
        iconType = 'apt';
      } else if (textLower.includes('unpacking') || textLower.includes('diffing') || textLower.includes('resolution') || textLower.includes('breakpoints') || textLower.includes('shellcode') || textLower.includes('isdebuggerpresent') || textLower.includes('patching') || textLower.includes('debugging') || textLower.includes('ctf')) {
        category = 'Reverse Engineering Techniques';
        iconType = 'binary';
      } else if (textLower.includes('stealer') || textLower.includes('amos') || textLower.includes('beacon') || textLower.includes('c2') || textLower.includes('backdoor') || textLower.includes('rat') || textLower.includes('botnet') || textLower.includes('trojan') || textLower.includes('emotet') || textLower.includes('credential')) {
        category = 'Malware Family Analysis';
        iconType = 'stealer';
      }

      // Read time calculation (~200 words / min)
      const wordCount = cleanContent.split(/\s+/).length;
      const readMinutes = Math.max(8, Math.min(25, Math.round(wordCount / 180)));
      let readTime = `${readMinutes} min read`;

      // Date: extracted authentic commit date fallback if not set in meta.json
      let date = null;

      // Threat Profile Defaults
      let family = dirName.replace(/Malware|Analysis|Report|Sample/gi, '').trim() || dirName;
      let classification = category;
      let delivery = 'Staged Executable / Dropper';
      let c2 = 'Dynamic Protocol / HTTP';
      let targets = 'Windows Endpoints / Memory';

      if (os === 'macOS') targets = 'macOS Keychains & Crypto Wallets';
      if (os === 'Linux') targets = 'Linux Kernels & Sockets';
      if (iconType === 'stealer') classification = `${os} Infostealer`;
      if (iconType === 'wiper') classification = `${os} Disk Wiper / Ransomware`;
      if (iconType === 'apt') classification = 'State-Sponsored Espionage Framework';

      // Apply Frontmatter overrides if present
      if (frontmatter.title) title = frontmatter.title;
      if (frontmatter.lead || frontmatter.subtitle) lead = frontmatter.lead || frontmatter.subtitle;
      if (frontmatter.family) family = frontmatter.family;
      if (frontmatter.category) category = frontmatter.category;
      if (frontmatter.classification) classification = frontmatter.classification;
      if (frontmatter.delivery) delivery = frontmatter.delivery;
      if (frontmatter.c2) c2 = frontmatter.c2;
      if (frontmatter.targets) targets = frontmatter.targets;
      if (frontmatter.hash || frontmatter.hashVal) {
        hashVal = frontmatter.hash || frontmatter.hashVal;
        hashType = frontmatter.hashType || (hashVal.length === 64 ? 'SHA-256' : 'MD5');
      }
      if (frontmatter.date) date = frontmatter.date;

      // E. Extract First Image in README.md as default card thumbnail
      let firstImage = null;
      const mdImg = cleanContent.match(/!\[.*?\]\((.+?)\)/);
      const htmlImg = rawContent.match(/<img[^>]+src=["']([^"']+)["']/i);
      let foundImg = null;
      if (mdImg && htmlImg) {
        foundImg = (mdImg.index < htmlImg.index) ? mdImg[1].trim() : htmlImg[1].trim();
      } else if (mdImg) {
        foundImg = mdImg[1].trim();
      } else if (htmlImg) {
        foundImg = htmlImg[1].trim();
      }
      if (foundImg) {
        if (foundImg.startsWith('http://') || foundImg.startsWith('https://')) {
          firstImage = foundImg;
        } else {
          const cleanFound = decodeURIComponent(foundImg);
          const baseName = path.basename(cleanFound).replace(/[^\w.-]/g, '_');
          firstImage = `images/${encodeURIComponent(baseName)}`;
        }
      }

      let thumbnail = null;
      let subtitle = null;
      let featured = false;
      let navTitle = null;
      let navDropdown = null;
      let hideFromNav = false;
      let source = null;
      let difficulty = null;
      let tools = null;
      let challengeUrl = null;
      let actor = null;
      let campaign = null;
      let tlp = 'TLP:CLEAR';
      let severity = null;
      let confidence = null;
      let mitreTactics = null;
      let mitreTechniques = null;
      let architecture = null;
      let toolchain = null;
      let codeSigning = null;
      let secondaryHash = null;
      let imphash = null;
      let targetSectors = null;
      let targetGeo = null;
      let author = 'Chandra Kant Bauri (@Lynk4)';

      // Load optional meta.json if present in the folder
      const metaFile = path.join(fullDir, 'meta.json');
      if (fs.existsSync(metaFile)) {
        try {
          const meta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
          if (meta.id) id = meta.id;
          if (meta.title) title = meta.title;
          if (meta.lead) lead = meta.lead;
          if (meta.subtitle) subtitle = meta.subtitle;
          if (!lead && subtitle) lead = subtitle;
          if (!subtitle && lead) subtitle = lead;
          if (meta.thumbnail || meta.thumb || meta.image) {
            let rawThumb = String(meta.thumbnail || meta.thumb || meta.image).trim();
            if (rawThumb.startsWith('http://') || rawThumb.startsWith('https://')) {
              thumbnail = rawThumb;
            } else if (rawThumb.startsWith('images/')) {
              thumbnail = rawThumb;
            } else {
              const baseName = path.basename(decodeURIComponent(rawThumb)).replace(/[^\w.-]/g, '_');
              thumbnail = `images/${encodeURIComponent(baseName)}`;
            }
            firstImage = thumbnail;
          }
          if (meta.category) category = meta.category;
          if (meta.date) date = meta.date;
          if (meta.readTime) readTime = meta.readTime;
          if (meta.family) family = meta.family;
          if (meta.classification) classification = meta.classification;
          if (meta.delivery) delivery = meta.delivery;
          if (meta.c2) c2 = meta.c2;
          if (meta.targets) targets = meta.targets;
          if (meta.hashType) hashType = meta.hashType;
          if (meta.hashVal || meta.hash) hashVal = meta.hashVal || meta.hash;
          if (meta.featured !== undefined) featured = Boolean(meta.featured);
          if (meta.highlight !== undefined) featured = Boolean(meta.highlight);
          if (meta.pinned !== undefined) featured = Boolean(meta.pinned);
          if (meta.navHighlight !== undefined) featured = Boolean(meta.navHighlight);
          if (meta.navTitle || meta.shortTitle) navTitle = meta.navTitle || meta.shortTitle;
          if (meta.source) source = meta.source;
          if (meta.difficulty) difficulty = meta.difficulty;
          if (meta.tools) tools = meta.tools;
          if (meta.challengeUrl) challengeUrl = meta.challengeUrl;
          if (meta.actor) actor = meta.actor;
          if (meta.campaign) campaign = meta.campaign;
          if (meta.tlp) tlp = meta.tlp;
          if (meta.severity) severity = meta.severity;
          if (meta.confidence) confidence = meta.confidence;
          if (meta.mitreTactics) mitreTactics = meta.mitreTactics;
          if (meta.mitreTechniques) mitreTechniques = meta.mitreTechniques;
          if (meta.architecture) architecture = meta.architecture;
          if (meta.toolchain) toolchain = meta.toolchain;
          if (meta.codeSigning) codeSigning = meta.codeSigning;
          if (meta.secondaryHash) secondaryHash = meta.secondaryHash;
          if (meta.imphash) imphash = meta.imphash;
          if (meta.targetSectors) targetSectors = meta.targetSectors;
          if (meta.targetGeo) targetGeo = meta.targetGeo;
          if (meta.author) author = meta.author;
          if (meta.navDropdown !== undefined) {
            if (typeof meta.navDropdown === 'string') navDropdown = meta.navDropdown.toLowerCase();
            else if (meta.navDropdown === false) hideFromNav = true;
            else if (meta.navDropdown === true) featured = true;
          }
          if (meta.hideFromNav !== undefined) hideFromNav = Boolean(meta.hideFromNav);
        } catch (e) {
          console.warn(`[Warning] Could not parse meta.json in ${fullDir}:`, e.message);
        }
      }

      if (!date) {
        date = getGitAddedDate(mdPath, id) || 'August 2026';
      }

      discovered.push({
        id,
        dirName,
        os,
        category,
        iconType,
        title,
        lead,
        subtitle,
        date,
        readTime,
        family,
        classification,
        delivery,
        c2,
        targets,
        hashType,
        hashVal,
        firstImage,
        thumbnail,
        featured,
        navTitle,
        navDropdown,
        hideFromNav,
        source,
        difficulty,
        tools,
        challengeUrl,
        actor,
        campaign,
        tlp,
        severity,
        confidence,
        mitreTactics,
        mitreTechniques,
        architecture,
        toolchain,
        codeSigning,
        secondaryHash,
        imphash,
        targetSectors,
        targetGeo,
        author,
        srcDir: fullDir,
        mdPath
      });
    });
  });

  return discovered;
}

// Helper to determine concise, human-friendly titles for navigation dropdowns
const KNOWN_NAV_TITLES = {
  'rustbucket-2': 'RustBucket (macOS)',
  'rustbucket': 'RustBucket Part 1',
  'digit-stealer': 'Digit Stealer (JXA)',
  'atomic-macos-stealer': 'Atomic Stealer (AMOS)',
  'kittystealer': 'Kitty Stealer (macOS)',
  'macho-static-analysis': 'Mach-O Static Analysis',
  'bpfdoor': 'BPFDoor (Linux)',
  'mirai-botnet': 'Mirai Botnet (Linux)',
  'wannacry': 'WannaCry (SMB Worm)',
  'qakbot-unpacking': 'Qakbot (Banking)',
  'unpacking-modified-upx-malware': 'Modified UPX Unpacking',
  'x64dbg-conditional-breakpoints': 'x64dbg Breakpoints',
  'dynamic-api-resolution': 'Dynamic API Resolution',
  'api-unhooking': 'EDR API Unhooking',
  'malware-binary-diffing': 'BinDiff Code Comparison',
  'bypassing-isdebuggerpresent': 'IsDebuggerPresent Evasion',
  'automated-unpacking': 'Automated Unpacking',
  'shellcode-extraction': 'Shellcode Extraction',
  'cobalt-strike-beacon': 'Cobalt Strike Beacon',
  'agent-tesla': 'Agent Tesla Harvester',
  'deconstructing-emotet': 'Deconstructing Emotet',
  'dll-malware-emotet': 'Emotet DLL Loader',
  'etherrat': 'EtherRAT Ethereum C2',
  'notpetya-ransomware': 'NotPetya Wiper',
  'whispergate-mbr-wiper': 'WhisperGate MBR Wiper',
  'notepad-chrysalis': 'Notepad++ Chrysalis',
  'patching-a-malware': 'Binary Patching',
  'debugging-malware': 'Manual CS Beacon Dump',
  'payload-extraction': 'Payload Extraction',
  'regin-malware': 'Regin Nation-State APT',
  'reversing-hash-based-api-resolution': 'Hash-Based API Resolution',
  'shellcode-triage-and-api-resolution': 'Shellcode CAPA & Binja',
  'reversing-a-packed-autoit-malware-sample': 'AutoIt Malware Decompilation',
  'reverse-engineering-a-packed-trojan': 'Packed Trojan Analysis',
  'bangladesh-gpca': 'Bangladesh GPCA Espionage',
  'npm-axios': 'NPM Axios Typosquat',
  'cyber-talents-ctf': 'Cyber Talents CTF',
  'singularity': 'Singularity (Linux Rootkit)',
  'kernel-shield': 'Kernel Shield (EDR Killer)',
  'rokrat-loader': 'RokRat Loader (Lazarus)',
  'equationdrug': 'EquationDrug (Kernel APC)',
  'katz-stealer': 'Katz Stealer (Harvester)',
  'simda': 'Simda (Multi-Stage Packer)',
  'carbanak': 'Carbanak (Banking Trojan)',
  'shinyspider': 'ShinySpider (Go Ransomware)',
  'valleyrat': 'ValleyRAT (In-Memory PE)',
  'aurawiper': 'AuraWiper (MBR Wiper)',
  'hvnc-implant': 'macOS HVNC Implant',
  'dissecting-avenger-stealer': 'Avenger Stealer'
};

function getReportNavTitle(r) {
  if (r.navTitle) return r.navTitle;
  if (r.shortTitle) return r.shortTitle;
  if (KNOWN_NAV_TITLES[r.id]) return KNOWN_NAV_TITLES[r.id];

  // Automatic clean title for any new or unmapped report
  if (r.family && r.family.length <= 22 && !r.family.toLowerCase().includes('sample')) {
    return r.family;
  }

  let t = r.title || r.id;
  t = t.replace(/part\s+\d+:\s*/gi, '');
  if (t.includes(':')) {
    const parts = t.split(':');
    const p0 = parts[0].trim();
    const p1 = parts[1].trim();
    if (p0.toLowerCase().includes('malware analysis') || p0.toLowerCase().includes('reverse engineering')) {
      t = p1;
    } else if (p1.toLowerCase().includes('inside') || p1.toLowerCase().includes('analysis') || p1.length > 25) {
      t = p0;
    } else {
      t = p0.length < p1.length ? p0 : p1;
    }
  }
  if (t.includes(' — ')) {
    t = t.split(' — ').pop().trim();
  } else if (t.includes(' - ')) {
    const parts = t.split(' - ');
    t = parts[0].length >= 4 && parts[0].length <= 25 ? parts[0].trim() : parts.pop().trim();
  }

  t = t.replace(/\s+(malware|analysis|sample|report)$/gi, '').trim();
  if (t.length > 26) {
    t = t.substring(0, 24).trim() + '...';
  }
  return t;
}

function formatCardDate(dateStr) {
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return dateStr || '';
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function formatCardMeta(r) {
  let fallbackImg = 'assets/home/card-threatintel.webp';
  let badgeClass = 'badge-cross';
  let badgeText = r.os || 'Cross-platform';

  if (r.source === 'malops') {
    badgeClass = 'badge-malops';
    badgeText = `MALOPS • ${(r.difficulty || 'CHALLENGE').toUpperCase()}`;
    fallbackImg = 'assets/home/card-threatintel.webp';
  } else if (r.os === 'macOS') {
    fallbackImg = 'assets/home/card-macos.webp';
    badgeClass = 'badge-macos';
    badgeText = 'macOS';
  } else if (r.os === 'Windows') {
    fallbackImg = 'assets/home/card-windows.webp';
    badgeClass = 'badge-windows';
    badgeText = 'Windows';
  } else if (r.os === 'Linux') {
    fallbackImg = 'assets/home/card-threatintel.webp';
    badgeClass = 'badge-linux';
    badgeText = 'Linux';
  }

  let cardImg = fallbackImg;
  let img = r.firstImage || r.image;
  if (img) {
    if (img.startsWith('http://') || img.startsWith('https://')) {
      cardImg = img;
    } else {
      const webpCandidate = img.replace(/\.(png|jpe?g)$/i, '.webp');
      const targetWebp = path.join(REPORTS_DIR, r.id, webpCandidate);
      if (fs.existsSync(targetWebp)) {
        img = webpCandidate;
      }
      cardImg = `${r.id}/${img}`;
    }
  }

  let displayTitle = r.title;
  let displayDesc = r.subtitle || r.lead;
  let displayDate = formatCardDate(r.date);
  let displayReadTime = r.readTime || '14 min read';

  if (r.id === 'rustbucket-2') {
    displayTitle = 'macOS Malware Analysis — Part 2: Reverse Engineering RustBucket';
    displayDesc = 'In-depth analysis of a macOS sample focusing on Mach-O internals, ARM64 assembly, Swift symbols, and reverse engineering techniques used to understand its functionality.';
    displayReadTime = '18 min read';
    badgeClass = 'badge-macos';
    badgeText = 'macOS';
  } else if (r.id === 'unpacking-modified-upx-malware') {
    displayTitle = 'Unpacking Modified UPX Malware';
    displayDesc = 'Analysis of a modified UPX-packed executable, focusing on PE header reconstruction, section metadata, and techniques to recover a valid structure for further static analysis.';
    displayReadTime = '13 min read';
    badgeClass = 'badge-windows';
    badgeText = 'Windows';
  } else if (r.id === 'digit-stealer') {
    displayTitle = 'Digit Stealer: Inside a macOS Campaign';
    displayDesc = 'Technical analysis of Digit Stealer, examining sample artifacts, infrastructure, and key implementation details observed in the campaign.';
    displayReadTime = '16 min read';
    badgeClass = 'badge-macos';
    badgeText = 'macOS';
  }

  return {
    id: r.id,
    title: displayTitle,
    subtitle: displayDesc || '',
    os: r.os,
    category: r.category,
    source: r.source || '',
    date: r.date,
    formattedDate: displayDate,
    readTime: displayReadTime,
    cardImg,
    badgeClass,
    badgeText,
    family: r.family || '',
    classification: r.classification || '',
    delivery: r.delivery || '',
    targets: r.targets || '',
    c2: r.c2 || '',
    hashType: r.hashType || '',
    hashVal: r.hashVal || '',
    image: r.firstImage || r.image || '',
    navTitle: getReportNavTitle(r),
    featured: Boolean(r.featured)
  };
}

function renderPortalCardHtml(m) {
  const searchKeywords = `${m.title} ${m.subtitle} ${m.category} ${m.os} ${m.family} ${m.targets} ${m.delivery}`.toLowerCase();
  return `
        <article class="inv-card" data-os="${escapeHtml(m.os)}" data-category="${escapeHtml(m.category)}" data-source="${escapeHtml(m.source || '')}" data-search="${escapeHtml(searchKeywords)}">
          <a href="${escapeHtml(m.id)}/index.html" class="card-banner" aria-label="${escapeHtml(m.title)}">
            <span class="card-platform-badge ${escapeHtml(m.badgeClass)}">${escapeHtml(m.badgeText)}</span>
            <img src="${escapeHtml(m.cardImg)}" alt="${escapeHtml(m.title)}" class="card-banner-img" loading="lazy">
          </a>
          <div class="card-content-body">
            <a href="${escapeHtml(m.id)}/index.html" style="text-decoration:none; color:inherit;">
              <h3 class="card-title">${escapeHtml(m.title)}</h3>
            </a>
            <p class="card-desc">${escapeHtml(m.subtitle)}</p>
            <div class="card-footer">
              <div class="card-meta-left">
                <span class="meta-date">
                  <svg class="meta-icon-svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                  <span>${escapeHtml(m.formattedDate)}</span>
                </span>
                <span class="meta-readtime">
                  <svg class="meta-icon-svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                  <span>${escapeHtml(m.readTime)}</span>
                </span>
              </div>
              <a href="${escapeHtml(m.id)}/index.html" class="card-arrow-btn" aria-label="Read ${escapeHtml(m.title)}">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
              </a>
            </div>
          </div>
        </article>`;
}

function generateCatalogData(allReports) {
  const dataDir = path.join(REPORTS_DIR, 'data');
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  const catalog = allReports.map(formatCardMeta);
  fs.writeFileSync(path.join(dataDir, 'catalog.json'), JSON.stringify(catalog, null, 2), 'utf8');
  fs.writeFileSync(path.join(dataDir, 'catalog.js'), 'window.__MARE_CATALOG__ = ' + JSON.stringify(catalog) + ';\n', 'utf8');
  return catalog;
}

function renderCommandPaletteModal() {
  return [
    '<!-- MARE Global Command Palette Modal (⌘K / /) -->',
    '<div id="mare-cmd-palette-backdrop" class="cmd-palette-backdrop" style="display:none;" aria-hidden="true">',
    '  <div class="cmd-palette-modal" role="dialog" aria-modal="true" aria-label="Global Threat Research Search">',
    '    <div class="cmd-palette-header">',
    '      <svg class="cmd-search-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">',
    '        <circle cx="11" cy="11" r="8"></circle>',
    '        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>',
    '      </svg>',
    '      <input type="text" id="mare-cmd-input" class="cmd-palette-input" placeholder="Search investigations, malware families, hashes, C2s, platforms..." autocomplete="off" spellcheck="false" aria-label="Search threat investigations" />',
    '      <span class="cmd-palette-esc-badge" id="mare-cmd-close-btn" title="Close search (Esc)">ESC</span>',
    '    </div>',
    '    <div class="cmd-palette-filters" id="mare-cmd-filters">',
    '      <button type="button" class="cmd-filter-pill active" data-filter="all">All</button>',
    '      <button type="button" class="cmd-filter-pill" data-filter="Windows">Windows</button>',
    '      <button type="button" class="cmd-filter-pill" data-filter="macOS">macOS</button>',
    '      <button type="button" class="cmd-filter-pill" data-filter="Linux">Linux</button>',
    '      <button type="button" class="cmd-filter-pill" data-filter="Cross-Platform">Cross-Platform</button>',
    '      <button type="button" class="cmd-filter-pill" data-filter="MalOps">MalOps</button>',
    '    </div>',
    '    <div class="cmd-palette-results" id="mare-cmd-results" role="listbox"></div>',
    '    <div class="cmd-palette-footer">',
    '      <div class="cmd-footer-stats" id="mare-cmd-stats">Ready</div>',
    '      <div class="cmd-footer-shortcuts">',
    '        <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>',
    '        <span><kbd>↵</kbd> open</span>',
    '        <span><kbd>tab</kbd> filter</span>',
    '        <span><kbd>esc</kbd> close</span>',
    '      </div>',
    '    </div>',
    '  </div>',
    '</div>'
  ].join('\n');
}

function getCommandPaletteCss() {
  return "";
}

function getCommandPaletteJs(basePath) {
  return `
  (function() {
    var basePath = ${JSON.stringify(basePath)};
    var catalog = Array.isArray(window.__MARE_CATALOG__) ? window.__MARE_CATALOG__ : [];
    var backdrop = document.getElementById('mare-cmd-palette-backdrop');
    var input = document.getElementById('mare-cmd-input');
    var resultsContainer = document.getElementById('mare-cmd-results');
    var statsEl = document.getElementById('mare-cmd-stats');
    var filterPills = document.querySelectorAll('.cmd-filter-pill');
    var closeBtn = document.getElementById('mare-cmd-close-btn');
    var navSearchBtn = document.getElementById('nav-search-btn');
    
    var isOpen = false;
    var activeFilter = 'all';
    var selectedIndex = 0;
    var currentResults = [];

    function loadCatalogFallback() {
      if (catalog && catalog.length > 0) return;
      try {
        fetch(basePath + 'data/catalog.json')
          .then(function(res) { return res.json(); })
          .then(function(data) {
            if (Array.isArray(data)) {
              catalog = data;
              window.__MARE_CATALOG__ = data;
              if (isOpen) render();
            }
          })
          .catch(function() {});
      } catch (e) {}
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function escapeRegex(str) {
      return str.replace(/[-\\\\/\\\\^$*+?.()|[\\]{}]/g, '\\\\\\\\$&');
    }

    function highlightTokens(text, tokens) {
      if (!text) return '';
      var escaped = escapeHtml(text);
      if (!tokens || tokens.length === 0) return escaped;
      tokens.forEach(function(t) {
        if (!t) return;
        var cleanToken = escapeRegex(t);
        var regex = new RegExp('(' + cleanToken + ')', 'gi');
        escaped = escaped.replace(regex, '<mark class="cmd-highlight">$1</mark>');
      });
      return escaped;
    }

    function getPlatformClass(os, source) {
      if (source === 'malops') return 'malops';
      var o = (os || '').toLowerCase();
      if (o.indexOf('mac') !== -1) return 'macos';
      if (o.indexOf('win') !== -1) return 'windows';
      if (o.indexOf('linux') !== -1) return 'linux';
      return 'cross-platform';
    }

    function openPalette(initialQuery) {
      if (!backdrop || !input) return;
      loadCatalogFallback();
      backdrop.style.display = 'flex';
      void backdrop.offsetWidth;
      backdrop.classList.add('open');
      isOpen = true;
      document.body.style.overflow = 'hidden';
      if (typeof initialQuery === 'string') {
        input.value = initialQuery;
      }
      input.focus();
      input.select();
      selectedIndex = 0;
      render();
    }

    function closePalette() {
      if (!backdrop) return;
      backdrop.classList.remove('open');
      isOpen = false;
      document.body.style.overflow = '';
      setTimeout(function() {
        if (!isOpen) backdrop.style.display = 'none';
      }, 200);
    }

    function filterAndScore(query, filter) {
      if (!catalog || !catalog.length) return [];
      var q = (query || '').trim().toLowerCase();
      var tokens = q ? q.split(/\\\\s+/).filter(Boolean) : [];

      var filtered = catalog.filter(function(item) {
        if (filter === 'MalOps') {
          return item.source === 'malops';
        } else if (filter !== 'all') {
          return (item.os || '').toLowerCase() === filter.toLowerCase();
        }
        return true;
      });

      if (!tokens.length) {
        return filtered.slice(0, 10).map(function(item) {
          return {
            item: item,
            matchType: 'recent',
            snippet: item.subtitle || '',
            score: 10
          };
        });
      }

      var matches = [];
      filtered.forEach(function(item) {
        var title = (item.title || '').toLowerCase();
        var subtitle = (item.subtitle || '').toLowerCase();
        var family = (item.family || '').toLowerCase();
        var classification = (item.classification || '').toLowerCase();
        var os = (item.os || '').toLowerCase();
        var category = (item.category || '').toLowerCase();
        var hashVal = (item.hashVal || '').toLowerCase();
        var c2 = (item.c2 || '').toLowerCase();
        var delivery = (item.delivery || '').toLowerCase();
        var targets = (item.targets || '').toLowerCase();

        var haystack = title + ' ' + subtitle + ' ' + family + ' ' + classification + ' ' + os + ' ' + category + ' ' + hashVal + ' ' + c2 + ' ' + delivery + ' ' + targets;

        var allMatched = tokens.every(function(t) {
          return haystack.indexOf(t) !== -1;
        });

        if (!allMatched) return;

        var score = 0;
        var matchType = 'text';
        var snippet = item.subtitle || '';

        if (hashVal && tokens.some(function(t) { return hashVal.indexOf(t) !== -1; })) {
          score += 200;
          matchType = 'hash';
          snippet = item.hashVal;
        } else if (c2 && tokens.some(function(t) { return c2.indexOf(t) !== -1; })) {
          score += 120;
          matchType = 'c2';
          snippet = item.c2;
        } else if (family && tokens.some(function(t) { return family.indexOf(t) !== -1; })) {
          score += 80;
          matchType = 'family';
          snippet = 'Malware Family: ' + item.family + ' — ' + (item.classification || '');
        } else if (delivery && tokens.some(function(t) { return delivery.indexOf(t) !== -1; })) {
          score += 60;
          matchType = 'delivery';
          snippet = 'Delivery: ' + item.delivery;
        } else if (title && tokens.some(function(t) { return title.indexOf(t) !== -1; })) {
          score += 50;
          matchType = 'title';
        } else {
          score += 20;
        }

        if (item.featured) score += 5;

        matches.push({
          item: item,
          matchType: matchType,
          snippet: snippet,
          score: score
        });
      });

      matches.sort(function(a, b) {
        if (b.score !== a.score) return b.score - a.score;
        return new Date(b.item.date).getTime() - new Date(a.item.date).getTime();
      });

      return matches.slice(0, 30);
    }

    function render() {
      if (!resultsContainer || !input) return;
      var q = input.value.trim();
      var tokens = q ? q.toLowerCase().split(/\\\\s+/).filter(Boolean) : [];
      var results = filterAndScore(q, activeFilter);
      currentResults = results;

      if (selectedIndex >= results.length) selectedIndex = Math.max(0, results.length - 1);

      if (statsEl) {
        var total = catalog ? catalog.length : 0;
        if (!q && activeFilter === 'all') {
          statsEl.textContent = total + ' investigations cataloged';
        } else {
          statsEl.textContent = results.length + ' result' + (results.length === 1 ? '' : 's') + ' found (' + total + ' total)';
        }
      }

      if (results.length === 0) {
        resultsContainer.innerHTML = '<div class="cmd-palette-empty">' +
          '<h4>No threat research found</h4>' +
          '<p>No investigations matched "' + escapeHtml(q) + '".<br>Try searching for a platform (e.g. macOS), malware family, hash, or C2 domain.</p>' +
          '</div>';
        return;
      }

      var html = '';
      if (!q) {
        html += '<div class="cmd-section-label">Featured &amp; Recent Research</div>';
      }

      results.forEach(function(res, idx) {
        var r = res.item;
        var isSelected = idx === selectedIndex;
        var pClass = getPlatformClass(r.os, r.source);
        var pLabel = r.source === 'malops' ? 'MALOPS' : (r.os || 'RESEARCH');

        var titleHtml = highlightTokens(r.title, tokens);
        var snippetHtml = '';

        if (res.matchType === 'hash') {
          snippetHtml = '<span class="cmd-match-tag">HASH</span> <code class="cmd-match-code">' + highlightTokens(res.snippet, tokens) + '</code>';
        } else if (res.matchType === 'c2') {
          snippetHtml = '<span class="cmd-match-tag">C2</span> <code class="cmd-match-code">' + highlightTokens(res.snippet, tokens) + '</code>';
        } else if (res.matchType === 'family' || res.matchType === 'delivery') {
          snippetHtml = '<span class="cmd-match-tag">' + res.matchType.toUpperCase() + '</span> ' + highlightTokens(res.snippet, tokens);
        } else {
          var snip = res.snippet || r.subtitle || '';
          if (snip.length > 130) snip = snip.substring(0, 126) + '...';
          snippetHtml = highlightTokens(snip, tokens);
        }

        html += '<a href="' + basePath + escapeHtml(r.id) + '/index.html" class="cmd-item' + (isSelected ? ' selected' : '') + '" role="option" data-idx="' + idx + '" tabindex="-1">' +
          '<div class="cmd-item-platform platform-' + pClass + '">' + escapeHtml(pLabel) + '</div>' +
          '<div class="cmd-item-main">' +
            '<div class="cmd-item-title">' + titleHtml + '</div>' +
            '<div class="cmd-item-snippet">' + snippetHtml + '</div>' +
            '<div class="cmd-item-meta">' +
              '<span class="cmd-meta-family">' + escapeHtml(r.family || r.category || 'Malware Analysis') + '</span>' +
              '<span class="cmd-meta-dot">•</span>' +
              '<span>' + escapeHtml(r.date || '') + '</span>' +
              '<span class="cmd-meta-dot">•</span>' +
              '<span>' + escapeHtml(r.readTime || '') + '</span>' +
            '</div>' +
          '</div>' +
          '<div class="cmd-item-action"><span class="cmd-item-enter">↵</span></div>' +
        '</a>';
      });

      resultsContainer.innerHTML = html;
      updateSelectionScroll();
    }

    function updateSelectionScroll() {
      if (!resultsContainer) return;
      var selected = resultsContainer.querySelector('.cmd-item.selected');
      if (selected && selected.scrollIntoView) {
        selected.scrollIntoView({ block: 'nearest' });
      }
    }

    function updateSelection() {
      if (!resultsContainer) return;
      var items = resultsContainer.querySelectorAll('.cmd-item');
      items.forEach(function(item, idx) {
        if (idx === selectedIndex) {
          item.classList.add('selected');
        } else {
          item.classList.remove('selected');
        }
      });
      updateSelectionScroll();
    }

    window.addEventListener('keydown', function(e) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) {
          closePalette();
        } else {
          openPalette();
        }
        return;
      }

      if (e.key === '/' && !isOpen) {
        var tag = (document.activeElement && document.activeElement.tagName) ? document.activeElement.tagName.toLowerCase() : '';
        if (tag !== 'input' && tag !== 'textarea' && !(document.activeElement && document.activeElement.isContentEditable)) {
          e.preventDefault();
          openPalette();
          return;
        }
      }

      if (isOpen) {
        if (e.key === 'Escape') {
          e.preventDefault();
          closePalette();
        } else if (e.key === 'ArrowDown') {
          e.preventDefault();
          if (currentResults.length > 0) {
            selectedIndex = (selectedIndex + 1) % currentResults.length;
            updateSelection();
          }
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          if (currentResults.length > 0) {
            selectedIndex = (selectedIndex - 1 + currentResults.length) % currentResults.length;
            updateSelection();
          }
        } else if (e.key === 'Tab') {
          e.preventDefault();
          var pillList = Array.prototype.slice.call(filterPills);
          var currentPillIdx = 0;
          for (var i = 0; i < pillList.length; i++) {
            if (pillList[i].classList.contains('active')) {
              currentPillIdx = i;
              break;
            }
          }
          var nextPillIdx = (currentPillIdx + (e.shiftKey ? -1 : 1) + pillList.length) % pillList.length;
          pillList[nextPillIdx].click();
        } else if (e.key === 'Enter') {
          e.preventDefault();
          if (currentResults.length > 0 && currentResults[selectedIndex]) {
            var target = currentResults[selectedIndex].item;
            window.location.href = basePath + target.id + '/index.html';
          }
        }
      }
    });

    if (input) {
      input.addEventListener('input', function() {
        selectedIndex = 0;
        render();
      });
    }

    if (filterPills) {
      filterPills.forEach(function(pill) {
        pill.addEventListener('click', function() {
          filterPills.forEach(function(p) { p.classList.remove('active'); });
          pill.classList.add('active');
          activeFilter = pill.getAttribute('data-filter') || 'all';
          selectedIndex = 0;
          render();
          if (input) input.focus();
        });
      });
    }

    if (backdrop) {
      backdrop.addEventListener('click', function(e) {
        if (e.target === backdrop) closePalette();
      });
    }

    if (closeBtn) {
      closeBtn.addEventListener('click', function() {
        closePalette();
      });
    }

    if (navSearchBtn) {
      navSearchBtn.addEventListener('mouseenter', function() { loadCatalogFallback(); }, { once: true });
      navSearchBtn.addEventListener('focus', function() { loadCatalogFallback(); }, { once: true });
      navSearchBtn.addEventListener('click', function(e) {
        e.preventDefault();
        openPalette();
      });
    }

    window.mareOpenSearch = openPalette;

    // Instant Navigation via speculative hover & touch prefetch
    (function initInstantNav() {
      if (typeof document === 'undefined' || !document.addEventListener) return;
      try {
        var conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        if (conn && (conn.saveData || (conn.effectiveType && conn.effectiveType.indexOf('2g') !== -1))) return;
      } catch (e) {}

      var prefetched = {};

      function prefetchUrl(url) {
        if (!url || prefetched[url]) return;
        prefetched[url] = true;
        var link = document.createElement('link');
        link.rel = 'prefetch';
        link.as = 'document';
        link.href = url;
        document.head.appendChild(link);
      }

      function handleHoverOrTouch(e) {
        var target = e.target;
        if (!target) return;
        var a = target.closest ? target.closest('a[href]') : null;
        if (!a) return;
        var rawHref = a.getAttribute('href');
        if (!rawHref || rawHref.charAt(0) === '#' || rawHref.indexOf('javascript:') === 0 || rawHref.indexOf('mailto:') === 0) return;
        if (a.origin !== window.location.origin) return;
        if (/\\.(zip|exe|bin|dll|pcap|gz|tar|7z|sh)$/i.test(a.pathname)) return;
        prefetchUrl(a.href);
      }

      document.addEventListener('pointerover', handleHoverOrTouch, { passive: true });
      document.addEventListener('touchstart', handleHoverOrTouch, { passive: true });
    })();
  })();
  `;
}

// 2. CONVERT MARKDOWN AND BUNDLE ALL REFERENCED SCREENSHOTS LOCALLY

function copyGlobalAssets() {
  ['home', 'css'].forEach(folder => {
    const srcDir = path.join(ROOT_DIR, 'assets', folder);
    const targetDir = path.join(REPORTS_DIR, 'assets', folder);
    if (fs.existsSync(srcDir)) {
      if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
      fs.cpSync(srcDir, targetDir, { recursive: true });
    }
  });
}

function buildReportPage(r) {
  const reportDir = path.join(REPORTS_DIR, r.id);
  const imagesDir = path.join(reportDir, 'images');

  if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });
  if (!fs.existsSync(imagesDir)) fs.mkdirSync(imagesDir, { recursive: true });



  let mdContent = fs.readFileSync(r.mdPath, 'utf8');

  // Strip YAML frontmatter if present
  mdContent = mdContent.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '');


  // Cyber Talents CTF supplement
  if (r.id === 'cyber-talents-ctf') {
    const pureLuck = path.join(ROOT_DIR, 'Malware Analysis/Cross-Platform/cyber talents/Pure Luck/README.md');
    const elfMaster = path.join(ROOT_DIR, 'Malware Analysis/Cross-Platform/cyber talents/ELF Master/README.md');
    const m0v = path.join(ROOT_DIR, 'Malware Analysis/Cross-Platform/cyber talents/m0v/README.md');
    mdContent = `# Cyber Talents CTF: Reverse Engineering Challenge Series\n\n`;
    if (fs.existsSync(pureLuck)) mdContent += `\n## Challenge 1: Pure Luck (ELF 32-bit & UPX Recovery)\n` + fs.readFileSync(pureLuck, 'utf8');
    if (fs.existsSync(elfMaster)) mdContent += `\n## Challenge 2: ELF Master (Binary Ninja & XOR Decoding)\n` + fs.readFileSync(elfMaster, 'utf8');
    if (fs.existsSync(m0v)) mdContent += `\n## Challenge 3: m0v (Assembly Register Tracing)\n` + fs.readFileSync(m0v, 'utf8');
  }

  // Pre-process: consolidate multi-line table cells into single lines.
  // Standard markdown tables require each row on one line. If a row starts
  // with | but doesn't end with |, accumulate continuation lines until a
  // closing | is found, joining values with ' · '.
  mdContent = (function consolidateMultiLineTableCells(md) {
    const srcLines = md.split('\n');
    const result = [];
    let pendingRow = null;
    let inCode = false;

    for (let i = 0; i < srcLines.length; i++) {
      const line = srcLines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith('```')) {
        inCode = !inCode;
        if (pendingRow !== null) {
          result.push(pendingRow + (pendingRow.endsWith('|') ? '' : ' |'));
          pendingRow = null;
        }
        result.push(line);
        continue;
      }

      if (inCode) {
        result.push(line);
        continue;
      }

      if (pendingRow !== null) {
        // If the new line starts with '|', then the previous pendingRow was just missing its closing pipe!
        if (trimmed.startsWith('|')) {
          result.push(pendingRow + (pendingRow.endsWith('|') ? '' : ' |'));
          pendingRow = null;
          // fall through to process the current line below
        } else if (trimmed.startsWith('#') || trimmed.startsWith('---') || trimmed.startsWith('>')) {
          // Hit heading/divider - flush pendingRow
          result.push(pendingRow + (pendingRow.endsWith('|') ? '' : ' |'));
          pendingRow = null;
          result.push(line);
          continue;
        } else if (trimmed === '') {
          // Empty line inside a potential multi-line cell: check ahead if subsequent lines close the cell before a heading/codeblock
          let hasClosingPipeAhead = false;
          for (let j = i + 1; j < Math.min(srcLines.length, i + 10); j++) {
            const nextTrim = srcLines[j].trim();
            if (nextTrim.startsWith('#') || nextTrim.startsWith('```') || nextTrim.startsWith('|')) break;
            if (nextTrim.endsWith('|')) {
              hasClosingPipeAhead = true;
              break;
            }
          }
          if (hasClosingPipeAhead) {
            // Continuation across empty line
            continue;
          } else {
            // Table ended
            result.push(pendingRow + (pendingRow.endsWith('|') ? '' : ' |'));
            pendingRow = null;
            result.push(line);
            continue;
          }
        } else if (trimmed.endsWith('|')) {
          // Closing line of a multi-line cell
          pendingRow += ' · ' + trimmed.replace(/\|$/, '').trim() + ' |';
          result.push(pendingRow);
          pendingRow = null;
          continue;
        } else {
          // Intermediate line of a multi-line cell
          pendingRow += ' · ' + trimmed;
          continue;
        }
      }

      // Check if this line starts a table row without closing pipe
      if (trimmed.startsWith('|') && !trimmed.endsWith('|') && trimmed.includes('|')) {
        pendingRow = trimmed;
        continue;
      }

      result.push(line);
    }

    if (pendingRow !== null) {
      result.push(pendingRow + (pendingRow.endsWith('|') ? '' : ' |'));
    }
    return result.join('\n');
  })(mdContent);

  // Parse Markdown & Bundle Images Locally
  const lines = mdContent.split('\n');
  const tocItems = [];
  const htmlBuffer = [];
  const seenHeadingIds = new Set();
  const getUniqueHeadingId = (title) => {
    let baseId = slugify(title) || 'section';
    let id = baseId;
    let counter = 2;
    while (seenHeadingIds.has(id)) {
      id = `${baseId}-${counter}`;
      counter++;
    }
    seenHeadingIds.add(id);
    return id;
  };

  let inCodeBlock = false;
  let codeBlockLang = '';
  let codeBlockBuffer = [];
  let codeSnippetCounter = 0;

  let inTable = false;
  let tableHeader = [];
  let tableRows = [];

  function enhanceHashCell(cell) {
    if (!cell) return '';
    if (cell.includes('<button') || cell.includes('btn-copy')) return cell;

    // Pattern 1: Exact <code>hash</code> cell (hex characters between 24 and 64)
    const exactCode = cell.match(/^<code>([a-fA-F0-9]{24,64})<\/code>$/);
    if (exactCode) {
      const hash = exactCode[1];
      return `<div class="hash-cell-wrapper"><code>${hash}</code><button class="btn-copy" onclick="copyText('${hash}', this)" title="Copy hash to clipboard">Copy</button></div>`;
    }

    // Pattern 2: Exact TLSH cell (starts with T1, ~70-72 chars)
    const exactTlsh = cell.match(/^(?:<code>)?(T[1-9A-Fa-f][a-fA-F0-9]{68,70})(?:<\/code>)?$/i);
    if (exactTlsh) {
      const tlsh = exactTlsh[1];
      return `<div class="hash-cell-wrapper"><code class="tlsh-code">${tlsh}</code><button class="btn-copy" onclick="copyText('${tlsh}', this)" title="Copy TLSH to clipboard">Copy</button></div>`;
    }

    // Pattern 3: Exact SSDEEP cell
    const exactSsdeep = cell.match(/^(?:<code>)?(\d+:[a-zA-Z0-9/+=]+:[a-zA-Z0-9/+=]+)(?:<\/code>)?$/);
    if (exactSsdeep) {
      const ssdeep = exactSsdeep[1];
      return `<div class="hash-cell-wrapper"><code class="ssdeep-code">${ssdeep}</code><button class="btn-copy" onclick="copyText('${ssdeep}', this)" title="Copy SSDEEP to clipboard">Copy</button></div>`;
    }

    // Pattern 4: Raw hex hash without code tags (between 24 and 64 characters)
    const rawClean = cell.replace(/<[^>]+>/g, '').trim();
    if (/^[a-fA-F0-9]{24,64}$/.test(rawClean)) {
      return `<div class="hash-cell-wrapper"><code>${rawClean}</code><button class="btn-copy" onclick="copyText('${rawClean}', this)" title="Copy hash to clipboard">Copy</button></div>`;
    }

    // Pattern 5: Any <code>hash</code> embedded in text within the cell
    if (/<code>([a-fA-F0-9]{24,64})<\/code>/.test(cell)) {
      return cell.replace(/<code>([a-fA-F0-9]{24,64})<\/code>/g, (match, hash) => {
        return `<span class="hash-cell-wrapper"><code>${hash}</code><button class="btn-copy" onclick="copyText('${hash}', this)" title="Copy hash to clipboard">Copy</button></span>`;
      });
    }

    return cell;
  }

  function flushTable() {
    if (!inTable) return;
    inTable = false;
    const colCount = tableHeader.length;
    const isTwoCol = colCount === 2;
    const allHeaders = tableHeader.map(h => (h || '').replace(/<[^>]+>/g, '').trim().toLowerCase());
    const header0 = allHeaders[0] || '';
    const header1 = allHeaders[1] || '';
    const isMetadataTable = isTwoCol && (
      (header0.includes('property') || header0.includes('attribute') || header0.includes('parameter') || header0 === 'field' || header0 === 'key' || header0.includes('file name')) &&
      (header1.includes('value') || header1.includes('telemetry') || header1.includes('detail') || header1.includes('sha256') || header1.includes('hash'))
    );
    const isMitreTable = allHeaders.some(h => h.includes('tactic')) && allHeaders.some(h => h.includes('technique'));
    const isSectionTable = allHeaders.some(h => h.includes('virtual address') || h.includes('raw size') || h.includes('offset') || h.includes('section'));

    let tableClasses = ['data-table'];
    if (isMetadataTable) tableClasses.push('table-metadata');
    if (isMitreTable) tableClasses.push('table-mitre');
    if (isSectionTable) tableClasses.push('table-sections');
    if (colCount >= 4) tableClasses.push('table-wide');
    if (colCount === 3) tableClasses.push('table-three-col');

    let html = `<div class="table-responsive"><table class="${tableClasses.join(' ')}"><thead><tr>`;
    tableHeader.forEach(cell => { html += `<th>${cell}</th>`; });
    html += '</tr></thead><tbody>';
    tableRows.forEach(row => {
      // If table is 2 columns, but this row has >2 cells due to internal pipes, join the rest into column 2
      if (isTwoCol && row.length > 2) {
        row = [row[0], row.slice(1).join(' · ')];
      }
      html += '<tr>';
      row.forEach((cell, idx) => {
        // If it is a 2-col metadata table and this is the value cell (idx === 1)
        if (isMetadataTable && idx === 1) {
          const propName = row[0].replace(/<[^>]+>/g, '').trim().toLowerCase();
          const isHashProp = ['md5', 'sha-1', 'sha1', 'sha-256', 'sha256', 'vhash', 'ssdeep', 'tlsh', 'cdhash', 'symhash', 'imphash', 'authentihash', 'rich header', 'sample hash', 'file hash', 'hash'].some(k => propName.includes(k));
          if (isHashProp && !cell.includes('<button') && !cell.includes('btn-copy')) {
            const rawVal = cell.replace(/<[^>]+>/g, '').trim();
            if (rawVal && rawVal.toLowerCase() !== 'n/a' && rawVal.length > 8) {
              cell = `<div class="hash-cell-wrapper"><code>${escapeHtml(rawVal)}</code><button class="btn-copy" onclick="copyText('${escapeHtml(rawVal)}', this)" title="Copy ${escapeHtml(propName.toUpperCase())} to clipboard">Copy</button></div>`;
            }
          }
        }
        html += `<td>${enhanceHashCell(cell)}</td>`;
      });
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    htmlBuffer.push(html);
    tableHeader = [];
    tableRows = [];
  }

  function formatMitreBadge(id) {
    const parts = id.split('.');
    const url = parts.length === 2
      ? `https://attack.mitre.org/techniques/${parts[0]}/${parts[1]}/`
      : `https://attack.mitre.org/techniques/${parts[0]}/`;
    return `<a href="${url}" target="_blank" rel="noopener noreferrer" class="mitre-badge" title="MITRE ATT&amp;CK Technique ${id}"><span class="mitre-label">ATT&amp;CK</span><span class="mitre-id">${id}</span><span class="mitre-arrow">↗</span></a>`;
  }

  function inlineFormat(text) {
    if (!text) return '';
    const codes = [];
    let processed = text.replace(/`([^`]+)`/g, (match, code) => {
      codes.push(code);
      return `\x00CODE_${codes.length - 1}\x00`;
    });

    processed = processed
      .replace(/&lt;br\s*\/?&gt;/gi, '<br>')
      .replace(/\*\*\*([^*]+)\*\*\*/g, '<strong><em>$1</em></strong>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/__([^_]+)__/g, '<strong>$1</strong>')
      .replace(/\*([^*]+)\*/g, '<em>$1</em>')
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');

    // Auto-badge raw MITRE ATT&CK technique IDs outside existing <a> tags
    processed = processed.replace(/(<a\s+[^>]*>[\s\S]*?<\/a>)|(\bT1[0-9]{3}(?:\.[0-9]{3})?\b(?![0-9a-fA-F_]))/g, (match, link, mitreId) => {
      if (link) return link;
      return formatMitreBadge(mitreId);
    });

    return processed.replace(/\x00CODE_(\d+)\x00/g, (match, idx) => {
      const codeVal = codes[Number(idx)];
      if (/^T1[0-9]{3}(?:\.[0-9]{3})?$/.test(codeVal.trim())) {
        return formatMitreBadge(codeVal.trim());
      }
      return `<code>${codeVal}</code>`;
    });
  }

  function splitTableRow(line) {
    let trimmed = line.trim();
    if (trimmed.startsWith('|')) trimmed = trimmed.slice(1);
    if (trimmed.endsWith('|')) trimmed = trimmed.slice(0, -1);

    const cells = [];
    let current = '';
    let inCode = false;

    for (let i = 0; i < trimmed.length; i++) {
      const ch = trimmed[i];
      if (ch === '`') {
        inCode = !inCode;
        current += ch;
      } else if (ch === '\\' && i + 1 < trimmed.length && trimmed[i + 1] === '|') {
        current += '|';
        i++;
      } else if (ch === '|' && !inCode) {
        cells.push(current.trim());
        current = '';
      } else {
        current += ch;
      }
    }
    cells.push(current.trim());
    return cells;
  }

  function copyOrConvertImage(srcFile, targetDir, baseName) {
    const ext = path.extname(baseName).toLowerCase();
    const rawTarget = path.join(targetDir, baseName);

    if (ext === '.png' || ext === '.jpg' || ext === '.jpeg') {
      const webpName = baseName.replace(/\.[^.]+$/, '.webp');
      const webpTarget = path.join(targetDir, webpName);

      if (fs.existsSync(webpTarget) && fs.statSync(webpTarget).size > 100 && fs.statSync(webpTarget).mtimeMs >= fs.statSync(srcFile).mtimeMs) {
        if (fs.existsSync(rawTarget)) {
          try { fs.unlinkSync(rawTarget); } catch (e) {}
        }
        return `images/${encodeURIComponent(webpName)}`;
      }

      try {
        execSync(`cwebp -q 85 "${srcFile}" -o "${webpTarget}"`, { stdio: 'ignore' });
        if (fs.existsSync(webpTarget) && fs.statSync(webpTarget).size > 100) {
          if (fs.existsSync(rawTarget)) {
            try { fs.unlinkSync(rawTarget); } catch (e) {}
          }
          return `images/${encodeURIComponent(webpName)}`;
        }
      } catch (e) {
        // Fallback to direct copy if cwebp fails
      }
    }

    try {
      if (!fs.existsSync(rawTarget) || fs.statSync(rawTarget).mtimeMs < fs.statSync(srcFile).mtimeMs) {
        fs.copyFileSync(srcFile, rawTarget);
      }
      return `images/${encodeURIComponent(baseName)}`;
    } catch (e) {
      console.warn(`[Warning] Could not copy image ${srcFile}:`, e.message);
      return `images/${encodeURIComponent(baseName)}`;
    }
  }

  // Copies image locally to reports/<id>/images/ and returns self-contained relative path 'images/<name>'
  function bundleImageLocally(rawSrc) {
    if (rawSrc.startsWith('http://') || rawSrc.startsWith('https://')) {
      try {
        const urlObj = new URL(rawSrc);
        let baseName = path.basename(urlObj.pathname);
        if (!baseName || baseName.length < 3 || !/\.(png|jpe?g|webp|gif|svg)$/i.test(baseName)) {
          const cleanPart = baseName ? baseName.replace(/[^\w-]/g, '') : 'remote_img';
          baseName = `banner_${cleanPart}.webp`;
        }
        const targetPath = path.join(imagesDir, baseName);
        if (!fs.existsSync(targetPath) || fs.statSync(targetPath).size === 0) {
          execSync(`curl -sL --max-time 15 "${rawSrc}" -o "${targetPath}"`, { stdio: 'ignore' });
        }
        if (fs.existsSync(targetPath) && fs.statSync(targetPath).size > 100) {
          return copyOrConvertImage(targetPath, imagesDir, baseName);
        }
      } catch (e) {
        // Fallback to raw remote URL
      }
      return rawSrc;
    }
    const cleanSrc = decodeURIComponent(rawSrc.trim());
    let absSrc = path.resolve(r.srcDir, cleanSrc);

    if (!fs.existsSync(absSrc) || !fs.statSync(absSrc).isFile()) {
      // Fallback: search anywhere inside report directory recursively for matching image filename
      const targetBase = path.basename(cleanSrc);
      const findImageRec = (dir) => {
        try {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const ent of entries) {
            if (ent.name.startsWith('.')) continue;
            const full = path.join(dir, ent.name);
            if (ent.isDirectory()) {
              const res = findImageRec(full);
              if (res) return res;
            } else if (ent.isFile() && (ent.name === targetBase || ent.name.toLowerCase() === targetBase.toLowerCase())) {
              return full;
            }
          }
        } catch (e) {}
        return null;
      };
      const found = findImageRec(r.srcDir);
      if (found) absSrc = found;
    }

    if (fs.existsSync(absSrc) && fs.statSync(absSrc).isFile()) {
      const baseName = path.basename(absSrc).replace(/[^\w.-]/g, '_');
      return copyOrConvertImage(absSrc, imagesDir, baseName);
    }
    return rawSrc;
  }

  let firstEncounteredImage = null;
  if (r.thumbnail) {
    const rawThumb = decodeURIComponent(String(r.thumbnail).trim().replace(/^images\//, ''));
    let absThumb = path.resolve(r.srcDir, rawThumb);
    if (!fs.existsSync(absThumb) || !fs.statSync(absThumb).isFile()) {
      const targetBase = path.basename(rawThumb);
      const findImageRec = (dir) => {
        try {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const ent of entries) {
            if (ent.name.startsWith('.')) continue;
            const full = path.join(dir, ent.name);
            if (ent.isDirectory()) {
              const res = findImageRec(full);
              if (res) return res;
            } else if (ent.isFile() && (ent.name === targetBase || ent.name.toLowerCase() === targetBase.toLowerCase())) {
              return full;
            }
          }
        } catch (e) {}
        return null;
      };
      const found = findImageRec(r.srcDir);
      if (found) absThumb = found;
    }
    if (fs.existsSync(absThumb) && fs.statSync(absThumb).isFile()) {
      const baseName = path.basename(absThumb).replace(/[^\w.-]/g, '_');
      r.thumbnail = copyOrConvertImage(absThumb, imagesDir, baseName);
      r.firstImage = r.thumbnail;
      firstEncounteredImage = r.thumbnail;
    }
  }
  let firstH1Encountered = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Single-line code block e.g. ```text```
    if (line.trim().startsWith('```') && line.trim().endsWith('```') && line.trim().length > 3) {
      if (!inCodeBlock) {
        flushTable();
        const content = line.trim().slice(3, -3).trim();
        codeSnippetCounter++;
        const snippetId = `code-block-${codeSnippetCounter}`;
        const { label, langClass } = getCodeBlockMeta('', content);
        const highlighted = highlightCode(content, langClass, label);
        htmlBuffer.push(`
          <div class="code-box ${langClass}">
            <div class="code-box-header">
              <span class="code-box-title"><span class="code-box-dot"></span>${escapeHtml(label)}</span>
              <button class="btn-copy" onclick="copySnippet('${snippetId}', this)">Copy Snippet</button>
            </div>
            <pre><code id="${snippetId}">${highlighted}</code></pre>
          </div>
        `);
        continue;
      }
    }

    // Code blocks
    if (line.trim().startsWith('```')) {
      if (inCodeBlock) {
        inCodeBlock = false;
        codeSnippetCounter++;
        const snippetId = `code-block-${codeSnippetCounter}`;
        const rawCode = codeBlockBuffer.join('\n');
        const { label, langClass } = getCodeBlockMeta(codeBlockLang, rawCode);
        const highlighted = highlightCode(rawCode, langClass, label);
        htmlBuffer.push(`
          <div class="code-box ${langClass}">
            <div class="code-box-header">
              <span class="code-box-title"><span class="code-box-dot"></span>${escapeHtml(label)}</span>
              <button class="btn-copy" onclick="copySnippet('${snippetId}', this)">Copy Snippet</button>
            </div>
            <pre><code id="${snippetId}">${highlighted}</code></pre>
          </div>
        `);
        codeBlockBuffer = [];
        codeBlockLang = '';
        continue;
      } else {
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

    // Markdown tables
    let tableCandidate = line.trim();
    if (tableCandidate.startsWith('|')) {
      if (!tableCandidate.endsWith('|') && tableCandidate.includes('|')) {
        tableCandidate += ' |';
      }
    }
    if (tableCandidate.startsWith('|') && tableCandidate.endsWith('|')) {
      const parts = splitTableRow(tableCandidate);
      if (parts.every(p => /^:?-+:?$/.test(p))) continue;
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

    // Dividers
    if (/^---+\s*$/.test(line.trim())) continue;

    // Headings
    const h1Match = line.match(/^#\s+(.+)$/);
    const h2Match = line.match(/^##\s+(.+)$/);
    const h3Match = line.match(/^###\s+(.+)$/);
    const h4Match = line.match(/^####\s+(.+)$/);

    if (h1Match) {
      if (!firstH1Encountered) {
        firstH1Encountered = true;
        // Skip any immediate subtitle / divider that mirrors the header lead
        let j = i + 1;
        while (j < lines.length) {
          const nextTrimmed = lines[j].trim();
          if (!nextTrimmed) {
            j++;
            continue;
          }
          const italicMatch = nextTrimmed.match(/^[*_]{1,2}(.*?)[*_]{1,2}$/);
          if (italicMatch) {
            const candidate = italicMatch[1].trim().toLowerCase();
            const leadLower = (r.lead || '').trim().toLowerCase();
            const subLower = (r.subtitle || '').trim().toLowerCase();
            if (candidate === leadLower || candidate === subLower || (subLower && subLower.startsWith(candidate)) || (leadLower && leadLower.startsWith(candidate))) {
              i = j;
              j++;
              continue;
            }
          }
          if (/^---+$|^___+$|^\*\*\*+$/.test(nextTrimmed)) {
            i = j;
            j++;
            continue;
          }
          break;
        }
        continue;
      }
      const title = h1Match[1].replace(/[*_`]/g, '').trim();
      const id = getUniqueHeadingId(title);
      tocItems.push({ id, title });
      htmlBuffer.push(`</section><section id="${id}"><h1 class="content-h1">${escapeHtml(title)}</h1>`);
      continue;
    }

    if (h2Match) {
      const title = h2Match[1].replace(/[*_`]/g, '').trim();
      const id = getUniqueHeadingId(title);
      tocItems.push({ id, title });
      htmlBuffer.push(`</section><section id="${id}"><h2>${escapeHtml(title)}</h2>`);
      continue;
    }

    if (h3Match) {
      const title = h3Match[1].replace(/[*_`]/g, '').trim();
      const id = getUniqueHeadingId(title);
      htmlBuffer.push(`<h3 id="${id}">${escapeHtml(title)}</h3>`);
      continue;
    }

    if (h4Match) {
      const title = h4Match[1].replace(/[*_`]/g, '').trim();
      htmlBuffer.push(`<h4>${escapeHtml(title)}</h4>`);
      continue;
    }

    // Helper to format figure captions and clean alt text
    function parseImageCaption(rawAlt) {
      if (!rawAlt) return { formattedCaption: '', cleanAlt: '' };
      let captionText = rawAlt.trim();
      // Unwrap outer bold/italic if the entire caption was wrapped in **...** or *...*
      if (/^\*\*([^*]+)\*\*$/.test(captionText)) {
        captionText = captionText.slice(2, -2).trim();
      } else if (/^\*([^*]+)\*$/.test(captionText)) {
        captionText = captionText.slice(1, -1).trim();
      }
      // Strip redundant "Figure:" prefix if author wrote it
      captionText = captionText.replace(/^(?:<strong>)?Figure\s*(?:\d+)?\s*:\s*(?:<\/strong>)?\s*/i, '');
      const formattedCaption = inlineFormat(escapeHtml(captionText));
      const cleanAlt = rawAlt.replace(/[*_`]/g, '').trim();
      return { formattedCaption, cleanAlt };
    }

    // Images
    const mdImgMatch = line.match(/!\[([^\]]*)\]\((.+)\)/);
    if (mdImgMatch) {
      const alt = mdImgMatch[1] ? mdImgMatch[1].trim() : '';
      const localSrc = bundleImageLocally(mdImgMatch[2]);
      if (!firstEncounteredImage && localSrc) {
        firstEncounteredImage = localSrc;
        r.firstImage = localSrc;
      }
      const { formattedCaption, cleanAlt } = parseImageCaption(alt);
      const captionHtml = formattedCaption ? `
          <div class="figure-caption">
            <span><strong>Figure:</strong> ${formattedCaption}</span>
            <span class="zoom-link" style="font-size: 11.5px; color: var(--accent-blue-hover); cursor: pointer;">Click to zoom ↗</span>
          </div>` : '';
      htmlBuffer.push(`
        <div class="figure-wrapper">
          <div class="figure-image-container">
            <img src="${localSrc}" alt="${escapeHtml(cleanAlt)}" loading="lazy" decoding="async">
          </div>${captionHtml}
        </div>
      `);

      // Consume duplicate caption line if the markdown author repeated the caption immediately below the image
      const normText = str => str.replace(/[*_`]/g, '').replace(/&[a-z]+;/gi, '').trim().toLowerCase();
      const altNorm = normText(alt);
      if (altNorm && altNorm.length > 3) {
        let peek = i + 1;
        while (peek < lines.length && lines[peek].trim() === '') {
          peek++;
        }
        if (peek < lines.length && normText(lines[peek]) === altNorm) {
          i = peek; // Skip the redundant duplicate paragraph
        }
      }
      continue;
    }

    const htmlImgMatch = line.match(/<img[^>]+src=["']([^"']+)["'][^>]*>/i);
    if (htmlImgMatch) {
      const localSrc = bundleImageLocally(htmlImgMatch[1]);
      if (!firstEncounteredImage && localSrc) {
        firstEncounteredImage = localSrc;
        r.firstImage = localSrc;
      }
      const altMatch = line.match(/alt=["']([^"']*)["']/i);
      const alt = (altMatch && altMatch[1]) ? altMatch[1].trim() : '';
      const { formattedCaption, cleanAlt } = parseImageCaption(alt);
      const captionHtml = formattedCaption ? `
          <div class="figure-caption">
            <span><strong>Figure:</strong> ${formattedCaption}</span>
            <span class="zoom-link" style="font-size: 11.5px; color: var(--accent-blue-hover); cursor: pointer;">Click to zoom ↗</span>
          </div>` : '';
      htmlBuffer.push(`
        <div class="figure-wrapper">
          <div class="figure-image-container">
            <img src="${localSrc}" alt="${escapeHtml(cleanAlt)}" loading="lazy" decoding="async">
          </div>${captionHtml}
        </div>
      `);

      const normText = str => str.replace(/[*_`]/g, '').replace(/&[a-z]+;/gi, '').trim().toLowerCase();
      const altNorm = normText(alt);
      if (altNorm && altNorm.length > 3) {
        let peek = i + 1;
        while (peek < lines.length && lines[peek].trim() === '') {
          peek++;
        }
        if (peek < lines.length && normText(lines[peek]) === altNorm) {
          i = peek;
        }
      }
      continue;
    }

    // Callouts / Blockquotes
    if (line.trim().startsWith('>')) {
      const quoteText = line.trim().replace(/^>\s*/, '');
      htmlBuffer.push(`<div class="callout-box"><p>${inlineFormat(escapeHtml(quoteText))}</p></div>`);
      continue;
    }

    // Lists
    if (/^\s*[-*•]\s+(.+)$/.test(line)) {
      const itemMatch = line.match(/^\s*[-*•]\s+(.+)$/);
      let formatted = inlineFormat(escapeHtml(itemMatch[1]));
      formatted = formatted.replace(/<code>([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})<\/code>/g, (m, h) => {
        return `<code>${h}</code><button class="btn-copy" style="margin-left: 8px; vertical-align: middle; padding: 2px 8px; font-size: 11px;" onclick="copyText('${h}', this)">Copy</button>`;
      });
      htmlBuffer.push(`<div class="list-bullet-item"><span class="bullet-dot">▪</span><span>${formatted}</span></div>`);
      continue;
    }

    if (/^\s*\d+\.\s+(.+)$/.test(line)) {
      const numMatch = line.match(/^\s*(\d+)\.\s+(.+)$/);
      htmlBuffer.push(`<div class="list-bullet-item"><span class="bullet-num">${numMatch[1]}.</span><span>${inlineFormat(escapeHtml(numMatch[2]))}</span></div>`);
      continue;
    }

    if (line.trim().length > 0) {
      htmlBuffer.push(`<p>${inlineFormat(escapeHtml(line))}</p>`);
    }
  }

  if (inCodeBlock && codeBlockBuffer.length > 0) {
    codeSnippetCounter++;
    const snippetId = `code-block-${codeSnippetCounter}`;
    const rawCode = codeBlockBuffer.join('\n');
    const { label, langClass } = getCodeBlockMeta(codeBlockLang, rawCode);
    const highlighted = highlightCode(rawCode, langClass, label);
    htmlBuffer.push(`
      <div class="code-box ${langClass}">
        <div class="code-box-header">
          <span class="code-box-title"><span class="code-box-dot"></span>${escapeHtml(label)}</span>
          <button class="btn-copy" onclick="copySnippet('${snippetId}', this)">Copy Snippet</button>
        </div>
        <pre><code id="${snippetId}">${highlighted}</code></pre>
      </div>
    `);
    codeBlockBuffer = [];
    inCodeBlock = false;
  }

  flushTable();

  if (!r.firstImage && fs.existsSync(imagesDir)) {
    const existingImages = fs.readdirSync(imagesDir).filter(f => !f.startsWith('.') && /\.(png|jpe?g|webp|gif|svg)$/i.test(f));
    if (existingImages.length > 0) {
      r.firstImage = `images/${encodeURIComponent(existingImages[0])}`;
    }
  }

  let bodyHtml = htmlBuffer.join('\n');
  if (!bodyHtml.startsWith('</section>')) {
    seenHeadingIds.add('overview');
    bodyHtml = `<section id="overview">${bodyHtml}</section>`;
  } else {
    bodyHtml = bodyHtml.replace(/^<\/section>/, '') + '</section>';
  }

  if (tocItems.length === 0) {
    tocItems.push({ id: 'overview', title: 'Executive Overview' });
  }

  const tocListHtml = tocItems.map((item, idx) => {
    const num = String(idx + 1).padStart(2, '0');
    const activeClass = idx === 0 ? 'class="active"' : '';
    const cleanTitle = item.title.replace(/^(\d+[\.\)]|\b\d+\s*[-–—])\s*/, '');
    return `<li><a href="#${item.id}" ${activeClass}>${num}. ${escapeHtml(cleanTitle)}</a></li>`;
  }).join('\n');

  const mobileTocHtml = `
        <details class="mobile-toc-drawer" id="mobile-toc-drawer">
          <summary class="mobile-toc-summary">
            <div class="mobile-toc-summary-left">
              <svg class="mobile-toc-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="12" x2="17" y2="12"></line><line x1="3" y1="18" x2="13" y2="18"></line></svg>
              <span class="mobile-toc-label">Table of Contents</span>
            </div>
            <div class="mobile-toc-summary-right">
              <span class="mobile-toc-pill">${tocItems.length} Sections</span>
              <svg class="mobile-toc-chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
            </div>
          </summary>
          <div class="mobile-toc-content">
            <ul class="mobile-toc-nav">
              ${tocListHtml}
            </ul>
          </div>
        </details>`;

  const hashLabel = r.hashType === 'SHA-256' ? 'Sample SHA-256' : (r.hashType === 'MD5' ? 'Sample MD5' : 'Sample Hash');
  const fullHash = r.hashVal;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title>${escapeHtml(r.title)} | ${AUTHOR_NAME}</title>
  <link rel="icon" type="image/png" href="../assets/home/mare-logo.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="../assets/css/report.css">
</head>
<body>

  <div id="progress-bar"></div>

  <nav class="site-nav">
    <div class="nav-left">
      <a href="../index.html" class="nav-back-btn" title="Back to all investigations">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
        <span>Reports</span>
      </a>
      <div class="nav-breadcrumbs">
        <a href="../index.html" class="brand-title" style="display:inline-flex;align-items:center;gap:8px;">
          <img src="../assets/home/mare-logo.png" alt="MARE Logo" width="18" height="18" style="vertical-align:middle;border-radius:3px;">
          <span>MARE</span>
          <span class="nav-slash" style="opacity:0.4;font-size:11px;">/</span>
          <span class="nav-subtitle">THREAT RESEARCH</span>
        </a>
        <span class="meta-divider">/</span>
        <span class="nav-section-title">${r.source === 'malops' ? 'MALOPS INVESTIGATIONS' : escapeHtml(r.os.toUpperCase()) + ' INVESTIGATIONS'}</span>
      </div>
    </div>

    <div class="nav-actions">
      <button class="nav-search-btn" id="nav-search-btn" title="Search investigations (⌘K or /)" aria-label="Search investigations">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        <span>Search</span>
        <kbd>⌘K</kbd>
      </button>
      <span class="badge-tlp">● TLP:CLEAR</span>
    </div>
  </nav>

  <article class="article-wrap">

    <header class="article-header">
      <div class="meta-pills">
        ${r.source === 'malops' ? `
        <span class="pill-category pill-malops">MALOPS</span>
        <span class="meta-divider">•</span>
        <span class="pill-difficulty difficulty-${(r.difficulty || 'medium').toLowerCase()}">${escapeHtml((r.difficulty || 'MEDIUM').toUpperCase())}</span>
        <span class="meta-divider">•</span>
        ` : ''}
        <span class="pill-category">${escapeHtml(r.category)}</span>
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

    <div class="article-layout">
      
      <div class="article-content">
        ${mobileTocHtml}
        ${r.source === 'malops' ? `
        <div class="malops-challenge-callout">
          <div class="callout-header">
            <div class="callout-title-group">
              <span class="callout-tag">MALOPS CHALLENGE</span>
              <span class="difficulty-badge difficulty-${(r.difficulty || 'medium').toLowerCase()}">${escapeHtml(r.difficulty || 'Medium')}</span>
            </div>
            ${r.challengeUrl ? `<a href="${r.challengeUrl}" target="_blank" rel="noopener noreferrer" class="btn-external-challenge">Live Challenge &#8599;</a>` : ''}
          </div>
          <div class="callout-meta-row">
            <span class="callout-meta-item"><strong>Platform:</strong> ${escapeHtml(r.os)}</span>
            <span class="callout-meta-item"><strong>Tools:</strong> ${escapeHtml(r.tools || 'IDA Pro, x64dbg')}</span>
            <span class="callout-meta-item"><strong>Source:</strong> <a href="https://github.com/Lynk4/malops.io" target="_blank" rel="noopener noreferrer">Lynk4/malops.io</a></span>
          </div>
        </div>
        ` : ''}
        ${bodyHtml}
      </div>

      <aside class="sidebar-sticky">
        <div class="sidebar-desktop-toc">
          <div class="sidebar-block-title">Table of Contents</div>
          <ul class="toc-nav">
            ${tocListHtml}
          </ul>
        </div>

        <div class="sidebar-threat-profile">
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
              <span class="threat-v mono hash-interactive" title="Click to copy full ${r.hashType} hash" onclick="copyText('${fullHash}', this)">${fullHash}</span>
            </div>
          </div>
        </div>

      </aside>

    </div>

  </article>

  <div id="lightbox" class="lightbox-modal">
    <span class="lightbox-close" onclick="closeLightbox()">&times;</span>
    <div class="lightbox-content-wrap">
      <img id="lightbox-img" src="" alt="Zoomed Screenshot Preview">
      <div id="lightbox-caption" class="lightbox-caption-text"></div>
    </div>
  </div>

  <div id="toast-msg">Copied</div>

  <button id="btn-back-to-top" class="btn-floating-top" onclick="window.scrollTo({top: 0, behavior: 'smooth'})" aria-label="Scroll to top" title="Back to top">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>
  </button>

  <script>
    // Instant Jump + Target Heading Glow Engine (Option 1)
    function getNavOffset() {
      const nav = document.querySelector('.site-nav');
      if (!nav) return window.innerWidth <= 768 ? 56 : (window.innerWidth <= 1024 ? 68 : 80);
      return Math.round(nav.getBoundingClientRect().height) + 14;
    }

    function setActiveTOCLink(activeId) {
      document.querySelectorAll('.toc-nav a, .mobile-toc-nav a').forEach(link => {
        const href = link.getAttribute('href');
        const targetId = href ? href.replace(/^#/, '') : '';
        link.classList.toggle('active', targetId === activeId);
      });
    }

    function syncSidebarScroll(activeId) {
      if (window.innerWidth <= 1024) return;
      const sidebar = document.querySelector('.sidebar-sticky');
      const activeLink = document.querySelector('.sidebar-desktop-toc .toc-nav a[href="#' + activeId + '"]');
      if (sidebar && activeLink && !sidebar.matches(':hover') && sidebar.scrollHeight > sidebar.clientHeight) {
        const linkRect = activeLink.getBoundingClientRect();
        const sidebarRect = sidebar.getBoundingClientRect();
        if (linkRect.top < sidebarRect.top + 30) {
          sidebar.scrollTop = Math.max(0, sidebar.scrollTop + (linkRect.top - sidebarRect.top - 30));
        } else if (linkRect.bottom > sidebarRect.bottom - 30) {
          sidebar.scrollTop = sidebar.scrollTop + (linkRect.bottom - sidebarRect.bottom + 30);
        }
      }
    }

    function triggerTargetGlow(targetEl) {
      if (!targetEl) return;
      document.querySelectorAll('.section-targeted').forEach(el => el.classList.remove('section-targeted'));
      document.querySelectorAll('.heading-target-pulse').forEach(el => el.classList.remove('heading-target-pulse'));

      void targetEl.offsetWidth; // Force reflow to restart animation
      targetEl.classList.add('section-targeted');

      const heading = targetEl.querySelector('h1, h2, h3');
      if (heading) {
        void heading.offsetWidth;
        heading.classList.add('heading-target-pulse');
      }
    }

    function instantJumpToTarget(targetEl, href) {
      if (!targetEl) return;

      const targetId = targetEl.id;
      setActiveTOCLink(targetId);
      syncSidebarScroll(targetId);

      // 1. Native instant element alignment with CSS scroll-margin-top
      targetEl.scrollIntoView({ behavior: 'auto', block: 'start' });

      // 2. Micro-adjust for exact sticky nav offset across all device pixel densities
      const navOffset = getNavOffset();
      const rect = targetEl.getBoundingClientRect();
      if (Math.abs(rect.top - navOffset) > 2) {
        window.scrollTo({
          top: Math.max(0, Math.round(rect.top + window.pageYOffset - navOffset)),
          behavior: 'auto'
        });
      }

      // 3. Update history without jumping
      if (history.pushState) {
        history.pushState(null, '', href);
      }

      // 4. Trigger sleek pulse glow on target heading & section
      triggerTargetGlow(targetEl);
    }

    // Click handling for Desktop & Mobile TOC links
    document.querySelectorAll('.toc-nav a, .mobile-toc-nav a').forEach(link => {
      link.addEventListener('click', (e) => {
        const href = link.getAttribute('href');
        if (!href || !href.startsWith('#')) return;
        const targetId = href.substring(1);
        const targetEl = document.getElementById(targetId);
        if (targetEl) {
          e.preventDefault();
          const drawer = document.getElementById('mobile-toc-drawer');
          if (drawer && drawer.hasAttribute('open')) {
            // Close mobile drawer FIRST so height collapses before jumping
            drawer.removeAttribute('open');
            requestAnimationFrame(() => {
              instantJumpToTarget(targetEl, href);
            });
          } else {
            instantJumpToTarget(targetEl, href);
          }
        }
      });
    });

    // Support browser back/forward buttons (hash navigation)
    window.addEventListener('popstate', () => {
      if (window.location.hash) {
        const el = document.querySelector(window.location.hash);
        if (el) {
          instantJumpToTarget(el, window.location.hash);
        }
      }
    });

    // Floating Back to Top Button Visibility
    const btnTop = document.getElementById('btn-back-to-top');
    if (btnTop) {
      window.addEventListener('scroll', () => {
        if ((window.scrollY || document.documentElement.scrollTop) > 400) {
          btnTop.classList.add('visible');
        } else {
          btnTop.classList.remove('visible');
        }
      }, { passive: true });
    }

    // Scroll spy for Table of Contents during normal reading
    const sectionEls = Array.from(document.querySelectorAll('.article-content section[id]'));
    let isTOCScrolling = false;

    function updateTOC() {
      if (sectionEls.length === 0) return;

      const winScroll = window.scrollY || document.documentElement.scrollTop;
      const scrollHeight = document.documentElement.scrollHeight;
      const clientHeight = document.documentElement.clientHeight;
      const atBottom = (winScroll + clientHeight >= scrollHeight - 60);

      let activeId = sectionEls[0].id;
      if (atBottom) {
        activeId = sectionEls[sectionEls.length - 1].id;
      } else {
        const threshold = getNavOffset() + 24;
        for (let i = 0; i < sectionEls.length; i++) {
          const rect = sectionEls[i].getBoundingClientRect();
          if (rect.top <= threshold) {
            activeId = sectionEls[i].id;
          } else {
            break;
          }
        }
      }

      setActiveTOCLink(activeId);
      syncSidebarScroll(activeId);
    }

    window.addEventListener('scroll', () => {
      const winScroll = window.scrollY || document.documentElement.scrollTop;
      const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
      const scrolled = height > 0 ? (winScroll / height) * 100 : 0;
      const pb = document.getElementById('progress-bar');
      if (pb) pb.style.width = scrolled + '%';

      if (!isTOCScrolling) {
        window.requestAnimationFrame(() => {
          updateTOC();
          isTOCScrolling = false;
        });
        isTOCScrolling = true;
      }
    }, { passive: true });

    // Initial check on load
    updateTOC();

    if (window.location.hash) {
      setTimeout(() => {
        const initialEl = document.querySelector(window.location.hash);
        if (initialEl) {
          instantJumpToTarget(initialEl, window.location.hash);
        }
      }, 50);
    }

    function openLightbox(src, caption) {
      const modal = document.getElementById('lightbox');
      const img = document.getElementById('lightbox-img');
      const cap = document.getElementById('lightbox-caption');
      if (!modal || !img) return;
      img.src = src;
      img.classList.remove('expanded');
      if (cap) {
        cap.textContent = caption || '';
        cap.style.display = caption ? 'block' : 'none';
      }
      modal.style.display = 'flex';
      document.body.style.overflow = 'hidden';
    }

    function closeLightbox() {
      const modal = document.getElementById('lightbox');
      if (!modal) return;
      modal.style.display = 'none';
      document.body.style.overflow = '';
      const img = document.getElementById('lightbox-img');
      if (img) img.classList.remove('expanded');
    }

    let toastTimeout;
    function showToast(msg) {
      const toast = document.getElementById('toast-msg');
      if (!toast) return;
      toast.textContent = msg;
      toast.classList.add('toast-show');
      clearTimeout(toastTimeout);
      toastTimeout = setTimeout(() => {
        toast.classList.remove('toast-show');
      }, 2000);
    }

    function copyToClipboard(txt) {
      if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(txt).catch(() => fallbackCopy(txt));
      } else {
        fallbackCopy(txt);
        return Promise.resolve();
      }
    }

    function fallbackCopy(txt) {
      const ta = document.createElement('textarea');
      ta.value = txt;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      ta.style.top = '-9999px';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      try {
        document.execCommand('copy');
      } catch (err) {
        console.error('Fallback copy failed', err);
      }
      document.body.removeChild(ta);
    }

    function copyText(txt, el) {
      copyToClipboard(txt);
      showToast('Copied: ' + (txt.length > 22 ? txt.substring(0, 18) + '...' : txt));
      if (el) {
        if (el.classList.contains('hash-interactive')) {
          const origHtml = el.innerHTML;
          el.classList.add('copied');
          el.innerHTML = '<span>✓ Copied to clipboard</span>';
          setTimeout(() => {
            el.innerHTML = origHtml;
            el.classList.remove('copied');
          }, 1800);
        } else if (el.classList.contains('btn-copy') || el.tagName === 'BUTTON') {
          const orig = el.innerText;
          el.innerText = 'Copied!';
          el.classList.add('btn-copied');
          setTimeout(() => {
            el.innerText = orig;
            el.classList.remove('btn-copied');
          }, 1800);
        } else {
          const btn = el.closest ? el.closest('.hash-cell-wrapper')?.querySelector('.btn-copy') : null;
          if (btn) {
            const orig = btn.innerText;
            btn.innerText = 'Copied!';
            btn.classList.add('btn-copied');
            setTimeout(() => {
              btn.innerText = orig;
              btn.classList.remove('btn-copied');
            }, 1800);
          }
        }
      }
    }

    function copySnippet(id, btn) {
      const codeEl = document.getElementById(id);
      if (!codeEl) return;
      const code = codeEl.innerText;
      copyToClipboard(code);
      showToast('Copied code snippet');
      if (btn) {
        const orig = btn.innerText;
        btn.innerText = 'Copied!';
        btn.classList.add('btn-copied');
        setTimeout(() => {
          btn.innerText = orig;
          btn.classList.remove('btn-copied');
        }, 1800);
      }
    }

    function copyAllHashes(btn) {
      const hashStr = '${fullHash}  ${r.family}';
      copyToClipboard(hashStr);
      showToast('Copied investigation IOC hash');
      if (btn) {
        const orig = btn.innerText;
        btn.innerText = 'Copied!';
        btn.classList.add('btn-copied');
        setTimeout(() => {
          btn.innerText = orig;
          btn.classList.remove('btn-copied');
        }, 1800);
      }
    }

    // Toggle zoom on lightbox image click
    const lightboxImg = document.getElementById('lightbox-img');
    if (lightboxImg) {
      lightboxImg.addEventListener('click', (e) => {
        e.stopPropagation();
        lightboxImg.classList.toggle('expanded');
      });
    }

    // Close on background click
    const lightboxModal = document.getElementById('lightbox');
    if (lightboxModal) {
      lightboxModal.addEventListener('click', (e) => {
        if (e.target === lightboxModal || e.target.classList.contains('lightbox-close')) {
          closeLightbox();
        }
      });
    }

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeLightbox();
      }
    });

    // Global click listener for images and copy elements
    document.addEventListener('click', (e) => {
      // Image or image container click
      const figTarget = e.target.closest('.figure-image-container, .figure-wrapper img, .article-content img');
      if (figTarget && figTarget.id !== 'lightbox-img') {
        const wrapper = figTarget.closest('.figure-wrapper');
        const img = figTarget.tagName === 'IMG' ? figTarget : figTarget.querySelector('img');
        if (img) {
          const cap = wrapper ? (wrapper.querySelector('.figure-caption span')?.innerText || img.alt) : img.alt;
          openLightbox(img.src, cap);
          return;
        }
      }

      // Click to zoom link
      const zoomLink = e.target.closest('.zoom-link');
      if (zoomLink) {
        const wrapper = zoomLink.closest('.figure-wrapper');
        const imgEl = wrapper ? wrapper.querySelector('img') : null;
        if (imgEl) {
          const cap = wrapper.querySelector('.figure-caption span')?.innerText || imgEl.alt;
          openLightbox(imgEl.src, cap);
        }
        return;
      }

      // Hash cell code click
      const codeEl = e.target.closest('.hash-cell-wrapper code');
      if (codeEl) {
        const wrapper = codeEl.closest('.hash-cell-wrapper');
        const btn = wrapper ? wrapper.querySelector('.btn-copy') : null;
        copyText(codeEl.innerText.trim(), btn);
        return;
      }

      // Delegated btn-copy click without inline onclick
      const copyBtn = e.target.closest('.btn-copy');
      if (copyBtn && !copyBtn.getAttribute('onclick')) {
        const wrapper = copyBtn.closest('.hash-cell-wrapper');
        const code = wrapper ? wrapper.querySelector('code') : null;
        if (code) {
          copyText(code.innerText.trim(), copyBtn);
        }
        return;
      }
    });

    // Auto-detect any raw table cells with hashes that missed build-time enhancement
    document.querySelectorAll('table td').forEach(td => {
      if (td.querySelector('.btn-copy') || td.querySelector('button')) return;
      const text = td.innerText.trim();
      if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^T[1-9A-Fa-f][a-fA-F0-9]{68,70}$|^\\d+:[a-zA-Z0-9/+=]+:[a-zA-Z0-9/+=]+$/i.test(text)) {
        td.innerHTML = '<div class="hash-cell-wrapper"><code>' + text + '</code><button class="btn-copy" type="button">Copy</button></div>';
      }
    });
  </script>
  ${renderCommandPaletteModal()}
  <script>
${getCommandPaletteJs('../')}
  </script>
</body>
</html>
`;

  fs.writeFileSync(path.join(reportDir, 'index.html'), html, 'utf8');
}

// 3. GENERATE HOMEPAGE PORTAL (REPORTS/INDEX.HTML)
function buildPortalIndex(allReports) {
  copyGlobalAssets();

  // Sort reports by date descending
  allReports.sort((a, b) => {
    const diff = new Date(b.date).getTime() - new Date(a.date).getTime();
    if (diff !== 0) return diff;
    return a.title.localeCompare(b.title);
  });

  const totalCount = allReports.length;
  const counts = {
    All: totalCount,
    Windows: allReports.filter(r => r.os === 'Windows').length,
    macOS: allReports.filter(r => r.os === 'macOS').length,
    Linux: allReports.filter(r => r.os === 'Linux').length,
    'Cross-Platform': allReports.filter(r => r.os === 'Cross-Platform').length,
    MalOps: allReports.filter(r => r.source === 'malops').length
  };

  const catCounts = {
    'Reverse Engineering Techniques': allReports.filter(r => r.category === 'Reverse Engineering Techniques').length,
    'Malware Family Analysis': allReports.filter(r => r.category === 'Malware Family Analysis').length,
    'Threat Intelligence & APTs': allReports.filter(r => r.category === 'Threat Intelligence & APTs').length,
    'Ransomware & Wipers': allReports.filter(r => r.category === 'Ransomware & Wipers').length
  };

  // Dynamic generation of navigation dropdowns
  // 1. Malware Families Dropdown: reports with category 'Malware Family Analysis' or explicitly tagged with navDropdown: 'malware' or featured
  const malwareFamilyReports = allReports.filter(r => {
    if (r.hideFromNav) return false;
    if (r.navDropdown === 'malware') return true;
    if (r.navDropdown === 'techniques') return false;
    if (r.category === 'Malware Family Analysis') return true;
    if (r.featured && r.category !== 'Reverse Engineering Techniques') return true;
    return false;
  });

  malwareFamilyReports.sort((a, b) => {
    if (a.featured && !b.featured) return -1;
    if (!a.featured && b.featured) return 1;
    const diff = new Date(b.date).getTime() - new Date(a.date).getTime();
    if (diff !== 0) return diff;
    return a.title.localeCompare(b.title);
  });

  const topMalwareReports = malwareFamilyReports.slice(0, 6);
  const malwareDropdownHtml = topMalwareReports.map(r => 
    `            <a href="${r.id}/index.html" class="dropdown-link">${escapeHtml(getReportNavTitle(r))}</a>`
  ).join('\n') + `
            <div class="dropdown-divider"></div>
            <a href="#investigations" class="dropdown-link dropdown-view-all" onclick="filterByCategory('Malware Family Analysis')">
              <span>View all Malware Families</span>
              <span class="dropdown-count-tag">(${catCounts['Malware Family Analysis'] || malwareFamilyReports.length}) &rarr;</span>
            </a>`;

  // 2. Techniques Dropdown: reports with category 'Reverse Engineering Techniques' or explicitly tagged with navDropdown: 'techniques'
  const techniqueReports = allReports.filter(r => {
    if (r.hideFromNav) return false;
    if (r.navDropdown === 'techniques') return true;
    if (r.navDropdown === 'malware') return false;
    if (r.category === 'Reverse Engineering Techniques') return true;
    if (r.featured && r.category === 'Reverse Engineering Techniques') return true;
    return false;
  });

  techniqueReports.sort((a, b) => {
    if (a.featured && !b.featured) return -1;
    if (!a.featured && b.featured) return 1;
    const diff = new Date(b.date).getTime() - new Date(a.date).getTime();
    if (diff !== 0) return diff;
    return a.title.localeCompare(b.title);
  });

  const topTechniqueReports = techniqueReports.slice(0, 6);
  const techniquesDropdownHtml = topTechniqueReports.map(r => 
    `            <a href="${r.id}/index.html" class="dropdown-link">${escapeHtml(getReportNavTitle(r))}</a>`
  ).join('\n') + `
            <div class="dropdown-divider"></div>
            <a href="#investigations" class="dropdown-link dropdown-view-all" onclick="filterByCategory('Reverse Engineering Techniques')">
              <span>View all Techniques</span>
              <span class="dropdown-count-tag">(${catCounts['Reverse Engineering Techniques'] || techniqueReports.length}) &rarr;</span>
            </a>`;

  // Sort order: display reports strictly by latest date descending
  const displayReports = allReports;

  const portalHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MARE — Malware Analysis &amp; Reverse Engineering</title>
  <link rel="icon" type="image/png" href="assets/home/mare-logo.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@500;600;700;800&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="assets/css/portal.css">
</head>
<body>

  <div class="bg-grid-overlay" aria-hidden="true"></div>

  <!-- Top Navigation -->
  <header class="site-nav">
    <div class="nav-container">
      <a href="index.html" class="brand-group" aria-label="MARE Home">
        <img src="assets/home/mare-logo.png" alt="MARE Logo" class="brand-logo-img" width="32" height="32">
        <div class="brand-text-block">
          <span class="brand-title">MARE</span>
          <div class="brand-vsep" aria-hidden="true"></div>
          <div class="brand-subtext">
            <span>MALWARE ANALYSIS</span>
            <span>&amp; REVERSE ENGINEERING</span>
          </div>
        </div>
      </a>

      <nav class="center-nav" aria-label="Main Navigation">
        <div class="nav-link-item">
          <a class="nav-link" href="#investigations">
            <span>Research</span>
            <svg class="nav-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none"><path d="M1 1L5 5L9 1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </a>
          <div class="nav-dropdown">
            <a href="#investigations" class="dropdown-link" onclick="selectFilter('all')">All Investigations (${totalCount})</a>
            <a href="#investigations" class="dropdown-link" onclick="selectFilter('Windows')">Windows Research (${counts.Windows})</a>
            <a href="#investigations" class="dropdown-link" onclick="selectFilter('macOS')">macOS Research (${counts.macOS})</a>
            <a href="#investigations" class="dropdown-link" onclick="selectFilter('Linux')">Linux Research (${counts.Linux})</a>
            <a href="#investigations" class="dropdown-link" onclick="selectFilter('Cross-Platform')">Cross-Platform (${counts['Cross-Platform']})</a>
            <div class="dropdown-divider"></div>
            <a href="#investigations" class="dropdown-link dropdown-view-all" onclick="selectFilter('malops')">
              <span>MalOps Challenges</span>
              <span class="dropdown-count-tag">(${counts.MalOps}) &rarr;</span>
            </a>
          </div>
        </div>

        <div class="nav-link-item">
          <a class="nav-link" href="#investigations" onclick="filterByCategory('Malware Family Analysis')">
            <span>Malware Families</span>
            <svg class="nav-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none"><path d="M1 1L5 5L9 1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </a>
          <div class="nav-dropdown">
${malwareDropdownHtml}
          </div>
        </div>

        <div class="nav-link-item">
          <a class="nav-link" href="#investigations" onclick="filterByCategory('Reverse Engineering Techniques')">
            <span>Techniques</span>
            <svg class="nav-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none"><path d="M1 1L5 5L9 1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </a>
          <div class="nav-dropdown">
${techniquesDropdownHtml}
          </div>
        </div>

        <div class="nav-link-item">
          <button class="nav-link nav-btn-about" id="desktop-about-btn" aria-haspopup="true" aria-expanded="false">
            <span>About Me</span>
            <svg class="nav-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none"><path d="M1 1L5 5L9 1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </button>
          <div class="nav-dropdown about-dropdown" id="desktop-about-dropdown">
            <div class="about-author-header">
              <div class="about-author-name">Chandra Kant Bauri</div>
              <div class="about-author-role">Security Researcher &amp; Reverse Engineer</div>
            </div>
            <div class="about-divider"></div>
            <a href="https://github.com/Lynk4" target="_blank" rel="noopener noreferrer" class="social-dropdown-link">
              <div class="social-left">
                <svg class="social-icon" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
                <div class="social-info">
                  <span class="social-name">GitHub</span>
                  <span class="social-handle">@Lynk4</span>
                </div>
              </div>
              <span class="social-ext-arrow">&#8599;</span>
            </a>
            <a href="https://www.linkedin.com/in/chandra-kant-bauri-b33114230/" target="_blank" rel="noopener noreferrer" class="social-dropdown-link">
              <div class="social-left">
                <svg class="social-icon" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>
                <div class="social-info">
                  <span class="social-name">LinkedIn</span>
                  <span class="social-handle">chandra-kant-bauri</span>
                </div>
              </div>
              <span class="social-ext-arrow">&#8599;</span>
            </a>
            <a href="https://x.com/c_kant_" target="_blank" rel="noopener noreferrer" class="social-dropdown-link">
              <div class="social-left">
                <svg class="social-icon" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
                <div class="social-info">
                  <span class="social-name">X (Twitter)</span>
                  <span class="social-handle">@c_kant_</span>
                </div>
              </div>
              <span class="social-ext-arrow">&#8599;</span>
            </a>
          </div>
        </div>
      </nav>

      <div class="right-nav-actions">
        <button class="nav-search-btn" id="nav-search-btn" title="Search investigations (⌘K or /)" aria-label="Search investigations">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          <span>Search</span>
          <kbd>⌘K</kbd>
        </button>
        <div class="mobile-about-wrapper">
          <button class="mobile-about-btn" id="mobile-about-btn" aria-label="About Me &amp; Social Links" title="About Chandra Kant Bauri">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
            <span>About</span>
          </button>
          <div class="nav-dropdown about-dropdown mobile-about-dropdown" id="mobile-about-dropdown">
            <div class="about-author-header">
              <div class="about-author-name">Chandra Kant Bauri</div>
              <div class="about-author-role">Security Researcher &amp; Reverse Engineer</div>
            </div>
            <div class="about-divider"></div>
            <a href="https://github.com/Lynk4" target="_blank" rel="noopener noreferrer" class="social-dropdown-link">
              <div class="social-left">
                <svg class="social-icon" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
                <div class="social-info">
                  <span class="social-name">GitHub</span>
                  <span class="social-handle">@Lynk4</span>
                </div>
              </div>
              <span class="social-ext-arrow">&#8599;</span>
            </a>
            <a href="https://www.linkedin.com/in/chandra-kant-bauri-b33114230/" target="_blank" rel="noopener noreferrer" class="social-dropdown-link">
              <div class="social-left">
                <svg class="social-icon" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>
                <div class="social-info">
                  <span class="social-name">LinkedIn</span>
                  <span class="social-handle">chandra-kant-bauri</span>
                </div>
              </div>
              <span class="social-ext-arrow">&#8599;</span>
            </a>
            <a href="https://x.com/c_kant_" target="_blank" rel="noopener noreferrer" class="social-dropdown-link">
              <div class="social-left">
                <svg class="social-icon" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
                <div class="social-info">
                  <span class="social-name">X (Twitter)</span>
                  <span class="social-handle">@c_kant_</span>
                </div>
              </div>
              <span class="social-ext-arrow">&#8599;</span>
            </a>
          </div>
        </div>
        <a href="#investigations" class="btn-explore-reports">
          <span>Explore Reports</span>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
        </a>
      </div>
    </div>
  </header>

  <!-- Hero Section -->
  <section class="hero-immersive-section">
    <div class="immersive-bg-wrapper">
      <picture class="immersive-bg-picture">
        <source srcset="assets/home/re-battlestation-2.webp" type="image/webp">
        <img src="assets/home/re-battlestation-2.jpg" alt="16:9 HD Malware Analysis Studio" class="immersive-bg-img" loading="eager" fetchpriority="high">
      </picture>
      <div class="immersive-gradient-mask"></div>
    </div>

    <canvas id="hero-sparks-canvas" class="hero-full-canvas"></canvas>

    <div class="immersive-container">
      <div class="cover-borderless-badge" aria-label="Break the Binary - Intelligence Beyond Indicators">
        <span class="hud-pulsing-dot" aria-hidden="true"></span>
        <span class="bb-lime">Break the Binary.</span>
        <span class="bb-slash" aria-hidden="true">//</span>
        <span class="bb-cyan">Intelligence Beyond Indicators.</span>
        <span class="bb-cursor" aria-hidden="true"></span>
      </div>

      <div class="immersive-content-box-borderless">
        <div class="cover-eyebrow">
          <span class="cover-eyebrow-dash" aria-hidden="true"></span>
          <span class="cover-eyebrow-text">INDEPENDENT THREAT RESEARCH</span>
        </div>

        <h1 class="cover-headline">
          Tracing the <span class="cover-hl-lime">unknown</span>
        </h1>

        <p class="cover-lead-text">
          Reverse engineering, malware dissection, and adversary tradecraft &mdash; documented through real static and dynamic technical investigations.
        </p>

        <div class="cover-cta-row">
          <a href="#investigations" class="btn-cover-explore">
            <span>Explore ${totalCount} Investigations</span>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
          </a>
        </div>

        <div class="hero-stats-row">
          <div class="stat-item clickable-stat" onclick="filterByCategory('all')" title="View all investigations">
            <div class="stat-num">${totalCount}</div>
            <div class="stat-label">Investigations</div>
            <div class="stat-sub">Technical reports</div>
          </div>
          <div class="stat-vdivider" aria-hidden="true"></div>
          <div class="stat-item">
            <div class="stat-num">4</div>
            <div class="stat-label">Platforms</div>
            <div class="stat-sub">Windows &bull; macOS &bull; Linux &bull; Cross-platform</div>
          </div>
          <div class="stat-vdivider" aria-hidden="true"></div>
          <div class="stat-item clickable-stat" onclick="filterByCategory('Reverse Engineering Techniques')" title="Filter by Reverse Engineering">
            <div class="stat-num">${catCounts['Reverse Engineering Techniques'] || 13}</div>
            <div class="stat-label">Reverse Engineering</div>
            <div class="stat-sub">In-depth studies</div>
          </div>
          <div class="stat-vdivider" aria-hidden="true"></div>
          <div class="stat-item clickable-stat" onclick="filterByCategory('Malware Family Analysis')" title="Filter by Malware Families">
            <div class="stat-num">${catCounts['Malware Family Analysis'] || 17}</div>
            <div class="stat-label">Malware Families</div>
            <div class="stat-sub">Analyzed and documented</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Optical Laser Conduit Scroll Cue (Zero Text, Zero Icons) -->
    <div class="hero-scroll-cue-wrapper">
      <a href="#investigations" class="opt-conduit" title="Explore research stream" aria-label="Scroll down to research investigations">
        <div class="cue-conduit-node" aria-hidden="true"></div>
        <div class="cue-conduit-track" aria-hidden="true">
          <div class="cue-conduit-beam"></div>
        </div>
      </a>
    </div>
  </section>

  <!-- Horizontal Section Divider -->
  <div class="section-hdivider">
    <div class="section-hdivider-line"></div>
  </div>

  <!-- Latest Investigations Section -->
  <section class="investigations-section" id="investigations">
    <div class="investigations-header">
      <div class="header-title-col">
        <div class="inv-eyebrow">
          <span class="inv-dash"></span>
          <span class="inv-eyebrow-text">RECENT RESEARCH</span>
        </div>
        <h2 class="inv-main-title">
          <span>Latest Investigations</span>
          <span class="inv-title-arrow" aria-hidden="true">&gt;</span>
        </h2>
      </div>

      <div class="header-controls-col">
        <div class="search-input-wrapper">
          <svg class="search-icon-svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          <input type="text" id="live-search" class="live-search-box" placeholder="Search reports, malware, IOCs..." autocomplete="off" spellcheck="false" aria-label="Search investigations">
          <span class="search-shortcut-badge" aria-hidden="true">&#8984; K</span>
          <button id="search-clear-btn" class="search-clear-btn" aria-label="Clear search">&times;</button>
        </div>

        <div class="platform-filter-group" role="tablist" aria-label="Filter by platform">
          <button class="filter-pill active" data-filter="all" role="tab" aria-selected="true">All (${counts.All})</button>
          <button class="filter-pill" data-filter="Windows" role="tab" aria-selected="false">Windows (${counts.Windows})</button>
          <button class="filter-pill" data-filter="macOS" role="tab" aria-selected="false">macOS (${counts.macOS})</button>
          <button class="filter-pill" data-filter="Linux" role="tab" aria-selected="false">Linux (${counts.Linux})</button>
          <button class="filter-pill" data-filter="Cross-Platform" role="tab" aria-selected="false">Cross-platform (${counts['Cross-Platform']})</button>
          <button class="filter-pill filter-pill-malops" data-filter="malops" role="tab" aria-selected="false">MalOps (${counts.MalOps})</button>
        </div>
      </div>
    </div>

    <!-- Active Filter Indicator -->
    <div id="active-filter-indicator" class="active-filter-indicator" style="display:none;">
      <span id="active-filter-label"></span>
      <button type="button" class="btn-clear-active-filter" onclick="resetFilters()" aria-label="Clear active filter">
        <span>Clear filter</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>

    <!-- Cards Stream Grid (Initial 9 Cards Static for Instant Paint & SEO) -->
    <div class="investigations-grid" id="investigations-grid">
      ${displayReports.slice(0, 9).map(r => renderPortalCardHtml(formatCardMeta(r))).join('\n')}

      <div id="empty-search-state" class="empty-search-state" style="display:none;">
        <h3>No matching investigations</h3>
        <p>No research reports match your search query or selected platform filter.</p>
        <button class="reset-btn" onclick="resetFilters()">Reset All Filters</button>
      </div>
    </div>

    <!-- Load More Container -->
    <div class="load-more-container" id="load-more-container"${displayReports.length <= 9 ? ' style="display:none;"' : ''}>
      <button type="button" id="btn-load-more" class="btn-load-more" aria-label="Load more threat research investigations">
        <span>Load More Investigations</span>
        <span class="btn-load-more-badge" id="load-more-badge">${Math.max(0, displayReports.length - 9)} remaining</span>
        <svg class="btn-load-more-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </button>
      <div class="load-more-status" id="load-more-status">Showing ${Math.min(9, displayReports.length)} of ${displayReports.length} investigations</div>
    </div>
  </section>

  <script>
    const searchInput = document.getElementById('live-search');
    const clearBtn = document.getElementById('search-clear-btn');
    const searchKbd = document.querySelector('.search-shortcut-badge');
    const filterPills = document.querySelectorAll('.filter-pill');
    const gridContainer = document.getElementById('investigations-grid');
    const emptyState = document.getElementById('empty-search-state');
    const loadMoreContainer = document.getElementById('load-more-container');
    const btnLoadMore = document.getElementById('btn-load-more');
    const loadMoreBadge = document.getElementById('load-more-badge');
    const loadMoreStatus = document.getElementById('load-more-status');

    const INITIAL_PAGE_SIZE = 9;
    const PAGE_STEP = 9;
    let visibleLimit = INITIAL_PAGE_SIZE;

    let currentFilter = 'all';
    let currentCategory = 'all';
    let searchQuery = '';

    let allCatalog = Array.isArray(window.__MARE_CATALOG__) ? window.__MARE_CATALOG__ : [];
    let isFetchingCatalog = false;
    let catalogCallbacks = [];

    function ensureCatalog(cb) {
      if (allCatalog.length > 0) {
        if (cb) cb();
        return;
      }
      if (cb) catalogCallbacks.push(cb);
      if (isFetchingCatalog) return;
      isFetchingCatalog = true;

      fetch('data/catalog.json')
        .then(function(res) { return res.json(); })
        .then(function(data) {
          isFetchingCatalog = false;
          if (Array.isArray(data)) {
            allCatalog = data;
            window.__MARE_CATALOG__ = data;
            if (catalogCallbacks.length > 0) {
              const cbs = catalogCallbacks.slice();
              catalogCallbacks = [];
              cbs.forEach(function(fn) { fn(); });
            } else {
              updateLoadMoreUI();
            }
          }
        })
        .catch(function() {
          isFetchingCatalog = false;
        });
    }

    if (typeof requestIdleCallback !== 'undefined') {
      requestIdleCallback(function() { ensureCatalog(); });
    } else {
      setTimeout(function() { ensureCatalog(); }, 80);
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function createCardElement(m) {
      const searchKeywords = (m.title + ' ' + m.subtitle + ' ' + m.category + ' ' + m.os + ' ' + (m.family || '') + ' ' + (m.targets || '') + ' ' + (m.delivery || '')).toLowerCase();
      const article = document.createElement('article');
      article.className = 'inv-card';
      article.setAttribute('data-os', m.os);
      article.setAttribute('data-category', m.category);
      article.setAttribute('data-source', m.source || '');
      article.setAttribute('data-search', searchKeywords);
      article.innerHTML = \`
        <a href="\${escapeHtml(m.id)}/index.html" class="card-banner" aria-label="\${escapeHtml(m.title)}">
          <span class="card-platform-badge \${escapeHtml(m.badgeClass)}">\${escapeHtml(m.badgeText)}</span>
          <img src="\${escapeHtml(m.cardImg)}" alt="\${escapeHtml(m.title)}" class="card-banner-img" loading="lazy">
        </a>
        <div class="card-content-body">
          <a href="\${escapeHtml(m.id)}/index.html" style="text-decoration:none; color:inherit;">
            <h3 class="card-title">\${escapeHtml(m.title)}</h3>
          </a>
          <p class="card-desc">\${escapeHtml(m.subtitle)}</p>
          <div class="card-footer">
            <div class="card-meta-left">
              <span class="meta-date">
                <svg class="meta-icon-svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                <span>\${escapeHtml(m.formattedDate || m.date)}</span>
              </span>
              <span class="meta-readtime">
                <svg class="meta-icon-svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                <span>\${escapeHtml(m.readTime || '14 min read')}</span>
              </span>
            </div>
            <a href="\${escapeHtml(m.id)}/index.html" class="card-arrow-btn" aria-label="Read \${escapeHtml(m.title)}">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
            </a>
          </div>
        </div>
      \`;
      return article;
    }

    function getMatchingReports() {
      const q = searchQuery.trim().toLowerCase();
      const tokens = q ? q.split(/\\s+/).filter(Boolean) : [];

      return allCatalog.filter(item => {
        let filterMatch = false;
        if (currentFilter === 'all') {
          filterMatch = true;
        } else if (currentFilter.toLowerCase() === 'malops') {
          filterMatch = ((item.source || '').toLowerCase() === 'malops');
        } else {
          filterMatch = ((item.os || '').toLowerCase() === currentFilter.toLowerCase());
        }
        if (!filterMatch) return false;

        if (currentCategory !== 'all' && (item.category || '').toLowerCase() !== currentCategory.toLowerCase()) {
          return false;
        }

        if (tokens.length > 0) {
          const haystack = (
            (item.title || '') + ' ' +
            (item.subtitle || '') + ' ' +
            (item.family || '') + ' ' +
            (item.os || '') + ' ' +
            (item.category || '') + ' ' +
            (item.hashVal || '') + ' ' +
            (item.c2 || '') + ' ' +
            (item.delivery || '') + ' ' +
            (item.targets || '')
          ).toLowerCase();
          return tokens.every(t => haystack.includes(t));
        }

        return true;
      });
    }

    function updateLoadMoreUI() {
      if (!loadMoreContainer) return;
      const matched = getMatchingReports();
      const sliceCount = Math.min(visibleLimit, matched.length);
      if (matched.length > sliceCount) {
        loadMoreContainer.style.display = 'flex';
        if (btnLoadMore) btnLoadMore.style.display = 'inline-flex';
        const remaining = matched.length - sliceCount;
        if (loadMoreBadge) loadMoreBadge.textContent = remaining + ' remaining';
        if (loadMoreStatus) loadMoreStatus.textContent = 'Showing ' + sliceCount + ' of ' + matched.length + ' investigations';
      } else if (matched.length > 0 && sliceCount > INITIAL_PAGE_SIZE) {
        loadMoreContainer.style.display = 'flex';
        if (btnLoadMore) btnLoadMore.style.display = 'none';
        if (loadMoreStatus) loadMoreStatus.textContent = 'All ' + matched.length + ' investigations loaded';
      } else {
        loadMoreContainer.style.display = 'none';
        if (btnLoadMore) btnLoadMore.style.display = 'inline-flex';
      }
    }

    function filterCards() {
      if (!allCatalog.length) {
        ensureCatalog(filterCards);
        return;
      }
      const matched = getMatchingReports();
      const q = searchQuery.trim();

      if (gridContainer) {
        gridContainer.querySelectorAll('.inv-card').forEach(c => c.remove());
        const sliceCount = Math.min(visibleLimit, matched.length);
        const toRender = matched.slice(0, sliceCount);
        const fragment = document.createDocumentFragment();
        toRender.forEach(item => {
          fragment.appendChild(createCardElement(item));
        });
        gridContainer.insertBefore(fragment, emptyState);
      }

      if (emptyState) {
        emptyState.style.display = (matched.length === 0) ? 'block' : 'none';
      }

      const activeFilterIndicator = document.getElementById('active-filter-indicator');
      const activeFilterLabel = document.getElementById('active-filter-label');
      if (activeFilterIndicator && activeFilterLabel) {
        if (currentCategory !== 'all') {
          activeFilterIndicator.style.display = 'inline-flex';
          activeFilterLabel.innerHTML = 'Category: <strong>' + escapeHtml(currentCategory) + '</strong> &bull; ' + matched.length + ' report' + (matched.length === 1 ? '' : 's');
        } else if (q) {
          activeFilterIndicator.style.display = 'inline-flex';
          activeFilterLabel.innerHTML = 'Search: &ldquo;<strong>' + escapeHtml(q) + '</strong>&rdquo; &bull; ' + matched.length + ' match' + (matched.length === 1 ? '' : 'es');
        } else {
          activeFilterIndicator.style.display = 'none';
        }
      }

      if (clearBtn && searchKbd) {
        if (q.length > 0) {
          clearBtn.style.display = 'block';
          searchKbd.style.display = 'none';
        } else {
          clearBtn.style.display = 'none';
          searchKbd.style.display = 'block';
        }
      }

      updateLoadMoreUI();
    }

    if (btnLoadMore) {
      btnLoadMore.addEventListener('click', () => {
        visibleLimit += PAGE_STEP;
        filterCards();
      });
    }

    function filterByCategory(catName) {
      currentCategory = catName;
      currentFilter = 'all';
      visibleLimit = INITIAL_PAGE_SIZE;
      filterPills.forEach(pill => {
        const isAll = (pill.getAttribute('data-filter') === 'all');
        pill.classList.toggle('active', isAll);
        pill.setAttribute('aria-selected', isAll ? 'true' : 'false');
      });
      filterCards();
      const invSec = document.getElementById('investigations');
      if (invSec) invSec.scrollIntoView({ behavior: 'smooth' });
    }

    function selectFilter(filterName) {
      currentFilter = filterName;
      currentCategory = 'all';
      visibleLimit = INITIAL_PAGE_SIZE;
      filterPills.forEach(pill => {
        const isActive = (pill.getAttribute('data-filter').toLowerCase() === filterName.toLowerCase());
        pill.classList.toggle('active', isActive);
        pill.setAttribute('aria-selected', isActive ? 'true' : 'false');
      });
      filterCards();
    }

    filterPills.forEach(pill => {
      pill.addEventListener('click', () => {
        selectFilter(pill.getAttribute('data-filter'));
      });
    });

    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value;
        visibleLimit = INITIAL_PAGE_SIZE;
        filterCards();
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        searchInput.value = '';
        searchQuery = '';
        visibleLimit = INITIAL_PAGE_SIZE;
        filterCards();
        searchInput.focus();
      });
    }

    function resetFilters() {
      if (searchInput) searchInput.value = '';
      searchQuery = '';
      currentCategory = 'all';
      visibleLimit = INITIAL_PAGE_SIZE;
      selectFilter('all');
    }

    // In-page live search escape listener
    if (searchInput) {
      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          searchInput.value = '';
          searchQuery = '';
          visibleLimit = INITIAL_PAGE_SIZE;
          filterCards();
          searchInput.blur();
        }
      });
    }

    if (searchKbd) {
      searchKbd.addEventListener('click', () => {
        if (typeof window.mareOpenSearch === 'function') {
          window.mareOpenSearch();
        }
      });
    }

    // About Me Dropdown click/toggle behavior
    const mobileAboutBtn = document.getElementById('mobile-about-btn');
    const mobileAboutDropdown = document.getElementById('mobile-about-dropdown');
    if (mobileAboutBtn && mobileAboutDropdown) {
      mobileAboutBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = mobileAboutDropdown.classList.toggle('open');
        mobileAboutBtn.classList.toggle('active', isOpen);
      });
    }

    const desktopAboutBtn = document.getElementById('desktop-about-btn');
    const desktopAboutDropdown = document.getElementById('desktop-about-dropdown');
    if (desktopAboutBtn && desktopAboutDropdown) {
      desktopAboutBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = desktopAboutDropdown.classList.toggle('open');
        desktopAboutBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      });
    }

    document.addEventListener('click', (e) => {
      if (mobileAboutDropdown && !mobileAboutDropdown.contains(e.target) && e.target !== mobileAboutBtn) {
        mobileAboutDropdown.classList.remove('open');
        if (mobileAboutBtn) mobileAboutBtn.classList.remove('active');
      }
      if (desktopAboutDropdown && !desktopAboutDropdown.contains(e.target) && e.target !== desktopAboutBtn) {
        desktopAboutDropdown.classList.remove('open');
        if (desktopAboutBtn) desktopAboutBtn.setAttribute('aria-expanded', 'false');
      }
    });

    // Support URL param e.g. ?platform=Linux or ?category=Malware+Family+Analysis
    let hasUrlFilter = false;
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const p = urlParams.get('platform');
      const c = urlParams.get('category');
      if (p) {
        selectFilter(p);
        hasUrlFilter = true;
      } else if (c) {
        filterByCategory(c);
        hasUrlFilter = true;
      }
    } catch (e) {}


    // Ambient neon sparks for upper hero body
    (function initAmbientSparks() {
      if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      const canvas = document.getElementById("hero-sparks-canvas");
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      let width, height;
      let particles = [];
      let isVisible = true;
      let animId = null;

      function resize() {
        const section = canvas.closest(".hero-immersive-section");
        if (!section) return;
        width = canvas.width = section.offsetWidth;
        height = canvas.height = section.offsetHeight;
      }

      class Spark {
        constructor() { this.reset(true); }
        reset(initial) {
          this.x = Math.random() * (width || 800);
          this.y = initial ? Math.random() * (height || 500) : (height || 500) + 10;
          this.vx = (Math.random() - 0.45) * 0.45;
          this.vy = -(Math.random() * 0.65 + 0.25);
          this.size = Math.random() * 1.8 + 0.6;
          this.alpha = Math.random() * 0.6 + 0.2;
          this.color = Math.random() > 0.4 ? "183, 255, 60" : "53, 229, 208";
        }
        update() {
          this.x += this.vx;
          this.y += this.vy;
          if (this.y < -10 || this.x < -10 || this.x > width + 10) {
            this.reset(false);
          }
        }
        draw() {
          ctx.fillStyle = "rgba(" + this.color + ", " + this.alpha + ")";
          ctx.beginPath();
          ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      function init() {
        resize();
        particles = [];
        const count = Math.min(36, Math.floor((width || 800) / 35));
        for (let i = 0; i < count; i++) {
          particles.push(new Spark());
        }
      }

      function loop() {
        if (!isVisible) return;
        ctx.clearRect(0, 0, width, height);
        for (let i = 0; i < particles.length; i++) {
          particles[i].update();
          particles[i].draw();
        }
        animId = requestAnimationFrame(loop);
      }

      window.addEventListener("resize", () => { resize(); });

      if ("IntersectionObserver" in window) {
        const observer = new IntersectionObserver((entries) => {
          entries.forEach(entry => {
            if (entry.isIntersecting) {
              if (!isVisible) {
                isVisible = true;
                loop();
              }
            } else {
              isVisible = false;
              if (animId) cancelAnimationFrame(animId);
            }
          });
        }, { threshold: 0.05 });

        const sec = canvas.closest(".hero-immersive-section");
        if (sec) observer.observe(sec);
      }

      init();
      loop();
    })();

    if (!hasUrlFilter) {
      filterCards();
    }
  </script>
  ${renderCommandPaletteModal()}
  <script>
${getCommandPaletteJs('')}
  </script>
</body>
</html>
`;

  fs.writeFileSync(path.join(REPORTS_DIR, 'index.html'), portalHtml, 'utf8');

  // Generate SEO-friendly XML Sitemap
  const siteUrl = 'https://lynk4.github.io/mare';
  const sitemapUrls = [
    `  <url>\n    <loc>${siteUrl}/</loc>\n    <changefreq>daily</changefreq>\n    <priority>1.0</priority>\n  </url>`,
    ...allReports.map(r => {
      let isoDate = new Date().toISOString().split('T')[0];
      try {
        const d = new Date(r.date);
        if (!isNaN(d.getTime())) isoDate = d.toISOString().split('T')[0];
      } catch (e) {}
      return `  <url>\n    <loc>${siteUrl}/${r.id}/index.html</loc>\n    <lastmod>${isoDate}</lastmod>\n    <changefreq>monthly</changefreq>\n    <priority>0.8</priority>\n  </url>`;
    })
  ];
  const sitemapXml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${sitemapUrls.join('\n')}\n</urlset>\n`;
  fs.writeFileSync(path.join(REPORTS_DIR, 'sitemap.xml'), sitemapXml, 'utf8');

  // Generate Autonomous RSS 2.0 Feed for threat researchers and aggregators
  const rssItems = allReports.slice(0, 30).map(r => {
    let pubDate = new Date().toUTCString();
    try {
      const d = new Date(r.date);
      if (!isNaN(d.getTime())) pubDate = d.toUTCString();
    } catch (e) {}
    return `    <item>
      <title>${escapeHtml(r.title)}</title>
      <link>${siteUrl}/${r.id}/index.html</link>
      <guid>${siteUrl}/${r.id}/index.html</guid>
      <pubDate>${pubDate}</pubDate>
      <description>${escapeHtml(r.lead || r.subtitle || '')}</description>
      <category>${escapeHtml(r.category)}</category>
    </item>`;
  }).join('\n');

  const rssFeed = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>MARE — Malware Analysis &amp; Reverse Engineering</title>
    <link>${siteUrl}/</link>
    <description>Publication-grade threat intelligence and binary dissection portal.</description>
    <language>en-us</language>
    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
    <atom:link href="${siteUrl}/feed.xml" rel="self" type="application/rss+xml"/>
${rssItems}
  </channel>
</rss>\n`;
  fs.writeFileSync(path.join(REPORTS_DIR, 'feed.xml'), rssFeed, 'utf8');
}


// 4. MAIN BUILD PROCESS
console.log('=== Building 100% Autonomous Threat Research Portal ===');
const allReports = discoverReports();
allReports.sort((a, b) => {
  const diff = new Date(b.date).getTime() - new Date(a.date).getTime();
  if (diff !== 0) return diff;
  return a.title.localeCompare(b.title);
});
console.log(`Discovered ${allReports.length} reports dynamically across folders.`);

const platformStats = {};
allReports.forEach(r => {
  platformStats[r.os] = (platformStats[r.os] || 0) + 1;
});
console.log('Platform Breakdown:', platformStats);

copyGlobalAssets();
const buildCache = loadBuildCache();
let builtCount = 0;
let cachedCount = 0;

allReports.forEach(r => {
  const sourceHash = computeReportSourceHash(r);
  const reportHtml = path.join(REPORTS_DIR, r.id, 'index.html');
  const cachedEntry = buildCache[r.id];

  if (cachedEntry && cachedEntry.sourceHash === sourceHash && fs.existsSync(reportHtml)) {
    if (!r.firstImage && cachedEntry.firstImage) {
      r.firstImage = cachedEntry.firstImage;
    }
    cachedCount++;
  } else {
    buildReportPage(r);
    buildCache[r.id] = {
      sourceHash,
      firstImage: r.firstImage || null,
      updatedAt: new Date().toISOString()
    };
    builtCount++;
  }
});

generateCatalogData(allReports);
console.log('Catalog Index: generated reports/data/catalog.json and reports/data/catalog.js');

saveBuildCache(buildCache);
console.log(`Compilation: ${builtCount} built, ${cachedCount} unchanged (cached).`);

buildPortalIndex(allReports);
console.log('=== Build complete! All reports self-contained and live in reports/ ===');
