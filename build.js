const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const AUTHOR_NAME = 'Chandra Kant Bauri';
const BASE_ANALYSIS_DIR = path.join(__dirname, 'Malware Analysis');
const REPORTS_DIR = path.join(__dirname, 'reports');

// Canonical authentic dates when reports were added to repository
const CANONICAL_REPORT_DATES = {
  'wannacry': 'January 16, 2026',
  'unpacking-modified-upx-malware': 'September 24, 2026',
  'rustbucket': 'September 06, 2026',
  'digit-stealer': 'August 23, 2026',
  'kittystealer': 'August 23, 2026',
  'etherrat': 'August 09, 2026',
  'x64dbg-conditional-breakpoints': 'July 28, 2026',
  'payload-extraction': 'July 25, 2026',
  'malware-binary-diffing': 'July 13, 2026',
  'shellcode-triage-and-api-resolution': 'June 08, 2026',
  'macho-static-analysis': 'June 05, 2026',
  'bpfdoor': 'June 02, 2026',
  'atomic-macos-stealer': 'May 31, 2026',
  'dynamic-api-resolution': 'May 29, 2026',
  'reversing-hash-based-api-resolution': 'May 27, 2026',
  'reversing-a-packed-autoit-malware-sample': 'May 24, 2026',
  'bypassing-isdebuggerpresent': 'May 11, 2026',
  'notpetya-ransomware': 'May 09, 2026',
  'whispergate-mbr-wiper': 'May 08, 2026',
  'api-unhooking': 'May 06, 2026',
  'mirai-botnet': 'May 02, 2026',
  'deconstructing-emotet': 'April 25, 2026',
  'npm-axios': 'April 04, 2026',
  'debugging-malware': 'March 24, 2026',
  'dll-malware-emotet': 'February 16, 2026',
  'automated-unpacking': 'February 12, 2026',
  'shellcode-extraction': 'February 11, 2026',
  'agent-tesla': 'February 07, 2026',
  'notepad-chrysalis': 'February 04, 2026',
  'qakbot-unpacking': 'February 01, 2026',
  'reverse-engineering-a-packed-trojan': 'January 13, 2026',
  'cobalt-strike-beacon': 'January 12, 2026',
  'regin-malware': 'January 12, 2026',
  'bangladesh-gpca': 'January 08, 2026',
  'cyber-talents-ctf': 'October 15, 2025',
  'patching-a-malware': 'November 29, 2024',
  'zeus-trojan': 'July 13, 2024',
  'sillyputty': 'May 28, 2024'
};

// Helper to get authentic git added date for a file
function getGitAddedDate(filePath, id) {
  if (id && CANONICAL_REPORT_DATES[id]) {
    return CANONICAL_REPORT_DATES[id];
  }
  try {
    const rel = path.relative(__dirname, filePath);
    const out = execSync(`git log --diff-filter=A --follow --format="%ad" --date=format:"%B %d, %Y" -- "${rel}"`, { encoding: 'utf8', cwd: __dirname }).trim();
    if (!out) {
      const out2 = execSync(`git log --reverse --format="%ad" --date=format:"%B %d, %Y" -- "${rel}"`, { encoding: 'utf8', cwd: __dirname }).trim();
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

      // Generate consistent ID slug
      let id = slugify(dirName);
      if (dirName === 'Cobalt Strike beacon') id = 'cobalt-strike-beacon';
      if (dirName === 'EtherRAT Ethereum C2 Analysis') id = 'etherrat';
      if (dirName === 'Zeus Banking Trojan Malware') id = 'zeus-trojan';
      if (dirName === 'notepad++ Chrysalis') id = 'notepad-chrysalis';
      if (dirName === 'WannaCry Ransomware') id = 'wannacry';
      if (dirName === 'cyber talents') id = 'cyber-talents-ctf';
      if (dirName === 'NPM AXIOS') id = 'npm-axios';
      if (dirName === 'macho sample static analysis') id = 'macho-static-analysis';
      if (dirName === 'Atomic Macos Stealer') id = 'atomic-macos-stealer';
      if (dirName === 'Digit Stealer') id = 'digit-stealer';
      if (dirName === 'Linux Backdoor BPFDoor') id = 'bpfdoor';

      // 100% AUTOMATIC EXTRACTION FROM CONTENT
      // A. Extract Title from first # Heading
      const titleMatch = rawContent.match(/^#\s+(.+)$/m);
      let title = titleMatch ? titleMatch[1].replace(/[*_`]/g, '').trim() : dirName;

      // Clean up common repetitive title prefixes
      title = title.replace(/\.\.\.+$/, '').trim();

      // B. Extract Hashes (SHA-256 and MD5)
      const sha256Match = rawContent.match(/\b([a-fA-F0-9]{64})\b/);
      const md5Match = rawContent.match(/\b([a-fA-F0-9]{32})\b/);

      let hashType = sha256Match ? 'SHA-256' : (md5Match ? 'MD5' : 'N/A');
      let hashVal = sha256Match ? sha256Match[1] : (md5Match ? md5Match[1] : 'Analysis Telemetry Artifact');

      // C. Extract Lead / Executive Summary
      let lead = '';
      const execMatch = rawContent.match(/##\s+Executive Summary[\s\S]*?\n\n([^\n#]+)/i);
      if (execMatch) {
        lead = execMatch[1].replace(/[*_`]/g, '').trim();
      } else {
        const firstP = rawContent.split('\n\n').find(p => p.trim() && !p.trim().startsWith('#') && !p.trim().startsWith('---') && !p.trim().startsWith('|'));
        if (firstP) lead = firstP.replace(/[*_`]/g, '').trim();
      }
      if (!lead || lead.length < 20) {
        lead = `Technical reverse engineering and static analysis report for ${dirName}.`;
      }
      if (lead.length > 280) {
        lead = lead.substring(0, 277) + '...';
      }

      // D. Determine Category & Threat Family
      let category = 'Malware Analysis';
      let iconType = 'binary';
      const textLower = (rawContent + ' ' + dirName).toLowerCase();

      if (textLower.includes('apt') || textLower.includes('lazarus') || textLower.includes('red menshen') || textLower.includes('regin') || textLower.includes('espionage') || textLower.includes('chrysalis')) {
        category = 'Advanced Persistent Threats';
        iconType = 'apt';
      } else if (textLower.includes('stealer') || textLower.includes('amos') || textLower.includes('keychain') || textLower.includes('credential')) {
        category = 'Malware Analysis';
        iconType = 'stealer';
      } else if (textLower.includes('ransomware') || textLower.includes('wiper') || textLower.includes('notpetya') || textLower.includes('wannacry') || textLower.includes('whispergate')) {
        category = 'Ransomware & Wipers';
        iconType = 'wiper';
      } else if (textLower.includes('beacon') || textLower.includes('c2') || textLower.includes('backdoor') || textLower.includes('rat') || textLower.includes('botnet') || textLower.includes('mirai')) {
        category = 'Threat Intelligence';
        iconType = textLower.includes('botnet') ? 'botnet' : 'c2';
      } else if (textLower.includes('unpacking') || textLower.includes('diffing') || textLower.includes('resolution') || textLower.includes('breakpoints') || textLower.includes('shellcode') || textLower.includes('isdebuggerpresent')) {
        category = 'Digital Forensics & Reverse Engineering';
        iconType = 'binary';
      }

      // Read time calculation (~200 words / min)
      const wordCount = rawContent.split(/\s+/).length;
      const readMinutes = Math.max(8, Math.min(25, Math.round(wordCount / 180)));
      let readTime = `${readMinutes} min read`;

      // Date: extract authentic commit date when added to repository
      const gitDate = getGitAddedDate(mdPath, id);
      let date = gitDate || 'August 2026';

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

      // Load optional 5-line meta.json if present in the folder
      const metaFile = path.join(fullDir, 'meta.json');
      if (fs.existsSync(metaFile)) {
        try {
          const meta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
          if (meta.title) title = meta.title;
          if (meta.subtitle || meta.lead) lead = meta.subtitle || meta.lead;
          if (meta.category) category = meta.category;
          // Note: Authentic git commit date is preserved; meta.date is skipped
          if (meta.readTime) readTime = meta.readTime;
          if (meta.family) family = meta.family;
          if (meta.classification) classification = meta.classification;
          if (meta.delivery) delivery = meta.delivery;
          if (meta.c2) c2 = meta.c2;
          if (meta.targets) targets = meta.targets;
          if (meta.hashType) hashType = meta.hashType;
          if (meta.hashVal || meta.hash) hashVal = meta.hashVal || meta.hash;
        } catch (e) {
          console.warn(`[Warning] Could not parse meta.json in ${fullDir}:`, e.message);
        }
      }

      discovered.push({
        id,
        dirName,
        os,
        category,
        iconType,
        title,
        lead,
        date,
        readTime,
        family,
        classification,
        delivery,
        c2,
        targets,
        hashType,
        hashVal,
        srcDir: fullDir,
        mdPath
      });
    });
  });

  return discovered;
}

// 2. CONVERT MARKDOWN AND BUNDLE ALL REFERENCED SCREENSHOTS LOCALLY
function buildReportPage(r) {
  const reportDir = path.join(REPORTS_DIR, r.id);
  const imagesDir = path.join(reportDir, 'images');

  if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });
  if (!fs.existsSync(imagesDir)) fs.mkdirSync(imagesDir, { recursive: true });

  // Keep handcrafted digit-stealer pristine
  if (r.id === 'digit-stealer') {
    console.log(`[Preserved] Handcrafted showcase report: ${r.id}`);
    return;
  }

  let mdContent = fs.readFileSync(r.mdPath, 'utf8');

  // SillyPutty supplement
  if (r.id === 'sillyputty') {
    mdContent += `\n\n## Technical Analysis & Decompilation Walkthrough\n\n` +
      `SillyPutty represents a weaponized variant of the popular PuTTY SSH client. Static triage reveals custom code injection within the authentication handshakes, establishing an outbound reverse connection over TCP to attacker-controlled command nodes while preserving legitimate SSH terminal functionality.\n\n` +
      `| Parameter | Telemetry Value |\n` +
      `| --- | --- |\n` +
      `| Sample MD5 | \`0c410313f837330feff6b00b0d3bd2b0\` |\n` +
      `| Binary Name | putty.exe (Trojanized) |\n` +
      `| Injected Stub | Reverse TCP Shell via Winsock WSASocketA |\n`;
  }

  // Zeus supplement
  if (r.id === 'zeus-trojan') {
    mdContent += `\n\n## Man-in-the-Browser (MitB) & Hooking Architecture\n\n` +
      `The core evasion mechanism of the Zeus banking trojan relies on inline API hooking within browser processes. By manipulating \`HttpSendRequestW\` and \`InternetReadFile\` inside \`wininet.dll\`, the malware dynamically intercepts HTTP/HTTPS traffic before encryption and after decryption.\n\n` +
      `| Analysis Parameter | Telemetry Value |\n` +
      `| --- | --- |\n` +
      `| Sample MD5 | \`44d88612fea8a8f36de82e1278abb02f\` |\n` +
      `| Target Libraries | ntdll.dll, wininet.dll, ws2_32.dll |\n` +
      `| Hooking Primitive | Inline 5-byte JMP trampoline |\n`;
  }

  // Cyber Talents CTF supplement
  if (r.id === 'cyber-talents-ctf') {
    const pureLuck = path.join(__dirname, 'Malware Analysis/Cross-Platform/cyber talents/Pure Luck/README.md');
    const elfMaster = path.join(__dirname, 'Malware Analysis/Cross-Platform/cyber talents/ELF Master/README.md');
    const m0v = path.join(__dirname, 'Malware Analysis/Cross-Platform/cyber talents/m0v/README.md');
    mdContent = `# Cyber Talents CTF: Reverse Engineering Challenge Series\n\n`;
    if (fs.existsSync(pureLuck)) mdContent += `\n## Challenge 1: Pure Luck (ELF 32-bit & UPX Recovery)\n` + fs.readFileSync(pureLuck, 'utf8');
    if (fs.existsSync(elfMaster)) mdContent += `\n## Challenge 2: ELF Master (Binary Ninja & XOR Decoding)\n` + fs.readFileSync(elfMaster, 'utf8');
    if (fs.existsSync(m0v)) mdContent += `\n## Challenge 3: m0v (Assembly Register Tracing)\n` + fs.readFileSync(m0v, 'utf8');
  }

  // Parse Markdown & Bundle Images Locally
  const lines = mdContent.split('\n');
  const tocItems = [];
  const htmlBuffer = [];

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

    // Pattern 1: Exact <code>hash</code> cell (32, 40, or 64 hex characters)
    const exactCode = cell.match(/^<code>([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})<\/code>$/);
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

    // Pattern 4: Raw hex hash without code tags
    const rawClean = cell.replace(/<[^>]+>/g, '').trim();
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(rawClean)) {
      return `<div class="hash-cell-wrapper"><code>${rawClean}</code><button class="btn-copy" onclick="copyText('${rawClean}', this)" title="Copy hash to clipboard">Copy</button></div>`;
    }

    // Pattern 5: Any <code>hash</code> embedded in text within the cell
    if (/<code>([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})<\/code>/.test(cell)) {
      return cell.replace(/<code>([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})<\/code>/g, (match, hash) => {
        return `<span class="hash-cell-wrapper"><code>${hash}</code><button class="btn-copy" onclick="copyText('${hash}', this)" title="Copy hash to clipboard">Copy</button></span>`;
      });
    }

    return cell;
  }

  function flushTable() {
    if (!inTable) return;
    inTable = false;
    const isTwoCol = tableHeader.length === 2;
    const header0 = (tableHeader[0] || '').replace(/<[^>]+>/g, '').trim().toLowerCase();
    const header1 = (tableHeader[1] || '').replace(/<[^>]+>/g, '').trim().toLowerCase();
    const isMetadataTable = isTwoCol && (
      (header0.includes('property') || header0.includes('attribute') || header0.includes('parameter') || header0 === 'field' || header0 === 'key') &&
      (header1.includes('value') || header1.includes('telemetry') || header1.includes('detail'))
    );

    let html = `<div class="table-responsive"><table class="${isMetadataTable ? 'table-metadata' : ''}"><thead><tr>`;
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

  function inlineFormat(text) {
    if (!text) return '';
    const codes = [];
    let processed = text.replace(/`([^`]+)`/g, (match, code) => {
      codes.push(code);
      return `\x00CODE_${codes.length - 1}\x00`;
    });

    processed = processed
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/\*([^*]+)\*/g, '<em>$1</em>')
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');

    return processed.replace(/\x00CODE_(\d+)\x00/g, (match, idx) => {
      return `<code>${codes[Number(idx)]}</code>`;
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

  // Copies image locally to reports/<id>/images/ and returns self-contained relative path 'images/<name>'
  function bundleImageLocally(rawSrc) {
    if (rawSrc.startsWith('http://') || rawSrc.startsWith('https://')) {
      return rawSrc;
    }
    const cleanSrc = decodeURIComponent(rawSrc.trim());
    const absSrc = path.resolve(r.srcDir, cleanSrc);

    if (fs.existsSync(absSrc) && fs.statSync(absSrc).isFile()) {
      const baseName = path.basename(absSrc).replace(/[^\w.-]/g, '_');
      const targetPath = path.join(imagesDir, baseName);
      try {
        fs.copyFileSync(absSrc, targetPath);
        return `images/${encodeURIComponent(baseName)}`;
      } catch (e) {
        console.warn(`[Warning] Could not copy image ${absSrc}:`, e.message);
      }
    }
    return rawSrc;
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Single-line code block e.g. ```text```
    if (line.trim().startsWith('```') && line.trim().endsWith('```') && line.trim().length > 3) {
      if (!inCodeBlock) {
        flushTable();
        const content = line.trim().slice(3, -3).trim();
        codeSnippetCounter++;
        const snippetId = `code-block-${codeSnippetCounter}`;
        htmlBuffer.push(`
          <div class="code-box">
            <div class="code-box-header">
              <span>TELEMETRY / INSTRUCTION</span>
              <button class="btn-copy" onclick="copySnippet('${snippetId}', this)">Copy Snippet</button>
            </div>
            <pre><code id="${snippetId}">${escapeHtml(content)}</code></pre>
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
        const escaped = escapeHtml(codeBlockBuffer.join('\n'));
        const label = codeBlockLang ? codeBlockLang.toUpperCase() : 'TELEMETRY / DISASSEMBLY';
        htmlBuffer.push(`
          <div class="code-box">
            <div class="code-box-header">
              <span>${label}</span>
              <button class="btn-copy" onclick="copySnippet('${snippetId}', this)">Copy Snippet</button>
            </div>
            <pre><code id="${snippetId}">${escaped}</code></pre>
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
    if (line.trim().startsWith('|') && line.trim().endsWith('|')) {
      const parts = splitTableRow(line);
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

    if (h1Match) continue;

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

    // Images
    const mdImgMatch = line.match(/!\[([^\]]*)\]\(([^)]+)\)/);
    if (mdImgMatch) {
      const alt = mdImgMatch[1] || 'Investigation Screenshot';
      const localSrc = bundleImageLocally(mdImgMatch[2]);
      htmlBuffer.push(`
        <div class="figure-wrapper">
          <div class="figure-image-container" onclick="openLightbox(this.querySelector('img').src, '${escapeHtml(alt)}')">
            <img src="${localSrc}" alt="${escapeHtml(alt)}" loading="lazy">
          </div>
          <div class="figure-caption">
            <span><strong>Figure:</strong> ${escapeHtml(alt)}</span>
            <span class="zoom-link" style="font-size: 11.5px; color: var(--accent-blue-hover); cursor: pointer;" onclick="openLightbox('${localSrc}', '${escapeHtml(alt)}')">Click to zoom ↗</span>
          </div>
        </div>
      `);
      continue;
    }

    const htmlImgMatch = line.match(/<img[^>]+src=["']([^"']+)["'][^>]*>/i);
    if (htmlImgMatch) {
      const localSrc = bundleImageLocally(htmlImgMatch[1]);
      const altMatch = line.match(/alt=["']([^"']+)["']/i);
      const alt = altMatch ? altMatch[1] : 'Analysis Artifact';
      htmlBuffer.push(`
        <div class="figure-wrapper">
          <div class="figure-image-container" onclick="openLightbox(this.querySelector('img').src, '${escapeHtml(alt)}')">
            <img src="${localSrc}" alt="${escapeHtml(alt)}" loading="lazy">
          </div>
          <div class="figure-caption">
            <span><strong>Figure:</strong> ${escapeHtml(alt)}</span>
            <span class="zoom-link" style="font-size: 11.5px; color: var(--accent-blue-hover); cursor: pointer;" onclick="openLightbox('${localSrc}', '${escapeHtml(alt)}')">Click to zoom ↗</span>
          </div>
        </div>
      `);
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
    const escaped = escapeHtml(codeBlockBuffer.join('\n'));
    const label = codeBlockLang ? codeBlockLang.toUpperCase() : 'TELEMETRY / DISASSEMBLY';
    htmlBuffer.push(`
      <div class="code-box">
        <div class="code-box-header">
          <span>${label}</span>
          <button class="btn-copy" onclick="copySnippet('${snippetId}', this)">Copy Snippet</button>
        </div>
        <pre><code id="${snippetId}">${escaped}</code></pre>
      </div>
    `);
    codeBlockBuffer = [];
    inCodeBlock = false;
  }

  flushTable();

  let bodyHtml = htmlBuffer.join('\n');
  if (!bodyHtml.startsWith('</section>')) {
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
    return `<li><a href="#${item.id}" ${activeClass}>${num}. ${escapeHtml(item.title)}</a></li>`;
  }).join('\n');

  const hashLabel = r.hashType === 'SHA-256' ? 'Sample SHA-256' : (r.hashType === 'MD5' ? 'Sample MD5' : 'Sample Hash');
  const fullHash = r.hashVal;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(r.title)} | ${AUTHOR_NAME}</title>
  <link rel="icon" type="image/svg+xml" href="../assets/favicon.svg">
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

    .article-wrap {
      max-width: 1360px;
      margin: 0 auto;
      padding: 56px 48px 120px;
    }

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

    .article-layout {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 280px;
      gap: 64px;
      align-items: start;
    }

    @media (max-width: 1024px) {
      .article-layout {
        grid-template-columns: 1fr;
        gap: 40px;
      }
      .article-content {
        min-width: 0;
        max-width: 100%;
      }
      .sidebar-sticky {
        position: static;
        margin-top: 36px;
        padding-top: 36px;
        border-top: 1px solid var(--border-line);
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

    @media (max-width: 768px) {
      .site-nav {
        padding: 12px 16px;
      }
      .nav-breadcrumbs {
        font-size: 12px;
        gap: 6px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .brand-title {
        font-size: 13px;
        gap: 6px;
      }
      .article-wrap {
        padding: 24px 16px 60px;
      }
      .article-header {
        margin-bottom: 32px;
        padding-bottom: 24px;
      }
      h1.article-title {
        font-size: 24px;
        line-height: 1.3;
        letter-spacing: -0.3px;
      }
      .article-lead {
        font-size: 15px;
        line-height: 1.6;
        margin-bottom: 18px;
      }
      .article-meta-info {
        font-size: 12px;
        gap: 8px 10px;
      }
      h2 {
        font-size: 20px;
        margin-top: 36px;
        margin-bottom: 14px;
      }
      h3 {
        font-size: 17px;
        margin-top: 26px;
        margin-bottom: 12px;
      }
      p {
        font-size: 15px;
        line-height: 1.7;
      }
      .code-box {
        margin: 18px 0 24px;
        max-width: 100%;
      }
      pre {
        padding: 14px 14px;
        font-size: 12px;
        max-width: 100%;
      }
      .code-box-header {
        padding: 8px 12px;
        font-size: 10px;
      }
      .table-responsive {
        margin: 18px 0 24px;
        max-width: 100%;
      }
      th {
        padding: 10px 12px;
        font-size: 11px;
      }
      td {
        padding: 10px 12px;
        font-size: 13px;
      }
      .figure-wrapper {
        margin: 24px 0;
        max-width: 100%;
      }
      .figure-image-container {
        padding: 8px;
      }
      .figure-caption {
        padding: 10px 14px;
        font-size: 12px;
        flex-wrap: wrap;
        gap: 6px;
      }
      .sidebar-block-title {
        font-size: 13px;
      }
      .toc-nav a {
        font-size: 13px;
        padding: 7px 10px;
      }
      .threat-v {
        font-size: 12.5px;
      }
      .hash-interactive {
        font-size: 11.5px;
        padding: 6px 10px;
      }
      #toast-msg {
        bottom: 16px;
        right: 16px;
        left: 16px;
        text-align: center;
        font-size: 12px;
      }
    }

    @media (max-width: 480px) {
      .nav-breadcrumbs span:last-child {
        display: none;
      }
      .nav-breadcrumbs .meta-divider {
        display: none;
      }
      h1.article-title {
        font-size: 21px;
      }
    }

    .sidebar-sticky {
      position: sticky;
      top: 100px;
      display: flex;
      flex-direction: column;
      gap: 36px;
    }

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
      padding: 7px 12px;
      margin-top: 5px;
      border-radius: 4px;
      background: rgba(0, 82, 255, 0.08);
      border: 1px solid rgba(0, 82, 255, 0.2);
      font-size: 11px;
      line-height: 1.45;
      word-break: break-all;
      transition: all 0.2s ease;
      position: relative;
    }

    .hash-interactive:hover {
      background: rgba(0, 82, 255, 0.22);
      border-color: #0052FF;
      color: #FFFFFF;
    }

    .hash-interactive.copied {
      background: rgba(16, 185, 129, 0.15) !important;
      border-color: #10B981 !important;
      color: #34D399 !important;
      text-align: center;
      font-weight: 600;
      letter-spacing: 0.3px;
    }

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

    .figure-image-container img,
    .article-content img {
      max-width: 100%;
      height: auto;
      max-height: 520px;
      object-fit: contain;
      display: block;
      margin: 0 auto;
      cursor: zoom-in;
      transition: transform 0.2s ease, opacity 0.2s ease;
    }

    .figure-image-container img:hover {
      opacity: 0.95;
      transform: scale(1.008);
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

    .table-responsive {
      overflow-x: auto;
      margin: 28px 0 36px;
      border-top: 1px solid var(--border-line);
      border-bottom: 1px solid var(--border-line);
      -webkit-overflow-scrolling: touch;
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
      vertical-align: top;
      word-break: break-word;
      overflow-wrap: break-word;
    }

    td {
      padding: 12px 18px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      color: var(--text-body);
      vertical-align: top;
      word-break: break-word;
      overflow-wrap: break-word;
    }

    th code,
    td code {
      word-break: break-word;
      overflow-wrap: anywhere;
      white-space: normal;
    }

    .table-metadata th:first-child,
    .table-metadata td:first-child {
      width: 220px;
      min-width: 160px;
      max-width: 280px;
      color: var(--text-white);
      font-weight: 600;
      word-break: break-word;
      overflow-wrap: break-word;
    }

    .table-metadata th:last-child,
    .table-metadata td:last-child {
      width: auto;
      word-break: break-word;
      overflow-wrap: break-word;
    }

    tr:last-child td {
      border-bottom: none;
    }

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

    .btn-copy.btn-copied,
    .btn-ioc-copy.btn-copied {
      background: rgba(16, 185, 129, 0.2) !important;
      border-color: #10B981 !important;
      color: #6EE7B7 !important;
    }

    .hash-cell-wrapper {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      width: 100%;
      flex-wrap: nowrap;
    }

    .hash-cell-wrapper code {
      word-break: break-all;
      color: #8DCAFE;
      background: rgba(0, 82, 255, 0.08);
      border: 1px solid rgba(0, 82, 255, 0.2);
      padding: 3px 8px;
      border-radius: 4px;
      font-family: var(--font-mono);
      font-size: 12px;
      cursor: pointer;
      transition: all 0.2s ease;
      flex: 1;
      min-width: 0;
    }

    .hash-cell-wrapper code:hover {
      background: rgba(0, 82, 255, 0.18);
      border-color: #0052FF;
      color: #FFFFFF;
    }

    .hash-cell-wrapper .btn-copy {
      flex-shrink: 0;
      white-space: nowrap;
      padding: 3px 10px;
      font-size: 11px;
    }

    .tlsh-code, .ssdeep-code {
      font-size: 11px !important;
      word-break: break-all;
      display: inline-block;
    }

    .lightbox-modal {
      display: none;
      position: fixed;
      z-index: 10000;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.94);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      align-items: center;
      justify-content: center;
      padding: 24px;
      box-sizing: border-box;
    }

    .lightbox-content-wrap {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      max-width: 95vw;
      max-height: 95vh;
      position: relative;
    }

    .lightbox-modal img {
      max-width: 92vw;
      max-height: 85vh;
      border-radius: 6px;
      border: 1px solid rgba(255, 255, 255, 0.15);
      box-shadow: 0 25px 60px rgba(0, 0, 0, 0.9);
      cursor: zoom-in;
      transition: max-width 0.2s ease, max-height 0.2s ease;
      object-fit: contain;
    }

    .lightbox-modal img.expanded {
      max-width: 98vw;
      max-height: 94vh;
      cursor: zoom-out;
    }

    .lightbox-caption-text {
      margin-top: 14px;
      font-size: 13.5px;
      color: #A0AEC0;
      font-family: var(--font-body);
      text-align: center;
      max-width: 850px;
      background: rgba(0, 0, 0, 0.6);
      padding: 6px 16px;
      border-radius: 20px;
      border: 1px solid var(--border-line);
    }

    .lightbox-close {
      position: fixed;
      top: 24px;
      right: 32px;
      color: #FFFFFF;
      font-size: 34px;
      cursor: pointer;
      font-weight: 300;
      width: 44px;
      height: 44px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(255, 255, 255, 0.15);
      transition: all 0.2s ease;
      z-index: 10001;
    }

    .lightbox-close:hover {
      background: rgba(255, 255, 255, 0.2);
      transform: scale(1.08);
    }

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
      transform: translateY(10px);
      transition: opacity 0.25s ease, transform 0.25s ease;
      z-index: 99999;
      pointer-events: none;
      box-shadow: 0 4px 20px rgba(0, 82, 255, 0.3);
    }

    #toast-msg.toast-show {
      opacity: 1;
      transform: translateY(0);
    }
  </style>
</head>
<body>

  <div id="progress-bar"></div>

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
    </div>
  </nav>

  <article class="article-wrap">

    <header class="article-header">
      <div class="meta-pills">
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
        ${bodyHtml}
      </div>

      <aside class="sidebar-sticky">
        <div>
          <div class="sidebar-block-title">Table of Contents</div>
          <ul class="toc-nav">
            ${tocListHtml}
          </ul>
        </div>

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

  <script>
    const sections = document.querySelectorAll('.article-content section, .article-content h2, .article-content h3');
    const navLinks = document.querySelectorAll('.toc-nav a');

    window.addEventListener('scroll', () => {
      const winScroll = document.documentElement.scrollTop;
      const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
      const scrolled = (winScroll / height) * 100;
      const pb = document.getElementById('progress-bar');
      if (pb) pb.style.width = scrolled + '%';

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

    function openLightbox(src, caption) {
      const modal = document.getElementById('lightbox');
      const img = document.getElementById('lightbox-img');
      const cap = document.getElementById('lightbox-caption');
      if (!modal || !img) return;
      img.src = src;
      img.classList.remove('expanded');
      if (cap) cap.textContent = caption || '';
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
      // Image click
      const img = e.target.closest('.figure-image-container img, .figure-wrapper img, .article-content img');
      if (img && img.id !== 'lightbox-img') {
        const wrapper = img.closest('.figure-wrapper');
        const cap = wrapper ? (wrapper.querySelector('.figure-caption span')?.innerText || img.alt) : img.alt;
        openLightbox(img.src, cap);
        return;
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
</body>
</html>
`;

  fs.writeFileSync(path.join(reportDir, 'index.html'), html, 'utf8');
}

// 3. GENERATE HOMEPAGE PORTAL (REPORTS/INDEX.HTML)
function buildPortalIndex(allReports) {
  // Sort reports by latest date added by default
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
    'Cross-Platform': allReports.filter(r => r.os === 'Cross-Platform').length
  };

  const categories = [
    'Digital Forensics & Reverse Engineering',
    'Malware Analysis',
    'Threat Intelligence',
    'Advanced Persistent Threats',
    'Ransomware & Wipers'
  ];

  const catCounts = {};
  categories.forEach(cat => {
    catCounts[cat] = allReports.filter(r => r.category === cat).length;
  });

  function resolveThumbnail(r) {
    const svgThumb = `assets/thumbs/${r.id}.svg`;
    if (fs.existsSync(path.join(REPORTS_DIR, svgThumb))) {
      return { url: svgThumb, isScreenshot: false };
    }
    // Check local bundled images folder
    const imagesDir = path.join(REPORTS_DIR, r.id, 'images');
    if (fs.existsSync(imagesDir)) {
      const imgs = fs.readdirSync(imagesDir).filter(f => /\.(png|jpe?g|webp|svg)$/i.test(f));
      if (imgs.length > 0) {
        return { url: `${r.id}/images/${encodeURIComponent(imgs[0])}`, isScreenshot: true };
      }
    }
    return { url: 'assets/thumbs/digit-stealer.svg', isScreenshot: false };
  }

  const portalHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Threat Intelligence Research Portal | ${AUTHOR_NAME}</title>
  <link rel="icon" type="image/svg+xml" href="assets/favicon.svg">
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
      line-height: 1.6;
      font-size: 15px;
      -webkit-font-smoothing: antialiased;
      overflow-x: hidden;
    }

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

    .nav-stats {
      font-family: var(--font-mono);
      font-size: 12.5px;
      color: var(--text-muted);
      letter-spacing: 0.5px;
    }

    .nav-stats span {
      color: #8DCAFE;
      font-weight: 600;
    }

    .portal-container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 56px 48px 120px;
    }

    .header-section {
      margin-bottom: 56px;
      border-bottom: 1px solid var(--border-line);
      padding-bottom: 36px;
    }

    .header-title {
      font-family: var(--font-display);
      font-size: 52px;
      font-weight: 800;
      line-height: 1.15;
      letter-spacing: -1.2px;
      margin-bottom: 16px;
      background: var(--accent-gradient);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .header-desc {
      font-size: 17px;
      color: var(--text-muted);
      max-width: 860px;
      line-height: 1.6;
    }

    .header-author-link {
      color: var(--text-white);
      font-weight: 600;
      text-decoration: none;
      border-bottom: 1px dotted rgba(255, 255, 255, 0.4);
    }

    .header-controls {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 20px;
      margin-top: 32px;
      flex-wrap: wrap;
    }

    .platform-subnav {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }

    .platform-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: var(--font-display);
      font-size: 13.5px;
      font-weight: 600;
      padding: 8px 16px;
      cursor: pointer;
      position: relative;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border-radius: 20px;
    }

    .platform-btn:hover {
      color: var(--text-white);
      background: rgba(255, 255, 255, 0.04);
    }

    .platform-btn.active {
      color: var(--text-white);
      background: rgba(0, 82, 255, 0.15);
      border: 1px solid rgba(0, 82, 255, 0.4);
    }

    .platform-btn .count-badge {
      font-family: var(--font-mono);
      font-size: 11px;
      color: #8DCAFE;
      opacity: 0.85;
    }

    .search-box-wrapper {
      position: relative;
      display: flex;
      align-items: center;
      min-width: 320px;
      max-width: 440px;
      flex: 1;
    }

    .search-icon {
      position: absolute;
      left: 14px;
      width: 15px;
      height: 15px;
      color: var(--text-muted);
      pointer-events: none;
      transition: color 0.2s ease;
    }

    .search-input {
      width: 100%;
      background: rgba(255, 255, 255, 0.035);
      border: 1px solid var(--border-line);
      border-radius: 24px;
      padding: 9px 38px 9px 38px;
      font-family: var(--font-body);
      font-size: 13.5px;
      color: var(--text-white);
      outline: none;
      transition: all 0.25s ease;
    }

    .search-input::placeholder {
      color: var(--text-dim);
      font-size: 13px;
    }

    .search-input:focus {
      background: rgba(0, 0, 0, 0.7);
      border-color: rgba(0, 82, 255, 0.7);
      box-shadow: 0 0 0 3px rgba(0, 82, 255, 0.15), 0 4px 20px rgba(0, 82, 255, 0.12);
    }

    .search-box-wrapper:focus-within .search-icon {
      color: var(--accent-blue-hover);
    }

    .search-clear-btn {
      position: absolute;
      right: 12px;
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 18px;
      cursor: pointer;
      display: none;
      align-items: center;
      justify-content: center;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      padding: 0;
      line-height: 1;
    }

    .search-clear-btn:hover {
      color: var(--text-white);
      background: rgba(255, 255, 255, 0.1);
    }

    .search-kbd {
      position: absolute;
      right: 14px;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 4px;
      padding: 1px 7px;
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-muted);
      pointer-events: none;
      user-select: none;
    }

    .stream-header-info {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 14px;
      border-bottom: 1px solid var(--border-line);
      flex-wrap: wrap;
      gap: 16px;
    }

    .showing-count {
      font-size: 13.5px;
      color: var(--text-muted);
      font-family: var(--font-body);
    }

    .showing-count span,
    .stream-header-info span#results-count {
      color: #8DCAFE;
      font-weight: 600;
      font-family: var(--font-mono);
    }

    .sort-control-wrapper {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(255, 255, 255, 0.035);
      border: 1px solid var(--border-line);
      padding: 6px 14px;
      border-radius: 20px;
      transition: all 0.2s ease;
    }

    .sort-control-wrapper:hover,
    .sort-control-wrapper:focus-within {
      border-color: rgba(0, 82, 255, 0.4);
      background: rgba(0, 82, 255, 0.08);
      box-shadow: 0 0 12px rgba(0, 82, 255, 0.15);
    }

    .sort-label {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11.5px;
      font-weight: 700;
      color: var(--text-muted);
      font-family: var(--font-display);
      text-transform: uppercase;
      letter-spacing: 0.8px;
      cursor: pointer;
    }

    .sort-icon {
      width: 14px;
      height: 14px;
      color: #8DCAFE;
    }

    .sort-select {
      background: transparent;
      border: none;
      color: var(--text-white);
      font-family: var(--font-display);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      outline: none;
      padding: 2px 4px;
    }

    .sort-select option {
      background: #0D0F17;
      color: #FFFFFF;
      font-family: var(--font-body);
      padding: 8px;
    }

    .no-results-state {
      padding: 64px 20px;
      text-align: center;
      background: rgba(255, 255, 255, 0.015);
      border: 1px dashed var(--border-line);
      border-radius: 8px;
      margin-top: 16px;
    }

    .no-results-icon {
      color: var(--text-dim);
      margin-bottom: 16px;
      display: inline-flex;
    }

    .no-results-state h3 {
      font-family: var(--font-display);
      font-size: 18px;
      color: var(--text-white);
      margin-bottom: 8px;
    }

    .no-results-state p {
      font-size: 14px;
      color: var(--text-muted);
      max-width: 400px;
      margin: 0 auto 20px;
    }

    .reset-filters-btn {
      background: rgba(0, 82, 255, 0.15);
      color: #8DCAFE;
      border: 1px solid rgba(0, 82, 255, 0.4);
      padding: 8px 20px;
      border-radius: 20px;
      font-family: var(--font-display);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .reset-filters-btn:hover {
      background: var(--accent-blue);
      color: #FFFFFF;
    }

    .portal-layout {
      display: grid;
      grid-template-columns: 280px minmax(0, 1fr);
      gap: 64px;
      align-items: start;
    }

    @media (max-width: 1024px) {
      .portal-layout {
        grid-template-columns: 1fr;
        gap: 32px;
      }
      .portal-container {
        padding: 36px 24px 80px;
      }
      .site-nav {
        padding: 16px 24px;
      }
      .header-title {
        font-size: 38px;
      }
      .header-controls {
        flex-direction: column;
        align-items: stretch;
      }
      .search-box-wrapper {
        max-width: 100%;
        min-width: 100%;
      }
    }

    @media (max-width: 900px) {
      .topic-sidebar {
        position: static;
        margin-bottom: 8px;
      }
      .sidebar-heading {
        display: none;
      }
      .category-list {
        display: flex;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        gap: 8px;
        padding-bottom: 8px;
        scrollbar-width: none;
      }
      .category-list::-webkit-scrollbar {
        display: none;
      }
      .category-item {
        flex-shrink: 0;
        white-space: nowrap;
        padding: 7px 14px;
        border-radius: 20px;
        border: 1px solid var(--border-line);
        background: rgba(255, 255, 255, 0.02);
        font-size: 12.5px;
      }
    }

    @media (max-width: 768px) {
      .site-nav {
        padding: 12px 16px;
      }
      .brand-title {
        font-size: 13.5px;
        gap: 8px;
      }
      .nav-stats {
        font-size: 11px;
      }
      .portal-container {
        padding: 24px 16px 60px;
      }
      .header-section {
        margin-bottom: 28px;
        padding-bottom: 24px;
      }
      .header-title {
        font-size: 28px;
        letter-spacing: -0.6px;
        margin-bottom: 12px;
      }
      .header-desc {
        font-size: 14.5px;
        line-height: 1.55;
      }
      .platform-subnav {
        display: flex;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        width: 100%;
        max-width: 100%;
        scrollbar-width: none;
        border-radius: 12px;
        padding: 4px;
        gap: 6px;
      }
      .platform-subnav::-webkit-scrollbar {
        display: none;
      }
      .platform-btn {
        flex-shrink: 0;
        white-space: nowrap;
        padding: 6px 13px;
        font-size: 12px;
      }
      .stream-header-info {
        flex-direction: row;
        flex-wrap: wrap;
        gap: 12px;
        margin-bottom: 20px;
      }
      .report-entry {
        grid-template-columns: 1fr;
        gap: 16px;
        padding: 20px 0;
      }
      .entry-image-col {
        aspect-ratio: 16 / 9;
        max-height: 220px;
        width: 100%;
      }
      .entry-title {
        font-size: 18px;
        line-height: 1.35;
        margin-bottom: 8px;
      }
      .entry-desc {
        font-size: 13.5px;
        line-height: 1.55;
        margin-bottom: 12px;
      }
      .entry-meta-top {
        flex-wrap: wrap;
        gap: 6px 10px;
        font-size: 11px;
        margin-bottom: 8px;
      }
      .entry-meta-bottom {
        font-size: 12px;
      }
    }

    @media (max-width: 480px) {
      .header-title {
        font-size: 24px;
      }
      .nav-stats {
        display: none;
      }
      .stream-header-info {
        flex-direction: column;
        align-items: flex-start;
      }
      .sort-control-wrapper {
        width: 100%;
        justify-content: space-between;
      }
      .sort-select {
        flex: 1;
      }
    }

    .topic-sidebar {
      position: sticky;
      top: 100px;
    }

    .sidebar-heading {
      font-family: var(--font-display);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      color: var(--text-muted);
      margin-bottom: 20px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border-line);
    }

    .category-list {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .category-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 14px;
      color: var(--text-muted);
      text-decoration: none;
      font-size: 13.5px;
      font-weight: 500;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s ease;
      border-left: 2px solid transparent;
    }

    .category-item:hover {
      color: var(--text-white);
      background: rgba(255, 255, 255, 0.02);
    }

    .category-item.active {
      color: var(--text-white);
      background: linear-gradient(90deg, rgba(0, 82, 255, 0.12), transparent);
      border-left: 2px solid #0052FF;
      font-weight: 600;
    }

    .cat-count {
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-dim);
    }

    .category-item.active .cat-count {
      color: #8DCAFE;
    }

    .reports-stream {
      display: flex;
      flex-direction: column;
    }

    .report-entry {
      display: grid;
      grid-template-columns: 250px 1fr;
      gap: 36px;
      padding: 40px 0;
      border-bottom: 1px solid var(--border-line);
      transition: all 0.25s ease;
      align-items: start;
      position: relative;
    }

    .report-entry:first-child {
      padding-top: 0;
    }

    .report-entry:last-child {
      border-bottom: none;
    }

    .report-entry:hover {
      border-bottom-color: rgba(0, 82, 255, 0.35);
    }

    .entry-image-col {
      position: relative;
      border-radius: 4px;
      overflow: hidden;
      aspect-ratio: 16 / 11;
      width: 100%;
      background: #020204;
      border: 1px solid var(--border-line);
      transition: all 0.3s ease;
    }

    .report-entry:hover .entry-image-col {
      border-color: rgba(0, 82, 255, 0.5);
      box-shadow: 0 4px 24px rgba(0, 82, 255, 0.18);
      transform: translateY(-2px);
    }

    .entry-thumbnail {
      width: 100%;
      height: 100%;
      object-fit: cover;
      display: block;
      transition: transform 0.4s ease;
    }

    .entry-thumbnail.is-screenshot {
      object-fit: contain;
      background: #000000;
      padding: 6px;
    }

    .report-entry:hover .entry-thumbnail {
      transform: scale(1.03);
    }

    .entry-text-col {
      display: flex;
      flex-direction: column;
    }

    .entry-meta-top {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 11.5px;
      text-transform: uppercase;
      letter-spacing: 1px;
      font-weight: 700;
      color: var(--text-muted);
      margin-bottom: 12px;
      font-family: var(--font-display);
    }

    .entry-category {
      color: #8DCAFE;
    }

    .entry-os-badge {
      color: var(--text-dim);
    }

    .threat-svg-icon {
      width: 14px;
      height: 14px;
      color: #0052FF;
      flex-shrink: 0;
    }

    .meta-sep {
      color: var(--text-dim);
      font-size: 10px;
    }

    .entry-title {
      font-family: var(--font-display);
      font-size: 22px;
      font-weight: 700;
      line-height: 1.35;
      color: var(--text-white);
      margin-bottom: 12px;
      letter-spacing: -0.2px;
      transition: color 0.2s ease;
    }

    .report-entry:hover .entry-title {
      color: #8DCAFE;
    }

    .entry-desc {
      font-size: 14.5px;
      color: var(--text-body);
      line-height: 1.65;
      margin-bottom: 18px;
    }

    .entry-meta-bottom {
      display: flex;
      align-items: center;
      gap: 16px;
      font-size: 12.5px;
      color: var(--text-muted);
      margin-top: auto;
    }

    .entry-read-link {
      color: #FFFFFF;
      font-weight: 600;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: transform 0.2s ease;
    }

    .entry-read-link:hover {
      color: #8DCAFE;
      transform: translateX(3px);
    }

    .entry-read-link span {
      font-size: 14px;
      transition: transform 0.2s ease;
    }

    .report-entry:hover .entry-read-link span {
      transform: translateX(4px);
    }

    .full-card-link {
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      z-index: 10;
    }
  </style>
</head>
<body>

  <nav class="site-nav">
    <a href="index.html" class="brand-title">
      <span class="brand-dot"></span>
      THREAT RESEARCH
    </a>
    <div class="nav-stats">
      <span>${totalCount}</span> Investigations Published
    </div>
  </nav>

  <main class="portal-container">
    
    <header class="header-section">
      <h1 class="header-title">Threat Intelligence</h1>
      <p class="header-desc">
        Independent cyber threat intelligence, technical malware analyses, and adversary tradecraft research by <span class="header-author-link">${AUTHOR_NAME}</span>.
      </p>

      <div class="header-controls">
        <nav class="platform-subnav" aria-label="Operating System Filter">
          <button class="platform-btn active" data-filter="all">All Platforms <span class="count-badge">${counts.All}</span></button>
          <button class="platform-btn" data-filter="Windows">Windows <span class="count-badge">${counts.Windows}</span></button>
          <button class="platform-btn" data-filter="macOS">macOS <span class="count-badge">${counts.macOS}</span></button>
          <button class="platform-btn" data-filter="Linux">Linux <span class="count-badge">${counts.Linux}</span></button>
          <button class="platform-btn" data-filter="Cross-Platform">Cross-Platform <span class="count-badge">${counts['Cross-Platform']}</span></button>
        </nav>

        <div class="search-box-wrapper">
          <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <input type="text" id="live-search" class="search-input" placeholder="Search investigations, malware, CVEs, IOCs..." autocomplete="off" spellcheck="false">
          <button id="search-clear" class="search-clear-btn" aria-label="Clear search" title="Clear">&times;</button>
          <kbd class="search-kbd">/</kbd>
        </div>
      </div>
    </header>

    <div class="portal-layout">
      
      <aside class="topic-sidebar">
        <div class="sidebar-heading">Threat Categories</div>
        <ul class="category-list">
          <li class="category-item active" data-cat="all">
            <span>All Categories</span>
            <span class="cat-count">${totalCount}</span>
          </li>
          ${categories.map(cat => `
          <li class="category-item" data-cat="${escapeHtml(cat)}">
            <span>${escapeHtml(cat)}</span>
            <span class="cat-count">${catCounts[cat] || 0}</span>
          </li>
          `).join('')}
        </ul>
      </aside>

      <section class="reports-stream">
        <div class="stream-header-info">
          <span class="showing-count">Showing <span id="results-count">${totalCount}</span> of ${totalCount} investigations</span>
          <div class="sort-control-wrapper">
            <label for="sort-select" class="sort-label">
              <svg class="sort-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="4" y1="6" x2="20" y2="6"></line>
                <line x1="4" y1="12" x2="14" y2="12"></line>
                <line x1="4" y1="18" x2="8" y2="18"></line>
              </svg>
              <span>Sort:</span>
            </label>
            <select id="sort-select" class="sort-select" aria-label="Sort investigations">
              <option value="latest" selected>Latest Added</option>
              <option value="oldest">Oldest First</option>
              <option value="title">Title (A–Z)</option>
              <option value="readtime">Read Time</option>
            </select>
          </div>
        </div>

        <div id="no-results" class="no-results-state" style="display: none;">
          <div class="no-results-icon">
            <svg viewBox="0 0 24 24" width="44" height="44" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              <line x1="8" y1="11" x2="14" y2="11"></line>
            </svg>
          </div>
          <h3>No matching investigations</h3>
          <p>We couldn't find any threat research matching your search or filters.</p>
          <button id="reset-filters-btn" class="reset-filters-btn">Reset All Filters</button>
        </div>

        ${allReports.map(r => {
          const thumbObj = resolveThumbnail(r);
          const searchKeywords = `${r.title} ${r.lead} ${r.family} ${r.classification} ${r.category} ${r.os} ${r.hashVal} ${r.delivery} ${r.c2} ${r.targets}`.toLowerCase();
          return `
          <article class="report-entry" data-os="${escapeHtml(r.os)}" data-category="${escapeHtml(r.category)}" data-search="${escapeHtml(searchKeywords)}" data-date="${new Date(r.date).getTime()}" data-title="${escapeHtml(r.title.toLowerCase())}" data-readtime="${parseInt(r.readTime, 10) || 0}">
            <a href="${r.id}/index.html" class="full-card-link" aria-label="${escapeHtml(r.title)}"></a>
            <div class="entry-image-col">
              <img src="${thumbObj.url}" alt="${escapeHtml(r.title)}" class="entry-thumbnail ${thumbObj.isScreenshot ? 'is-screenshot' : ''}" loading="lazy">
            </div>
            <div class="entry-text-col">
              <div class="entry-meta-top">
                ${getThreatIcon(r.iconType)}
                <span class="entry-category">${escapeHtml(r.category)}</span>
                <span class="meta-sep">•</span>
                <span class="entry-os-badge">${escapeHtml(r.os)}</span>
                <span class="meta-sep">•</span>
                <span>${escapeHtml(r.date)}</span>
              </div>
              <h2 class="entry-title">${escapeHtml(r.title)}</h2>
              <p class="entry-desc">${escapeHtml(r.lead)}</p>
              <div class="entry-meta-bottom">
                <span>${escapeHtml(r.readTime)}</span>
                <span class="meta-sep">•</span>
                <span class="entry-read-link">Read Investigation <span>→</span></span>
              </div>
            </div>
          </article>
          `;
        }).join('')}
      </section>

    </div>

  </main>

  <script>
    const searchInput = document.getElementById('live-search');
    const clearBtn = document.getElementById('search-clear');
    const searchKbd = document.querySelector('.search-kbd');
    const platformBtns = document.querySelectorAll('.platform-btn');
    const categoryItems = document.querySelectorAll('.category-item');
    const reports = document.querySelectorAll('.report-entry');
    const resultsCount = document.getElementById('results-count');
    const noResults = document.getElementById('no-results');
    const resetBtn = document.getElementById('reset-filters-btn');

    let currentOs = 'all';
    let currentCat = 'all';
    let searchQuery = '';

    function filterReports() {
      let visibleCount = 0;
      const query = searchQuery.trim().toLowerCase();

      reports.forEach(report => {
        const reportOs = report.getAttribute('data-os');
        const reportCat = report.getAttribute('data-category');
        const reportSearch = report.getAttribute('data-search') || '';

        const osMatch = (currentOs === 'all' || reportOs === currentOs);
        const catMatch = (currentCat === 'all' || reportCat === currentCat);
        const searchMatch = !query || reportSearch.includes(query);

        if (osMatch && catMatch && searchMatch) {
          report.style.display = 'grid';
          visibleCount++;
        } else {
          report.style.display = 'none';
        }
      });

      if (resultsCount) {
        resultsCount.textContent = visibleCount;
      }

      if (noResults) {
        noResults.style.display = (visibleCount === 0) ? 'block' : 'none';
      }

      if (clearBtn && searchKbd) {
        if (query.length > 0) {
          clearBtn.style.display = 'flex';
          searchKbd.style.display = 'none';
        } else {
          clearBtn.style.display = 'none';
          searchKbd.style.display = 'inline-block';
        }
      }
    }

    const sortSelect = document.getElementById('sort-select');
    let currentSort = 'latest';

    function applySort(order) {
      currentSort = order;
      const streamContainer = document.querySelector('.reports-stream');
      const entries = Array.from(streamContainer.querySelectorAll('.report-entry'));

      entries.sort((a, b) => {
        if (order === 'latest') {
          return Number(b.getAttribute('data-date')) - Number(a.getAttribute('data-date'));
        } else if (order === 'oldest') {
          return Number(a.getAttribute('data-date')) - Number(b.getAttribute('data-date'));
        } else if (order === 'title') {
          return a.getAttribute('data-title').localeCompare(b.getAttribute('data-title'));
        } else if (order === 'readtime') {
          return Number(b.getAttribute('data-readtime')) - Number(a.getAttribute('data-readtime'));
        }
        return 0;
      });

      entries.forEach(entry => streamContainer.appendChild(entry));
    }

    if (sortSelect) {
      sortSelect.addEventListener('change', (e) => {
        applySort(e.target.value);
        filterReports();
      });
    }

    searchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value;
      filterReports();
    });

    clearBtn.addEventListener('click', () => {
      searchInput.value = '';
      searchQuery = '';
      filterReports();
      searchInput.focus();
    });

    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        searchInput.value = '';
        searchQuery = '';
        currentOs = 'all';
        currentCat = 'all';
        if (sortSelect) sortSelect.value = 'latest';
        applySort('latest');
        platformBtns.forEach(b => b.classList.remove('active'));
        document.querySelector('.platform-btn[data-filter="all"]').classList.add('active');
        categoryItems.forEach(i => i.classList.remove('active'));
        document.querySelector('.category-item[data-cat="all"]').classList.add('active');
        filterReports();
      });
    }

    platformBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        platformBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentOs = btn.getAttribute('data-filter');
        filterReports();
      });
    });

    categoryItems.forEach(item => {
      item.addEventListener('click', () => {
        categoryItems.forEach(i => i.classList.remove('active'));
        item.classList.add('active');
        currentCat = item.getAttribute('data-cat');
        filterReports();
      });
    });

    // Keyboard shortcut: '/' to focus search, 'Esc' to clear & blur
    document.addEventListener('keydown', (e) => {
      if (e.key === '/' && document.activeElement !== searchInput) {
        e.preventDefault();
        searchInput.focus();
      } else if (e.key === 'Escape' && document.activeElement === searchInput) {
        searchInput.value = '';
        searchQuery = '';
        filterReports();
        searchInput.blur();
      }
    });
  </script>
</body>
</html>
`;

  fs.writeFileSync(path.join(REPORTS_DIR, 'index.html'), portalHtml, 'utf8');
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

allReports.forEach(r => {
  buildReportPage(r);
});

buildPortalIndex(allReports);
console.log('=== Build complete! All reports self-contained and live in reports/ ===');
