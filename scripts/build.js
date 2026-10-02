const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const AUTHOR_NAME = 'Chandra Kant Bauri';
const ROOT_DIR = path.resolve(__dirname, '..');
const BASE_ANALYSIS_DIR = path.join(ROOT_DIR, 'Malware Analysis');
const REPORTS_DIR = path.join(ROOT_DIR, 'reports');

// Canonical authentic dates when reports were added to repository
const CANONICAL_REPORT_DATES = {
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
  'cyber-talents-ctf': 'February 20, 2025'
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
      let category = 'Malware Family Analysis';
      let iconType = 'binary';
      const textLower = (rawContent + ' ' + dirName).toLowerCase();

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

      // E. Extract First Image in README.md as default card thumbnail
      let firstImage = null;
      const mdImg = rawContent.match(/!\[.*?\]\((.+?)\)/);
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

      // Load optional 5-line meta.json if present in the folder
      const metaFile = path.join(fullDir, 'meta.json');
      if (fs.existsSync(metaFile)) {
        try {
          const meta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
          if (meta.title) title = meta.title;
          if (meta.subtitle || meta.lead) lead = meta.subtitle || meta.lead;
          if (meta.thumbnail || meta.thumb || meta.image) thumbnail = meta.thumbnail || meta.thumb || meta.image;
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
        firstImage,
        thumbnail,
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



  let mdContent = fs.readFileSync(r.mdPath, 'utf8');


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
          return `images/${encodeURIComponent(baseName)}`;
        }
      } catch (e) {
        // Fallback to raw remote URL
      }
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

  let firstEncounteredImage = null;

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
      const alt = mdImgMatch[1] ? mdImgMatch[1].trim() : '';
      const localSrc = bundleImageLocally(mdImgMatch[2]);
      if (!firstEncounteredImage && localSrc) {
        firstEncounteredImage = localSrc;
        r.firstImage = localSrc;
      }
      const captionHtml = alt ? `
          <div class="figure-caption">
            <span><strong>Figure:</strong> ${escapeHtml(alt)}</span>
            <span class="zoom-link" style="font-size: 11.5px; color: var(--accent-blue-hover); cursor: pointer;" onclick="openLightbox('${localSrc}', '${escapeHtml(alt)}')">Click to zoom ↗</span>
          </div>` : '';
      htmlBuffer.push(`
        <div class="figure-wrapper">
          <div class="figure-image-container" onclick="openLightbox(this.querySelector('img').src, '${escapeHtml(alt)}')">
            <img src="${localSrc}" alt="${escapeHtml(alt)}" loading="lazy">
          </div>${captionHtml}
        </div>
      `);
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
      const captionHtml = alt ? `
          <div class="figure-caption">
            <span><strong>Figure:</strong> ${escapeHtml(alt)}</span>
            <span class="zoom-link" style="font-size: 11.5px; color: var(--accent-blue-hover); cursor: pointer;" onclick="openLightbox('${localSrc}', '${escapeHtml(alt)}')">Click to zoom ↗</span>
          </div>` : '';
      htmlBuffer.push(`
        <div class="figure-wrapper">
          <div class="figure-image-container" onclick="openLightbox(this.querySelector('img').src, '${escapeHtml(alt)}')">
            <img src="${localSrc}" alt="${escapeHtml(alt)}" loading="lazy">
          </div>${captionHtml}
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

  if (!r.firstImage && fs.existsSync(imagesDir)) {
    const existingImages = fs.readdirSync(imagesDir).filter(f => !f.startsWith('.') && /\.(png|jpe?g|webp|gif|svg)$/i.test(f));
    if (existingImages.length > 0) {
      r.firstImage = `images/${encodeURIComponent(existingImages[0])}`;
    }
  }

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
  <link rel="icon" type="image/png" href="../assets/home/mare-logo.png">
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
      color: var(--text-body);
      font-family: var(--font-body);
      line-height: 1.8;
      font-size: 16px;
      -webkit-font-smoothing: antialiased;
      overflow-x: hidden;
      min-height: 100vh;
      position: relative;
    }

    body::before {
      content: '';
      position: fixed;
      inset: 0;
      width: 100vw;
      height: 100vh;
      background-image: 
        radial-gradient(circle at 18% 0%, rgba(0, 60, 245, 0.16) 0%, transparent 42%),
        radial-gradient(circle at 82% 12%, rgba(0, 40, 190, 0.10) 0%, transparent 48%),
        radial-gradient(circle at 50% 50%, rgba(10, 16, 32, 0.4) 0%, transparent 70%);
      pointer-events: none;
      z-index: -1;
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

    /* Sticky Independently Scrollable Sidebar */
    .sidebar-sticky {
      position: sticky;
      top: 80px;
      max-height: calc(100vh - 100px);
      overflow-y: auto;
      overflow-x: hidden;
      overscroll-behavior: contain;
      scrollbar-width: thin;
      scrollbar-color: rgba(255, 255, 255, 0.15) transparent;
      padding-right: 8px;
      display: flex;
      flex-direction: column;
      gap: 36px;
    }

    .sidebar-sticky::-webkit-scrollbar {
      width: 4px;
    }
    .sidebar-sticky::-webkit-scrollbar-track {
      background: transparent;
    }
    .sidebar-sticky::-webkit-scrollbar-thumb {
      background: rgba(255, 255, 255, 0.15);
      border-radius: 4px;
    }
    .sidebar-sticky::-webkit-scrollbar-thumb:hover {
      background: rgba(0, 82, 255, 0.5);
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

    /* Responsive Breakpoints (Cascaded at bottom) */
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
        max-height: none;
        overflow-y: visible;
        padding-right: 0;
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
  </style>
</head>
<body>

  <div id="progress-bar"></div>

  <nav class="site-nav">
    <div class="nav-breadcrumbs">
      <a href="../index.html" class="brand-title" style="display:inline-flex;align-items:center;gap:8px;">
        <img src="../assets/home/mare-logo.png" alt="MARE Logo" width="18" height="18" style="vertical-align:middle;border-radius:3px;">
        <span>MARE</span>
        <span style="opacity:0.4;font-size:11px;">/</span>
        <span>THREAT RESEARCH</span>
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
    const navLinks = Array.from(document.querySelectorAll('.toc-nav a'));
    const linkMap = navLinks.map(link => {
      const href = link.getAttribute('href');
      const targetId = href ? href.replace(/^#/, '') : '';
      const targetEl = document.getElementById(targetId);
      return { link, targetId, targetEl };
    }).filter(item => item.targetEl);

    let isTOCScrolling = false;
    function updateTOC() {
      if (linkMap.length === 0) return;

      const winScroll = window.scrollY || document.documentElement.scrollTop;
      const scrollHeight = document.documentElement.scrollHeight;
      const clientHeight = document.documentElement.clientHeight;
      const atBottom = (winScroll + clientHeight >= scrollHeight - 60);

      let activeItem = linkMap[0];
      if (atBottom) {
        activeItem = linkMap[linkMap.length - 1];
      } else {
        for (let i = 0; i < linkMap.length; i++) {
          const rect = linkMap[i].targetEl.getBoundingClientRect();
          if (rect.top <= 160) {
            activeItem = linkMap[i];
          } else {
            break;
          }
        }
      }

      let activeChanged = false;
      linkMap.forEach(item => {
        const isActive = (item === activeItem);
        if (item.link.classList.contains('active') !== isActive) {
          item.link.classList.toggle('active', isActive);
          if (isActive) activeChanged = true;
        }
      });

      if (activeChanged && activeItem && activeItem.link) {
        const sidebar = document.querySelector('.sidebar-sticky');
        if (sidebar && !sidebar.matches(':hover') && sidebar.scrollHeight > sidebar.clientHeight) {
          const linkRect = activeItem.link.getBoundingClientRect();
          const sidebarRect = sidebar.getBoundingClientRect();
          if (linkRect.top < sidebarRect.top + 30 || linkRect.bottom > sidebarRect.bottom - 30) {
            activeItem.link.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
          }
        }
      }
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

    // Click handling for TOC links
    navLinks.forEach(link => {
      link.addEventListener('click', () => {
        navLinks.forEach(l => l.classList.remove('active'));
        link.classList.add('active');
        setTimeout(updateTOC, 400);
      });
    });

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
  // Ensure assets/home are copied to reports/assets/home
  const srcHomeAssets = path.join(ROOT_DIR, 'assets/home');
  const targetHomeAssets = path.join(REPORTS_DIR, 'assets/home');
  if (fs.existsSync(srcHomeAssets)) {
    if (!fs.existsSync(targetHomeAssets)) fs.mkdirSync(targetHomeAssets, { recursive: true });
    fs.cpSync(srcHomeAssets, targetHomeAssets, { recursive: true });
  }

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
    'Cross-Platform': allReports.filter(r => r.os === 'Cross-Platform').length
  };

  const catCounts = {
    'Reverse Engineering Techniques': allReports.filter(r => r.category === 'Reverse Engineering Techniques').length,
    'Malware Family Analysis': allReports.filter(r => r.category === 'Malware Family Analysis').length,
    'Threat Intelligence & APTs': allReports.filter(r => r.category === 'Threat Intelligence & APTs').length,
    'Ransomware & Wipers': allReports.filter(r => r.category === 'Ransomware & Wipers').length
  };

  function formatCardDate(dateStr) {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  }

  // Featured 3 investigations shown at top of the reference image
  const featuredIds = ['rustbucket-2', 'unpacking-modified-upx-malware', 'digit-stealer'];
  const featuredReports = [];
  const otherReports = [];

  featuredIds.forEach(fid => {
    const found = allReports.find(r => r.id === fid);
    if (found) featuredReports.push(found);
  });
  allReports.forEach(r => {
    if (!featuredIds.includes(r.id)) otherReports.push(r);
  });

  const displayReports = [...featuredReports, ...otherReports];

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
  <style>
    :root {
      --bg-page: #05090D;
      --bg-panel: #0A1118;
      --bg-card: #0A1118;
      --bg-card-hover: #0D1620;
      --neon-lime: #B7FF3C;
      --neon-cyan: #35E5D0;
      --text-main: #F5F7FA;
      --text-secondary: #98A5B3;
      --text-muted: #5F6E7E;
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-card: rgba(255, 255, 255, 0.08);
      --border-hover: rgba(183, 255, 60, 0.35);
      --font-display: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-body: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }

    body {
      background-color: var(--bg-page);
      color: var(--text-main);
      font-family: var(--font-body);
      line-height: 1.6;
      font-size: 15px;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      overflow-x: hidden;
      min-height: 100vh;
      position: relative;
    }

    /* Ambient cybernetic background glow behind hero cube */
    body::before {
      content: '';
      position: fixed;
      inset: 0;
      width: 100%;
      height: 100%;
      background-image:
        radial-gradient(circle at 75% 240px, rgba(53, 229, 208, 0.07) 0%, transparent 45%),
        radial-gradient(circle at 62% 280px, rgba(183, 255, 60, 0.04) 0%, transparent 35%),
        radial-gradient(circle at 20% 120px, rgba(53, 229, 208, 0.03) 0%, transparent 40%);
      pointer-events: none;
      z-index: -1;
    }

    /* Subtle isometric floor grid lines */
    .bg-grid-overlay {
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 600px;
      background-image: 
        linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.015) 1px, transparent 1px);
      background-size: 48px 48px;
      pointer-events: none;
      z-index: 0;
      mask-image: linear-gradient(to bottom, black 40%, transparent 100%);
      -webkit-mask-image: linear-gradient(to bottom, black 40%, transparent 100%);
    }

    /* Top Navigation */
    .site-nav {
      position: sticky;
      top: 0;
      z-index: 100;
      background: rgba(5, 9, 13, 0.88);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--border-subtle);
      height: 60px;
    }

    .nav-container {
      max-width: 1480px;
      margin: 0 auto;
      height: 100%;
      padding: 0 44px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .brand-group {
      display: flex;
      align-items: center;
      text-decoration: none;
      gap: 14px;
      user-select: none;
    }

    .brand-logo-img {
      width: 30px;
      height: 30px;
      object-fit: contain;
      filter: drop-shadow(0 0 10px rgba(53, 229, 208, 0.4));
    }

    .brand-text-block {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand-title {
      font-family: var(--font-display);
      font-size: 18px;
      font-weight: 800;
      letter-spacing: 1.5px;
      color: #FFFFFF;
    }

    .brand-vsep {
      width: 1px;
      height: 22px;
      background: rgba(255, 255, 255, 0.16);
    }

    .brand-subtext {
      display: flex;
      flex-direction: column;
      font-family: var(--font-mono);
      font-size: 8.5px;
      font-weight: 600;
      letter-spacing: 1.2px;
      line-height: 1.35;
      color: var(--text-secondary);
    }

    /* Center Nav Links */
    .center-nav {
      display: flex;
      align-items: center;
      gap: 28px;
    }

    .nav-link-item {
      position: relative;
    }

    .nav-link {
      color: var(--text-secondary);
      font-size: 13.5px;
      font-weight: 500;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: color 0.2s ease;
      cursor: pointer;
      padding: 6px 0;
    }

    .nav-link:hover {
      color: #FFFFFF;
    }

    .nav-chevron {
      stroke: var(--text-muted);
      transition: transform 0.2s ease, stroke 0.2s ease;
    }

    .nav-link:hover .nav-chevron {
      stroke: var(--neon-lime);
      transform: translateY(1px);
    }

    /* Dropdown Menus */
    .nav-dropdown {
      position: absolute;
      top: 100%;
      left: 50%;
      transform: translateX(-50%) translateY(8px);
      background: #0A1118;
      border: 1px solid var(--border-card);
      border-radius: 12px;
      padding: 12px 0;
      min-width: 220px;
      box-shadow: 0 16px 36px rgba(0, 0, 0, 0.8), 0 0 12px rgba(53, 229, 208, 0.08);
      opacity: 0;
      visibility: hidden;
      pointer-events: none;
      transition: all 0.2s ease;
      z-index: 200;
    }

    .nav-link-item:hover .nav-dropdown {
      opacity: 1;
      visibility: visible;
      pointer-events: auto;
      transform: translateX(-50%) translateY(2px);
    }

    .dropdown-link {
      display: block;
      padding: 9px 20px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 13.5px;
      font-weight: 500;
      transition: all 0.15s ease;
    }

    .dropdown-link:hover {
      color: var(--neon-lime);
      background: rgba(183, 255, 60, 0.06);
      padding-left: 24px;
    }

    /* Right Nav Actions */
    .right-nav-actions {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .nav-search-icon-btn {
      background: transparent;
      border: none;
      color: var(--text-secondary);
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      width: 34px;
      height: 34px;
      border-radius: 50%;
      transition: color 0.2s, background 0.2s;
    }

    .nav-search-icon-btn:hover {
      color: #FFFFFF;
      background: rgba(255, 255, 255, 0.06);
    }

    .btn-explore-reports {
      border: 1px solid rgba(255, 255, 255, 0.18);
      background: transparent;
      color: #F5F7FA;
      font-size: 13px;
      font-weight: 500;
      padding: 7px 18px;
      border-radius: 9999px;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s ease;
    }

    .btn-explore-reports:hover {
      border-color: var(--neon-lime);
      color: var(--neon-lime);
      background: rgba(183, 255, 60, 0.06);
      box-shadow: 0 0 16px rgba(183, 255, 60, 0.2);
    }

    /* Hero Section */
    .hero-section {
      position: relative;
      z-index: 1;
      padding: 16px 0 8px;
      overflow: hidden;
    }

    .hero-container {
      max-width: 1480px;
      margin: 0 auto;
      padding: 0 44px;
      display: grid;
      grid-template-columns: 1.08fr 1fr;
      gap: 16px;
      align-items: center;
      min-height: auto;
    }

    .hero-left-col {
      display: flex;
      flex-direction: column;
      justify-content: center;
      z-index: 2;
    }

    .hero-eyebrow {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 10px;
    }

    .eyebrow-dash {
      width: 16px;
      height: 2px;
      background: var(--neon-lime);
      border-radius: 2px;
    }

    .eyebrow-text {
      color: var(--neon-lime);
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 2px;
      text-transform: uppercase;
    }

    .hero-headline {
      font-family: var(--font-display);
      font-size: 58px;
      font-weight: 800;
      line-height: 1.05;
      letter-spacing: -1.8px;
      margin-bottom: 12px;
    }

    .hl-white {
      color: #FFFFFF;
    }

    .hl-lime {
      color: var(--neon-lime);
      text-shadow: 0 0 35px rgba(183, 255, 60, 0.35);
    }

    .hero-lead-text {
      color: var(--text-secondary);
      font-size: 15px;
      line-height: 1.5;
      max-width: 510px;
      margin-bottom: 20px;
      font-weight: 400;
    }

    .hero-cta-group {
      display: flex;
      align-items: center;
      gap: 14px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }

    .btn-cta-primary {
      background: var(--neon-lime);
      color: #05090D;
      font-family: var(--font-body);
      font-weight: 700;
      font-size: 13.5px;
      padding: 10px 22px;
      border-radius: 9999px;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 9px;
      transition: all 0.2s ease;
      box-shadow: 0 0 20px rgba(183, 255, 60, 0.3);
    }

    .btn-cta-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 0 28px rgba(183, 255, 60, 0.5);
    }

    .btn-cta-secondary {
      background: rgba(10, 17, 24, 0.85);
      color: #F5F7FA;
      font-family: var(--font-body);
      font-weight: 600;
      font-size: 13.5px;
      padding: 10px 22px;
      border-radius: 9999px;
      text-decoration: none;
      border: 1px solid rgba(255, 255, 255, 0.14);
      display: inline-flex;
      align-items: center;
      transition: all 0.2s ease;
    }

    .btn-cta-secondary:hover {
      border-color: rgba(255, 255, 255, 0.35);
      background: rgba(255, 255, 255, 0.05);
      color: #FFFFFF;
    }

    /* 4 Research Statistics */
    .hero-stats-row {
      display: flex;
      align-items: center;
      gap: 0;
      flex-wrap: nowrap;
      width: 100%;
    }

    .stat-item {
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
    }

    .stat-num {
      font-family: var(--font-display);
      font-size: 28px;
      font-weight: 800;
      color: #FFFFFF;
      line-height: 1;
      margin-bottom: 4px;
    }

    .stat-label {
      font-size: 12.5px;
      font-weight: 700;
      color: #F5F7FA;
      line-height: 1.2;
      margin-bottom: 2px;
      white-space: nowrap;
    }

    .stat-sub {
      font-size: 10.5px;
      color: var(--text-muted);
      line-height: 1.25;
      white-space: nowrap;
    }

    .stat-vdivider {
      width: 1px;
      height: 38px;
      background: rgba(255, 255, 255, 0.16);
      margin: 0 18px;
      flex-shrink: 0;
    }

    /* Hero Right Column (The 3D Cube Illustration) */
    .hero-right-col {
      position: relative;
      display: flex;
      justify-content: flex-end;
      align-items: center;
      z-index: 1;
    }

    .hero-cube-visual-wrapper {
      position: relative;
      width: 100%;
      max-width: 860px;
      display: flex;
      justify-content: flex-end;
      align-items: center;
    }

    .hero-cube-img {
      width: 100%;
      height: auto;
      max-height: 430px;
      object-fit: contain;
      filter: drop-shadow(0 0 35px rgba(53, 229, 208, 0.12));
      user-select: none;
    }

    /* Horizontal Section Divider */
    .section-hdivider {
      max-width: 1480px;
      margin: 8px auto 14px;
      padding: 0 44px;
    }

    .section-hdivider-line {
      width: 100%;
      height: 1px;
      background: var(--border-subtle);
    }

    /* Investigations Section */
    .investigations-section {
      max-width: 1480px;
      margin: 0 auto;
      padding: 0 44px 50px;
      position: relative;
      z-index: 2;
    }

    .investigations-header {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      margin-bottom: 14px;
      flex-wrap: wrap;
      gap: 16px;
    }

    .header-title-col {
      display: flex;
      flex-direction: column;
    }

    .inv-eyebrow {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 4px;
    }

    .inv-dash {
      width: 14px;
      height: 2px;
      background: var(--neon-lime);
      border-radius: 2px;
    }

    .inv-eyebrow-text {
      color: var(--neon-lime);
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 1.5px;
      text-transform: uppercase;
    }

    .inv-main-title {
      font-family: var(--font-display);
      font-size: 28px;
      font-weight: 800;
      color: #FFFFFF;
      letter-spacing: -0.6px;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }

    .inv-title-arrow {
      color: var(--text-secondary);
      font-weight: 400;
      font-size: 24px;
      margin-left: 2px;
    }

    .header-controls-col {
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
    }

    /* Search Box */
    .search-input-wrapper {
      position: relative;
      width: 290px;
    }

    .search-icon-svg {
      position: absolute;
      left: 14px;
      top: 50%;
      transform: translateY(-50%);
      stroke: var(--text-muted);
      pointer-events: none;
    }

    .live-search-box {
      width: 100%;
      height: 36px;
      background: var(--bg-card);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 9999px;
      padding: 0 42px 0 36px;
      color: var(--text-main);
      font-size: 13px;
      font-family: var(--font-body);
      transition: all 0.2s ease;
    }

    .live-search-box:focus {
      outline: none;
      border-color: var(--neon-lime);
      box-shadow: 0 0 14px rgba(183, 255, 60, 0.25);
    }

    .search-shortcut-badge {
      position: absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      font-family: var(--font-mono);
      font-size: 11px;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 4px;
      padding: 2px 6px;
      color: var(--text-secondary);
      pointer-events: none;
    }

    .search-clear-btn {
      position: absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      background: transparent;
      border: none;
      color: var(--text-secondary);
      font-size: 18px;
      cursor: pointer;
      display: none;
      line-height: 1;
    }

    /* Platform Filter Pills */
    .platform-filter-group {
      display: flex;
      align-items: center;
      gap: 4px;
      background: rgba(10, 17, 24, 0.65);
      padding: 3px;
      border-radius: 9999px;
      border: 1px solid var(--border-subtle);
    }

    .filter-pill {
      background: transparent;
      color: var(--text-secondary);
      font-family: var(--font-body);
      font-size: 12.5px;
      font-weight: 500;
      padding: 6px 15px;
      border-radius: 9999px;
      border: none;
      cursor: pointer;
      transition: all 0.2s ease;
      white-space: nowrap;
    }

    .filter-pill:hover {
      color: #FFFFFF;
      background: rgba(255, 255, 255, 0.05);
    }

    .filter-pill.active {
      background: var(--neon-lime);
      color: #05090D;
      font-weight: 700;
      box-shadow: 0 0 12px rgba(183, 255, 60, 0.3);
    }

    /* Cards Grid */
    .investigations-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 20px;
    }

    /* Single Investigation Card */
    .inv-card {
      background: var(--bg-card);
      border: 1px solid var(--border-card);
      border-radius: 14px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      text-decoration: none;
      color: inherit;
      position: relative;
      transition: transform 0.25s ease, border-color 0.25s ease, box-shadow 0.25s ease;
    }

    .inv-card:hover {
      transform: translateY(-4px);
      border-color: rgba(183, 255, 60, 0.35);
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.6), 0 0 16px rgba(183, 255, 60, 0.08);
    }

    .card-banner {
      position: relative;
      width: 100%;
      height: 158px;
      background: #070D13;
      overflow: hidden;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }

    .card-banner-img {
      width: 100%;
      height: 100%;
      object-fit: cover;
      transition: transform 0.4s ease;
    }

    .inv-card:hover .card-banner-img {
      transform: scale(1.03);
    }

    /* Platform Badges */
    .card-platform-badge {
      position: absolute;
      top: 12px;
      left: 12px;
      z-index: 2;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 11.5px;
      font-weight: 600;
      letter-spacing: 0.2px;
      user-select: none;
    }

    .badge-macos {
      background: rgba(20, 32, 44, 0.92);
      color: #F5F7FA;
      border: 1px solid rgba(255, 255, 255, 0.16);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
    }

    .badge-windows {
      background: #1877F2;
      color: #FFFFFF;
      border: none;
      box-shadow: 0 2px 10px rgba(24, 119, 242, 0.35);
    }

    .badge-cross {
      background: #6D28D9;
      color: #FFFFFF;
      border: none;
      box-shadow: 0 2px 10px rgba(109, 40, 217, 0.35);
    }

    .badge-linux {
      background: #0D9488;
      color: #FFFFFF;
      border: none;
      box-shadow: 0 2px 10px rgba(13, 148, 136, 0.35);
    }

    /* Card Content Body */
    .card-content-body {
      padding: 14px 18px 12px;
      display: flex;
      flex-direction: column;
      flex: 1;
    }

    .card-title {
      font-family: var(--font-display);
      font-size: 16px;
      font-weight: 700;
      line-height: 1.32;
      color: var(--text-main);
      margin-bottom: 6px;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
      min-height: 42px;
      transition: color 0.2s ease;
    }

    .inv-card:hover .card-title {
      color: var(--neon-lime);
    }

    .card-desc {
      color: var(--text-secondary);
      font-size: 12.5px;
      line-height: 1.42;
      margin-bottom: 12px;
      flex: 1;
      display: -webkit-box;
      -webkit-line-clamp: 3;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }

    /* Card Meta Footer */
    .card-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-top: auto;
      padding-top: 8px;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
    }

    .card-meta-left {
      display: flex;
      align-items: center;
      gap: 14px;
      font-size: 12px;
      color: var(--text-muted);
      font-family: var(--font-body);
    }

    .meta-date, .meta-readtime {
      display: flex;
      align-items: center;
      gap: 5px;
    }

    .meta-icon-svg {
      stroke: var(--text-muted);
      flex-shrink: 0;
    }

    .card-arrow-btn {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      border: 1px solid rgba(255, 255, 255, 0.15);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #F5F7FA;
      transition: all 0.2s ease;
      flex-shrink: 0;
    }

    .inv-card:hover .card-arrow-btn {
      background: var(--neon-lime);
      border-color: var(--neon-lime);
      color: #05090D;
      transform: translateX(2px);
    }

    /* Empty state */
    .empty-search-state {
      grid-column: 1 / -1;
      text-align: center;
      padding: 70px 20px;
      background: var(--bg-card);
      border: 1px dashed var(--border-card);
      border-radius: 16px;
    }

    .empty-search-state h3 {
      font-family: var(--font-display);
      font-size: 20px;
      color: #FFFFFF;
      margin-bottom: 8px;
    }

    .empty-search-state p {
      color: var(--text-secondary);
      font-size: 14px;
      margin-bottom: 20px;
    }

    .reset-btn {
      background: transparent;
      border: 1px solid var(--neon-lime);
      color: var(--neon-lime);
      padding: 8px 22px;
      border-radius: 9999px;
      font-size: 13.5px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .reset-btn:hover {
      background: var(--neon-lime);
      color: #05090D;
    }

    /* Responsive */
    @media (max-width: 1200px) {
      .hero-container {
        grid-template-columns: 1fr;
        gap: 36px;
      }
      .hero-cube-visual-wrapper {
        justify-content: center;
      }
      .hero-headline {
        font-size: 52px;
      }
      .investigations-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 900px) {
      .hero-container {
        grid-template-columns: 1fr;
        gap: 28px;
        padding: 0 24px;
      }
      .hero-stats-row {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 18px 20px;
        width: 100%;
        max-width: 480px;
      }
      .stat-vdivider {
        display: none;
      }
      .stat-item {
        flex-shrink: 1;
        min-width: 0;
      }
      .stat-label, .stat-sub {
        white-space: normal;
        overflow-wrap: break-word;
      }
      .hero-cube-visual-wrapper {
        max-width: 100%;
        justify-content: center;
      }
      .hero-cube-img {
        max-height: 320px;
      }
    }

    @media (max-width: 768px) {
      .site-nav {
        padding: 0 20px;
      }
      .nav-container {
        padding: 0;
      }
      .center-nav {
        display: none;
      }
      .brand-subtext {
        display: none;
      }
      .brand-vsep {
        display: none;
      }
      .hero-container {
        padding: 0 20px;
      }
      .hero-headline {
        font-size: clamp(36px, 8.5vw, 44px);
        letter-spacing: -1.2px;
      }
      .hero-lead-text {
        font-size: 14.5px;
      }
      .section-hdivider {
        padding: 0 20px;
      }
      .investigations-section {
        padding: 0 20px 60px;
      }
      .investigations-header {
        flex-direction: column;
        align-items: stretch;
        gap: 16px;
      }
      .header-controls-col {
        width: 100%;
        flex-direction: column;
        align-items: stretch;
        gap: 12px;
      }
      .search-input-wrapper {
        width: 100%;
      }
      .search-shortcut-badge {
        display: none;
      }
      .platform-filter-group {
        overflow-x: auto;
        width: 100%;
        white-space: nowrap;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: none;
        padding: 4px;
        gap: 6px;
      }
      .platform-filter-group::-webkit-scrollbar {
        display: none;
      }
      .filter-pill {
        flex-shrink: 0;
      }
      .investigations-grid {
        grid-template-columns: 1fr;
        gap: 20px;
      }
    }

    @media (max-width: 480px) {
      .site-nav {
        padding: 0 16px;
        height: 56px;
      }
      .brand-group {
        gap: 10px;
      }
      .brand-logo-img {
        width: 26px;
        height: 26px;
      }
      .brand-title {
        font-size: 16px;
        letter-spacing: 1px;
      }
      .right-nav-actions {
        gap: 10px;
      }
      .nav-search-icon-btn {
        width: 30px;
        height: 30px;
      }
      .btn-explore-reports {
        padding: 6px 12px;
        font-size: 12px;
        gap: 6px;
      }
      .btn-explore-reports svg {
        width: 12px;
        height: 12px;
      }
      .hero-section {
        padding: 14px 0 8px;
      }
      .hero-container {
        padding: 0 16px;
        gap: 20px;
      }
      .hero-eyebrow {
        margin-bottom: 8px;
      }
      .eyebrow-text {
        font-size: 10px;
        letter-spacing: 1px;
        white-space: normal;
        line-height: 1.35;
      }
      .hero-headline {
        font-size: clamp(32px, 8.5vw, 40px);
        letter-spacing: -1px;
        margin-bottom: 10px;
      }
      .hero-lead-text {
        font-size: 14px;
        line-height: 1.45;
        margin-bottom: 16px;
      }
      .hero-cta-group {
        margin-bottom: 20px;
      }
      .btn-cta-primary {
        width: 100%;
        justify-content: center;
        padding: 11px 20px;
        font-size: 13.5px;
      }
      .hero-stats-row {
        grid-template-columns: 1fr 1fr;
        gap: 14px 10px;
        width: 100%;
        max-width: 100%;
      }
      .stat-num {
        font-size: 24px;
      }
      .stat-label {
        font-size: 12px;
        white-space: normal;
      }
      .stat-sub {
        font-size: 10px;
        white-space: normal;
        line-height: 1.25;
      }
      .hero-cube-visual-wrapper {
        max-width: 100%;
        justify-content: center;
      }
      .hero-cube-img {
        max-height: 240px;
      }
      .section-hdivider {
        padding: 0 16px;
        margin: 2px auto 12px;
      }
      .investigations-section {
        padding: 0 16px 50px;
      }
      .inv-main-title {
        font-size: 23px;
      }
      .card-banner {
        height: 190px;
      }
      .card-content-body {
        padding: 14px 14px 12px;
      }
      .card-title {
        font-size: 15px;
        min-height: auto;
        margin-bottom: 6px;
      }
      .card-desc {
        font-size: 12px;
        margin-bottom: 10px;
      }
      .card-meta-left {
        gap: 10px;
        font-size: 11.5px;
      }
      .card-arrow-btn {
        width: 30px;
        height: 30px;
      }
    }
  </style>
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
          </div>
        </div>

        <div class="nav-link-item">
          <a class="nav-link" href="#investigations">
            <span>Malware Families</span>
            <svg class="nav-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none"><path d="M1 1L5 5L9 1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </a>
          <div class="nav-dropdown">
            <a href="rustbucket-2/index.html" class="dropdown-link">RustBucket (macOS)</a>
            <a href="digit-stealer/index.html" class="dropdown-link">Digit Stealer (JXA)</a>
            <a href="atomic-macos-stealer/index.html" class="dropdown-link">Atomic Stealer (AMOS)</a>
            <a href="wannacry/index.html" class="dropdown-link">WannaCry (SMB Worm)</a>
            <a href="bpfdoor/index.html" class="dropdown-link">BPFDoor (Linux)</a>
            <a href="qakbot-unpacking/index.html" class="dropdown-link">Qakbot (Banking)</a>
          </div>
        </div>

        <div class="nav-link-item">
          <a class="nav-link" href="#investigations">
            <span>Techniques</span>
            <svg class="nav-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none"><path d="M1 1L5 5L9 1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </a>
          <div class="nav-dropdown">
            <a href="unpacking-modified-upx-malware/index.html" class="dropdown-link">Modified UPX Unpacking</a>
            <a href="x64dbg-conditional-breakpoints/index.html" class="dropdown-link">x64dbg Breakpoints</a>
            <a href="dynamic-api-resolution/index.html" class="dropdown-link">Dynamic API Resolution</a>
            <a href="api-unhooking/index.html" class="dropdown-link">EDR API Unhooking</a>
            <a href="malware-binary-diffing/index.html" class="dropdown-link">BinDiff Code Comparison</a>
          </div>
        </div>
      </nav>

      <div class="right-nav-actions">
        <button class="nav-search-icon-btn" id="nav-search-btn" title="Search investigations (⌘K)" aria-label="Search">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        </button>
        <a href="#investigations" class="btn-explore-reports">
          <span>Explore Reports</span>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
        </a>
      </div>
    </div>
  </header>

  <!-- Hero Section -->
  <section class="hero-section">
    <div class="hero-container">
      <div class="hero-left-col">
        <div class="hero-eyebrow">
          <span class="eyebrow-dash"></span>
          <span class="eyebrow-text">INDEPENDENT THREAT RESEARCH &bull; 2024 &mdash; 2026</span>
        </div>

        <h1 class="hero-headline">
          <span class="hl-white">Understand</span><br>
          <span class="hl-white">the </span><span class="hl-lime">unknown.</span>
        </h1>

        <p class="hero-lead-text">
          Reverse engineering, malware analysis, and adversary tradecraft &mdash; documented through technical investigations.
        </p>

        <div class="hero-cta-group">
          <a href="#investigations" class="btn-cta-primary">
            <span>Explore investigations</span>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
          </a>
        </div>

        <div class="hero-stats-row">
          <div class="stat-item">
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
          <div class="stat-item">
            <div class="stat-num">${catCounts['Reverse Engineering Techniques'] || 14}</div>
            <div class="stat-label">Reverse Engineering</div>
            <div class="stat-sub">In-depth studies</div>
          </div>
          <div class="stat-vdivider" aria-hidden="true"></div>
          <div class="stat-item">
            <div class="stat-num">${catCounts['Malware Family Analysis'] || 12}</div>
            <div class="stat-label">Malware Families</div>
            <div class="stat-sub">Analyzed and documented</div>
          </div>
        </div>
      </div>

      <div class="hero-right-col">
        <div class="hero-cube-visual-wrapper">
          <img src="assets/home/hero-cube.png" alt="MARE 3D Binary Analysis HUD" class="hero-cube-img" width="876" height="474" fetchpriority="high">
        </div>
      </div>
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
          <button class="filter-pill active" data-filter="all" role="tab" aria-selected="true">All</button>
          <button class="filter-pill" data-filter="Windows" role="tab" aria-selected="false">Windows</button>
          <button class="filter-pill" data-filter="macOS" role="tab" aria-selected="false">macOS</button>
          <button class="filter-pill" data-filter="Linux" role="tab" aria-selected="false">Linux</button>
          <button class="filter-pill" data-filter="Cross-Platform" role="tab" aria-selected="false">Cross-platform</button>
        </div>
      </div>
    </div>

    <!-- Cards Stream Grid -->
    <div class="investigations-grid" id="investigations-grid">
      ${displayReports.map(r => {
        let fallbackImg = 'assets/home/card-threatintel.png';
        let badgeClass = 'badge-cross';
        let badgeText = r.os || 'Cross-platform';

        if (r.os === 'macOS') {
          fallbackImg = 'assets/home/card-macos.png';
          badgeClass = 'badge-macos';
          badgeText = 'macOS';
        } else if (r.os === 'Windows') {
          fallbackImg = 'assets/home/card-windows.png';
          badgeClass = 'badge-windows';
          badgeText = 'Windows';
        } else if (r.os === 'Linux') {
          fallbackImg = 'assets/home/card-threatintel.png';
          badgeClass = 'badge-linux';
          badgeText = 'Linux';
        } else {
          fallbackImg = 'assets/home/card-threatintel.png';
          badgeClass = 'badge-cross';
          badgeText = 'Cross-platform';
        }

        // Use first image from report if available, else clean platform banner
        let cardImg = r.firstImage ? `${r.id}/${r.firstImage}` : fallbackImg;

        // Custom exact overrides for the 3 featured reference cards
        let displayTitle = r.title;
        let displayDesc = r.lead || r.subtitle;
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

        const searchKeywords = `${displayTitle} ${displayDesc} ${r.category} ${r.os} ${r.family} ${r.targets} ${r.delivery}`.toLowerCase();

        return `
        <article class="inv-card" data-os="${escapeHtml(r.os)}" data-category="${escapeHtml(r.category)}" data-search="${escapeHtml(searchKeywords)}">
          <a href="${r.id}/index.html" class="card-banner" aria-label="${escapeHtml(displayTitle)}">
            <span class="card-platform-badge ${badgeClass}">${escapeHtml(badgeText)}</span>
            <img src="${cardImg}" alt="${escapeHtml(displayTitle)}" class="card-banner-img" loading="lazy">
          </a>
          <div class="card-content-body">
            <a href="${r.id}/index.html" style="text-decoration:none; color:inherit;">
              <h3 class="card-title">${escapeHtml(displayTitle)}</h3>
            </a>
            <p class="card-desc">${escapeHtml(displayDesc)}</p>
            <div class="card-footer">
              <div class="card-meta-left">
                <span class="meta-date">
                  <svg class="meta-icon-svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                  <span>${displayDate}</span>
                </span>
                <span class="meta-readtime">
                  <svg class="meta-icon-svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                  <span>${displayReadTime}</span>
                </span>
              </div>
              <a href="${r.id}/index.html" class="card-arrow-btn" aria-label="Read ${escapeHtml(displayTitle)}">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
              </a>
            </div>
          </div>
        </article>
        `;
      }).join('')}

      <div id="empty-search-state" class="empty-search-state" style="display:none;">
        <h3>No matching investigations</h3>
        <p>No research reports match your search query or selected platform filter.</p>
        <button class="reset-btn" onclick="resetFilters()">Reset All Filters</button>
      </div>
    </div>
  </section>

  <script>
    const searchInput = document.getElementById('live-search');
    const clearBtn = document.getElementById('search-clear-btn');
    const searchKbd = document.querySelector('.search-shortcut-badge');
    const filterPills = document.querySelectorAll('.filter-pill');
    const cards = document.querySelectorAll('.inv-card');
    const emptyState = document.getElementById('empty-search-state');

    let currentFilter = 'all';
    let searchQuery = '';

    function filterCards() {
      const q = searchQuery.trim().toLowerCase();
      let visible = 0;

      cards.forEach(card => {
        const cardOs = card.getAttribute('data-os');
        const cardSearch = card.getAttribute('data-search') || '';

        const osMatch = (currentFilter === 'all' || cardOs.toLowerCase() === currentFilter.toLowerCase());
        const searchMatch = !q || cardSearch.includes(q);

        if (osMatch && searchMatch) {
          card.style.display = 'flex';
          visible++;
        } else {
          card.style.display = 'none';
        }
      });

      if (emptyState) {
        emptyState.style.display = (visible === 0) ? 'block' : 'none';
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
    }

    function selectFilter(filterName) {
      currentFilter = filterName;
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
        filterCards();
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        searchInput.value = '';
        searchQuery = '';
        filterCards();
        searchInput.focus();
      });
    }

    function resetFilters() {
      if (searchInput) searchInput.value = '';
      searchQuery = '';
      selectFilter('all');
    }

    // Keyboard shortcuts: ⌘K or / to search, Esc to clear
    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (searchInput) searchInput.focus();
      } else if (e.key === '/' && document.activeElement !== searchInput) {
        e.preventDefault();
        if (searchInput) searchInput.focus();
      } else if (e.key === 'Escape' && document.activeElement === searchInput) {
        searchInput.value = '';
        searchQuery = '';
        filterCards();
        searchInput.blur();
      }
    });

    // Nav search trigger
    const navSearchBtn = document.getElementById('nav-search-btn');
    if (navSearchBtn) {
      navSearchBtn.addEventListener('click', () => {
        const invSec = document.getElementById('investigations');
        if (invSec) invSec.scrollIntoView({ behavior: 'smooth' });
        setTimeout(() => { if (searchInput) searchInput.focus(); }, 400);
      });
    }

    // Support URL param e.g. ?platform=Linux
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const p = urlParams.get('platform');
      if (p) selectFilter(p);
    } catch (e) {}
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
