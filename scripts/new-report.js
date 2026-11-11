#!/usr/bin/env node
/**
 * MARE Autonomous Report Scaffolder
 * Generates publication-grade report templates with zero external dependencies.
 * Automatically computes authentic cryptographic hashes and identifies file formats
 * if a local sample binary is provided.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const ROOT_DIR = path.resolve(__dirname, '..');
const ANALYSIS_DIR = path.join(ROOT_DIR, 'Malware Analysis');

const PLATFORMS = {
  1: 'Windows',
  2: 'macOS',
  3: 'Linux',
  4: 'Cross-Platform'
};

const CATEGORIES = {
  1: 'Malware Family Analysis',
  2: 'Threat Intelligence & APTs',
  3: 'Reverse Engineering Techniques',
  4: 'Ransomware & Wipers'
};

function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-');
}

function formatDate(date) {
  const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  return `${months[date.getMonth()]} ${String(date.getDate()).padStart(2, '0')}, ${date.getFullYear()}`;
}

// Inspect binary header magic and compute cryptographic hashes directly from disk
function inspectSampleFile(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const stats = fs.statSync(filePath);
  if (!stats.isFile()) return null;

  const buffer = fs.readFileSync(filePath);
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const md5 = crypto.createHash('md5').update(buffer).digest('hex');
  const sizeBytes = stats.size;
  const sizeFormatted = sizeBytes > 1024 * 1024
    ? `${(sizeBytes / (1024 * 1024)).toFixed(2)} MB (${sizeBytes.toLocaleString()} bytes)`
    : `${(sizeBytes / 1024).toFixed(2)} KB (${sizeBytes.toLocaleString()} bytes)`;

  let magic = 'Binary Telemetry Artifact';
  let suggestedPlatform = 'Windows';
  let arch = 'x86_64';

  if (buffer.length >= 4) {
    if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
      suggestedPlatform = 'Windows';
      magic = 'PE32/PE64 Executable (MZ)';
      arch = buffer.length > 0x3c + 4 && buffer[0x3c] === 0x50 ? 'x86_64 PE' : 'PE';
    } else if (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
      suggestedPlatform = 'Linux';
      const is64 = buffer[4] === 2;
      arch = is64 ? 'ELF 64-bit' : 'ELF 32-bit';
      magic = `ELF ${is64 ? '64-bit' : '32-bit'} executable`;
    } else if (buffer.readUInt32LE(0) === 0xfeedfacf) {
      suggestedPlatform = 'macOS';
      arch = buffer.readUInt32LE(4) === 0x0100000c ? 'ARM64 (Apple Silicon)' : 'x86_64 Mach-O';
      magic = `Mach-O 64-bit executable (${arch})`;
    } else if (buffer.readUInt32BE(0) === 0xcafebabe) {
      suggestedPlatform = 'macOS';
      arch = 'Universal Fat Binary';
      magic = 'Mach-O Universal Binary';
    }
  }

  return { sha256, md5, sizeBytes, sizeFormatted, magic, suggestedPlatform, arch };
}

function promptAsync(rl, question, defaultVal = '') {
  return new Promise(resolve => {
    const promptText = defaultVal ? `${question} [${defaultVal}]: ` : `${question}: `;
    rl.question(promptText, ans => {
      resolve(ans.trim() || defaultVal);
    });
  });
}

async function main() {
  console.log('\n\x1b[1m\x1b[36m⚡ MARE — Technical Investigation Scaffolder\x1b[0m\n');

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    // 1. Optional binary sample inspection
    const sampleInput = await promptAsync(rl, 'Local binary sample path (optional, press Enter to skip)');
    let sampleData = null;
    if (sampleInput) {
      const resolvedPath = path.resolve(process.cwd(), sampleInput);
      sampleData = inspectSampleFile(resolvedPath);
      if (sampleData) {
        console.log(`\n\x1b[32m✓ Verified Sample on Disk:\x1b[0m`);
        console.log(`  • Platform: ${sampleData.suggestedPlatform}`);
        console.log(`  • Architecture: ${sampleData.arch}`);
        console.log(`  • SHA-256: ${sampleData.sha256}`);
        console.log(`  • MD5:     ${sampleData.md5}`);
        console.log(`  • Size:    ${sampleData.sizeFormatted}\n`);
      } else {
        console.log(`\x1b[33m⚠ File not found or unreadable. Continuing manual entry.\x1b[0m\n`);
      }
    }

    // 2. Platform Selection
    console.log('Select Target Platform:');
    console.log('  1) Windows\n  2) macOS\n  3) Linux\n  4) Cross-Platform');
    const defaultPlatNum = sampleData && sampleData.suggestedPlatform === 'macOS' ? '2' : (sampleData && sampleData.suggestedPlatform === 'Linux' ? '3' : '1');
    const platChoice = await promptAsync(rl, 'Choice (1-4)', defaultPlatNum);
    const platform = PLATFORMS[parseInt(platChoice, 10)] || 'Windows';

    // 3. Metadata fields
    const family = await promptAsync(rl, 'Malware Family or Threat Name (e.g. Lumma Stealer, Avenger)');
    const defaultFolder = family ? family : 'New Threat Investigation';
    const folderName = await promptAsync(rl, 'Folder Name', defaultFolder);

    const defaultTitle = `${family}: Comprehensive Static and Dynamic Analysis`;
    const title = await promptAsync(rl, 'Full Technical Title', defaultTitle);

    const defaultSlug = slugify(folderName);
    const slug = await promptAsync(rl, 'URL Slug', defaultSlug);

    console.log('\nSelect Category Taxonomy:');
    console.log('  1) Malware Family Analysis\n  2) Threat Intelligence & APTs\n  3) Reverse Engineering Techniques\n  4) Ransomware & Wipers');
    const catChoice = await promptAsync(rl, 'Choice (1-4)', '1');
    const category = CATEGORIES[parseInt(catChoice, 10)] || 'Malware Family Analysis';

    const defaultClassification = `${platform} ${category === 'Ransomware & Wipers' ? 'Ransomware / Wiper' : (category === 'Threat Intelligence & APTs' ? 'Espionage Backdoor' : 'Infostealer')}`;
    const classification = await promptAsync(rl, 'Classification', defaultClassification);

    const delivery = await promptAsync(rl, 'Delivery Vector', platform === 'macOS' ? 'Ad-Hoc Signed Mach-O Dropper' : 'Staged Executable / Dropper');
    const c2 = await promptAsync(rl, 'C2 Protocol / Host', 'HTTPS / Custom JSON Protocol');
    const targets = await promptAsync(rl, 'Target Assets', platform === 'macOS' ? 'User Credentials, macOS Keychains, Web Browsers' : 'System Memory, Browser Sessions, Endpoints');

    const hashType = sampleData ? 'SHA-256' : 'SHA-256';
    const hashVal = sampleData ? sampleData.sha256 : await promptAsync(rl, 'Sample Hash (SHA-256 or MD5)', '0000000000000000000000000000000000000000000000000000000000000000');
    const md5Val = sampleData ? sampleData.md5 : '00000000000000000000000000000000';

    const defaultSubtitle = `Reverse engineering and behavioral dissection of ${family}, uncovering execution pipelines, persistence vectors, and command-and-control infrastructure.`;
    const subtitle = await promptAsync(rl, 'Technical Synopsis (1-2 sentences for card & search)', defaultSubtitle);

    const defaultNavTitle = family.length <= 22 ? family : family.slice(0, 20);
    const navTitle = await promptAsync(rl, 'Short Navigation Label', defaultNavTitle);

    const readTime = await promptAsync(rl, 'Estimated Read Time', '15 min read');
    const dateStr = formatDate(new Date());

    // 4. Create directory structure
    const targetDir = path.join(ANALYSIS_DIR, platform, folderName);
    const imagesDir = path.join(targetDir, 'images');

    if (fs.existsSync(targetDir)) {
      console.log(`\n\x1b[31mError: Target directory already exists at ${targetDir}\x1b[0m\n`);
      rl.close();
      return;
    }

    fs.mkdirSync(imagesDir, { recursive: true });

    // 5. Generate meta.json
    const metaPayload = {
      id: slug,
      title,
      subtitle,
      lead: subtitle,
      category,
      date: dateStr,
      readTime,
      family,
      classification,
      delivery,
      c2,
      targets,
      hashType,
      hashVal,
      thumbnail: 'images/cover.png',
      featured: true,
      navDropdown: category === 'Reverse Engineering Techniques' ? 'techniques' : 'malware',
      navTitle
    };

    fs.writeFileSync(path.join(targetDir, 'meta.json'), JSON.stringify(metaPayload, null, 2) + '\n', 'utf8');

    // 6. Generate README.md
    const readmeContent = `# ${title}

---

![${family} Technical Analysis](images/cover.png)

---

## Executive Summary

${subtitle}

---

# Sample Overview

| Property | Value |
| :--- | :--- |
| **Malware Family** | \`${family}\` |
| **Classification** | ${classification} |
| **Target Platform** | ${platform} |
| **Architecture** | \`${sampleData ? sampleData.arch : 'x86_64 / ARM64'}\` |
| **File Format / Magic** | \`${sampleData ? sampleData.magic : 'Executable Binary'}\` |
| **File Size** | \`${sampleData ? sampleData.sizeFormatted : 'N/A'}\` |
| **SHA-256** | \`${hashVal}\` |
| **MD5** | \`${md5Val}\` |

---

# Static Analysis & Binary Internals

Initial triage of the executable structure, dynamic library dependencies, and imported API symbols.

\`\`\`bash
# Triage dynamic imports and signature status
file ./${hashVal}
\`\`\`

### Key Imported Symbols

Detailed call-site analysis of critical subsystem imports and anti-analysis routines.

---

# Behavioral Telemetry & Execution Lifecycle

Trace of process invocation, memory allocation primitives, and persistence installations.

\`\`\`bash
# Telemetry trace
\`\`\`

---

# Command and Control (C2) Infrastructure

Analysis of network communication routines, cryptographic key exchange, and staging protocols.

| Indicator Type | Value / Address | Description |
| :--- | :--- | :--- |
| **Primary C2 Endpoint** | \`${c2}\` | Main exfiltration host |
| **Delivery Mechanism** | \`${delivery}\` | Initial infection vector |

---

# Detection Signatures

High-fidelity detection rule anchored with strict magic headers and multi-indicator behavioral clusters.

\`\`\`yara
rule Threat_${family.replace(/[^a-zA-Z0-9_]/g, '_')} {
    meta:
        description = "Detects ${family} ${classification} payloads"
        author = "Chandra Kant Bauri"
        date = "${dateStr.split(',')[1].trim()}-${String(new Date().getMonth() + 1).padStart(2, '0')}-${String(new Date().getDate()).padStart(2, '0')}"
        hash = "${hashVal}"

    strings:
        // Anchored behavioral indicators
        $magic = { 4D 5A } // Update based on architecture (e.g. CF FA ED FE for Mach-O)
        $str1  = "${family}" ascii nocase

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        all of them
}
\`\`\`

---

# Indicators of Compromise (IoCs)

### File Identifiers

| Component | SHA-256 Hash | MD5 Hash | Description |
| :--- | :--- | :--- | :--- |
| **Main Binary** | \`${hashVal}\` | \`${md5Val}\` | ${family} core agent |

### Network Telemetry

| Type | Indicator | Context |
| :--- | :--- | :--- |
| **C2 Server** | \`${c2}\` | Command and control endpoint |
`;

    fs.writeFileSync(path.join(targetDir, 'README.md'), readmeContent, 'utf8');

    console.log(`\n\x1b[32m\x1b[1m✓ Successfully created new investigation:\x1b[0m`);
    console.log(`  📁 Location: Malware Analysis/${platform}/${folderName}`);
    console.log(`  📄 Metadata: meta.json`);
    console.log(`  📝 Analysis: README.md`);
    console.log(`  🖼️ Assets:   images/\n`);
    console.log(`To validate your new report, run: \x1b[36mnpm run lint\x1b[0m`);
    console.log(`To compile the portal, run:       \x1b[36mnpm run build\x1b[0m\n`);

  } catch (err) {
    console.error(`\x1b[31mError generating report: ${err.message}\x1b[0m`);
  } finally {
    rl.close();
  }
}

main();
