#!/usr/bin/env node
/**
 * MARE Report Validator & Linter
 * Ensures all technical analyses maintain publication-grade integrity,
 * valid metadata schema, sanitized image assets, and verified IoCs.
 */

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const ANALYSIS_DIR = path.join(ROOT_DIR, 'Malware Analysis');
const PLATFORMS = ['Windows', 'macOS', 'Linux', 'Cross-Platform'];

// Colors for terminal output
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';
const DIM = '\x1b[2m';

const VALID_CATEGORIES = new Set([
  'Malware Family Analysis',
  'Threat Intelligence & APTs',
  'Reverse Engineering Techniques',
  'Ransomware & Wipers'
]);

let totalReports = 0;
let totalErrors = 0;
let totalWarnings = 0;

console.log(`${BOLD}${CYAN}=== MARE Pre-Flight Technical Report Validator ===${RESET}\n`);

if (!fs.existsSync(ANALYSIS_DIR)) {
  console.error(`${RED}Error: Malware Analysis directory not found at ${ANALYSIS_DIR}${RESET}`);
  process.exit(1);
}

PLATFORMS.forEach(os => {
  const osDir = path.join(ANALYSIS_DIR, os);
  if (!fs.existsSync(osDir)) return;

  const entries = fs.readdirSync(osDir).filter(e => !e.startsWith('.') && fs.statSync(path.join(osDir, e)).isDirectory());

  entries.forEach(dirName => {
    totalReports++;
    const fullDir = path.join(osDir, dirName);
    const mdPath = path.join(fullDir, 'README.md');
    const metaPath = path.join(fullDir, 'meta.json');

    const errors = [];
    const warnings = [];

    // 1. Check README.md
    if (!fs.existsSync(mdPath)) {
      errors.push(`Missing README.md in investigation folder`);
    } else {
      const mdContent = fs.readFileSync(mdPath, 'utf8');

      // Check for Heading 1
      if (!mdContent.match(/^#\s+.+$/m)) {
        warnings.push(`README.md lacks a primary '# Title' heading`);
      }

      // Check for unclosed code blocks
      const codeFenceCount = (mdContent.match(/```/g) || []).length;
      if (codeFenceCount % 2 !== 0) {
        errors.push(`Unclosed markdown code block detected (odd count of \`\`\` fences: ${codeFenceCount})`);
      }

      // Check all markdown images
      const imgRegex = /!\[([^\]]*)\]\(([^)]+)\)|<img[^>]+src=["']([^"']+)["']/gi;
      let imgMatch;
      while ((imgMatch = imgRegex.exec(mdContent)) !== null) {
        const rawSrc = (imgMatch[2] || imgMatch[3] || '').trim();
        if (!rawSrc) continue;

        // Skip remote URLs
        if (rawSrc.startsWith('http://') || rawSrc.startsWith('https://')) continue;

        const cleanSrc = decodeURIComponent(rawSrc.split('#')[0].split('?')[0]);
        const absImgPath = path.resolve(fullDir, cleanSrc);

        if (!fs.existsSync(absImgPath)) {
          errors.push(`Broken image reference: "${rawSrc}" does not exist on disk`);
        } else {
          // Check for unsafe characters in original local image filename
          const baseName = path.basename(absImgPath);
          if (/[ ()\[\]]/.test(baseName)) {
            warnings.push(`Image filename contains spaces or parentheses: "${baseName}" (recommend snake_case or hyphens)`);
          }
        }
      }
    }

    // 2. Check meta.json
    if (!fs.existsSync(metaPath)) {
      warnings.push(`No meta.json found — report relies entirely on dynamic build heuristics`);
    } else {
      try {
        const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));

        if (!meta.title) warnings.push(`meta.json missing 'title' field`);
        if (meta.category && !VALID_CATEGORIES.has(meta.category)) {
          warnings.push(`Unrecognized category: "${meta.category}". Standard categories are: ${Array.from(VALID_CATEGORIES).join(', ')}`);
        }

        // Validate hash formatting if present
        if (meta.hashVal) {
          const h = meta.hashVal.trim();
          if (meta.hashType === 'SHA-256' && !/^[a-fA-F0-9]{64}$/.test(h)) {
            warnings.push(`Invalid SHA-256 format in meta.json: "${h}" (expected 64 hex characters)`);
          } else if (meta.hashType === 'MD5' && !/^[a-fA-F0-9]{32}$/.test(h)) {
            warnings.push(`Invalid MD5 format in meta.json: "${h}" (expected 32 hex characters)`);
          }
        }
      } catch (err) {
        errors.push(`Invalid JSON syntax in meta.json: ${err.message}`);
      }
    }

    // Report status
    if (errors.length > 0) {
      totalErrors += errors.length;
      console.log(`${RED}✗ [${os}] ${dirName}${RESET}`);
      errors.forEach(e => console.log(`   ${RED}• ERROR: ${e}${RESET}`));
      warnings.forEach(w => console.log(`   ${YELLOW}• WARN: ${w}${RESET}`));
    } else if (warnings.length > 0) {
      totalWarnings += warnings.length;
      console.log(`${YELLOW}⚠ [${os}] ${dirName}${RESET}`);
      warnings.forEach(w => console.log(`   ${YELLOW}• WARN: ${w}${RESET}`));
    }
  });
});

console.log(`\n${BOLD}========================================${RESET}`);
console.log(`${BOLD}Total Reports Audited:${RESET} ${totalReports}`);
console.log(`${BOLD}Errors:${RESET}   ${totalErrors === 0 ? GREEN + '0' : RED + totalErrors}${RESET}`);
console.log(`${BOLD}Warnings:${RESET} ${totalWarnings === 0 ? GREEN + '0' : YELLOW + totalWarnings}${RESET}`);

if (totalErrors > 0) {
  console.log(`\n${RED}${BOLD}Validation failed with ${totalErrors} error(s). Please fix before building.${RESET}\n`);
  process.exit(1);
} else {
  console.log(`\n${GREEN}${BOLD}✓ All reports passed pre-flight validation!${RESET}\n`);
  process.exit(0);
}
