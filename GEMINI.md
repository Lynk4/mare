# MARE Project Memory & Development Guidelines

> **Project**: MARE (Malware Analysis & Reverse Engineering)  
> **Author & Lead Researcher**: Chandra Kant Bauri ([@Lynk4](https://github.com/Lynk4) | [@c_kant_](https://x.com/c_kant_))  
> **Repository**: [Lynk4/mare](https://github.com/Lynk4/mare.git)  
> **Primary Tagline**: `BREAK THE BINARY. // INTELLIGENCE BEYOND INDICATORS.`  
> **Eyebrow**: `INDEPENDENT THREAT RESEARCH`  
> **Headline**: `Tracing the unknown`

---

## 1. System Architecture & Directory Map

MARE is an autonomous, publication-grade threat intelligence and binary dissection portal. It generates 100% self-contained static HTML pages with zero external runtime dependencies.

```
mare/
├── Malware Analysis/               # Primary investigation reports
│   ├── Windows/                    # Windows malware, PE internals, MalOps writeups
│   ├── Linux/                      # Linux rootkits, ELF analysis, BPFDoor, Singularity
│   ├── macOS/                      # macOS Mach-O teardowns, AMOS, RustBucket, Avenger Stealer
│   └── Cross-Platform/             # Cross-platform frameworks, CTF challenges
├── assets/
│   └── home/                       # Core branding, hero cover, platform badges, logo
├── external/                       # Local git cache (git-ignored, used by sync pipeline)
│   └── malops/                     # Shallow clone of Lynk4/malops.io
├── scripts/
│   ├── build.js                    # Core static site generator and report compiler
│   └── sync-malops.js              # MalOps automated challenge ingestion engine
├── reports/                        # Production build output (git-ignored, built via npm run build)
├── package.json                    # npm scripts: "build", "sync:malops", "build:all"
├── GEMINI.md                       # Project memory, rules, and development guidelines (this file)
└── .gitignore                      # Ignores reports/, external/, .DS_Store, binaries (*.exe, *.dll)
```

---

## 2. Core Decisions & UI/UX History

### A. Hero Section & Typography
- **Tagline**: `⚡ BREAK THE BINARY. // INTELLIGENCE BEYOND INDICATORS.` with a green blinking cursor (`.blinking-cursor`).
- **Cover Image**: Positioned to balance text readability on the left and cybersecurity workstation graphics on the right on both standard laptops and ultrawide external monitors (`assets/home/threat_analyst_reverse_engineer_cover_png_1793306087136.jpg`).
- **Color Palette**: Neon lime (`--neon-lime: #B7FF3C`), cyan (`--neon-cyan: #35E5D0`), deep dark terminal background (`#0A0D12` / `#0D1117`).

### B. Investigation Cards & Dynamic Pagination
- **Initial Load**: Shows 9 latest reports on the homepage.
- **Load More Button**: Dynamic remaining count, e.g., `Load more Investigations (41 remaining)`. Updates automatically when new reports are added.
- **Hero Stats**: Dynamic stat counters (Total Investigations, Platforms, Reverse Engineering, Malware Families) computed at build time.

### C. Report Pages & Table of Contents (TOC)
- **Instant Jump + Glow**: Smooth scrolling was replaced with instant jump (`scroll-behavior: auto !important;`) to eliminate page stutter and blank-screen delays on long, media-heavy technical reports.
- **Target Glow**: Active target heading briefly pulses with an ambient glow (`@keyframes target-heading-glow`) to visually anchor the reader.
- **Mobile Compatibility**: Fully verified and responsive across desktop, tablet, and mobile viewport widths.

---

## 3. Workflow for Adding New Malware Analyses

When adding or updating an investigation:
1. **Directory Placement**:
   Place under `Malware Analysis/<Platform>/<Report Folder Name>/`.
   Must contain `README.md` and an image assets folder.
2. **Image Asset Rules**:
   - Sanitize all image filenames: use alphanumeric characters, underscores, or hyphens (e.g. `image_1.png` instead of `image (1).png`).
   - Markdown image links must be properly formatted: `![Caption](Folder/filename.png)`.
3. **`meta.json` Schema**:
   Always create a `meta.json` in the report folder:
   ```json
   {
     "id": "slug-name",
     "title": "Full Technical Title",
     "subtitle": "2-3 sentence technical synopsis for card and search",
     "lead": "Executive summary paragraph",
     "category": "Malware Family Analysis | Threat Intelligence & APTs | Reverse Engineering Techniques | Ransomware & Wipers",
     "date": "Month DD, YYYY",
     "readTime": "XX min read",
     "family": "Malware Family Name",
     "classification": "Technical classification string",
     "delivery": "Delivery vector / loader mechanism",
     "c2": "C2 protocol / endpoint",
     "targets": "Targeted assets and environments",
     "hashType": "SHA-256 | MD5",
     "hashVal": "<verified hash string>",
     "thumbnail": "images/<banner_image_name>.png",
     "featured": true,
     "navDropdown": "malware | techniques",
     "navTitle": "Short Nav Label"
   }
   ```
4. **Build Engine Registration**:
   In `scripts/build.js`:
   - Add entry to `CANONICAL_REPORT_DATES` with the authentic publication date.
   - Add entry to `KNOWN_NAV_TITLES` if a custom short label is preferred.
5. **Clean & Compile**:
   - Remove any local `.DS_Store` files before staging.
   - Run `npm run build` (`node scripts/build.js`).
   - Verify report output in `reports/<slug>/index.html` and homepage card in `reports/index.html`.
6. **Deploy**:
   - Stage source files and `scripts/build.js`.
   - Commit with clear message: `feat(<platform>): add <Name> analysis, meta.json, and assets`.
   - Push to `origin main`.

---

## 4. Standing Rules for Technical Reporting

- **Never Assume or Guess**: Every statement, IOC, API behavior, and capability must be verified directly against the binary, assembly, or dynamic trace.
- **Disassemble Call Sites**: Never infer behavior from an imported symbol name alone. Verify registers, parameters, and match limits (e.g., single item vs. bulk extraction).
- **Disk Verification**: Never generate hashes from memory. Compute SHA-256 and MD5 directly from the file on disk.
- **Zero-FP Signatures**: YARA and Sigma rules must be anchored with file magic, size caps, and multi-indicator behavioral clusters.
