const fs = require('fs');
const path = require('path');

const AUTHOR_NAME = 'Chandra Kant Bauri';

// Load the 37 verified .md reports from generate-reports.js
const grCode = fs.readFileSync(path.join(__dirname, 'generate-reports.js'), 'utf8');
const match = grCode.match(/const reports = (\[[\s\S]*?\n\];)/);
const reportsRaw = eval(match[1].replace(/;$/, ''));

const allReports = reportsRaw.map(r => {
  let iconType = 'binary';
  const fLower = (r.family + ' ' + r.category).toLowerCase();
  if (fLower.includes('stealer')) iconType = 'stealer';
  else if (fLower.includes('wiper') || fLower.includes('ransomware')) iconType = 'wiper';
  else if (fLower.includes('apt') || fLower.includes('persistent') || fLower.includes('espionage') || fLower.includes('regin')) iconType = 'apt';
  else if (fLower.includes('c2') || fLower.includes('beacon') || fLower.includes('backdoor') || fLower.includes('rat')) iconType = 'c2';
  else if (fLower.includes('botnet') || fLower.includes('mirai')) iconType = 'botnet';

  return {
    id: r.id,
    title: r.title,
    os: r.os,
    category: r.category,
    iconType: iconType,
    date: r.date,
    readTime: r.readTime,
    thumb: null,
    desc: r.lead,
    url: `${r.id}/index.html`,
    folder: path.dirname(r.src)
  };
});

// Helper to return tailored minimalist SVG threat icons
function getThreatIcon(type) {
  switch (type) {
    case 'stealer':
      return `<svg class="threat-svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-1.5 1.5L16 7l1.5 1.5L16 10l-1.5-1.5L13 10l-1.5-1.5L10 10 3 17v4h4l7-7 1.5 1.5 1.5-1.5-1.5-1.5L17 11l1.5-1.5L20 8l1-1z"/></svg>`;
    case 'wiper':
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

// Future-proof thumbnail resolver:
// 1. If dedicated SVG card exists in assets/thumbs/${r.id}.svg, use it!
// 2. If explicit thumb is provided, use it
// 3. For FUTURE reports: automatically detect the first screenshot from report directory!
function findFirstImage(dir) {
  if (!fs.existsSync(dir)) return null;
  try {
    const list = fs.readdirSync(dir);
    for (const f of list) {
      if (f.startsWith('.')) continue;
      const full = path.join(dir, f);
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        const found = findFirstImage(full);
        if (found) return found;
      } else if (/\.(png|jpe?g|webp|svg)$/i.test(f)) {
        return full;
      }
    }
  } catch (e) {}
  return null;
}

function resolveThumbnail(r) {
  // Check if dedicated high-res SVG threat card exists
  const svgThumb = `assets/thumbs/${r.id}.svg`;
  const localSvgPath = path.join(__dirname, 'reports', svgThumb);
  if (fs.existsSync(localSvgPath)) {
    return { url: svgThumb, isScreenshot: false };
  }

  // If explicit thumb is provided
  if (r.thumb) {
    return { url: r.thumb, isScreenshot: !r.thumb.endsWith('.svg') };
  }

  // Future reports: Automatically pick the first screenshot from report folder!
  if (r.folder) {
    try {
      const found = findFirstImage(path.join(__dirname, r.folder));
      if (found) {
        const relToReports = path.relative(path.join(__dirname, 'reports'), found).replace(/\\/g, '/');
        const encoded = relToReports.split('/').map(encodeURIComponent).join('/');
        return {
          url: encoded,
          isScreenshot: true
        };
      }
    } catch (e) {}
  }

  // Default fallback card
  return { url: 'assets/thumbs/digit-stealer.svg', isScreenshot: false };
}

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

const portalHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Threat Intelligence Research Portal | ${AUTHOR_NAME}</title>
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

    /* Top Navigation */
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

    /* Portal Container */
    .portal-container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 56px 48px 120px;
    }

    /* Header Section */
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

    /* Platform Subnav Filters */
    .platform-subnav {
      display: flex;
      gap: 12px;
      margin-top: 32px;
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

    /* Two-Column Editorial Layout */
    .portal-layout {
      display: grid;
      grid-template-columns: 280px minmax(0, 1fr);
      gap: 64px;
      align-items: start;
    }

    @media (max-width: 1024px) {
      .portal-layout {
        grid-template-columns: 1fr;
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
    }

    /* Left Sidebar: Topic Categories */
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

    /* Right Column: Reports List */
    .reports-stream {
      display: flex;
      flex-direction: column;
    }

    /* Group-IB Clean Editorial Row (NO BOX, NO CONTAINER, LEFT IMAGE / RIGHT CONTENT) */
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

    /* Left Image Column */
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

    /* Right Text Column */
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

    @media (max-width: 768px) {
      .report-entry {
        grid-template-columns: 1fr;
        gap: 20px;
      }
      .entry-image-col {
        aspect-ratio: 16 / 9;
      }
    }
  </style>
</head>
<body>

  <!-- Top Navigation -->
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
    
    <!-- Header Section -->
    <header class="header-section">
      <h1 class="header-title">Threat Intelligence</h1>
      <p class="header-desc">
        Independent cyber threat intelligence, technical malware analyses, and adversary tradecraft research by <span class="header-author-link">${AUTHOR_NAME}</span>.
      </p>

      <!-- Platform Subnav Filters -->
      <nav class="platform-subnav" aria-label="Operating System Filter">
        <button class="platform-btn active" data-filter="all">All Platforms <span class="count-badge">${counts.All}</span></button>
        <button class="platform-btn" data-filter="Windows">Windows <span class="count-badge">${counts.Windows}</span></button>
        <button class="platform-btn" data-filter="macOS">macOS <span class="count-badge">${counts.macOS}</span></button>
        <button class="platform-btn" data-filter="Linux">Linux <span class="count-badge">${counts.Linux}</span></button>
        <button class="platform-btn" data-filter="Cross-Platform">Cross-Platform <span class="count-badge">${counts['Cross-Platform']}</span></button>
      </nav>
    </header>

    <!-- Two-Column Editorial Layout -->
    <div class="portal-layout">
      
      <!-- Left Column: Topic Categories -->
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

      <!-- Right Column: Reports List -->
      <section class="reports-stream">
        ${allReports.map(r => {
          const thumbObj = resolveThumbnail(r);
          return `
          <article class="report-entry" data-os="${escapeHtml(r.os)}" data-category="${escapeHtml(r.category)}">
            <a href="${r.url}" class="full-card-link" aria-label="${escapeHtml(r.title)}"></a>
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
              <p class="entry-desc">${escapeHtml(r.desc)}</p>
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
    // Live interactive platform & category filtering
    const platformBtns = document.querySelectorAll('.platform-btn');
    const categoryItems = document.querySelectorAll('.category-item');
    const reports = document.querySelectorAll('.report-entry');

    let currentOs = 'all';
    let currentCat = 'all';

    function filterReports() {
      let visibleCount = 0;
      reports.forEach(report => {
        const reportOs = report.getAttribute('data-os');
        const reportCat = report.getAttribute('data-category');

        const osMatch = (currentOs === 'all' || reportOs === currentOs);
        const catMatch = (currentCat === 'all' || reportCat === currentCat);

        if (osMatch && catMatch) {
          report.style.display = 'grid';
          visibleCount++;
        } else {
          report.style.display = 'none';
        }
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
  </script>
</body>
</html>
`;

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const destPath = path.join(__dirname, 'reports', 'index.html');
fs.writeFileSync(destPath, portalHtml, 'utf8');
console.log(`[Success] Updated portal index: ${destPath}`);
console.log(`Total verified .md reports: ${totalCount}`);
console.log(`Windows: ${counts.Windows}, macOS: ${counts.macOS}, Linux: ${counts.Linux}, Cross-Platform: ${counts['Cross-Platform']}`);
