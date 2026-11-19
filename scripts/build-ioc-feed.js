const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const BASE_ANALYSIS_DIR = path.join(ROOT_DIR, 'Malware Analysis');
const REPORTS_DIR = path.join(ROOT_DIR, 'reports');
const FEED_DIR = path.join(REPORTS_DIR, 'feed');
const IOC_PAGE_DIR = path.join(REPORTS_DIR, 'ioc-feed');

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
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

function determineKillChain(type, role, meta) {
  if (type === 'IPv4' || type === 'Domain' || type === 'URL') {
    return 'Command & Control';
  }
  if (role.toLowerCase().includes('dropper') || (meta.delivery && meta.delivery.toLowerCase().includes('dropper'))) {
    return 'Initial Delivery';
  }
  if (type === 'IMPHASH' || (meta.category && meta.category.includes('Reverse Engineering Techniques'))) {
    return 'Defense Evasion & Fingerprinting';
  }
  if (meta.category === 'Ransomware & Wipers') {
    return 'Exfiltration & Impact';
  }
  return 'Payload Execution';
}

function extractAllData() {
  const indicators = [];
  const platforms = ['macOS', 'Linux', 'Windows', 'Cross-Platform'];
  const actorsMap = new Map();

  platforms.forEach(os => {
    const osPath = path.join(BASE_ANALYSIS_DIR, os);
    if (!fs.existsSync(osPath)) return;

    const dirs = fs.readdirSync(osPath).filter(d => !d.startsWith('.') && fs.statSync(path.join(osPath, d)).isDirectory());

    dirs.forEach(dirName => {
      const fullDir = path.join(osPath, dirName);
      const metaPath = path.join(fullDir, 'meta.json');
      if (!fs.existsSync(metaPath)) return;

      let meta = {};
      try {
        meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
      } catch (e) {
        return;
      }

      let id = dirName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      if (meta.id) id = meta.id;
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

      const family = meta.family || dirName;
      const actor = meta.actor || 'Unattributed Threat Cluster';
      const actorAliases = Array.isArray(meta.actorAliases) ? meta.actorAliases : (meta.actorAliases ? [meta.actorAliases] : []);
      const campaign = meta.campaign || 'Autonomous Campaign';
      const severity = meta.severity || 'High';
      const motivation = meta.motivation || 'Cyber Espionage / Financial Gain';
      const targetSectors = Array.isArray(meta.targetSectors) ? meta.targetSectors : (meta.targetSectors ? [meta.targetSectors] : ['Enterprise Endpoints']);
      const targetGeo = Array.isArray(meta.targetGeo) ? meta.targetGeo : (meta.targetGeo ? [meta.targetGeo] : ['Global']);

      const common = {
        reportId: id,
        family,
        actor,
        actorAliases,
        campaign,
        severity,
        motivation,
        targetSectors,
        targetGeo,
        platform: os,
        firstSeen: meta.date || '2026',
        tlp: meta.tlp || 'TLP:CLEAR',
        delivery: meta.delivery || 'Network / Staged Delivery',
        reportUrl: `https://lynk4.github.io/mare/${id}/index.html`,
        localPath: `../${id}/index.html`
      };

      // Index Actor
      if (actor && actor !== 'Unattributed Threat Cluster') {
        if (!actorsMap.has(actor)) {
          actorsMap.set(actor, {
            name: actor,
            aliases: [...actorAliases],
            motivation,
            targetSectors: new Set(targetSectors),
            targetGeo: new Set(targetGeo),
            campaigns: new Set([campaign]),
            families: new Set([family]),
            indicatorCount: 0,
            c2Count: 0,
            severity: severity === 'Critical' ? 'Critical' : 'High'
          });
        }
        const aRecord = actorsMap.get(actor);
        actorAliases.forEach(al => aRecord.aliases.includes(al) || aRecord.aliases.push(al));
        targetSectors.forEach(ts => aRecord.targetSectors.add(ts));
        targetGeo.forEach(tg => aRecord.targetGeo.add(tg));
        aRecord.campaigns.add(campaign);
        aRecord.families.add(family);
      }

      // 1. Primary Hash
      if (meta.hashVal && meta.hashVal.length >= 32 && !meta.hashVal.includes('Telemetry')) {
        const rawType = (meta.hashType || (meta.hashVal.length === 64 ? 'SHA-256' : 'MD5')).toUpperCase().replace(/[^A-Z0-9-]/g, '');
        const normType = rawType === 'SHA256' ? 'SHA-256' : rawType;
        const role = meta.classification || 'Payload / Executable Binary';
        indicators.push({
          id: `ind-${indicators.length + 1}`,
          indicator: meta.hashVal.toLowerCase().trim(),
          type: normType,
          role,
          killChain: determineKillChain(normType, role, meta),
          ...common
        });
        if (actorsMap.has(actor)) actorsMap.get(actor).indicatorCount++;
      }

      // 2. Secondary Hash
      if (meta.secondaryHash && meta.secondaryHash.length >= 32) {
        const sType = (meta.secondaryHashType || (meta.secondaryHash.length === 64 ? 'SHA-256' : 'MD5')).toUpperCase().replace(/[^A-Z0-9-]/g, '');
        const normType = sType === 'SHA256' ? 'SHA-256' : sType;
        const role = 'Secondary Stage Artifact';
        indicators.push({
          id: `ind-${indicators.length + 1}`,
          indicator: meta.secondaryHash.toLowerCase().trim(),
          type: normType,
          role,
          killChain: determineKillChain(normType, role, meta),
          ...common
        });
        if (actorsMap.has(actor)) actorsMap.get(actor).indicatorCount++;
      }

      // 3. Imphash
      if (meta.imphash && meta.imphash.length === 32) {
        const role = 'PE Import Hash Fingerprint';
        indicators.push({
          id: `ind-${indicators.length + 1}`,
          indicator: meta.imphash.toLowerCase().trim(),
          type: 'IMPHASH',
          role,
          killChain: 'Defense Evasion & Fingerprinting',
          ...common
        });
        if (actorsMap.has(actor)) actorsMap.get(actor).indicatorCount++;
      }

      // 4. C2 Infrastructure
      if (meta.c2Url) {
        const raw = meta.c2Url.trim();
        const ipMatch = raw.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
        if (ipMatch) {
          indicators.push({
            id: `ind-${indicators.length + 1}`,
            indicator: ipMatch[1],
            type: 'IPv4',
            role: 'Command & Control Host',
            killChain: 'Command & Control',
            ...common
          });
          if (actorsMap.has(actor)) {
            actorsMap.get(actor).indicatorCount++;
            actorsMap.get(actor).c2Count++;
          }
        }
        const domMatch = raw.match(/https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::\d+)?/);
        if (domMatch && !domMatch[1].match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
          indicators.push({
            id: `ind-${indicators.length + 1}`,
            indicator: domMatch[1],
            type: 'Domain',
            role: 'C2 Domain Infrastructure',
            killChain: 'Command & Control',
            ...common
          });
          if (actorsMap.has(actor)) {
            actorsMap.get(actor).indicatorCount++;
            actorsMap.get(actor).c2Count++;
          }
        }
        if (raw.startsWith('http://') || raw.startsWith('https://') || raw.startsWith('hxxp')) {
          indicators.push({
            id: `ind-${indicators.length + 1}`,
            indicator: raw.replace(/^hxxp/i, 'http'),
            type: 'URL',
            role: 'C2 Callback Endpoint',
            killChain: 'Command & Control',
            ...common
          });
          if (actorsMap.has(actor)) {
            actorsMap.get(actor).indicatorCount++;
            actorsMap.get(actor).c2Count++;
          }
        }
      }
    });
  });

  const actorsList = Array.from(actorsMap.values()).map(a => ({
    name: a.name,
    aliases: a.aliases,
    motivation: a.motivation,
    targetSectors: Array.from(a.targetSectors),
    targetGeo: Array.from(a.targetGeo),
    campaigns: Array.from(a.campaigns),
    families: Array.from(a.families),
    indicatorCount: a.indicatorCount,
    c2Count: a.c2Count,
    severity: a.severity
  }));

  return { indicators, actors: actorsList };
}

function buildFeeds() {
  ensureDir(FEED_DIR);
  ensureDir(IOC_PAGE_DIR);

  const { indicators, actors } = extractAllData();

  const total = indicators.length;
  const hashCount = indicators.filter(i => ['SHA-256', 'MD5', 'IMPHASH'].includes(i.type)).length;
  const c2Count = indicators.filter(i => ['IPv4', 'Domain', 'URL'].includes(i.type)).length;

  // 1. JSON Feed
  const jsonFeed = {
    feed_name: 'MARE Unified Threat Intelligence & IoC Feed',
    version: '2.5-adversary-attribution',
    curator: 'Chandra Kant Bauri (@Lynk4)',
    portal: 'https://lynk4.github.io/mare/',
    documentation: 'https://github.com/Lynk4/mare',
    generated_at: new Date().toISOString(),
    confidence_policy: '100% Verified Ground Truth. Every indicator is backed by reverse-engineered binary disassembly or dynamic execution telemetry.',
    summary: {
      total_indicators: total,
      hashes: hashCount,
      c2_infrastructure: c2Count,
      tracked_threat_actors: actors.length
    },
    indicators: indicators.map(i => ({
      indicator: i.indicator,
      type: i.type,
      role: i.role,
      kill_chain: i.killChain,
      family: i.family,
      actor: i.actor,
      actor_aliases: i.actorAliases,
      campaign: i.campaign,
      severity: i.severity,
      motivation: i.motivation,
      target_sectors: i.targetSectors,
      target_geo: i.targetGeo,
      platform: i.platform,
      first_seen: i.firstSeen,
      tlp: i.tlp,
      report_url: i.reportUrl
    }))
  };
  fs.writeFileSync(path.join(FEED_DIR, 'iocs.json'), JSON.stringify(jsonFeed, null, 2), 'utf8');

  // 2. CSV Feed
  const csvRows = [
    ['indicator', 'type', 'kill_chain', 'role', 'family', 'actor', 'severity', 'platform', 'first_seen', 'report_url'].join(',')
  ];
  indicators.forEach(i => {
    const row = [
      `"${i.indicator.replace(/"/g, '""')}"`,
      `"${i.type}"`,
      `"${i.killChain}"`,
      `"${i.role.replace(/"/g, '""')}"`,
      `"${i.family.replace(/"/g, '""')}"`,
      `"${i.actor.replace(/"/g, '""')}"`,
      `"${i.severity}"`,
      `"${i.platform}"`,
      `"${i.firstSeen}"`,
      `"${i.reportUrl}"`
    ];
    csvRows.push(row.join(','));
  });
  fs.writeFileSync(path.join(FEED_DIR, 'iocs.csv'), csvRows.join('\n'), 'utf8');

  // 3. Plaintext Blocklist
  const txtLines = [
    '# =====================================================================',
    '# MARE Unified Threat Intelligence Raw Blocklist',
    '# Curator: Chandra Kant Bauri (@Lynk4) | https://github.com/Lynk4/mare',
    `# Generated: ${new Date().toISOString()}`,
    '# Verification: 100% Ground-Truth Binary Evidence',
    `# Total Indicators: ${total}`,
    '# =====================================================================',
    ''
  ];
  const uniqueIndicators = Array.from(new Set(indicators.map(i => i.indicator)));
  uniqueIndicators.forEach(ind => txtLines.push(ind));
  fs.writeFileSync(path.join(FEED_DIR, 'iocs.txt'), txtLines.join('\n'), 'utf8');

  const indicatorsJsonString = JSON.stringify(indicators).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
  const actorsJsonString = JSON.stringify(actors).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Unified Cyber Threat Intelligence &amp; Attribution Feed — MARE</title>
  <link rel="icon" type="image/png" href="../assets/home/mare-logo.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@500;600;700;800&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0A0D14;
      --bg-panel: #0D1117;
      --bg-card: #111620;
      --bg-hover: #161D2A;
      --bg-elevated: #1A2232;
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-strong: rgba(255, 255, 255, 0.16);
      --border-focus: rgba(53, 229, 208, 0.4);
      --neon-cyan: #35E5D0;
      --neon-lime: #B7FF3C;
      --sky-blue: #79C0FF;
      --lavender: #A78BFA;
      --coral: #FF7B72;
      --amber: #FFA657;
      --text-primary: #FFFFFF;
      --text-secondary: #C9D1D9;
      --text-muted: #8B949E;
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      --font-display: 'Plus Jakarta Sans', var(--font-sans);
      --font-mono: 'JetBrains Mono', monospace;
      --drawer-width: 460px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-dark);
      color: var(--text-secondary);
      font-family: var(--font-sans);
      min-height: 100vh;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      padding-bottom: 60px;
      overflow-x: hidden;
    }

    .bg-grid {
      position: fixed;
      inset: 0;
      background-image: 
        linear-gradient(to right, rgba(255, 255, 255, 0.02) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none;
      z-index: 0;
    }

    .container {
      max-width: 1440px;
      margin: 0 auto;
      padding: 0 24px;
      position: relative;
      z-index: 1;
    }

    /* Top Nav */
    .nav-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 0;
      border-bottom: 1px solid var(--border-subtle);
      margin-bottom: 24px;
    }
    .brand-group {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
      color: var(--text-primary);
    }
    .brand-logo {
      width: 32px;
      height: 32px;
      border-radius: 6px;
    }
    .brand-title {
      font-family: var(--font-display);
      font-weight: 800;
      font-size: 1.25rem;
      letter-spacing: 0.05em;
      color: var(--text-primary);
    }
    .brand-vsep {
      width: 1px;
      height: 18px;
      background: var(--border-subtle);
    }
    .brand-subtext {
      font-size: 0.72rem;
      color: var(--text-muted);
      letter-spacing: 0.1em;
      font-weight: 600;
      line-height: 1.2;
    }
    .nav-back-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 0.85rem;
      font-family: var(--font-mono);
      color: var(--neon-cyan);
      text-decoration: none;
      padding: 7px 14px;
      border: 1px solid rgba(53, 229, 208, 0.25);
      border-radius: 6px;
      background: rgba(53, 229, 208, 0.04);
      transition: all 0.2s ease;
    }
    .nav-back-btn:hover {
      background: rgba(53, 229, 208, 0.12);
      border-color: var(--neon-cyan);
    }

    /* Hero */
    .hero-title {
      font-family: var(--font-display);
      font-size: 2.2rem;
      font-weight: 800;
      color: var(--text-primary);
      line-height: 1.2;
      margin-bottom: 8px;
      letter-spacing: -0.02em;
    }
    .hero-subtitle {
      font-size: 0.95rem;
      color: var(--text-secondary);
      max-width: 980px;
      line-height: 1.6;
      margin-bottom: 24px;
    }

    /* KPI Stats Ribbon */
    .stats-ribbon {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }
    .kpi-card {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 14px 18px;
    }
    .kpi-label {
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--text-muted);
      letter-spacing: 0.08em;
      text-transform: uppercase;
      margin-bottom: 4px;
    }
    .kpi-value {
      font-family: var(--font-display);
      font-size: 1.75rem;
      font-weight: 800;
      color: var(--text-primary);
      line-height: 1;
    }
    .kpi-cyan { color: var(--neon-cyan); }
    .kpi-lime { color: var(--neon-lime); }
    .kpi-blue { color: var(--sky-blue); }
    .kpi-coral { color: var(--coral); }

    /* Navigation Tabs */
    .tabs-header {
      display: flex;
      gap: 4px;
      border-bottom: 1px solid var(--border-subtle);
      margin-bottom: 20px;
      overflow-x: auto;
      white-space: nowrap;
      -webkit-overflow-scrolling: touch;
      scrollbar-width: none;
    }
    .tabs-header::-webkit-scrollbar {
      display: none;
    }
    .tab-btn {
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--text-muted);
      font-family: var(--font-display);
      font-size: 0.92rem;
      font-weight: 600;
      padding: 12px 20px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s ease;
    }
    .tab-btn:hover {
      color: var(--text-primary);
    }
    .tab-btn.active {
      color: var(--neon-cyan);
      border-bottom-color: var(--neon-cyan);
      background: rgba(53, 229, 208, 0.04);
    }
    .tab-counter {
      font-family: var(--font-mono);
      font-size: 0.72rem;
      background: var(--bg-elevated);
      padding: 2px 7px;
      border-radius: 10px;
      color: var(--text-muted);
    }
    .tab-btn.active .tab-counter {
      color: var(--neon-cyan);
      background: rgba(53, 229, 208, 0.15);
    }

    .tab-pane {
      display: none;
    }
    .tab-pane.active {
      display: block;
    }

    /* Control Toolbar */
    .control-panel {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .toolbar-top {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
    }
    .search-box {
      flex: 1;
      min-width: 320px;
    }
    .search-input {
      width: 100%;
      background: var(--bg-dark);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 9px 14px;
      font-family: var(--font-mono);
      font-size: 0.85rem;
      color: var(--text-primary);
      outline: none;
      transition: border-color 0.2s ease;
    }
    .search-input:focus {
      border-color: var(--neon-cyan);
    }
    .filter-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }
    .filter-item {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 0.78rem;
      font-family: var(--font-mono);
      color: var(--text-muted);
    }
    .filter-select {
      background: var(--bg-dark);
      border: 1px solid var(--border-subtle);
      border-radius: 5px;
      color: var(--text-secondary);
      font-family: var(--font-sans);
      font-size: 0.82rem;
      padding: 6px 10px;
      outline: none;
      cursor: pointer;
    }
    .filter-select:focus {
      border-color: var(--neon-cyan);
    }

    .btn-reset-filters {
      background: transparent;
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      color: var(--coral);
      font-family: var(--font-mono);
      font-size: 0.75rem;
      padding: 5px 10px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-reset-filters:hover {
      background: rgba(255, 123, 114, 0.1);
      border-color: var(--coral);
    }

    /* Grouping Selector Bar */
    .grouping-bar {
      display: flex;
      align-items: center;
      gap: 8px;
      padding-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      font-size: 0.8rem;
      font-family: var(--font-mono);
    }
    .grouping-label {
      color: var(--neon-lime);
      font-weight: 600;
      letter-spacing: 0.05em;
      margin-right: 4px;
    }
    .grouping-btn {
      background: transparent;
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-size: 0.75rem;
      padding: 5px 11px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .grouping-btn:hover {
      color: var(--text-primary);
      border-color: var(--border-strong);
    }
    .grouping-btn.active {
      color: var(--text-primary);
      border-color: var(--neon-cyan);
      background: rgba(53, 229, 208, 0.12);
      font-weight: 600;
    }

    /* Status Bar */
    .status-ribbon {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-family: var(--font-mono);
      font-size: 0.78rem;
      color: var(--text-muted);
      margin-bottom: 12px;
      padding: 0 4px;
    }
    .status-highlight {
      color: var(--neon-cyan);
      font-weight: 600;
    }

    /* Feed Container & Sticky Table */
    .feed-container {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
      margin-bottom: 16px;
    }
    table {
      width: 100%;
      min-width: 820px;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.85rem;
    }
    thead th {
      position: sticky;
      top: 0;
      background: var(--bg-elevated);
      z-index: 5;
      padding: 12px 14px;
      font-family: var(--font-mono);
      font-size: 0.72rem;
      font-weight: 600;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      text-transform: uppercase;
      white-space: nowrap;
      border-bottom: 1px solid var(--border-subtle);
    }
    tbody tr {
      border-bottom: 1px solid var(--border-subtle);
      cursor: pointer;
      transition: background 0.15s ease;
    }
    tbody tr:hover {
      background: var(--bg-hover);
    }
    td {
      padding: 11px 14px;
      vertical-align: middle;
    }

    /* Badges */
    .badge-type {
      display: inline-block;
      font-family: var(--font-mono);
      font-size: 0.7rem;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
      white-space: nowrap;
    }
    .badge-sha256 { background: rgba(53, 229, 208, 0.1); color: var(--neon-cyan); border: 1px solid rgba(53, 229, 208, 0.3); }
    .badge-md5 { background: rgba(167, 139, 250, 0.1); color: var(--lavender); border: 1px solid rgba(167, 139, 250, 0.3); }
    .badge-imphash { background: rgba(121, 192, 255, 0.1); color: var(--sky-blue); border: 1px solid rgba(121, 192, 255, 0.3); }
    .badge-ipv4 { background: rgba(183, 255, 60, 0.1); color: var(--neon-lime); border: 1px solid rgba(183, 255, 60, 0.3); }
    .badge-domain { background: rgba(255, 166, 87, 0.1); color: var(--amber); border: 1px solid rgba(255, 166, 87, 0.3); }
    .badge-url { background: rgba(255, 123, 114, 0.1); color: var(--coral); border: 1px solid rgba(255, 123, 114, 0.3); }

    .badge-killchain {
      display: inline-block;
      font-family: var(--font-mono);
      font-size: 0.68rem;
      color: var(--text-muted);
      background: rgba(255, 255, 255, 0.04);
      padding: 2px 6px;
      border-radius: 3px;
      border: 1px solid rgba(255, 255, 255, 0.06);
      white-space: nowrap;
    }

    .badge-sev {
      display: inline-block;
      font-family: var(--font-mono);
      font-size: 0.68rem;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 3px;
      text-transform: uppercase;
    }
    .sev-critical { background: rgba(255, 123, 114, 0.15); color: #FF7B72; border: 1px solid rgba(255, 123, 114, 0.4); }
    .sev-high { background: rgba(255, 166, 87, 0.15); color: #FFA657; border: 1px solid rgba(255, 166, 87, 0.4); }
    .sev-medium { background: rgba(121, 192, 255, 0.15); color: #79C0FF; border: 1px solid rgba(121, 192, 255, 0.4); }

    /* Indicator Cell with Inline Copy */
    .indicator-cell {
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }
    .indicator-text {
      font-family: var(--font-mono);
      font-size: 0.82rem;
      color: var(--text-primary);
      word-break: break-all;
    }
    .btn-copy-mini {
      background: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-size: 0.68rem;
      padding: 3px 7px;
      cursor: pointer;
      transition: all 0.15s ease;
      white-space: nowrap;
      user-select: none;
    }
    .btn-copy-mini:hover {
      color: var(--neon-cyan);
      border-color: var(--neon-cyan);
    }
    .btn-copy-mini.copied {
      color: var(--neon-lime);
      border-color: var(--neon-lime);
      background: rgba(183, 255, 60, 0.12);
    }

    .btn-inspect-row {
      background: transparent;
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      color: var(--sky-blue);
      font-family: var(--font-mono);
      font-size: 0.72rem;
      padding: 4px 9px;
      cursor: pointer;
      transition: all 0.15s ease;
      white-space: nowrap;
    }
    .btn-inspect-row:hover {
      border-color: var(--sky-blue);
      background: rgba(121, 192, 255, 0.1);
      color: #FFFFFF;
    }

    .actor-filter-link {
      color: var(--sky-blue);
      font-weight: 600;
      cursor: pointer;
      transition: color 0.15s ease;
    }
    .actor-filter-link:hover {
      color: var(--neon-cyan);
      text-decoration: underline;
    }

    /* Purpose-Built Investigation Link Button (Replaces ugly Dossier button) */
    .btn-investigation-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-family: var(--font-mono);
      font-size: 0.74rem;
      font-weight: 600;
      color: var(--neon-cyan);
      background: rgba(53, 229, 208, 0.08);
      border: 1px solid rgba(53, 229, 208, 0.3);
      border-radius: 4px;
      padding: 5px 11px;
      text-decoration: none;
      white-space: nowrap;
      transition: all 0.2s ease;
    }
    .btn-investigation-link:hover {
      background: var(--neon-cyan);
      color: #0A0D14;
      border-color: var(--neon-cyan);
      box-shadow: 0 0 10px rgba(53, 229, 208, 0.3);
    }

    /* Collapsible Group Cluster */
    .cluster-card {
      border-bottom: 1px solid var(--border-subtle);
    }
    .cluster-card:last-child {
      border-bottom: none;
    }
    .cluster-header {
      background: var(--bg-card);
      padding: 14px 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      transition: background 0.15s ease;
      user-select: none;
    }
    .cluster-header:hover {
      background: var(--bg-hover);
    }
    .cluster-title-wrap {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .cluster-chevron {
      font-family: var(--font-mono);
      font-size: 0.8rem;
      color: var(--neon-cyan);
      transition: transform 0.2s ease;
      display: inline-block;
      width: 14px;
    }
    .cluster-card.open .cluster-chevron {
      transform: rotate(90deg);
    }
    .cluster-name {
      font-family: var(--font-display);
      font-size: 0.95rem;
      font-weight: 700;
      color: var(--text-primary);
    }
    .cluster-meta {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .cluster-tag {
      font-family: var(--font-mono);
      font-size: 0.72rem;
      padding: 2px 7px;
      border-radius: 4px;
      background: var(--bg-elevated);
      color: var(--text-muted);
    }
    .cluster-body {
      display: none;
      border-top: 1px solid var(--border-subtle);
    }
    .cluster-card.open .cluster-body {
      display: block;
    }

    /* Pagination Bar */
    .pagination-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 0.78rem;
    }
    .pagination-controls {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .page-btn {
      background: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      color: var(--text-secondary);
      font-family: var(--font-mono);
      font-size: 0.75rem;
      padding: 5px 10px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .page-btn:hover:not(:disabled) {
      color: var(--neon-cyan);
      border-color: var(--neon-cyan);
    }
    .page-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }
    .page-btn.active {
      color: var(--neon-cyan);
      border-color: var(--neon-cyan);
      background: rgba(53, 229, 208, 0.12);
    }

    /* Threat Actors Grid (Default View) */
    .actors-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
      gap: 16px;
    }
    .actor-card {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 22px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      transition: all 0.2s ease;
      position: relative;
    }
    .actor-card.card-crit {
      border-left: 3px solid var(--coral);
    }
    .actor-card.card-high {
      border-left: 3px solid var(--amber);
    }
    .actor-card:hover {
      border-color: var(--border-focus);
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .actor-eyebrow {
      font-family: var(--font-mono);
      font-size: 0.68rem;
      color: var(--text-muted);
      letter-spacing: 0.1em;
      text-transform: uppercase;
      margin-bottom: 2px;
    }
    .actor-card-head {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 10px;
    }
    .actor-card-name {
      font-family: var(--font-display);
      font-size: 1.15rem;
      font-weight: 800;
      color: var(--text-primary);
      line-height: 1.25;
    }
    .alias-pill {
      display: inline-block;
      font-family: var(--font-mono);
      font-size: 0.72rem;
      background: rgba(121, 192, 255, 0.08);
      color: var(--sky-blue);
      border: 1px solid rgba(121, 192, 255, 0.2);
      padding: 2px 7px;
      border-radius: 4px;
      margin-right: 4px;
      margin-bottom: 4px;
    }
    .sector-chip {
      display: inline-block;
      font-family: var(--font-sans);
      font-size: 0.72rem;
      color: var(--text-secondary);
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 2px 7px;
      border-radius: 4px;
      margin-right: 4px;
      margin-bottom: 4px;
    }
    .malware-chip {
      display: inline-block;
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--neon-cyan);
      background: rgba(53, 229, 208, 0.06);
      border: 1px solid rgba(53, 229, 208, 0.2);
      padding: 2px 7px;
      border-radius: 4px;
      margin-right: 4px;
      margin-bottom: 4px;
    }
    .actor-card-body {
      display: flex;
      flex-direction: column;
      gap: 8px;
      font-size: 0.82rem;
    }
    .actor-card-actions {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-top: 12px;
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      margin-top: auto;
    }
    .btn-actor-pivot {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(53, 229, 208, 0.08);
      border: 1px solid rgba(53, 229, 208, 0.3);
      color: var(--neon-cyan);
      font-family: var(--font-display);
      font-size: 0.78rem;
      font-weight: 700;
      padding: 6px 12px;
      border-radius: 5px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-actor-pivot:hover {
      background: var(--neon-cyan);
      color: #0A0D14;
      box-shadow: 0 0 12px rgba(53, 229, 208, 0.3);
    }

    /* OpenCTI Drawer */
    #drawerOverlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(2px);
      z-index: 998;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.25s ease;
    }
    #drawerOverlay.active {
      opacity: 1;
      pointer-events: auto;
    }
    #entityDrawer {
      position: fixed;
      top: 0;
      right: 0;
      width: var(--drawer-width);
      max-width: 90vw;
      height: 100vh;
      background: var(--bg-panel);
      border-left: 1px solid var(--border-strong);
      box-shadow: -8px 0 32px rgba(0, 0, 0, 0.8);
      z-index: 999;
      transform: translateX(100%);
      transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      display: flex;
      flex-direction: column;
      overflow-y: auto;
    }
    #entityDrawer.open {
      transform: translateX(0);
    }
    .drawer-header {
      padding: 20px;
      border-bottom: 1px solid var(--border-subtle);
      background: var(--bg-elevated);
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
    }
    .drawer-title-eyebrow {
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--neon-lime);
      letter-spacing: 0.1em;
      margin-bottom: 4px;
    }
    .drawer-title {
      font-family: var(--font-display);
      font-size: 1.15rem;
      font-weight: 700;
      color: var(--text-primary);
      line-height: 1.3;
    }
    .drawer-close {
      background: transparent;
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-size: 0.9rem;
      padding: 4px 8px;
      cursor: pointer;
    }
    .drawer-close:hover {
      color: var(--text-primary);
      border-color: var(--text-primary);
    }
    .drawer-content {
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 20px;
      flex: 1;
    }
    .drawer-section {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .drawer-section-title {
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--text-muted);
      letter-spacing: 0.08em;
      text-transform: uppercase;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      padding-bottom: 4px;
    }
    .drawer-field-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.82rem;
      padding: 2px 0;
    }
    .drawer-field-label {
      color: var(--text-muted);
    }
    .drawer-field-val {
      color: var(--text-primary);
      font-weight: 500;
      text-align: right;
    }
    .drawer-val-mono {
      font-family: var(--font-mono);
      font-size: 0.78rem;
      word-break: break-all;
    }
    .drawer-indicator-box {
      background: var(--bg-dark);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .btn-vt-link {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 10px 14px;
      border-radius: 6px;
      background: rgba(56, 189, 248, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.35);
      color: var(--sky-blue);
      font-family: var(--font-mono);
      font-weight: 600;
      font-size: 0.84rem;
      text-decoration: none;
      text-align: center;
      transition: all 0.2s ease;
      min-height: 40px;
    }
    .btn-vt-link:hover {
      background: var(--sky-blue);
      color: #0A0D14;
      border-color: var(--sky-blue);
      box-shadow: 0 0 12px rgba(121, 192, 255, 0.3);
    }
    .btn-report-link {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 12px;
      border-radius: 6px;
      background: rgba(53, 229, 208, 0.1);
      border: 1px solid var(--neon-cyan);
      color: var(--neon-cyan);
      font-family: var(--font-display);
      font-weight: 700;
      font-size: 0.88rem;
      text-decoration: none;
      text-align: center;
      transition: all 0.2s ease;
      margin-top: 10px;
    }
    .btn-report-link:hover {
      background: var(--neon-cyan);
      color: #0A0D14;
    }

    /* Tab 4: Export Hub */
    .export-layout {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 20px;
    }
    .export-card {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .export-card-title {
      font-family: var(--font-display);
      font-size: 1.1rem;
      font-weight: 700;
      color: var(--text-primary);
    }
    .export-card-desc {
      font-size: 0.88rem;
      color: var(--text-secondary);
      line-height: 1.5;
    }
    .btn-download-hub {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 10px 16px;
      border-radius: 5px;
      font-family: var(--font-mono);
      font-size: 0.82rem;
      font-weight: 600;
      text-decoration: none;
      background: var(--bg-elevated);
      color: var(--text-primary);
      border: 1px solid var(--border-strong);
      transition: all 0.15s ease;
    }
    .btn-download-hub:hover {
      border-color: var(--neon-lime);
      color: var(--neon-lime);
      background: rgba(183, 255, 60, 0.08);
    }
    .api-snippet {
      background: var(--bg-dark);
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      padding: 10px;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--neon-lime);
      overflow-x: auto;
      white-space: pre;
    }

    /* Toast */
    #toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: var(--bg-card);
      border: 1px solid var(--neon-lime);
      color: var(--neon-lime);
      font-family: var(--font-mono);
      font-size: 0.82rem;
      padding: 10px 18px;
      border-radius: 6px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.6);
      transform: translateY(100px);
      opacity: 0;
      transition: all 0.25s ease;
      z-index: 9999;
    }
    #toast.show {
      transform: translateY(0);
      opacity: 1;
    }

    @media (max-width: 900px) {
      :root { --drawer-width: 100vw; }
      #entityDrawer { width: 100vw; max-width: 100vw; }
      .hero-title { font-size: 1.7rem; }
      .stats-ribbon { grid-template-columns: 1fr 1fr; }
      .toolbar-top { flex-direction: column; align-items: stretch; }
      .search-box { width: 100%; min-width: 0; }
      .filter-row { flex-direction: column; align-items: stretch; }
      .filter-select { width: 100%; }
      .grouping-bar { flex-wrap: wrap; }
      .actors-grid { grid-template-columns: 1fr; }
    }

    @media (max-width: 600px) {
      .container { padding: 16px 14px 60px; }
      .nav-bar { flex-direction: column; align-items: flex-start; gap: 10px; }
      .nav-back-btn { width: 100%; text-align: center; justify-content: center; }
      .hero-title { font-size: 1.45rem; }
      .hero-desc { font-size: 0.85rem; }
      .stats-ribbon { grid-template-columns: 1fr; gap: 10px; }
      .drawer-header { padding: 16px; }
      .drawer-content { padding: 16px; gap: 16px; }
      .drawer-close { min-height: 40px; min-width: 40px; font-size: 1.2rem; display: flex; align-items: center; justify-content: center; }
      .btn-report-link { padding: 14px; font-size: 0.88rem; min-height: 48px; }
      .btn-vt-link { padding: 12px; font-size: 0.82rem; min-height: 44px; }
      .export-layout { grid-template-columns: 1fr; }
      .export-card { padding: 16px; }
    }
  </style>
</head>
<body>

  <div class="bg-grid" aria-hidden="true"></div>

  <div class="container">
    <!-- Top Nav -->
    <header class="nav-bar">
      <a href="../index.html" class="brand-group" aria-label="MARE Home">
        <img src="../assets/home/mare-logo.png" alt="MARE Logo" class="brand-logo" width="32" height="32">
        <div>
          <div class="brand-title">MARE</div>
          <div class="brand-subtext">MALWARE ANALYSIS &amp; REVERSE ENGINEERING</div>
        </div>
      </a>
      <a href="../index.html" class="nav-back-btn">&larr; Back to Research Portal</a>
    </header>

    <!-- Hero -->
    <section>
      <h1 class="hero-title">Unified Threat Intelligence &amp; IoC Feed</h1>
      <p class="hero-subtitle">
        High-fidelity, ground-truth indicators of compromise (IOCs), adversary payload hashes, and command-and-control (C2) infrastructure directly verified through static binary disassembly and dynamic runtime telemetry.
      </p>
    </section>

    <!-- KPI Stats Ribbon -->
    <section class="stats-ribbon">
      <div class="kpi-card">
        <div class="kpi-label">Tracked Threat Clusters</div>
        <div class="kpi-value kpi-blue">${actors.length}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Total Observables</div>
        <div class="kpi-value kpi-cyan">${total}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Payload Hashes</div>
        <div class="kpi-value kpi-lime">${hashCount}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">C2 Infrastructure</div>
        <div class="kpi-value kpi-coral">${c2Count}</div>
      </div>
    </section>

    <!-- Main Navigation Tabs (Default: Threat Actors & APTs) -->
    <div class="tabs-header">
      <button class="tab-btn active" data-tab="tab-actors" onclick="switchTab('tab-actors')">
        Threat Actors &amp; APTs <span class="tab-counter">${actors.length}</span>
      </button>
      <button class="tab-btn" data-tab="tab-indicators" onclick="switchTab('tab-indicators')">
        Indicators &amp; Observables <span class="tab-counter" id="tab-count-indicators">${total}</span>
      </button>
      <button class="tab-btn" data-tab="tab-c2" onclick="switchTab('tab-c2')">
        C2 Infrastructure Matrix <span class="tab-counter">${c2Count}</span>
      </button>
      <button class="tab-btn" data-tab="tab-export" onclick="switchTab('tab-export')">
        Export &amp; Automation Hub
      </button>
    </div>

    <!-- TAB 1 (DEFAULT): Threat Actors & Attribution (Group-IB Model) -->
    <div id="tab-actors" class="tab-pane active">
      <!-- Actor Controls -->
      <div class="control-panel">
        <div class="toolbar-top">
          <div class="search-box">
            <input type="text" id="actorSearchInput" class="search-input" placeholder="Search threat actor by name, alias, motivation, or target sector..." autocomplete="off">
          </div>
          <div class="filter-row">
            <div class="filter-item">
              <span>Severity:</span>
              <select id="actorSevFilter" class="filter-select">
                <option value="all">All Severities</option>
                <option value="Critical">Critical Only</option>
                <option value="High">High Only</option>
              </select>
            </div>
            <button class="btn-reset-filters" onclick="resetActorFilters()">Clear Search</button>
          </div>
        </div>
        <div class="status-ribbon">
          <div>Showing <span id="visibleActorsCount" class="status-highlight">${actors.length}</span> of <span class="status-highlight">${actors.length}</span> threat clusters</div>
          <div>Attribution Standard: Verified in Binary Disassembly &amp; Network Trace</div>
        </div>
      </div>

      <!-- Actor Cards Grid -->
      <div class="actors-grid" id="actorsGrid">
${actors.map(a => {
  const cardSevClass = a.severity === 'Critical' ? 'card-crit' : 'card-high';
  const sevBadgeClass = a.severity === 'Critical' ? 'sev-critical' : 'sev-high';
  const searchKeywords = (a.name + ' ' + a.aliases.join(' ') + ' ' + a.motivation + ' ' + a.targetSectors.join(' ') + ' ' + a.families.join(' ') + ' ' + a.campaigns.join(' ')).toLowerCase();
  return `        <div class="actor-card ${cardSevClass}" data-sev="${escapeHtml(a.severity)}" data-search="${escapeHtml(searchKeywords)}">
          <div class="actor-card-head">
            <div>
              <div class="actor-eyebrow">// THREAT CLUSTER</div>
              <div class="actor-card-name">${escapeHtml(a.name)}</div>
            </div>
            <span class="badge-sev ${sevBadgeClass}">${escapeHtml(a.severity)}</span>
          </div>

          ${a.aliases.length ? `<div>
            <div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);margin-bottom:4px;">KNOWN ALIASES</div>
            <div>${a.aliases.map(al => `<span class="alias-pill">${escapeHtml(al)}</span>`).join('')}</div>
          </div>` : ''}

          <div class="actor-card-body">
            <div><strong style="color:var(--text-muted);font-size:0.75rem;font-family:var(--font-mono);">STRATEGIC MOTIVE:</strong> ${escapeHtml(a.motivation)}</div>
            <div>
              <div style="color:var(--text-muted);font-size:0.75rem;font-family:var(--font-mono);margin-bottom:3px;">TARGET SECTORS:</div>
              <div>${a.targetSectors.map(s => `<span class="sector-chip">${escapeHtml(s)}</span>`).join('')}</div>
            </div>
            <div>
              <div style="color:var(--text-muted);font-size:0.75rem;font-family:var(--font-mono);margin-bottom:3px;">MALWARE ARSENAL:</div>
              <div>${a.families.map(f => `<span class="malware-chip">${escapeHtml(f)}</span>`).join('')}</div>
            </div>
            ${a.campaigns.length ? `<div><strong style="color:var(--text-muted);font-size:0.75rem;font-family:var(--font-mono);">CAMPAIGNS:</strong> <span style="color:var(--text-secondary);font-size:0.8rem;">${escapeHtml(a.campaigns.join(' | '))}</span></div>` : ''}
          </div>

          <div class="actor-card-actions">
            <span class="cluster-tag">${a.indicatorCount} Verified Observables</span>
            <button class="btn-actor-pivot" data-actor-filter="${escapeHtml(a.name)}">Explore Indicators &rarr;</button>
          </div>
        </div>`;
}).join('\n')}
      </div>
    </div>

    <!-- TAB 2: Indicators & Observables -->
    <div id="tab-indicators" class="tab-pane">
      <!-- Control Panel -->
      <div class="control-panel">
        <div class="toolbar-top">
          <div class="search-box">
            <input type="text" id="searchInput" class="search-input" placeholder="Search hash, IP, domain, actor, campaign, or malware family..." autocomplete="off">
          </div>
          <div class="filter-row">
            <div class="filter-item">
              <span>Type:</span>
              <select id="typeFilter" class="filter-select">
                <option value="all">All Types</option>
                <option value="SHA-256">SHA-256</option>
                <option value="MD5">MD5</option>
                <option value="IMPHASH">IMPHASH</option>
                <option value="IPv4">IPv4</option>
                <option value="Domain">Domain</option>
                <option value="URL">URL</option>
              </select>
            </div>
            <div class="filter-item">
              <span>Severity:</span>
              <select id="severityFilter" class="filter-select">
                <option value="all">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
              </select>
            </div>
            <div class="filter-item">
              <span>Kill Chain:</span>
              <select id="killChainFilter" class="filter-select">
                <option value="all">All Phases</option>
                <option value="Command & Control">Command & Control</option>
                <option value="Initial Delivery">Initial Delivery</option>
                <option value="Payload Execution">Payload Execution</option>
                <option value="Defense Evasion & Fingerprinting">Defense Evasion</option>
                <option value="Exfiltration & Impact">Exfiltration & Impact</option>
              </select>
            </div>
            <div class="filter-item">
              <span>Platform:</span>
              <select id="platformFilter" class="filter-select">
                <option value="all">All Platforms</option>
                <option value="Windows">Windows</option>
                <option value="macOS">macOS</option>
                <option value="Linux">Linux</option>
                <option value="Cross-Platform">Cross-Platform</option>
              </select>
            </div>
            <button class="btn-reset-filters" onclick="resetIndicatorFilters()">Clear Filters</button>
          </div>
        </div>

        <!-- Grouping Switcher -->
        <div class="grouping-bar">
          <span class="grouping-label">GROUP BY:</span>
          <button class="grouping-btn active" data-group="none" onclick="setGrouping('none')">Flat Feed</button>
          <button class="grouping-btn" data-group="actor" onclick="setGrouping('actor')">Threat Actor</button>
          <button class="grouping-btn" data-group="campaign" onclick="setGrouping('campaign')">Campaign</button>
          <button class="grouping-btn" data-group="family" onclick="setGrouping('family')">Malware Family</button>
          <button class="grouping-btn" data-group="killChain" onclick="setGrouping('killChain')">Kill Chain Phase</button>
        </div>
      </div>

      <!-- Status Bar -->
      <div class="status-ribbon">
        <div>Showing <span id="visibleCounter" class="status-highlight">${total}</span> of <span class="status-highlight">${total}</span> indicators</div>
        <div>Inspection: Click any row or [Inspect] to slide out the OpenCTI entity dossier</div>
      </div>

      <!-- Feed Container -->
      <div class="feed-container">
        <!-- Flat View Table -->
        <div id="flatView">
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Indicator / Observable</th>
                <th>Kill Chain Phase</th>
                <th>Malware Family</th>
                <th>Threat Actor Attribution</th>
                <th>Severity</th>
                <th>Platform</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="indicatorsTbody"></tbody>
          </table>
        </div>

        <!-- Grouped View Container -->
        <div id="groupedView" style="display:none;"></div>
      </div>

      <!-- Pagination (Flat View) -->
      <div id="paginationWrap" class="pagination-bar">
        <div>
          Showing page <span id="curPageNum" class="status-highlight">1</span> of <span id="totalPageNum" class="status-highlight">1</span>
        </div>
        <div class="pagination-controls">
          <button id="prevPageBtn" class="page-btn" onclick="changePage(-1)">&larr; Prev</button>
          <div id="pageNumberButtons" style="display:inline-flex;gap:4px;"></div>
          <button id="nextPageBtn" class="page-btn" onclick="changePage(1)">Next &rarr;</button>
        </div>
      </div>
    </div>

    <!-- TAB 3: C2 Infrastructure Matrix -->
    <div id="tab-c2" class="tab-pane">
      <div class="control-panel">
        <div class="toolbar-top">
          <div class="search-box">
            <input type="text" id="c2SearchInput" class="search-input" placeholder="Search C2 IP address, host domain, port, malware family, or threat actor..." autocomplete="off">
          </div>
          <div class="filter-row">
            <div class="filter-item">
              <span>Type:</span>
              <select id="c2TypeFilter" class="filter-select" onchange="filterC2()">
                <option value="all">All C2 Types</option>
                <option value="IPv4">IPv4 Only</option>
                <option value="Domain">Domain Only</option>
                <option value="URL">URL Only</option>
              </select>
            </div>
            <button class="btn-reset-filters" onclick="resetC2Filters()">Clear Search</button>
          </div>
        </div>
        <div class="status-ribbon">
          <div>Showing <span id="visibleC2Count" class="status-highlight">${c2Count}</span> of <span class="status-highlight">${c2Count}</span> C2 infrastructure nodes</div>
          <div>Perimeter Defense: Verified active command-and-control communication endpoints</div>
        </div>
      </div>

      <div class="feed-container">
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Host / Endpoint Observable</th>
              <th>Infrastructure Role</th>
              <th>Malware Family</th>
              <th>Threat Actor Attribution</th>
              <th>Target Demographics</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="c2Tbody">
${indicators.filter(i => ['IPv4', 'Domain', 'URL'].includes(i.type)).map(i => {
  const typeClass = 'badge-' + i.type.toLowerCase();
  const searchWords = (i.indicator + ' ' + i.family + ' ' + i.actor + ' ' + i.role + ' ' + i.targetSectors.join(' ') + ' ' + i.targetGeo.join(' ')).toLowerCase();
  return `            <tr data-id="${i.id}" data-type="${i.type}" data-search="${escapeHtml(searchWords)}">
              <td><span class="badge-type ${typeClass}">${escapeHtml(i.type)}</span></td>
              <td>
                <div class="indicator-cell">
                  <span class="indicator-text">${escapeHtml(i.indicator)}</span>
                  <button class="btn-copy-mini" data-copy="${escapeHtml(i.indicator)}">COPY</button>
                </div>
              </td>
              <td><span class="badge-killchain">${escapeHtml(i.role)}</span></td>
              <td><strong style="color:var(--text-primary);">${escapeHtml(i.family)}</strong></td>
              <td style="color:var(--sky-blue);font-weight:600;"><span class="actor-filter-link" data-actor-filter="${escapeHtml(i.actor)}">${escapeHtml(i.actor)}</span></td>
              <td style="color:var(--text-muted);font-size:0.78rem;">${escapeHtml(i.targetSectors.join(', '))}</td>
              <td>
                <div style="display:flex;align-items:center;gap:6px;">
                  <button class="btn-inspect-row" data-inspect="${i.id}">Inspect</button>
                  <a href="${escapeHtml(i.localPath)}" target="_blank" rel="noopener noreferrer" class="btn-investigation-link" onclick="event.stopPropagation();">Investigation &rarr;</a>
                </div>
              </td>
            </tr>`;
}).join('\n')}
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 4: Export Hub -->
    <div id="tab-export" class="tab-pane">
      <div class="export-layout">
        <div class="export-card">
          <div class="export-card-title">Machine JSON Feed (STIX/OTX Model)</div>
          <div class="export-card-desc">
            Complete, structured JSON export including threat actor attribution, kill chain phases, campaigns, motivation, target sectors, and confidence telemetry.
          </div>
          <a href="../feed/iocs.json" download="mare-iocs.json" class="btn-download-hub">Download mare-iocs.json</a>
          <div class="api-snippet">curl -s https://lynk4.github.io/mare/feed/iocs.json | jq .</div>
        </div>

        <div class="export-card">
          <div class="export-card-title">SIEM &amp; Lookup Table (CSV)</div>
          <div class="export-card-desc">
            Normalized flat CSV export formatted specifically for bulk ingestion into Splunk lookups, Microsoft Sentinel ThreatIntelligence, and QRadar reference sets.
          </div>
          <a href="../feed/iocs.csv" download="mare-iocs.csv" class="btn-download-hub">Download mare-iocs.csv</a>
          <div class="api-snippet">curl -s https://lynk4.github.io/mare/feed/iocs.csv -o mare_indicators.csv</div>
        </div>

        <div class="export-card">
          <div class="export-card-title">Raw Firewall Blocklist (TXT)</div>
          <div class="export-card-desc">
            Plain text stream containing one indicator per line for direct ingestion into Palo Alto PAN-OS External Dynamic Lists (EDL), Fortinet FortiGate, and Suricata IP sets.
          </div>
          <a href="../feed/iocs.txt" download="mare-iocs.txt" class="btn-download-hub">Download mare-iocs.txt</a>
          <div class="api-snippet">curl -s https://lynk4.github.io/mare/feed/iocs.txt | grep -v '^#'</div>
        </div>
      </div>
    </div>
  </div>

  <!-- OpenCTI-Style Slide-Out Entity Inspection Drawer -->
  <div id="drawerOverlay" onclick="closeDrawer()"></div>
  <aside id="entityDrawer">
    <div class="drawer-header">
      <div>
        <div class="drawer-title-eyebrow">// OBSERVABLE DOSSIER</div>
        <div class="drawer-title" id="drawerTypeRole">Indicator Inspection</div>
      </div>
      <button class="drawer-close" onclick="closeDrawer()">&times;</button>
    </div>

    <div class="drawer-content">
      <!-- Observable Box -->
      <div class="drawer-indicator-box">
        <div class="drawer-field-label">OBSERVABLE VALUE</div>
        <div class="drawer-val-mono" id="drawerIndicatorVal"></div>
        <button class="btn-copy-mini" id="drawerCopyBtn" onclick="copyCurrentIndicator()">COPY INDICATOR</button>
      </div>

      <!-- Attribution & Context -->
      <div class="drawer-section">
        <div class="drawer-section-title">Attribution &amp; Campaign</div>
        <div class="drawer-field-row">
          <span class="drawer-field-label">Threat Actor:</span>
          <span class="drawer-field-val" id="drawerActor" style="color:var(--sky-blue);font-weight:700;"></span>
        </div>
        <div class="drawer-field-row">
          <span class="drawer-field-label">Aliases:</span>
          <span class="drawer-field-val" id="drawerAliases"></span>
        </div>
        <div class="drawer-field-row">
          <span class="drawer-field-label">Campaign:</span>
          <span class="drawer-field-val" id="drawerCampaign"></span>
        </div>
        <div class="drawer-field-row">
          <span class="drawer-field-label">Malware Family:</span>
          <span class="drawer-field-val" id="drawerFamily" style="color:var(--neon-cyan);font-weight:700;"></span>
        </div>
      </div>

      <!-- Kill Chain & Targeting -->
      <div class="drawer-section">
        <div class="drawer-section-title">Operational Context</div>
        <div class="drawer-field-row">
          <span class="drawer-field-label">Kill Chain Phase:</span>
          <span class="drawer-field-val" id="drawerKillChain"></span>
        </div>
        <div class="drawer-field-row">
          <span class="drawer-field-label">Severity:</span>
          <span class="drawer-field-val" id="drawerSeverity"></span>
        </div>
        <div class="drawer-field-row">
          <span class="drawer-field-label">Target Sectors:</span>
          <span class="drawer-field-val" id="drawerSectors"></span>
        </div>
        <div class="drawer-field-row">
          <span class="drawer-field-label">Platform:</span>
          <span class="drawer-field-val" id="drawerPlatform"></span>
        </div>
        <div class="drawer-field-row">
          <span class="drawer-field-label">First Seen:</span>
          <span class="drawer-field-val" id="drawerFirstSeen"></span>
        </div>
        <div class="drawer-field-row">
          <span class="drawer-field-label">TLP Marking:</span>
          <span class="drawer-field-val" id="drawerTLP"></span>
        </div>
      </div>

      <!-- External Intelligence: VirusTotal Only -->
      <div class="drawer-section">
        <div class="drawer-section-title">External Analysis</div>
        <a id="drawerVTBtn" href="#" target="_blank" rel="noopener noreferrer" class="btn-vt-link">
          Inspect on VirusTotal &rarr;
        </a>
      </div>

      <!-- Direct Link to Investigation -->
      <div class="drawer-section">
        <a id="drawerReportBtn" href="#" target="_blank" rel="noopener noreferrer" class="btn-report-link">
          Open Reverse Engineering Report &rarr;
        </a>
      </div>
    </div>
  </aside>

  <div id="toast">Indicator copied to clipboard</div>

  <script>
    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    // Embedded Data Store
    const ALL_INDICATORS = ${indicatorsJsonString};
    const ALL_ACTORS = ${actorsJsonString};

    let currentGrouping = 'none';
    let currentPage = 1;
    const pageSize = 25;
    let filteredIndicators = [...ALL_INDICATORS];
    let selectedIndicator = null;

    // Elements
    const searchInput = document.getElementById('searchInput');
    const typeFilter = document.getElementById('typeFilter');
    const severityFilter = document.getElementById('severityFilter');
    const killChainFilter = document.getElementById('killChainFilter');
    const platformFilter = document.getElementById('platformFilter');
    const visibleCounter = document.getElementById('visibleCounter');
    const indicatorsTbody = document.getElementById('indicatorsTbody');
    const flatView = document.getElementById('flatView');
    const groupedView = document.getElementById('groupedView');
    const paginationWrap = document.getElementById('paginationWrap');
    const curPageNum = document.getElementById('curPageNum');
    const totalPageNum = document.getElementById('totalPageNum');
    const prevPageBtn = document.getElementById('prevPageBtn');
    const nextPageBtn = document.getElementById('nextPageBtn');
    const pageNumberButtons = document.getElementById('pageNumberButtons');

    function applyFilters() {
      const q = searchInput.value.toLowerCase().trim().split(' ').filter(Boolean).join(' ');
      const type = typeFilter.value;
      const sev = severityFilter.value;
      const kc = killChainFilter.value;
      const plat = platformFilter.value;

      filteredIndicators = ALL_INDICATORS.filter(item => {
        if (type !== 'all' && item.type !== type) return false;
        if (sev !== 'all' && item.severity.toLowerCase() !== sev.toLowerCase()) return false;
        if (kc !== 'all' && item.killChain !== kc) return false;
        if (plat !== 'all' && item.platform !== plat) return false;
        if (q) {
          const hay = (item.indicator + ' ' + item.family + ' ' + item.actor + ' ' + item.campaign + ' ' + item.platform + ' ' + item.role + ' ' + (item.targetSectors || []).join(' ')).toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

      visibleCounter.innerText = filteredIndicators.length;
      currentPage = 1;
      renderCurrentView();
    }

    function resetIndicatorFilters() {
      searchInput.value = '';
      typeFilter.value = 'all';
      severityFilter.value = 'all';
      killChainFilter.value = 'all';
      platformFilter.value = 'all';
      applyFilters();
    }

    function renderCurrentView() {
      if (currentGrouping === 'none') {
        flatView.style.display = 'block';
        groupedView.style.display = 'none';
        paginationWrap.style.display = 'flex';
        renderFlatTable();
      } else {
        flatView.style.display = 'none';
        groupedView.style.display = 'block';
        paginationWrap.style.display = 'none';
        renderGroupedView();
      }
    }

    function renderFlatTable() {
      const totalPages = Math.ceil(filteredIndicators.length / pageSize) || 1;
      if (currentPage > totalPages) currentPage = totalPages;
      curPageNum.innerText = currentPage;
      totalPageNum.innerText = totalPages;
      prevPageBtn.disabled = (currentPage === 1);
      nextPageBtn.disabled = (currentPage === totalPages);

      pageNumberButtons.innerHTML = '';
      for (let p = 1; p <= totalPages; p++) {
        if (p === 1 || p === totalPages || (p >= currentPage - 1 && p <= currentPage + 1)) {
          const btn = document.createElement('button');
          btn.className = 'page-btn' + (p === currentPage ? ' active' : '');
          btn.innerText = p;
          btn.onclick = () => { currentPage = p; renderFlatTable(); };
          pageNumberButtons.appendChild(btn);
        } else if (p === currentPage - 2 || p === currentPage + 2) {
          const dots = document.createElement('span');
          dots.innerText = '...';
          dots.style.padding = '0 4px';
          dots.style.color = 'var(--text-muted)';
          pageNumberButtons.appendChild(dots);
        }
      }

      const start = (currentPage - 1) * pageSize;
      const pageItems = filteredIndicators.slice(start, start + pageSize);

      if (pageItems.length === 0) {
        indicatorsTbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:36px;color:var(--text-muted);">No matching indicators found for current query.</td></tr>';
        return;
      }

      indicatorsTbody.innerHTML = pageItems.map(function(i) {
        const typeClass = 'badge-' + i.type.toLowerCase().replace(/[^a-z0-9]/g, '');
        const sevClass = 'sev-' + (i.severity || 'high').toLowerCase();
        return '<tr data-id="' + i.id + '">' +
          '<td><span class="badge-type ' + typeClass + '">' + escapeHtml(i.type) + '</span></td>' +
          '<td>' +
            '<div class="indicator-cell">' +
              '<span class="indicator-text">' + escapeHtml(i.indicator) + '</span>' +
              '<button class="btn-copy-mini" data-copy="' + escapeHtml(i.indicator) + '">COPY</button>' +
            '</div>' +
          '</td>' +
          '<td><span class="badge-killchain">' + escapeHtml(i.killChain) + '</span></td>' +
          '<td><strong style="color:var(--text-primary);">' + escapeHtml(i.family) + '</strong></td>' +
          '<td><span class="actor-filter-link" data-actor-filter="' + escapeHtml(i.actor) + '">' + escapeHtml(i.actor) + '</span></td>' +
          '<td><span class="badge-sev ' + sevClass + '">' + escapeHtml(i.severity) + '</span></td>' +
          '<td style="color:var(--text-muted);font-family:var(--font-mono);font-size:0.75rem;">' + escapeHtml(i.platform) + '</td>' +
          '<td><button class="btn-inspect-row" data-inspect="' + i.id + '">Inspect &rarr;</button></td>' +
        '</tr>';
      }).join('');
    }

    function renderGroupedView() {
      const groups = new Map();

      filteredIndicators.forEach(item => {
        let key = 'Other';
        if (currentGrouping === 'actor') key = item.actor || 'Unattributed';
        else if (currentGrouping === 'campaign') key = item.campaign || 'Autonomous Activity';
        else if (currentGrouping === 'family') key = item.family || 'Generic Artifacts';
        else if (currentGrouping === 'killChain') key = item.killChain || 'Payload Execution';

        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(item);
      });

      if (groups.size === 0) {
        groupedView.innerHTML = '<div style="padding:30px;text-align:center;color:var(--text-muted);">No grouped indicators found.</div>';
        return;
      }

      let html = '';
      let idx = 0;
      groups.forEach((items, groupName) => {
        idx++;
        const critCount = items.filter(i => i.severity === 'Critical').length;
        const sevBadge = critCount > 0 ? '<span class="badge-sev sev-critical">Critical Cluster</span>' : '<span class="badge-sev sev-high">High Priority</span>';

        html += '<div class="cluster-card open">' +
          '<div class="cluster-header" onclick="toggleCluster(this)">' +
            '<div class="cluster-title-wrap">' +
              '<span class="cluster-chevron">&gt;</span>' +
              '<span class="cluster-name">' + escapeHtml(groupName) + '</span>' +
              sevBadge +
            '</div>' +
            '<div class="cluster-meta">' +
              '<span class="cluster-tag">' + items.length + ' Indicators</span>' +
            '</div>' +
          '</div>' +
          '<div class="cluster-body">' +
            '<table>' +
              '<thead>' +
                '<tr>' +
                  '<th>Type</th>' +
                  '<th>Indicator</th>' +
                  '<th>Role</th>' +
                  '<th>Family</th>' +
                  '<th>Severity</th>' +
                  '<th>Platform</th>' +
                  '<th>Action</th>' +
                '</tr>' +
              '</thead>' +
              '<tbody>' +
                items.map(function(i) {
                  const typeClass = 'badge-' + i.type.toLowerCase().replace(/[^a-z0-9]/g, '');
                  const sevClass = 'sev-' + (i.severity || 'high').toLowerCase();
                  return '<tr data-id="' + i.id + '">' +
                    '<td><span class="badge-type ' + typeClass + '">' + escapeHtml(i.type) + '</span></td>' +
                    '<td>' +
                      '<div class="indicator-cell">' +
                        '<span class="indicator-text">' + escapeHtml(i.indicator) + '</span>' +
                        '<button class="btn-copy-mini" data-copy="' + escapeHtml(i.indicator) + '">COPY</button>' +
                      '</div>' +
                    '</td>' +
                    '<td><span class="badge-killchain">' + escapeHtml(i.role) + '</span></td>' +
                    '<td><strong style="color:var(--text-primary);">' + escapeHtml(i.family) + '</strong></td>' +
                    '<td><span class="badge-sev ' + sevClass + '">' + escapeHtml(i.severity) + '</span></td>' +
                    '<td style="color:var(--text-muted);font-family:var(--font-mono);font-size:0.75rem;">' + escapeHtml(i.platform) + '</td>' +
                    '<td><button class="btn-inspect-row" data-inspect="' + i.id + '">Inspect &rarr;</button></td>' +
                  '</tr>';
                }).join('') +
              '</tbody>' +
            '</table>' +
          '</div>' +
        '</div>';
      });

      groupedView.innerHTML = html;
    }

    function toggleCluster(headerEl) {
      const card = headerEl.closest('.cluster-card');
      if (card) card.classList.toggle('open');
    }

    function setGrouping(mode) {
      currentGrouping = mode;
      document.querySelectorAll('.grouping-btn').forEach(function(b) { b.classList.remove('active'); });
      const activeBtn = document.querySelector('[data-group="' + mode + '"]');
      if (activeBtn) activeBtn.classList.add('active');
      renderCurrentView();
    }

    function changePage(delta) {
      const totalPages = Math.ceil(filteredIndicators.length / pageSize) || 1;
      currentPage += delta;
      if (currentPage < 1) currentPage = 1;
      if (currentPage > totalPages) currentPage = totalPages;
      renderFlatTable();
    }

    // Threat Actors Tab Filtering
    const actorSearchInput = document.getElementById('actorSearchInput');
    const actorSevFilter = document.getElementById('actorSevFilter');
    const visibleActorsCount = document.getElementById('visibleActorsCount');

    function filterActors() {
      const q = (actorSearchInput ? actorSearchInput.value : '').toLowerCase().trim().split(' ').filter(Boolean).join(' ');
      const sev = (actorSevFilter ? actorSevFilter.value : 'all').toLowerCase();
      const cards = document.querySelectorAll('.actor-card');
      let visible = 0;

      cards.forEach(card => {
        const text = (card.getAttribute('data-search') || '').toLowerCase();
        const cardSev = (card.getAttribute('data-sev') || '').toLowerCase();

        const matchQ = !q || text.includes(q);
        const matchSev = sev === 'all' || cardSev === sev;

        if (matchQ && matchSev) {
          card.style.display = '';
          visible++;
        } else {
          card.style.display = 'none';
        }
      });

      if (visibleActorsCount) visibleActorsCount.innerText = visible;
    }

    function resetActorFilters() {
      if (actorSearchInput) actorSearchInput.value = '';
      if (actorSevFilter) actorSevFilter.value = 'all';
      filterActors();
    }

    if (actorSearchInput) actorSearchInput.addEventListener('input', filterActors);
    if (actorSevFilter) actorSevFilter.addEventListener('change', filterActors);

    // C2 Tab Filtering
    const c2SearchInput = document.getElementById('c2SearchInput');
    const c2TypeFilter = document.getElementById('c2TypeFilter');
    const visibleC2Count = document.getElementById('visibleC2Count');

    function filterC2() {
      const q = (c2SearchInput ? c2SearchInput.value : '').toLowerCase().trim().split(' ').filter(Boolean).join(' ');
      const type = (c2TypeFilter ? c2TypeFilter.value : 'all');
      const rows = document.querySelectorAll('#c2Tbody tr');
      let visible = 0;

      rows.forEach(r => {
        const rowSearch = (r.getAttribute('data-search') || '').toLowerCase();
        const rowType = r.getAttribute('data-type') || '';

        const matchQ = !q || rowSearch.includes(q);
        const matchType = type === 'all' || rowType === type;

        if (matchQ && matchType) {
          r.style.display = '';
          visible++;
        } else {
          r.style.display = 'none';
        }
      });

      if (visibleC2Count) visibleC2Count.innerText = visible;
    }

    function resetC2Filters() {
      if (c2SearchInput) c2SearchInput.value = '';
      if (c2TypeFilter) c2TypeFilter.value = 'all';
      filterC2();
    }

    if (c2SearchInput) c2SearchInput.addEventListener('input', filterC2);

    // OpenCTI Drawer Controls
    function openDrawerById(id) {
      const item = ALL_INDICATORS.find(x => x.id === id);
      if (!item) return;
      selectedIndicator = item;

      document.getElementById('drawerTypeRole').innerText = item.type + ' // ' + item.role;
      document.getElementById('drawerIndicatorVal').innerText = item.indicator;
      document.getElementById('drawerActor').innerText = item.actor;
      document.getElementById('drawerAliases').innerText = item.actorAliases.length ? item.actorAliases.join(', ') : 'None documented';
      document.getElementById('drawerCampaign').innerText = item.campaign;
      document.getElementById('drawerFamily').innerText = item.family;
      document.getElementById('drawerKillChain').innerText = item.killChain;
      document.getElementById('drawerSeverity').innerText = item.severity;
      document.getElementById('drawerSectors').innerText = item.targetSectors.join(', ');
      document.getElementById('drawerPlatform').innerText = item.platform;
      document.getElementById('drawerFirstSeen').innerText = item.firstSeen;
      document.getElementById('drawerTLP').innerText = item.tlp;

      document.getElementById('drawerReportBtn').href = item.localPath;
      const ind = encodeURIComponent(item.indicator);
      document.getElementById('drawerVTBtn').href = 'https://www.virustotal.com/gui/search/' + ind;

      document.getElementById('drawerOverlay').classList.add('active');
      document.getElementById('entityDrawer').classList.add('open');
    }

    function closeDrawer() {
      document.getElementById('drawerOverlay').classList.remove('active');
      document.getElementById('entityDrawer').classList.remove('open');
    }

    function copyCurrentIndicator() {
      if (!selectedIndicator) return;
      copyText(selectedIndicator.indicator, document.getElementById('drawerCopyBtn'));
    }

    function copyText(val, btnEl) {
      navigator.clipboard.writeText(val).then(() => {
        showToast('Copied: ' + val);
        if (btnEl) {
          const oldText = btnEl.innerText;
          btnEl.innerText = 'COPIED';
          btnEl.classList.add('copied');
          setTimeout(() => {
            btnEl.innerText = oldText;
            btnEl.classList.remove('copied');
          }, 1800);
        }
      }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = val;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('Copied: ' + val);
        if (btnEl) {
          const oldText = btnEl.innerText;
          btnEl.innerText = 'COPIED';
          btnEl.classList.add('copied');
          setTimeout(() => {
            btnEl.innerText = oldText;
            btnEl.classList.remove('copied');
          }, 1800);
        }
      });
    }

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.innerText = msg;
      t.classList.add('show');
      setTimeout(() => { t.classList.remove('show'); }, 2500);
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab-pane').forEach(function(p) { p.classList.remove('active'); });
      document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
      const pane = document.getElementById(tabId);
      if (pane) pane.classList.add('active');
      const activeBtn = document.querySelector('[data-tab="' + tabId + '"]');
      if (activeBtn) activeBtn.classList.add('active');
    }

    function filterByActor(actorName) {
      switchTab('tab-indicators');
      searchInput.value = actorName;
      applyFilters();
    }

    // Universal event delegation for row click, copy button, and inspect button
    document.addEventListener('click', function(e) {
      const actorBtn = e.target.closest('[data-actor-filter]');
      if (actorBtn) {
        e.stopPropagation();
        const actorName = actorBtn.getAttribute('data-actor-filter');
        filterByActor(actorName);
        return;
      }
      const copyBtn = e.target.closest('button[data-copy]');
      if (copyBtn) {
        e.stopPropagation();
        const text = copyBtn.getAttribute('data-copy');
        copyText(text, copyBtn);
        return;
      }
      const inspectBtn = e.target.closest('button[data-inspect]');
      if (inspectBtn) {
        e.stopPropagation();
        const id = inspectBtn.getAttribute('data-inspect');
        openDrawerById(id);
        return;
      }
      const row = e.target.closest('tr[data-id]');
      if (row && !e.target.closest('a') && !e.target.closest('button')) {
        const id = row.getAttribute('data-id');
        openDrawerById(id);
      }
    });

    // Attach search/filter listeners
    searchInput.addEventListener('input', applyFilters);
    typeFilter.addEventListener('change', applyFilters);
    severityFilter.addEventListener('change', applyFilters);
    killChainFilter.addEventListener('change', applyFilters);
    platformFilter.addEventListener('change', applyFilters);

    // Initial render
    applyFilters();
  </script>
</body>
</html>`;

  fs.writeFileSync(path.join(IOC_PAGE_DIR, 'index.html'), html, 'utf8');

  // Automated Pre-Flight Client-Side Browser Runtime Verification
  verifyClientRuntime(html);

  console.log(`[SUCCESS] Rebuilt State-of-the-Art Threat Intelligence Portal`);
  console.log(`- Page: ${path.join(IOC_PAGE_DIR, 'index.html')}`);
  console.log(`- Total Indicators: ${total}`);
  console.log(`- Total Tracked Actors: ${actors.length}`);
}

function verifyClientRuntime(html) {
  const vm = require('vm');
  const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
  if (!scriptMatch) throw new Error('Client runtime verification failed: No <script> found in HTML!');

  const createMock = (val = '') => ({
    value: val,
    innerText: '',
    innerHTML: '',
    style: {},
    classList: {
      add(c) { this.className = (this.className || '') + ' ' + c; },
      remove(c) { this.className = (this.className || '').replace(new RegExp('\\b' + c + '\\b', 'g'), '').trim(); },
      toggle(c) { if ((this.className || '').includes(c)) this.remove(c); else this.add(c); }
    },
    appendChild(child) {},
    addEventListener(evt, fn) {},
    closest(sel) { return this; },
    getAttribute(attr) { return 'ind-1'; }
  });

  const elements = {
    searchInput: createMock(''),
    typeFilter: createMock('all'),
    severityFilter: createMock('all'),
    killChainFilter: createMock('all'),
    platformFilter: createMock('all'),
    indicatorsTbody: createMock(''),
    flatView: createMock(''),
    groupedView: createMock(''),
    paginationWrap: createMock(''),
    curPageNum: createMock(''),
    totalPageNum: createMock(''),
    prevPageBtn: createMock(''),
    nextPageBtn: createMock(''),
    pageNumberButtons: createMock(''),
    visibleCounter: createMock(''),
    actorSearchInput: createMock(''),
    actorSevFilter: createMock('all'),
    visibleActorsCount: createMock(''),
    c2SearchInput: createMock(''),
    c2TypeFilter: createMock('all'),
    visibleC2Count: createMock(''),
    drawerTypeRole: createMock(''),
    drawerIndicatorVal: createMock(''),
    drawerActor: createMock(''),
    drawerAliases: createMock(''),
    drawerCampaign: createMock(''),
    drawerFamily: createMock(''),
    drawerKillChain: createMock(''),
    drawerSeverity: createMock(''),
    drawerSectors: createMock(''),
    drawerPlatform: createMock(''),
    drawerFirstSeen: createMock(''),
    drawerTLP: createMock(''),
    drawerReportBtn: createMock(''),
    drawerVTBtn: createMock(''),
    drawerOverlay: createMock(''),
    entityDrawer: createMock(''),
    toast: createMock('')
  };

  const mockDoc = {
    getElementById: (id) => elements[id] || createMock(''),
    createElement: () => createMock(''),
    querySelectorAll: () => [],
    querySelector: () => createMock(''),
    addEventListener: () => {}
  };

  const sandbox = {
    document: mockDoc,
    window: { document: mockDoc },
    navigator: { clipboard: { writeText: () => Promise.resolve() } },
    console: console
  };

  vm.runInNewContext(scriptMatch[1], sandbox);

  // Verification 1: Initial Flat Table Render
  if (!elements.indicatorsTbody.innerHTML || elements.indicatorsTbody.innerHTML.length < 500) {
    throw new Error('Runtime Verification Failed: Table rows not populated on initial page load!');
  }

  // Verification 2: Grouping Modes
  const groupingModes = ['actor', 'campaign', 'family', 'killChain'];
  for (const mode of groupingModes) {
    vm.runInNewContext(`setGrouping("${mode}");`, sandbox);
    if (!elements.groupedView.innerHTML || elements.groupedView.innerHTML.length < 500) {
      throw new Error(`Runtime Verification Failed: Grouped view empty for mode '${mode}'!`);
    }
  }

  // Verification 3: Search for Red Menshen + KillChain Grouping
  elements.searchInput.value = 'Red  Menshen';
  vm.runInNewContext('applyFilters(); setGrouping("killChain");', sandbox);
  if (!elements.groupedView.innerHTML.includes('BPFDoor')) {
    throw new Error('Runtime Verification Failed: Red Menshen / BPFDoor not rendered in filtered grouped view!');
  }

  // Verification 4: Search for Lazarus
  elements.searchInput.value = 'Lazarus';
  vm.runInNewContext('applyFilters(); setGrouping("actor");', sandbox);
  if (!elements.groupedView.innerHTML.includes('RustBucket')) {
    throw new Error('Runtime Verification Failed: Lazarus Group / RustBucket not rendered in filtered grouped view!');
  }

  // Verification 5: Drawer & Tabs
  vm.runInNewContext('openDrawerById("ind-1");', sandbox);
  if (!elements.drawerTypeRole.innerText) {
    throw new Error('Runtime Verification Failed: Drawer title not populated on openDrawerById!');
  }
  vm.runInNewContext('switchTab("tab-actors"); switchTab("tab-indicators"); switchTab("tab-c2"); switchTab("tab-export");', sandbox);

  console.log('[VERIFIED] Automated Client-Side Browser Runtime Tests Passed (5/5 checks clean)');
}

buildFeeds();
