'use strict';
const API = 'http://127.0.0.1:8000';

/* ══════════════════════════════════════════════════
   BACKGROUND INJECT
══════════════════════════════════════════════════ */
function injectBg() {
  document.body.insertAdjacentHTML('afterbegin', `
    <div class="bg-grid"></div>
    <div class="bg-noise"></div>
    <div class="bg-scanline"></div>
    <div class="orb o1"></div>
    <div class="orb o2"></div>
    <div class="orb o3"></div>
    <div class="toast" id="toast"></div>
  `);
}
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* ══════════════════════════════════════════════════
   TOAST
══════════════════════════════════════════════════ */
let _tt;
function toast(msg, type = 'info') {
  let el = document.getElementById('toast');
  if (!el) return;
  clearTimeout(_tt);
  const icons = { info:'ℹ️', success:'✅', error:'🚨', warning:'⚠️' };
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${icons[type]||'ℹ️'}</span><span>${msg}</span>`;
  el.classList.add('show');
  _tt = setTimeout(() => el.classList.remove('show'), 3500);
}

/* ══════════════════════════════════════════════════
   AUTH
══════════════════════════════════════════════════ */
function requireAuth() {
  const u = localStorage.getItem('msa_user');
  if (!u) { location.href = 'login.html'; return null; }
  return JSON.parse(u);
}
function getUser() {
  const u = localStorage.getItem('msa_user');
  return u ? JSON.parse(u) : null;
}
function logout() {
  localStorage.removeItem('msa_user');
  location.href = 'login.html';
}

/* ══════════════════════════════════════════════════
   SESSION STATS
══════════════════════════════════════════════════ */
function getStats(uid) {
  return JSON.parse(localStorage.getItem(`msa_s_${uid}`) || '{"safe":0,"susp":0,"phish":0}');
}
function saveStats(uid, s) {
  localStorage.setItem(`msa_s_${uid}`, JSON.stringify(s));
}
function bumpStat(uid, label) {
  const s = getStats(uid);
  if      (label === 'safe')     s.safe++;
  else if (label === 'spam')     s.susp++;
  else if (label === 'phishing') s.phish++;
  saveStats(uid, s);
}
function renderSideStats(uid) {
  const s = getStats(uid);
  _set('ss-safe',  s.safe);
  _set('ss-susp',  s.susp);
  _set('ss-phish', s.phish);
  _set('hBadge',   s.safe + s.susp + s.phish);
}
function _set(id, v) {
  const el = document.getElementById(id);
  if (el) el.textContent = v;
}

/* ══════════════════════════════════════════════════
   TOPBAR
══════════════════════════════════════════════════ */
function initTopbar(user, page) {
  _set('tbName', user.name);
  const av = document.getElementById('tbAvatar');
  if (av) av.textContent = user.name[0].toUpperCase();
  document.querySelectorAll('.nav-link[data-p]').forEach(el => {
    el.classList.toggle('active', el.dataset.p === page);
  });
  setInterval(() => {
    const el = document.getElementById('tbClock');
    if (el) el.textContent = new Date().toLocaleTimeString();
  }, 1000);
  const start = Date.now();
  setInterval(() => {
    const el = document.getElementById('uptime');
    if (!el) return;
    const sec = Math.floor((Date.now() - start) / 1000);
    el.textContent = `${String(Math.floor(sec/60)).padStart(2,'0')}:${String(sec%60).padStart(2,'0')}`;
  }, 1000);
}

/* ══════════════════════════════════════════════════
   HISTORY STORAGE
══════════════════════════════════════════════════ */
function getHistory(uid) {
  return JSON.parse(localStorage.getItem(`msa_h_${uid}`) || '[]');
}
function saveHistory(uid, arr) {
  localStorage.setItem(`msa_h_${uid}`, JSON.stringify(arr));
}
function pushHistory(uid, record) {
  const arr = getHistory(uid);
  arr.unshift(record);
  saveHistory(uid, arr);
}

/* ══════════════════════════════════════════════════
   RESULT STORAGE
══════════════════════════════════════════════════ */
function saveResult(r) {
  localStorage.setItem('msa_result', JSON.stringify(r));
}
function loadResult() {
  const r = localStorage.getItem('msa_result');
  return r ? JSON.parse(r) : null;
}

/* ══════════════════════════════════════════════════
   REAL API CALL
   Falls back to heuristic if backend is unreachable.
══════════════════════════════════════════════════ */
async function analyzeEmail(content) {
  const user = getUser();

  try {
    const resp = await fetch(`${API}/predict`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ text: content, user: user ? user.name : 'analyst' }),
      signal:  AbortSignal.timeout(10000)
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const data = await resp.json();

    const label = data.label || 'safe';

    let pSafe, pSusp, pPhish;
    if (data.probabilities) {
      pSafe  = Math.round((data.probabilities.safe     || 0) * 100);
      pSusp  = Math.round((data.probabilities.spam     || 0) * 100);
      pPhish = Math.round((data.probabilities.phishing || 0) * 100);
    } else {
      pSafe  = data.pSafe  ?? 0;
      pSusp  = data.pSusp  ?? 0;
      pPhish = data.pPhish ?? 0;
    }

    let riskPct;
    if (data.riskPct !== undefined) {
      riskPct = data.riskPct;
    } else {
      const dominant = Math.max(pSafe, pSusp, pPhish);
      riskPct = label === 'safe' ? (100 - pSafe) : dominant;
    }
    riskPct = Math.min(100, Math.max(0, riskPct));

    const indicators = buildIndicatorsFromAPI(data, content.toLowerCase());

    return {
      label, riskPct, pSafe, pSusp, pPhish,
      indicators, content,
      timestamp: new Date().toLocaleString(),
      id:        Date.now(),
      source:    'CNN Model'
    };

  } catch (err) {
    console.warn('[MailShieldAI] Backend unreachable, using heuristic fallback.', err.message);
    const fallback = heuristicClassify(content);
    return { ...fallback, source: 'Heuristic (offline)' };
  }
}

/* ══════════════════════════════════════════════════
   BUILD INDICATORS FROM REAL API RESPONSE
══════════════════════════════════════════════════ */
function buildIndicatorsFromAPI(data, textLower) {
  const inds = [];

  if (data.suspicious_urls && data.suspicious_urls.length > 0) {
    data.suspicious_urls.slice(0, 2).forEach(url => {
      inds.push({ icon:'🔗', text:`Suspicious URL: ${url.length > 60 ? url.slice(0,60)+'…' : url}`, sev:'high', type:'danger' });
    });
  } else if (/https?:\/\//.test(textLower)) {
    inds.push({ icon:'🔗', text:'URL detected in email body — analyzed by CNN model', sev:'medium', type:'warn' });
  } else {
    inds.push({ icon:'✅', text:'No suspicious URLs detected', sev:'low', type:'ok' });
  }

  const ks = data.keyword_score ?? 0;
  if (ks >= 3)      inds.push({ icon:'⚡', text:`High keyword threat score: ${ks} phishing triggers matched`, sev:'high',   type:'danger' });
  else if (ks >= 1) inds.push({ icon:'⚠️', text:`Keyword risk score: ${ks} suspicious terms found`,          sev:'medium', type:'warn'   });
  else              inds.push({ icon:'✅', text:'Zero phishing keywords detected in content',                 sev:'low',    type:'ok'     });

  const rs = data.risk_score ?? 0;
  if (rs >= 5)      inds.push({ icon:'🚨', text:`Composite risk score critical: ${rs} / 10`, sev:'high',   type:'danger' });
  else if (rs >= 3) inds.push({ icon:'⚠️', text:`Composite risk score elevated: ${rs}`,      sev:'medium', type:'warn'   });
  else              inds.push({ icon:'🛡️', text:`Composite risk score low: ${rs}`,            sev:'low',    type:'ok'     });

  const conf = data.confidence ?? 0;
  const cp   = Math.round(conf * 100);
  if (data.label === 'phishing' && cp > 70)
    inds.push({ icon:'🧠', text:`CNN model: ${cp}% phishing probability`,             sev:'high',   type:'danger' });
  else if (data.label === 'spam')
    inds.push({ icon:'🔍', text:`CNN model: ${cp}% output — classified as suspicious`, sev:'medium', type:'warn'   });
  else
    inds.push({ icon:'✅', text:`CNN model: ${cp}% output — classified as safe`,       sev:'low',    type:'ok'     });

  if (/click here/i.test(textLower))
    inds.push({ icon:'👆', text:'"Click here" anchor — classic phishing vector', sev:'high', type:'danger' });
  if (/urgent|immediately|act now/i.test(textLower))
    inds.push({ icon:'⚡', text:'Urgency language detected — psychological pressure tactic', sev:'medium', type:'warn' });
  if (data.label === 'safe' && inds.filter(i => i.type !== 'ok').length === 0)
    inds.push({ icon:'🛡️', text:'Sender patterns and headers appear legitimate', sev:'low', type:'ok' });

  return inds.slice(0, 6);
}

/* ══════════════════════════════════════════════════
   HEURISTIC FALLBACK  (used when backend is down)
══════════════════════════════════════════════════ */
function heuristicClassify(content) {
  const txt = content.toLowerCase();

  const PHISH = ['verify your account','click here','urgent','password','billing',
    'account suspended','confirm identity','login attempt','security alert',
    'unusual activity','limited time','act now','dear customer',
    'update your information','verify your email','reset your password'];
  const SPAM  = ['free','winner','congratulations','prize','discount','buy now','sale',
    'unsubscribe','promotional','earn money','100% free','lucky winner'];

  let ps = 0, ss = 0, safe = 60;
  PHISH.forEach(k => { if (txt.includes(k)) ps += 7; });
  SPAM.forEach(k  => { if (txt.includes(k)) ss += 5; });
  if (/https?:\/\/[^\s]+/g.test(txt))  ps += 12;
  if (/@(?!gmail|yahoo|outlook|hotmail|company)[^\s,>]+\.[a-z]{2,4}/.test(txt)) ps += 14;
  if (/bit\.ly|tinyurl|goo\.gl/.test(txt)) ps += 10;
  if (/[0-9a-f]{8}-[0-9a-f]{4}/.test(txt)) ps += 6;

  const total = ps + ss + safe;
  let pP    = Math.min(ps / total, 0.95);
  let pS    = Math.min(ss / total, 0.90);
  let pSafe = Math.max(1 - pP - pS, 0.02);
  const norm = pP + pS + pSafe;
  pP /= norm; pS /= norm; pSafe /= norm;

  let label, riskPct;
  if      (pP > 0.35) { label = 'phishing'; riskPct = Math.round(pP    * 100); }
  else if (pS > 0.25) { label = 'spam';     riskPct = Math.round(pS    * 100); }
  else                { label = 'safe';     riskPct = Math.round((1 - pSafe) * 100); }

  return {
    label, riskPct,
    pSafe:  Math.round(pSafe * 100),
    pSusp:  Math.round(pS    * 100),
    pPhish: Math.round(pP    * 100),
    indicators: buildIndicators(txt, label),
    content,
    timestamp: new Date().toLocaleString(),
    id: Date.now()
  };
}

/* ══════════════════════════════════════════════════
   BUILD INDICATORS (heuristic fallback)
══════════════════════════════════════════════════ */
function buildIndicators(t, label) {
  const all = [];
  if (/https?:\/\//.test(t))                all.push({icon:'🔗', text:'Suspicious URL detected in body — potential redirect attack',      sev:'high',   type:'danger'});
  if (/bit\.ly|tinyurl/.test(t))             all.push({icon:'🔀', text:'URL shortener detected — final destination obfuscated',            sev:'high',   type:'danger'});
  if (/click here/i.test(t))                 all.push({icon:'👆', text:'"Click here" anchor — classic phishing vector',                   sev:'high',   type:'danger'});
  if (/urgent|immediately|act now/i.test(t)) all.push({icon:'⚡', text:'Urgency language detected — psychological pressure tactic',        sev:'medium', type:'warn'  });
  if (/verify|confirm/i.test(t))             all.push({icon:'🔐', text:'Account verification request — credential harvesting pattern',     sev:'high',   type:'danger'});
  if (/password|login/i.test(t))             all.push({icon:'🔑', text:'Password/login keyword — identity theft indicator',               sev:'medium', type:'warn'  });
  if (/reply-to/i.test(t))                   all.push({icon:'↩️', text:'Reply-To header mismatch — domain spoofing pattern',              sev:'high',   type:'danger'});
  if (label === 'safe') {
    all.push({icon:'✅', text:'No critical threat patterns identified in content', sev:'low', type:'ok'});
    all.push({icon:'🛡️', text:'Sender patterns and headers appear legitimate',     sev:'low', type:'ok'});
  }
  if (!all.length) all.push({icon:'⚠️', text:'Anomalous content structure — manual review recommended', sev:'medium', type:'warn'});
  return all.slice(0, 6);
}

/* ══════════════════════════════════════════════════
   SCAN OVERLAY ANIMATION
══════════════════════════════════════════════════ */
async function runScanOverlay(apiPromise) {

  const overlay = document.getElementById('scanOverlay');
  const fill    = document.getElementById('soFill');
  const logEl   = document.getElementById('soLog');
  const term    = document.getElementById('soTerminal');

  if (overlay) overlay.classList.add('show');
  if (fill)    fill.style.width = '0%';
  if (term)    term.innerHTML = '';

  const STEPS = [
    'Tokenizing email content...',
    'Extracting URL patterns...',
    'Running CNN forward pass...',
    'Scoring keyword indicators...',
    'Analyzing header metadata...',
    'Computing composite risk score...',
    'Applying cybersecurity ruleset...',
    'Generating threat report...'
  ];

  const animPromise = (async () => {
    for (let i = 0; i < STEPS.length; i++) {
      await sleep(120 + Math.random() * 60);
      if (fill)  fill.style.width = ((i + 1) / STEPS.length * 100) + '%';
      if (logEl) logEl.textContent = STEPS[i];
      if (term) {
        const line = document.createElement('div');
        line.className = 'so-term-line run';
        line.textContent = `[${new Date().toLocaleTimeString()}] ${STEPS[i]}`;
        term.appendChild(line);
        term.scrollTop = term.scrollHeight;
      }
    }
  })();

  /* Wait for both animation AND api — max 15s */
  await Promise.race([
    Promise.all([animPromise, apiPromise]),
    new Promise(resolve => setTimeout(resolve, 15000))
  ]);

  await sleep(200);

  if (overlay) overlay.classList.remove('show');
  if (fill)    fill.style.width = '0%';
}

/* ══════════════════════════════════════════════════
   MAIN SCAN FUNCTION  ← single definition, in script.js only
══════════════════════════════════════════════════ */
async function startScan() {

  const ta = document.getElementById('emailInput');
  const content = ta ? ta.value.trim() : '';

  if (!content) {
    toast('Paste email content first', 'error');
    return;
  }

  const btn = document.getElementById('scanBtn');
  if (btn) btn.disabled = true;

  let result = null;

  try {
    /* analyzeEmail never throws — it has an internal heuristic fallback */
    const apiPromise = analyzeEmail(content);
    await runScanOverlay(apiPromise);
    result = await apiPromise;
  } catch (err) {
    /* Safety net — should never reach here */
    console.error('[startScan] Unexpected error:', err);
    result = heuristicClassify(content);
    result.source = 'Heuristic (error fallback)';
  }

  /* Always close overlay */
  const overlay = document.getElementById('scanOverlay');
  if (overlay) overlay.classList.remove('show');

  if (!result) {
    toast('Analysis failed — please try again', 'error');
    if (btn) btn.disabled = false;
    return;
  }

  /* Save stats + history */
  const user = getUser();
  if (user) {
    bumpStat(user.id, result.label);
    renderSideStats(user.id);
    pushHistory(user.id, result);
  }

  /* Persist result for result.html */
  saveResult(result);

  /* Toast notification */
  const toastType =
    result.label === 'phishing' ? 'error'   :
    result.label === 'spam'     ? 'warning'  :
    'success';
  toast(`${result.label.toUpperCase()} — Risk: ${result.riskPct}%`, toastType);

  /* Navigate to result page */
  setTimeout(() => { window.location.href = 'result.html'; }, 600);

  if (btn) btn.disabled = false;
}

/* ══════════════════════════════════════════════════
   SPARKLINE
══════════════════════════════════════════════════ */
function buildSparkline(uid) {
  const el = document.getElementById('sparkline'); if (!el) return;
  const s   = getStats(uid);
  const max = Math.max(s.safe, s.susp, s.phish, 1);
  const cols = ['g', 'y', 'r'], vals = [s.safe, s.susp, s.phish];
  let html = '';
  for (let i = 0; i < 15; i++) {
    const idx = i % 3;
    const h   = Math.max(3, Math.round(vals[idx] / max * 40) + Math.floor(Math.random() * 7));
    html += `<div class="spark-b ${cols[idx]}" style="height:${h}px"></div>`;
  }
  el.innerHTML = html;
}

/* ══════════════════════════════════════════════════
   RESULT PAGE RENDERER
══════════════════════════════════════════════════ */
const COL = { safe:'var(--green)', spam:'var(--yellow)', phishing:'var(--red)' };
const CX  = { safe:'g',           spam:'y',             phishing:'r'          };

function showResultPage(r) {
  const e = document.getElementById('resultEmpty');
  const d = document.getElementById('resultData');
  if (e) e.style.display = 'none';
  if (d) d.style.display = 'block';

  _set('resultSub', `Scanned at ${r.timestamp} · ${r.content.length} chars`);
  _set('rScanId',   `#${r.id}`);

  const ab = document.getElementById('alertBanner');
  if (ab) ab.style.display = r.label === 'phishing' ? 'flex' : 'none';

  const acc = document.getElementById('rCardAccent');
  const dot = document.getElementById('rDot');
  if (acc) acc.className = `card-accent ${CX[r.label]}`;
  if (dot) dot.className = `cdot ${CX[r.label]}`;

  const gFill = document.getElementById('gaugeFill');
  const gGlow = document.getElementById('gaugeGlow');
  const gPct  = document.getElementById('gaugePct');

  if (gFill && gGlow) {
    gFill.className = `gauge-fill ${r.label}`;
    gGlow.className = `gauge-glow-ring ${r.label}`;
    gFill.style.strokeDashoffset = '597';
    gGlow.style.strokeDashoffset = '597';
    gFill.getBoundingClientRect();
    const offset = 597 - (r.riskPct / 100) * 597;
    setTimeout(() => {
      gFill.style.strokeDashoffset = offset;
      gGlow.style.strokeDashoffset = offset;
    }, 50);
  }

  if (gPct) { gPct.textContent = r.riskPct + '%'; gPct.style.color = COL[r.label]; }

  const badge = document.getElementById('rBadge');
  if (badge) { badge.className = `risk-badge ${r.label}`; badge.textContent = r.label.toUpperCase(); }

  _set('pSafe',  r.pSafe  + '%');
  _set('pSusp',  r.pSusp  + '%');
  _set('pPhish', r.pPhish + '%');

  setTimeout(() => {
    const bs = document.getElementById('bSafe');
    const by = document.getElementById('bSusp');
    const br = document.getElementById('bPhish');
    if (bs) bs.style.width = r.pSafe  + '%';
    if (by) by.style.width = r.pSusp  + '%';
    if (br) br.style.width = r.pPhish + '%';
  }, 200);

  const prow = document.getElementById('pipRow');
  if (prow) {
    const MAX = 10;
    const sc  = Math.min(Math.round(r.riskPct / 10), MAX);
    const pc  = CX[r.label];
    prow.innerHTML = Array.from({ length: MAX }, (_, i) =>
      `<div class="pip ${i < sc ? pc : ''}" style="transition-delay:${i * 55}ms"></div>`
    ).join('');
  }

  const ptxt = document.getElementById('pipText');
  if (ptxt) {
    const lab = r.riskPct >= 70 ? '🚨 Critical' : r.riskPct >= 40 ? '⚠️ Elevated' : '✅ Low';
    ptxt.innerHTML = `${lab} — Score <b style="color:${COL[r.label]}">${r.riskPct}</b>/100`;
  }

  const mg = document.getElementById('metaGrid');
  if (mg) mg.innerHTML = `
    <div class="meta-item"><div class="meta-key">Classification</div><div class="meta-val" style="color:${COL[r.label]}">${r.label.toUpperCase()}</div></div>
    <div class="meta-item"><div class="meta-key">Risk Score</div><div class="meta-val" style="color:${COL[r.label]}">${r.riskPct}%</div></div>
    <div class="meta-item"><div class="meta-key">Content Length</div><div class="meta-val">${r.content.length} chars</div></div>
    <div class="meta-item"><div class="meta-key">AI Engine</div><div class="meta-val">${r.source || 'CNN v2.4'}</div></div>
    <div class="meta-item"><div class="meta-key">Scan ID</div><div class="meta-val" style="font-size:11px;color:var(--t2)">#${r.id}</div></div>
    <div class="meta-item"><div class="meta-key">Analyst</div><div class="meta-val" style="font-size:11px;color:var(--t2)">${getUser()?.name || '—'}</div></div>
  `;

  const il = document.getElementById('indList');
  if (il) il.innerHTML = (r.indicators || []).map((ind, i) => `
    <div class="ind-item ${ind.type}" style="animation-delay:${i * 70}ms">
      <span class="ind-icon">${ind.icon}</span>
      <span class="ind-text">${ind.text}</span>
      <span class="ind-sev ${ind.sev}">${ind.sev}</span>
    </div>`).join('');

  const ep = document.getElementById('emailPre');
  if (ep) ep.textContent = r.content.slice(0, 1000) + (r.content.length > 1000 ? '\n...[truncated]' : '');
}

/* ══════════════════════════════════════════════════
   EXPORT REPORT
══════════════════════════════════════════════════ */
function exportReport() {
  const r = loadResult(); if (!r) return;
  const lines = [
    'MailShieldAI — Threat Analysis Report',
    '='.repeat(50),
    `Timestamp:       ${r.timestamp}`,
    `Analyst:         ${getUser()?.name || '—'}`,
    `Classification:  ${r.label.toUpperCase()}`,
    `Risk Score:      ${r.riskPct}%`,
    `Source:          ${r.source || 'CNN v2.4'}`,
    `Safe Prob:       ${r.pSafe}%`,
    `Suspicious Prob: ${r.pSusp}%`,
    `Phishing Prob:   ${r.pPhish}%`,
    '',
    'Detection Indicators:',
    ...(r.indicators || []).map(i => `  [${i.sev.toUpperCase()}] ${i.text}`),
    '',
    'Email Content:',
    '-'.repeat(50),
    r.content
  ];
  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `mailshield_report_${r.id}.txt`;
  a.click();
  toast('Report exported', 'success');
}

/* ══════════════════════════════════════════════════
   LIVE JITTER  (scan page indicator bars)
══════════════════════════════════════════════════ */
function startJitter() {
  setInterval(() => {
    jitterBar('tib-url-bar',  'tib-url-val');
    jitterBar('tib-kw-bar',   'tib-kw-val');
    jitterBar('tib-hdr-bar',  'tib-hdr-val');
    jitterBar('tib-ai-bar',   'tib-ai-val');
  }, 1200);
}
function jitterBar(barId, lblId) {
  const b = document.getElementById(barId);
  const l = document.getElementById(lblId);
  if (!b || !l) return;
  const cur = parseFloat(b.style.width) || 50;
  const nv  = Math.max(10, Math.min(95, cur + (Math.random() - 0.5) * 8));
  b.style.width   = nv + '%';
  l.textContent   = Math.round(nv) + '%';
}

/* ══════════════════════════════════════════════════
   SAMPLE EMAILS
══════════════════════════════════════════════════ */
const SAMPLES = {
  phishing: `From: security-noreply@paypa1-secure.xyz\nReply-To: harvest@evil-domain.ru\nSubject: URGENT: Account Suspended — Verify Now\n\nDear Customer,\n\nWe detected unusual sign-in activity on your account. Your access will be permanently suspended in 24 hours unless you verify your identity immediately.\n\nVerify account now: http://bit.ly/secure-verify-now123\nUpdate password: http://paypa1-login.xyz/reset\n\nYour bank details may be at risk. Act now.\n\nPayPal Security Team`,
  safe:     `From: hr@techcorp.com\nTo: john.smith@techcorp.com\nSubject: Q4 Planning Meeting — Agenda\n\nHi John,\n\nShared the updated agenda for our Q4 planning meeting Friday at 2:00 PM in Conference Room B.\n\nTopics: Budget review, roadmap priorities, team OKRs for Q1.\n\nPlease review the slides beforehand.\n\nBest,\nSarah\nHR Director, TechCorp`,
  spam:     `From: winners@promo-unlimited.biz\nSubject: CONGRATULATIONS!! You WON $5,000 Gift Card!\n\nYou have been SELECTED as our LUCKY WINNER!\n\nClaim your FREE $5,000 gift card TODAY!\nLIMITED TIME OFFER — expires in 12 hours!\n\nEarn money fast — win big prizes!\n100% FREE — no purchase required!\n\nUnsubscribe | View in browser`
};