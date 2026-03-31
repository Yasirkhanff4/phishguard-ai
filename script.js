/**
 * PhishGuard AI — script.js
 * Handles all frontend logic: scanning, dashboard, history
 */

// ═══════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════
const API_BASE = "https://Yasirkhanff4-phishguard-ai.hf.space/api"; // Flask backend
let scanHistory = [];
let pieChart = null;
let barChart = null;

// ═══════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════
function showPage(name) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-tab").forEach(t => t.classList.remove("active"));
  document.getElementById("page-" + name).classList.add("active");
  const tabs = document.querySelectorAll(".nav-tab");
  const pages = ["scan", "dashboard", "history"];
  tabs.forEach((t, i) => { if (pages[i] === name) t.classList.add("active"); });
  if (name === "dashboard") updateDashboard();
  if (name === "history")   renderHistory();
}

function loadSample(url) {
  document.getElementById("urlInput").value = url;
}

// ═══════════════════════════════════════════════════════
// MAIN SCAN
// ═══════════════════════════════════════════════════════
async function startScan() {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) { showToast("⚠️ Enter a URL first"); return; }

  // Reset UI
  document.getElementById("resultCard").classList.remove("active");
  document.getElementById("loadingBlock").classList.add("active");
  document.getElementById("scanBtn").disabled = true;
  for (let i = 1; i <= 5; i++) {
    const el = document.getElementById("step" + i);
    el.classList.remove("active", "done");
  }

  // Animate steps
  for (let i = 1; i <= 5; i++) {
    await delay(500);
    document.getElementById("step" + i).classList.add("active");
    if (i > 1) document.getElementById("step" + (i - 1)).classList.replace("active", "done");
  }

  try {
    // Call backend
    const res = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();

    if (!res.ok) throw new Error(data.error || "Scan failed");

    await delay(300);
    document.getElementById("step5").classList.replace("active", "done");
    await delay(200);
    document.getElementById("loadingBlock").classList.remove("active");

    renderResult(data);
    scanHistory.unshift({ ...data, timestamp: new Date() });

  } catch (err) {
    // Fallback: client-side rule-based when backend unavailable
    console.warn("Backend unavailable, using client-side analysis:", err.message);
    const features = clientExtractFeatures(url);
    const verdict = features.risk_score >= 60 ? "phishing"
                  : features.risk_score >= 35 ? "suspicious" : "safe";
    const confidence = verdict === "phishing" ? Math.min(features.risk_score, 99)
                     : verdict === "suspicious" ? 50 + features.risk_score / 4
                     : 95 - features.risk_score;

    await delay(300);
    document.getElementById("step5").classList.replace("active", "done");
    await delay(200);
    document.getElementById("loadingBlock").classList.remove("active");

    const fallbackData = {
      url, verdict,
      confidence: Math.round(confidence),
      features,
      risk_score: features.risk_score,
      model_used: "client_rule_based"
    };
    renderResult(fallbackData);
    scanHistory.unshift({ ...fallbackData, timestamp: new Date() });
  }

  document.getElementById("scanBtn").disabled = false;
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// ═══════════════════════════════════════════════════════
// CLIENT-SIDE FEATURE EXTRACTOR (fallback)
// ═══════════════════════════════════════════════════════
function clientExtractFeatures(url) {
  const lower = url.toLowerCase();
  const ipPattern = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;
  const keywords = ["login","verify","update","secure","account","bank","paypal",
    "signin","password","confirm","alert","suspend","validate","credential"];
  let domain = "";
  try {
    const u = new URL(lower.startsWith("http") ? lower : "http://" + lower);
    domain = u.hostname;
  } catch(e) { domain = url; }

  const found = keywords.filter(k => lower.includes(k));
  const urlLength = url.length;
  const hasHttps = lower.startsWith("https://");
  const hasIP = ipPattern.test(lower);
  const atSign = url.includes("@");
  const doubleSlash = url.indexOf("//", 8) > -1;
  const hyphenCount = (domain.match(/-/g) || []).length;
  const subdomainCount = Math.max(0, domain.split(".").length - 2);
  const dotCount = (url.match(/\./g) || []).length;

  let score = 0;
  if (!hasHttps) score += 15;
  if (hasIP) score += 25;
  if (urlLength > 75) score += 10;
  if (urlLength > 100) score += 10;
  if (atSign) score += 20;
  if (doubleSlash) score += 15;
  if (hyphenCount > 2) score += 10;
  if (subdomainCount > 2) score += 15;
  score += found.length * 8;
  if (dotCount > 5) score += 8;

  return {
    url_length: urlLength,
    dot_count: dotCount,
    has_https: hasHttps,
    has_ip: hasIP,
    has_at_sign: atSign,
    has_double_slash: doubleSlash,
    hyphen_count: hyphenCount,
    subdomain_count: subdomainCount,
    suspicious_keyword_count: found.length,
    found_keywords: found,
    domain,
    risk_score: Math.min(score, 100),
  };
}

// ═══════════════════════════════════════════════════════
// RENDER RESULT
// ═══════════════════════════════════════════════════════
function renderResult(data) {
  const { url, verdict, confidence, features } = data;
  const card = document.getElementById("resultCard");
  card.className = "active " + verdict;
  card.id = "resultCard";

  const icons  = { phishing: "🚨", suspicious: "⚠️", safe: "✅" };
  const labels = { phishing: "PHISHING DETECTED", suspicious: "SUSPICIOUS URL", safe: "LEGITIMATE URL" };
  const subs   = {
    phishing:   "This URL exhibits multiple high-risk indicators",
    suspicious: "This URL has some concerning characteristics",
    safe:       "This URL appears to be legitimate"
  };

  document.getElementById("verdictIcon").textContent  = icons[verdict];
  document.getElementById("verdictLabel").textContent = labels[verdict];
  document.getElementById("verdictSub").textContent   = subs[verdict];
  document.getElementById("confNum").textContent      = confidence + "%";
  document.getElementById("confLbl").textContent      = "CONFIDENCE";

  const fill = document.getElementById("confFill");
  fill.style.width = "0%";
  setTimeout(() => { fill.style.width = confidence + "%"; }, 100);

  // Feature chips
  const f = features;
  const chips = [
    { label: "URL Length",   value: (f.url_length||url.length) + " chars",
      status: (f.url_length||url.length) < 54 ? "ok" : (f.url_length||url.length) < 75 ? "warning" : "danger",
      icon:   (f.url_length||url.length) < 75 ? "✅" : "🚨" },
    { label: "Protocol",    value: f.has_https ? "HTTPS ✓" : "HTTP (Insecure)",
      status: f.has_https ? "ok" : "danger", icon: f.has_https ? "🔒" : "🔓" },
    { label: "IP Address",  value: f.has_ip ? "IP detected!" : "Domain name",
      status: f.has_ip ? "danger" : "ok", icon: f.has_ip ? "🚨" : "✅" },
    { label: "@ Symbol",    value: f.has_at_sign ? "Found (Red flag)" : "Not found",
      status: f.has_at_sign ? "danger" : "ok", icon: f.has_at_sign ? "🚨" : "✅" },
    { label: "Double Slash", value: f.has_double_slash ? "Found (Redirect)" : "Not found",
      status: f.has_double_slash ? "warning" : "ok", icon: f.has_double_slash ? "⚠️" : "✅" },
    { label: "Hyphens",     value: (f.hyphen_count||0) + " in domain",
      status: f.hyphen_count > 2 ? "danger" : f.hyphen_count > 0 ? "warning" : "ok",
      icon:   f.hyphen_count > 2 ? "🚨" : f.hyphen_count > 0 ? "⚠️" : "✅" },
    { label: "Subdomains",  value: Math.max(0, f.subdomain_count||0) + " levels",
      status: f.subdomain_count > 2 ? "danger" : f.subdomain_count > 0 ? "warning" : "ok",
      icon:   f.subdomain_count > 2 ? "🚨" : "✅" },
    { label: "Keywords",    value: (f.found_keywords||[]).length > 0 ? (f.found_keywords||[]).slice(0,2).join(", ") : "None",
      status: (f.found_keywords||[f.suspicious_keyword_count]).length > 0 && f.suspicious_keyword_count > 0 ? "danger" : "ok",
      icon:   f.suspicious_keyword_count > 0 ? "🚨" : "✅" },
    { label: "Risk Score",  value: (f.risk_score||0) + " / 100",
      status: f.risk_score >= 60 ? "danger" : f.risk_score >= 35 ? "warning" : "ok",
      icon:   f.risk_score >= 60 ? "🚨" : f.risk_score >= 35 ? "⚠️" : "✅" },
  ];

  document.getElementById("featuresGrid").innerHTML = chips.map(c => `
    <div class="feature-chip ${c.status}">
      <span class="chip-icon">${c.icon}</span>
      <div>
        <div class="chip-label">${c.label}</div>
        <div class="chip-value">${c.value}</div>
      </div>
    </div>
  `).join("");

  // AI analysis note
  const aiEl = document.getElementById("aiText");
  if (data.ai_analysis) {
    aiEl.textContent = data.ai_analysis;
  } else {
    const modelNote = data.model_used === "ml_model" ? "ML model (Random Forest)" : "Rule-based engine";
    const kws = (f.found_keywords||[]).slice(0,3).join(", ") || "none";
    aiEl.textContent = `Analysis via ${modelNote}. Risk score: ${f.risk_score}/100. `
      + `Key signals: ${f.has_ip?"IP address used, ":""}${!f.has_https?"no HTTPS, ":""}${f.has_at_sign?"@ symbol present, ":""}suspicious keywords: [${kws}].`;
  }

  card.classList.add("active");
  setTimeout(() => card.scrollIntoView({ behavior: "smooth", block: "nearest" }), 100);
}

// ═══════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════
async function updateDashboard() {
  // Try to fetch stats from backend
  try {
    const [statsRes, scansRes] = await Promise.all([
      fetch(`${API_BASE}/stats`),
      fetch(`${API_BASE}/scans?limit=50`)
    ]);
    const stats = await statsRes.json();
    const scans = await scansRes.json();
    renderDashboard(stats, scans);
  } catch(e) {
    // Use in-memory history
    const total   = scanHistory.length;
    const phishing = scanHistory.filter(s => s.verdict === "phishing").length;
    const safe     = scanHistory.filter(s => s.verdict === "safe").length;
    const suspicious = scanHistory.filter(s => s.verdict === "suspicious").length;
    renderDashboard({ total, phishing, safe, suspicious }, scanHistory.slice(0, 50));
  }
}

function renderDashboard(stats, scans) {
  document.getElementById("statTotal").textContent    = stats.total;
  document.getElementById("statPhishing").textContent = stats.phishing;
  document.getElementById("statSafe").textContent     = stats.safe;
  const rate = stats.total > 0 ? Math.round((stats.phishing / stats.total) * 100) : 0;
  document.getElementById("statRate").textContent     = rate + "%";

  // Pie chart
  const pieCtx = document.getElementById("pieChart").getContext("2d");
  if (pieChart) pieChart.destroy();
  pieChart = new Chart(pieCtx, {
    type: "doughnut",
    data: {
      labels: ["Phishing", "Suspicious", "Safe"],
      datasets: [{
        data: [stats.phishing, stats.suspicious || 0, stats.safe],
        backgroundColor: ["rgba(255,45,85,.8)", "rgba(255,215,0,.8)", "rgba(0,255,136,.8)"],
        borderColor: ["#ff2d55", "#ffd700", "#00ff88"],
        borderWidth: 2
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: "65%",
      plugins: { legend: { labels: { color: "#4a6080", font: { family: "Share Tech Mono", size: 11 } } } }
    }
  });

  // Bar chart
  const last10 = scans.slice(0, 10).reverse();
  const barCtx = document.getElementById("barChart").getContext("2d");
  if (barChart) barChart.destroy();
  barChart = new Chart(barCtx, {
    type: "bar",
    data: {
      labels: last10.map((_, i) => "#" + (i + 1)),
      datasets: [{
        label: "Confidence %",
        data: last10.map(s => s.confidence),
        backgroundColor: last10.map(s =>
          s.verdict === "phishing" ? "rgba(255,45,85,.7)" :
          s.verdict === "suspicious" ? "rgba(255,215,0,.7)" : "rgba(0,255,136,.7)"
        ),
        borderRadius: 4
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: "rgba(26,37,64,.8)" }, ticks: { color: "#4a6080", font: { family: "Share Tech Mono", size: 10 } } },
        y: { grid: { color: "rgba(26,37,64,.8)" }, ticks: { color: "#4a6080", font: { family: "Share Tech Mono", size: 10 } }, max: 100 }
      }
    }
  });

  // Recent table
  const tbody = document.getElementById("recentBody");
  const empty = document.getElementById("dashEmpty");
  if (scans.length === 0) {
    tbody.innerHTML = "";
    empty.style.display = "block";
  } else {
    empty.style.display = "none";
    tbody.innerHTML = scans.slice(0, 8).map(s => `
      <tr>
        <td class="url-td muted-td" title="${esc(s.url)}">${esc(s.url)}</td>
        <td><span class="pill ${s.verdict}">${s.verdict === "phishing" ? "🚨" : s.verdict === "suspicious" ? "⚠️" : "✅"} ${s.verdict.toUpperCase()}</span></td>
        <td class="muted-td">${s.confidence}%</td>
        <td class="dim-td">${formatTs(s.timestamp)}</td>
      </tr>
    `).join("");
  }
}

// ═══════════════════════════════════════════════════════
// HISTORY
// ═══════════════════════════════════════════════════════
async function renderHistory() {
  let scans = scanHistory;
  try {
    const res = await fetch(`${API_BASE}/scans?limit=200`);
    scans = await res.json();
  } catch(e) { /* use memory */ }

  const tbody = document.getElementById("histBody");
  const empty = document.getElementById("histEmpty");
  if (scans.length === 0) {
    tbody.innerHTML = "";
    empty.style.display = "block";
  } else {
    empty.style.display = "none";
    tbody.innerHTML = scans.map((s, i) => {
      const f = typeof s.features === "string" ? JSON.parse(s.features) : s.features;
      const kws = (f?.found_keywords||[]).slice(0,2).join(", ") || "—";
      return `
        <tr>
          <td class="dim-td">${i + 1}</td>
          <td class="url-td" title="${esc(s.url)}">${esc(s.url)}</td>
          <td><span class="pill ${s.verdict}">${s.verdict === "phishing" ? "🚨" : s.verdict === "suspicious" ? "⚠️" : "✅"} ${s.verdict.toUpperCase()}</span></td>
          <td class="muted-td">${s.confidence}%</td>
          <td class="muted-td">${kws}</td>
          <td class="dim-td">${formatTs(s.timestamp)}</td>
        </tr>
      `;
    }).join("");
  }
}

async function clearHistory() {
  try {
    await fetch(`${API_BASE}/scans/clear`, { method: "DELETE" });
  } catch(e) { /* ignore */ }
  scanHistory = [];
  renderHistory();
  showToast("🗑 All records cleared");
}

// ═══════════════════════════════════════════════════════
// UTILS
// ═══════════════════════════════════════════════════════
function esc(str) {
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function formatTs(ts) {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch(e) { return "—"; }
}

function showToast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 3000);
}

// Enter key
document.addEventListener("DOMContentLoaded", () => {
  const inp = document.getElementById("urlInput");
  if (inp) inp.addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });
});
