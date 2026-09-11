const $ = (id) => document.getElementById(id);
function looksLikeSolana(addr) {
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(addr) && !addr.startsWith("0x");
}
function looksLikeEvm(addr) {
  return /^0x[a-fA-F0-9]{40}$/.test(addr);
}
function fmtUsd(n) {
  if (n == null || Number.isNaN(n)) return "—";
  const x = Number(n);
  if (x >= 1e9) return "$" + (x / 1e9).toFixed(2) + "B";
  if (x >= 1e6) return "$" + (x / 1e6).toFixed(2) + "M";
  if (x >= 1e3) return "$" + (x / 1e3).toFixed(1) + "K";
  return "$" + x.toFixed(2);
}
function ageHours(createdAt) {
  if (!createdAt) return null;
  return (Date.now() - Number(createdAt)) / 36e5;
}
async function fetchDex(address) {
  const url = "https://api.dexscreener.com/latest/dex/tokens/" + encodeURIComponent(address);
  const res = await fetch(url);
  if (!res.ok) throw new Error("DexScreener request failed");
  return res.json();
}
async function fetchRugcheck(mint) {
  const url = "https://api.rugcheck.xyz/v1/tokens/" + encodeURIComponent(mint) + "/report";
  const res = await fetch(url);
  if (!res.ok) return null;
  return res.json();
}
function pairAgeLabel(hours) {
  if (hours == null) return "unknown";
  if (hours < 1) return Math.round(hours * 60) + " min";
  if (hours < 48) return hours.toFixed(1) + " h";
  return (hours / 24).toFixed(1) + " d";
}
function buildLinks(addr, chain) {
  const links = [];
  if (looksLikeSolana(addr)) {
    links.push(["RugCheck", "https://rugcheck.xyz/tokens/" + addr]);
    links.push(["Birdeye", "https://birdeye.so/token/" + addr + "?chain=solana"]);
    links.push(["Solscan", "https://solscan.io/token/" + addr]);
    links.push(["Bubblemaps", "https://app.bubblemaps.io/sol/token/" + addr]);
    links.push(["DexScreener", "https://dexscreener.com/solana/" + addr]);
  } else {
    const c = (chain || "ethereum").toLowerCase();
    links.push(["TokenSniffer", "https://tokensniffer.com/token/" + addr]);
    links.push(["Honeypot.is", "https://honeypot.is/ethereum?address=" + addr]);
    links.push(["GoPlus", "https://gopluslabs.io/token-security/" + addr]);
    links.push(["Bubblemaps", "https://app.bubblemaps.io/eth/token/" + addr]);
    links.push(["DexScreener", "https://dexscreener.com/" + c + "/" + addr]);
  }
  return links;
}
function analyzePairs(data) {
  const pairs = (data && data.pairs) || [];
  if (!pairs.length) {
    return { found: false, flags: ["No DexScreener pair found. Confirm the contract from an official source, not a DM."], metrics: {} };
  }
  pairs.sort((a, b) => Number(b.liquidity?.usd || 0) - Number(a.liquidity?.usd || 0));
  const p = pairs[0];
  const liq = Number(p.liquidity?.usd || 0);
  const vol = Number(p.volume?.h24 || 0);
  const hours = ageHours(p.pairCreatedAt);
  const flags = [];
  let severity = "warn";
  if (liq < 10000) flags.push("Liquidity under $10k — a small sell can nuke the chart.");
  if (liq < 1000) flags.push("Critical: liquidity is dust. Treat as hard-rug ready.");
  if (hours != null && hours < 6) flags.push("Pair is under 6 hours old. Most rugs happen in the first day.");
  if (vol > 0 && liq > 0 && vol / liq > 40) flags.push("Volume is extremely high vs liquidity. Wash-trading is common here.");
  if ((p.txns?.h24?.buys || 0) + (p.txns?.h24?.sells || 0) < 20 && hours > 12) flags.push("Almost no organic flow.");
  if (liq < 1000 || (hours != null && hours < 1 && liq < 20000)) severity = "bad";
  else if (liq >= 50000 && hours >= 24 && flags.length === 0) severity = "good";
  return {
    found: true, pair: p, flags, severity,
    metrics: {
      name: (p.baseToken?.name || "Unknown") + " (" + (p.baseToken?.symbol || "?") + ")",
      price: p.priceUsd ? "$" + Number(p.priceUsd).toPrecision(4) : "—",
      liq: fmtUsd(liq), vol: fmtUsd(vol), age: pairAgeLabel(hours),
      chain: p.chainId || "—", dex: p.dexId || "—",
      change: p.priceChange?.h24 != null ? p.priceChange.h24.toFixed(1) + "%" : "—",
    },
  };
}
function rugFlags(report) {
  if (!report) return [];
  const out = [];
  if (report.mintAuthority != null && report.mintAuthority !== "") out.push("Mint authority still exists. Deployer can print supply.");
  if (report.freezeAuthority != null && report.freezeAuthority !== "") out.push("Freeze authority still exists.");
  if (report.topHolders) {
    const top = report.topHolders[0];
    if (top && Number(top.pct) > 20) out.push("Top holder controls more than 20% of supply.");
  }
  if (Array.isArray(report.risks)) {
    report.risks.slice(0, 6).forEach((r) => {
      out.push((r.name || r.level || "Risk") + (r.description || r.value ? " — " + (r.description || r.value) : ""));
    });
  }
  if (report.score != null) out.push("RugCheck raw score: " + report.score + " (higher usually means riskier).");
  return out;
}
async function runScan() {
  const raw = ($("ca").value || "").trim();
  const box = $("result");
  const verdict = $("verdict");
  const metrics = $("metrics");
  const flagsEl = $("flags");
  const linksEl = $("tool-links");
  if (!raw) { alert("Paste a contract / mint address first."); return; }
  if (!looksLikeSolana(raw) && !looksLikeEvm(raw)) {
    alert("That does not look like a Solana mint or an EVM 0x address."); return;
  }
  box.classList.add("show");
  verdict.className = "verdict warn";
  verdict.innerHTML = "<strong>Reading public tape…</strong><p>No wallet connect. Nothing is stored.</p>";
  metrics.innerHTML = ""; flagsEl.innerHTML = ""; linksEl.innerHTML = "";
  try {
    const dex = await fetchDex(raw);
    const analysis = analyzePairs(dex);
    let extra = [];
    if (looksLikeSolana(raw)) {
      try { extra = rugFlags(await fetchRugcheck(raw)); } catch (e) { extra = []; }
    }
    const allFlags = [...(analysis.flags || []), ...extra];
    let sev = analysis.severity || "warn";
    if (!analysis.found) sev = "bad";
    if (allFlags.some((f) => /mint authority|freeze authority|dust|Critical/i.test(f))) sev = "bad";
    verdict.className = "verdict " + sev;
    if (!analysis.found) verdict.innerHTML = "<strong>No public pair found.</strong><p>Do not buy from a screenshot.</p>";
    else if (sev === "bad") verdict.innerHTML = "<strong>High risk on first pass.</strong><p>Stop and verify on official scanners.</p>";
    else if (sev === "good") verdict.innerHTML = "<strong>First pass is not screaming.</strong><p>Still check holders, deployer history, and LP lock.</p>";
    else verdict.innerHTML = "<strong>Caution. Incomplete safety.</strong><p>Homework, not a green light.</p>";
    const m = analysis.metrics || {};
    const cells = [["Token", m.name || "—"],["Price", m.price || "—"],["Liquidity", m.liq || "—"],["24h volume", m.vol || "—"],["Pair age", m.age || "—"],["24h change", m.change || "—"],["Chain", m.chain || "—"],["DEX", m.dex || "—"]];
    metrics.innerHTML = cells.map(([k, v]) => `<div class="metric"><span>${k}</span><b>${v}</b></div>`).join("");
    flagsEl.innerHTML = allFlags.length ? ("<h3>Flags from public data</h3>" + allFlags.map((f) => `<div class="flag"><div class="tag">FLAG</div><div><p>${f}</p></div></div>`).join("")) : "<p class='sub'>No automatic flags. That is not safety.</p>";
    linksEl.innerHTML = buildLinks(raw, analysis.pair && analysis.pair.chainId).map(([n, u]) => `<a href="${u}" target="_blank" rel="noopener">${n} ↗</a>`).join("");
  } catch (err) {
    verdict.className = "verdict bad";
    verdict.innerHTML = "<strong>Scanner could not finish.</strong><p>" + (err.message || "Network error") + ". Use official tools below.</p>";
    linksEl.innerHTML = buildLinks(raw).map(([n, u]) => `<a href="${u}" target="_blank" rel="noopener">${n} ↗</a>`).join("");
  }
}
function scoreChecklist() {
  const boxes = [...document.querySelectorAll("#human-check input[type=checkbox]")];
  const total = boxes.length;
  const fail = boxes.filter((b) => !b.checked).length;
  const el = $("human-score");
  if (!el) return;
  if (fail >= 3) el.innerHTML = `<strong>Verdict: walk away.</strong> ${fail}/${total} checks failed.`;
  else if (fail >= 1) el.innerHTML = `<strong>Verdict: not clear.</strong> ${fail} failed check(s).`;
  else el.innerHTML = `<strong>Checklist complete — still not a buy rating.</strong> Size as if it can go to zero.`;
}
function cleanHandle(raw) {
  return String(raw || "").trim().replace(/^@/, "").split("/")[0].split("?")[0];
}
function cleanTicker(raw) {
  return String(raw || "").trim().replace(/^\$/, "").toUpperCase();
}
function buildCallerLinks() {
  const handle = cleanHandle($("handle") && $("handle").value);
  const ticker = cleanTicker($("ticker") && $("ticker").value);
  const out = $("caller-links");
  const note = $("caller-note");
  if (!handle) { alert("Paste an X handle first."); return; }
  const q = (s) => "https://x.com/search?q=" + encodeURIComponent(s) + "&src=typed_query&f=live";
  const links = [
    ["Open profile", "https://x.com/" + handle],
    ["Media only (look for cropped PnL)", q("from:" + handle + " filter:media")],
    ["All cashtag posts", q("from:" + handle + " $")],
  ];
  if (ticker) {
    links.push(["Search for $" + ticker + " from this handle", q("from:" + handle + " $" + ticker)]);
    links.push(["Just the ticker, any account", q("$" + ticker)]);
  }
  links.push(["Replies they make (often late shills)", "https://x.com/" + handle + "/with_replies"]);
  out.innerHTML = links.map(([n, u]) => `<a href="${u}" target="_blank" rel="noopener">${n} ↗</a>`).join("");
  note.innerHTML = "<strong>How to read the tape.</strong> Sort by Latest. Scroll to the first mention. If the first post is after a 3x–10x, they are late. If they only reply under bigger accounts, they are an amplifier. If losers are missing, they are a marketer.";
}
document.addEventListener("DOMContentLoaded", () => {
  if ($("scan-btn") && $("ca")) {
    $("scan-btn").addEventListener("click", runScan);
    $("ca").addEventListener("keydown", (e) => { if (e.key === "Enter") runScan(); });
  }
  document.querySelectorAll("#human-check input").forEach((b) => b.addEventListener("change", scoreChecklist));
  if ($("caller-btn")) {
    $("caller-btn").addEventListener("click", buildCallerLinks);
    ["handle", "ticker"].forEach((id) => {
      const el = $(id);
      if (el) el.addEventListener("keydown", (e) => { if (e.key === "Enter") buildCallerLinks(); });
    });
  }
});
