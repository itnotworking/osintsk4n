// SC4N popup: paste anything, or check the current site, and see the verdict here.
// Only what the user asks to check is sent, to sc4n.lol; the full report opens on the site.
const SITE = "https://sc4n.lol/";
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const VERDICT_CLASS = { "Likely Malicious": "bad", "Suspicious": "warn", "Low–Moderate": "lowmod", "Likely Legitimate": "good" };
const NO_SCORE = ["Domain Not Found", "Not In Use", "Inconclusive", "No Complaints Found"];
const hasChrome = typeof chrome !== "undefined" && chrome.tabs;

function show(html) { $("out").innerHTML = html; }

function openReport(target) {
  const url = SITE + "#q=" + encodeURIComponent(target);
  if (hasChrome) { chrome.tabs.create({ url }); window.close(); }
}

function render(d, target) {
  const v = d.verdict || "Unknown";
  const meta = (d.defanged || target) + (NO_SCORE.includes(v) ? "" : " · risk " + d.score + "/100");
  const reasons = (d.reasons || []).slice(0, 3);
  show(
    '<div class="verdict ' + (VERDICT_CLASS[v] || "neutral") + '"><div class="v">' + esc(v) + "</div>" +
    '<div class="meta">' + esc(meta) + "</div></div>" +
    (reasons.length ? "<ul>" + reasons.map((r) => "<li>" + esc(r) + "</li>").join("") + "</ul>" : "") +
    ((d.source_errors || []).length ? '<p class="note">Some sources didn\'t answer this time. The full report shows which.</p>' : "") +
    '<button id="full" class="full" type="button">Open the full report</button>'
  );
  $("full").onclick = () => openReport(target);
}

async function check(raw) {
  const target = String(raw || "").trim().slice(0, 2048);
  if (!target) return;
  show('<div class="loading">Checking <b>' + esc(target) + '</b><span class="bar"><i></i></span></div>');
  const body = new FormData();
  body.append("target", target);
  let res, data;
  try {
    res = await fetch(SITE + "analyze", { method: "POST", body });
    data = await res.json();
  } catch (e) {
    return show('<p class="err">SC4N couldn\'t be reached. Check your connection and try again.</p>');
  }
  if (res.status === 429) return show('<p class="err">Too many lookups in the last minute. Wait a moment and try again.</p>');
  if (!data || data.ok === false || data.error) {
    return show('<p class="err">' + esc((data && data.error) || "That lookup didn't work. Try again.") + "</p>");
  }
  render(data, target);
}

$("f").addEventListener("submit", (e) => { e.preventDefault(); check($("q").value); });

// "Check this site" for the tab the user is on (activeTab grants its address when the popup opens)
if (hasChrome) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs && tabs[0];
    if (!tab || !/^https?:/.test(tab.url || "")) return;
    const host = new URL(tab.url).hostname;
    $("host").textContent = host;
    $("site").hidden = false;
    $("site").onclick = () => { $("q").value = host; check(host); };
  });
}

// store screenshots: render a real lookup result captured from sc4n.lol (see STORE.md)
if (window.SC4N_SHOT) { $("q").value = window.SC4N_SHOT.target; render(window.SC4N_SHOT.data, window.SC4N_SHOT.target); }
