const $ = (s, r = document) => r.querySelector(s);
let STATE = null;

function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 1600);
}

async function api(path, opt) {
  const r = await fetch(path, opt);
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

function copy(text) {
  navigator.clipboard.writeText(text).then(() => toast("copied"));
}

function live(h) {
  if (h.live === true) return true;
  if (h.isHub) return true;
  const hs = h.handshake;
  if (!hs || hs === "unknown" || hs === "never") return false;
  const n = Number(hs);
  if (!Number.isFinite(n) || n <= 0) return false;
  if (n > 1e9) return Math.floor(Date.now() / 1000) - n < 180;
  return true;
}

function overlay(h) {
  return (h.overlay || h.address || "").split("/")[0];
}

function card(h, kind, selected) {
  const el = document.createElement("article");
  const on = live(h);
  el.className = "card" + (on ? " live" : "") + (selected ? " selected" : "");
  const cc = h.country || "";
  const fl = h.flag || "🏳️";
  el.innerHTML = `
    <div class="flag">${fl}</div>
    <div class="cc">${cc || "??"} ${h.country_name || ""}</div>
    <div class="name">${h.name}</div>
    <div class="ip">${overlay(h)}</div>
    <div class="badge">${kind} · ${h.os || ""} · ${on ? "up" : "down"}</div>
    <div class="badge">${h.wan || "wan unknown"}</div>
    <div class="row"></div>
  `;
  el.onclick = () => pick(kind, h.name);
  const row = $(".row", el);
  if (kind === "exit") {
    const ip = overlay(h);
    const b = document.createElement("button");
    b.className = "ghost";
    b.textContent = "socks";
    b.onclick = (e) => {
      e.stopPropagation();
      copy(`curl --socks5h ${ip}:1080 https://ifconfig.me`);
    };
    const b2 = document.createElement("button");
    b2.className = "ghost";
    b2.textContent = "proxy env";
    b2.onclick = (e) => {
      e.stopPropagation();
      copy(`export ALL_PROXY=socks5h://${ip}:1080 HTTPS_PROXY=socks5h://${ip}:1080`);
    };
    row.append(b, b2);
  }
  return el;
}

async function pick(kind, name) {
  const body = kind === "entry" ? { entry: name } : { exit: name };
  await api("/api/steer", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  await load();
}

function render(state) {
  STATE = state;
  const st = state.steer || {};
  $("#mesh-meta").textContent =
    `${state.name} · ${state.network} · ${state.source || "local"} · ${state.crypto?.aead || ""}`;
  const hub = Object.assign({ isHub: true, name: "hub" }, state.hub || {});
  const entries = [hub];
  const exits = (state.peers || []).filter((p) => p.exit !== false);
  const entryName = st.entry || hub.name;
  const exitName = st.exit || (exits[0] && exits[0].name) || "";
  const ent = entries.find((e) => e.name === entryName) || hub;
  const ex = exits.find((e) => e.name === exitName) || exits[0];
  const exIp = ex ? overlay(ex) : "";
  $("#steer").innerHTML = `
    <div class="path">${ent.flag || "🏳️"} ${ent.name}  →  ${ex ? (ex.flag || "🏳️") + " " + ex.name : "no exit"}</div>
    <code>${exIp ? "ALL_PROXY=socks5h://" + exIp + ":1080" : ""}</code>
  `;
  const elE = $("#entry-list");
  elE.innerHTML = "";
  for (const h of entries) elE.appendChild(card(h, "entry", h.name === entryName));
  const elX = $("#exit-list");
  elX.innerHTML = "";
  for (const h of exits) elX.appendChild(card(h, "exit", h.name === exitName));
}

async function load() {
  const state = await api("/api/state");
  render(state);
}

$("#new-peer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await api("/api/peer", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: fd.get("name"), os: fd.get("os") }),
  });
  e.target.reset();
  await load();
});

load();
setInterval(load, 10000);
