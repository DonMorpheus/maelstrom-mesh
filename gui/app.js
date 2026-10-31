const $ = (s, r = document) => r.querySelector(s);

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

function live(hs) {
  if (!hs || hs === "unknown" || hs === "never") return false;
  const n = Number(hs);
  if (!Number.isFinite(n) || n <= 0) return false;
  const now = Math.floor(Date.now() / 1000);
  if (n > 1e9) return now - n < 180;
  return true;
}

function render(state) {
  $("#mesh-meta").textContent =
    `${state.name} · ${state.network} · ${state.crypto.tunnel} · ${state.crypto.aead}`;
  $("#entry").innerHTML = `
    <div><span class="badge">entry</span></div>
    <div>endpoint <code>${state.endpoint}</code></div>
    <div>hub pub <code>${state.hub.public}</code></div>
  `;
  const nodes = $("#nodes");
  nodes.innerHTML = "";
  const all = [
    {
      name: state.hub.name,
      os: state.hub.os,
      address: state.hub.address,
      public: state.hub.public,
      mode: "hub",
      handshake: "hub",
      isHub: true,
    },
    ...state.peers,
  ];
  for (const p of all) {
    const ip = p.address.split("/")[0];
    const on = p.isHub || live(p.handshake);
    const el = document.createElement("article");
    el.className = "card" + (on ? " live" : "");
    el.innerHTML = `
      <div class="badge ${p.mode || ""}">${p.mode || "peer"} · ${p.os}</div>
      <div class="name">${p.name}</div>
      <div class="ip">${ip}</div>
      <div class="badge">hs ${p.handshake || "unknown"}</div>
      <div class="row"></div>
    `;
    const row = $(".row", el);
    if (!p.isHub) {
      const b1 = document.createElement("button");
      b1.className = "ghost";
      b1.textContent = "ssh";
      b1.onclick = () => copy(`ssh user@${ip}`);
      const b2 = document.createElement("button");
      b2.className = "ghost";
      b2.textContent = "rdp";
      b2.onclick = () => copy(`mstsc /v:${ip}`);
      const b3 = document.createElement("button");
      b3.className = "ghost";
      b3.textContent = "socks";
      b3.onclick = () => copy(`curl --socks5 ${ip}:1080 https://ifconfig.me`);
      const b4 = document.createElement("button");
      b4.className = "danger";
      b4.textContent = "revoke";
      b4.onclick = async () => {
        if (!confirm("revoke " + p.name + "?")) return;
        await api("/api/revoke", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: p.name }),
        });
        await load();
      };
      row.append(b1, b2, b3, b4);
    }
    nodes.appendChild(el);
  }
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
setInterval(load, 15000);
