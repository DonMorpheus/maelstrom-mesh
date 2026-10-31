const $ = (s, r = document) => r.querySelector(s);
let STATE = null;
let TOKEN = localStorage.getItem("riptide-token") || "";

function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 1600);
}

async function api(path, opt) {
  opt = opt || {};
  opt.headers = Object.assign({}, opt.headers || {});
  if (TOKEN) opt.headers.Authorization = "Bearer " + TOKEN;
  const r = await fetch(path, opt);
  if (r.status === 401) {
    TOKEN = "";
    localStorage.removeItem("riptide-token");
    showConnect();
    throw new Error("login");
  }
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

function steerGet() {
  try {
    return JSON.parse(localStorage.getItem("riptide-steer") || "{}");
  } catch {
    return {};
  }
}

function steerSet(kind, name) {
  const s = steerGet();
  s[kind] = name;
  localStorage.setItem("riptide-steer", JSON.stringify(s));
}

function isAdmin() {
  return (STATE && STATE.me && STATE.me.role) === "admin";
}

function card(h, kind, selected) {
  const el = document.createElement("article");
  const on = live(h);
  el.className = "card" + (on ? " live" : "") + (selected ? " selected" : "");
  const fl = h.flag || "🏳️";
  const wan = isAdmin() ? (h.wan || "") : "";
  el.innerHTML = `
    <div class="flag">${fl}</div>
    <div class="cc">${h.country || "??"} ${h.country_name || ""}</div>
    <div class="name">${h.name}</div>
    <div class="ip">${overlay(h)}</div>
    <div class="badge">${kind} · ${h.os || ""} · ${on ? "up" : "down"}</div>
    ${wan ? `<div class="badge">${wan}</div>` : ""}
    <div class="row"></div>
  `;
  el.onclick = () => {
    steerSet(kind, h.name);
    render(STATE);
  };
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

function render(state) {
  STATE = state;
  const st = steerGet();
  const me = state.me || {};
  $("#who").textContent = `${me.name || "?"} · ${me.role || "operator"}`;
  $("#enroll-box").hidden = me.role !== "admin";
  $("#mesh-meta").textContent =
    `${state.name} · ${state.network} · ${me.role || ""}`;
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
    <button type="button" class="ghost" id="logout">disconnect</button>
  `;
  $("#logout").onclick = () => {
    TOKEN = "";
    localStorage.removeItem("riptide-token");
    showConnect();
  };
  const elE = $("#entry-list");
  elE.innerHTML = "";
  for (const h of entries) elE.appendChild(card(h, "entry", h.name === entryName));
  const elX = $("#exit-list");
  elX.innerHTML = "";
  for (const h of exits) elX.appendChild(card(h, "exit", h.name === exitName));
}

function showConnect() {
  $("#connect-screen").hidden = false;
  $("#app").hidden = true;
}

function showApp() {
  $("#connect-screen").hidden = true;
  $("#app").hidden = false;
}

async function load() {
  const state = await api("/api/state");
  showApp();
  render(state);
}

$("#login").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-err").textContent = "";
  const fd = new FormData(e.target);
  try {
    const got = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user: fd.get("user"), password: fd.get("password") }),
    }).then((r) => r.json());
    if (!got.token) throw new Error(got.error || "login");
    TOKEN = got.token;
    localStorage.setItem("riptide-token", TOKEN);
    await load();
  } catch (err) {
    $("#login-err").textContent = "bad login";
  }
});

$("#new-peer").addEventListener("submit", async (e) => {
  e.preventDefault();
  toast("enroll on admin Kali: python3 mesh.py peer --out …");
});

if (TOKEN) {
  load().catch(() => showConnect());
} else {
  showConnect();
}
setInterval(() => {
  if (TOKEN && !$("#app").hidden) load().catch(() => {});
}, 10000);
