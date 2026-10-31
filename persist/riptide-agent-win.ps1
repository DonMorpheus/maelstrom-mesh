# Optional wrapper. Prefer the Go agent as a native service (SCM ImagePath).
# Example (lab, already admin):
#   sc.exe create IntelPma binPath= "C:\Program Files\Riptide\riptide-agent.exe --config `"C:\Program Files\Riptide\peer.conf`"" start= delayed-auto
#   sc.exe failure IntelPma reset= 86400 actions= restart/5000/restart/5000/restart/5000
#   sc.exe start IntelPma
param(
    [string]$Bin = "C:\Program Files\Riptide\riptide-agent.exe",
    [string]$Conf = "C:\Program Files\Riptide\peer.conf",
    [string]$Name = "IntelPma"
)
$binPath = "`"$Bin`" --config `"$Conf`""
sc.exe create $Name binPath= $binPath start= delayed-auto obj= "NT AUTHORITY\NetworkService"
sc.exe failure $Name reset= 86400 actions= restart/5000/restart/5000/restart/5000
sc.exe start $Name
