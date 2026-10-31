# Low-priv / Windows operator: riptide-agent must already be up.
# Agent splices http://127.0.0.1:7668/ onto the hub overlay roster.
# Login as operator (entry/exit) or admin (full roster).
$url = "http://127.0.0.1:7668/"
$edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
$edge2 = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
if (Test-Path $edge2) {
  Start-Process $edge2 -ArgumentList "--app=$url"
} elseif (Test-Path $edge) {
  Start-Process $edge -ArgumentList "--app=$url"
} else {
  Start-Process $url
}
