package main

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	testPriv = "uD0J+lvXeZgvj+tVIDI2P3UwAkwhtuut8UX0oI0U5GA="
	testPub  = "m/kdZEoVDZrXMuly5cxBkULQGKVD0+ngsuQsYzGd1lg="
)

func TestLoadHubsListenAndExtra(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "peer.conf")
	txt := `[Interface]
PrivateKey = ` + testPriv + `
Address = 10.66.0.2/32
ListenPort = 51820

[Peer]
PublicKey = ` + testPub + `
AllowedIPs = 10.66.0.1/32
Endpoint = 1.2.3.4:51820

[Peer]
PublicKey = ` + testPub + `
AllowedIPs = 10.66.0.3/32
Endpoint = 192.168.0.135:51820

[Riptide]
Hubs = maelstrom-c2.duckdns.org:51820,1.2.3.4:51820
Hubs.10.66.0.3 = 192.168.0.135:51820,9.9.9.9:51820
Failover = 10.66.0.3
`
	if err := os.WriteFile(p, []byte(txt), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConf(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !c.isHub() || c.Iface.ListenPort != 51820 {
		t.Fatalf("listen %d hub=%v", c.Iface.ListenPort, c.isHub())
	}
	if c.Riptide.Hubs == "" || c.Riptide.Failover != "10.66.0.3" {
		t.Fatalf("hubs=%q fail=%q", c.Riptide.Hubs, c.Riptide.Failover)
	}
	got := c.Riptide.HubEps["10.66.0.3"]
	if got != "192.168.0.135:51820,9.9.9.9:51820" {
		t.Fatalf("HubEps %q", got)
	}
	if ipc := c.ipc(); ipc == "" || !contains(ipc, "listen_port=51820") {
		t.Fatalf("ipc missing listen_port: %s", ipc)
	}
}

func TestStale(t *testing.T) {
	if !stale(0, 100) {
		t.Fatal("zero handshake should be stale")
	}
	if stale(50, 100) {
		t.Fatal("50s old should be live at 90s cutoff")
	}
	if !stale(1, 100) {
		t.Fatal("99s old should be stale")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})())
}
