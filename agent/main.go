package main

import (
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	cfgPath := flag.String("config", "peer.conf", "wireguard conf (hub or peer)")
	flag.Parse()
	if maybeService(*cfgPath) {
		return
	}
	runAgent(*cfgPath)
}

func runAgent(cfgPath string) {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("riptide ")

	c, err := loadConf(cfgPath)
	if err != nil {
		log.Fatalf("conf: %v", err)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{c.Iface.Address},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1420,
	)
	if err != nil {
		log.Fatalf("tun: %v", err)
	}

	level := device.LogLevelError
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(level, "wg "))
	if err := dev.IpcSet(c.ipc()); err != nil {
		log.Fatalf("ipc: %v", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatalf("up: %v", err)
	}

	if err := serveSOCKS(tnet, 1080); err != nil {
		log.Fatalf("socks: %v", err)
	}

	role := "peer"
	if c.isHub() {
		role = "hub"
	}
	log.Printf("%s overlay=%s socks=:1080 (userspace, no WinTUN)", role, c.Iface.Address)

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			dump, err := dev.IpcGet()
			if err != nil {
				continue
			}
			if hs := lastHandshake(dump); hs != "" {
				log.Printf("handshake %s", hs)
			}
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	_ = dev.Down()
	dev.Close()
}

func lastHandshake(ipc string) string {
	// ipc dump is key=value lines; last_handshake_time_sec > 0 means live
	best := ""
	for _, line := range splitLines(ipc) {
		if len(line) > 24 && line[:24] == "last_handshake_time_sec=" {
			best = line[24:]
		}
	}
	if best == "" || best == "0" {
		return ""
	}
	return best
}

func splitLines(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}


