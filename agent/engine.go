package main

import (
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

var overlayNet = netip.MustParsePrefix("10.66.0.0/24")

type engine struct {
	tnet    *netstack.Net
	overlay netip.Addr
	c2      []string
	c2Via   string
	allow   map[string]bool
	shields bool
	exit    atomic.Value // string overlay IP, empty = none
}

func (e *engine) setExit(ip string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		e.exit.Store("")
		return
	}
	e.exit.Store(ip)
}

func (e *engine) getExit() string {
	v, _ := e.exit.Load().(string)
	return v
}

func (e *engine) isC2(dest string) bool {
	if len(e.c2) == 0 {
		return false
	}
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		host = dest
		port = ""
	}
	host = strings.ToLower(host)
	for _, c := range e.c2 {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		ch, cp, err := net.SplitHostPort(c)
		if err != nil {
			if host == c {
				return true
			}
			continue
		}
		if host == strings.ToLower(ch) && (port == "" || port == cp) {
			return true
		}
	}
	return false
}

func (e *engine) srcOK(c net.Conn) bool {
	if !e.shields {
		return true
	}
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if a.String() == "10.66.0.1" {
		return true
	}
	return e.allow[a.String()]
}

func overlayAddr(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return overlayNet.Contains(ip)
}

func splice(a, b net.Conn) {
	errc := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); errc <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); errc <- struct{}{} }()
	<-errc
}

func (e *engine) overlayDial(addr string) (net.Conn, error) {
	return e.tnet.Dial("tcp", addr)
}

func (e *engine) dial(dest string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	if e.isC2(dest) && e.c2Via != "" {
		return e.overlayDial(e.c2Via)
	}
	if overlayAddr(host) {
		return e.overlayDial(net.JoinHostPort(host, port))
	}
	if ex := e.getExit(); ex != "" && overlayAddr(ex) {
		return socks5Dial(e.tnet, net.JoinHostPort(ex, "1080"), dest)
	}
	return net.DialTimeout("tcp", dest, 15*time.Second)
}
