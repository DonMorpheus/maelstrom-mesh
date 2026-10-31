package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

func handshakeMap(dump string) map[string]int64 {
	out := map[string]int64{}
	pub := ""
	for _, line := range splitLines(dump) {
		if strings.HasPrefix(line, "public_key=") {
			pub = strings.TrimPrefix(line, "public_key=")
			continue
		}
		if pub != "" && strings.HasPrefix(line, "last_handshake_time_sec=") {
			n, _ := strconv.ParseInt(strings.TrimPrefix(line, "last_handshake_time_sec="), 10, 64)
			out[pub] = n
			pub = ""
		}
	}
	return out
}

func stale(hs int64, now int64) bool {
	if hs <= 0 {
		return true
	}
	return now-hs > 90
}

func hubRotate(dev *device.Device, c *cfg) {
	if len(c.Peers) == 0 {
		return
	}
	eps := splitComma(c.Riptide.Hubs)
	primary := c.Peers[0]
	idx := 0
	extraIdx := map[string]int{}
	promoted := ""
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for range t.C {
		dump, err := dev.IpcGet()
		if err != nil {
			continue
		}
		now := time.Now().Unix()
		hs := handshakeMap(dump)
		primHS := hs[primary.PublicKey]
		if len(eps) > 1 && stale(primHS, now) {
			idx = (idx + 1) % len(eps)
			ep, err := resolveEndpoint(eps[idx])
			if err == nil {
				_ = dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\n", primary.PublicKey, ep))
				log.Printf("hub rotate endpoint %s", ep)
			}
		}
		for overlay, list := range c.Riptide.HubEps {
			heps := splitComma(list)
			if len(heps) < 2 {
				continue
			}
			p := peerByOverlay(c, overlay)
			if p == nil || !stale(hs[p.PublicKey], now) {
				continue
			}
			i := (extraIdx[overlay] + 1) % len(heps)
			extraIdx[overlay] = i
			ep, err := resolveEndpoint(heps[i])
			if err == nil {
				_ = dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\n", p.PublicKey, ep))
				log.Printf("hub rotate extra %s -> %s", overlay, ep)
			}
		}
		if c.Riptide.Failover == "" {
			continue
		}
		if stale(primHS, now) {
			for _, fo := range splitComma(c.Riptide.Failover) {
				p := peerByOverlay(c, fo)
				if p == nil {
					continue
				}
				if stale(hs[p.PublicKey], now) {
					continue
				}
				if promoted == p.PublicKey {
					break
				}
				_ = dev.IpcSet(fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=10.66.0.0/24\n", p.PublicKey))
				_ = dev.IpcSet(fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=10.66.0.1/32\n", primary.PublicKey))
				promoted = p.PublicKey
				log.Printf("hub failover overlay via %s", fo)
				break
			}
			continue
		}
		if promoted != "" {
			_ = dev.IpcSet(fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=10.66.0.0/24\n", primary.PublicKey))
			if p := peerByPub(c, promoted); p != nil {
				_ = dev.IpcSet(fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", p.PublicKey, overlayOf(c, *p)))
			}
			log.Printf("hub primary restored")
			promoted = ""
		}
	}
}

func peerByOverlay(c *cfg, ip string) *peer {
	want := ip + "/32"
	for i := range c.Peers {
		for _, a := range c.Peers[i].Allowed {
			if a == want || strings.Split(a, "/")[0] == ip {
				return &c.Peers[i]
			}
		}
	}
	return nil
}

func peerByPub(c *cfg, pub string) *peer {
	for i := range c.Peers {
		if c.Peers[i].PublicKey == pub {
			return &c.Peers[i]
		}
	}
	return nil
}

func overlayOf(c *cfg, p peer) string {
	if len(p.Allowed) > 0 {
		return strings.Split(p.Allowed[0], "/")[0]
	}
	return "10.66.0.1"
}
