package main

import (
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

type serveMap struct {
	port int
	dest string
}

func parseServe(s string) []serveMap {
	var out []serveMap
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, ":") {
			left, right, ok := strings.Cut(p, ":")
			if !ok {
				continue
			}
			n, err := strconv.Atoi(left)
			if err != nil || n <= 0 {
				continue
			}
			if _, _, err := net.SplitHostPort(right); err != nil {
				right = net.JoinHostPort("127.0.0.1", right)
			}
			out = append(out, serveMap{port: n, dest: right})
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 {
			continue
		}
		out = append(out, serveMap{port: n, dest: net.JoinHostPort("127.0.0.1", p)})
	}
	return out
}

func servePorts(tnet *netstack.Net, maps []serveMap) {
	for _, m := range maps {
		m := m
		ln, err := tnet.ListenTCP(&net.TCPAddr{Port: m.port})
		if err != nil {
			log.Printf("serve :%d: %v", m.port, err)
			continue
		}
		log.Printf("serve overlay :%d -> %s", m.port, m.dest)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					up, err := net.DialTimeout("tcp", m.dest, 15*time.Second)
					if err != nil {
						return
					}
					defer up.Close()
					splice(c, up)
				}(c)
			}
		}()
	}
}
