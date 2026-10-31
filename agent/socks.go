package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func serveSOCKS(tnet *netstack.Net, port int) error {
	ln, err := tnet.ListenTCP(&net.TCPAddr{Port: port})
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSOCKS(c)
		}
	}()
	return nil
}

func handleSOCKS(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 5 {
		return
	}
	nmethod := int(hdr[1])
	if nmethod < 0 || nmethod > 255 {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, nmethod)); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 5 || req[1] != 1 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 1:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		buf := make([]byte, l[0])
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = string(buf)
	case 4:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	default:
		_, _ = c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)
	_ = c.SetDeadline(time.Time{})

	dst := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	up, err := net.DialTimeout("tcp", dst, 15*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	errc := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); errc <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); errc <- struct{}{} }()
	<-errc
}
