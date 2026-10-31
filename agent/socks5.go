package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func socks5Dial(tnet *netstack.Net, proxy, dest string) (net.Conn, error) {
	host, portS, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	c, err := tnet.Dial("tcp", proxy)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, err
	}
	ack := make([]byte, 2)
	if _, err := io.ReadFull(c, ack); err != nil || ack[0] != 5 {
		c.Close()
		return nil, fmt.Errorf("socks greeting")
	}
	var req []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append([]byte{5, 1, 0, 1}, v4...)
		} else {
			req = append([]byte{5, 1, 0, 4}, ip.To16()...)
		}
	} else {
		req = append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	}
	p := uint16(0)
	fmt.Sscanf(portS, "%d", &p)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], p)
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks connect")
	}
	switch hdr[3] {
	case 1:
		_, _ = io.ReadFull(c, make([]byte, 6))
	case 4:
		_, _ = io.ReadFull(c, make([]byte, 18))
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			c.Close()
			return nil, err
		}
		_, _ = io.ReadFull(c, make([]byte, int(l[0])+2))
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}
