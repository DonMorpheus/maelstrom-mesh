package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type iface struct {
	PrivateKey string // hex
	Address    netip.Addr
	ListenPort int
}

type peer struct {
	PublicKey  string // hex
	PSK        string // hex, optional
	Endpoint   string
	Allowed    []string
	Keepalive  int
}

type extras struct {
	Tag     string
	Mode    string
	HTTP    string
	SOCKS   string
	C2      string
	C2Via   string
	Serve   string
	Routes  string
	Shields bool
	Allow   string
	Control  string
	Exit     string
	Hubs     string            // comma host:port rotation for primary hub
	Failover string            // extra hub overlay IPs, comma
	HubEps   map[string]string // overlay IP -> extra hub endpoints
	Tor      bool
	DNS      string
}

type cfg struct {
	Iface  iface
	Peers  []peer
	Riptide extras
}

func b64ToHex(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key length %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func tryLoadConf(path string) (*cfg, error) {
	p := strings.TrimSpace(path)
	if strings.HasPrefix(strings.ToLower(p), "reg:") {
		return loadConfReg(strings.TrimSpace(p[4:]))
	}
	return loadConf(p)
}

func loadConf(path string) (*cfg, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseConf(f)
}

func parseConf(r io.Reader) (*cfg, error) {
	c := &cfg{Riptide: extras{HubEps: map[string]string{}}}
	section := ""
	var cur *peer
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.EqualFold(line, "[Interface]") {
			section = "iface"
			cur = nil
			continue
		}
		if strings.EqualFold(line, "[Peer]") {
			section = "peer"
			p := peer{}
			c.Peers = append(c.Peers, p)
			cur = &c.Peers[len(c.Peers)-1]
			continue
		}
		if strings.EqualFold(line, "[Riptide]") {
			section = "riptide"
			cur = nil
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch section {
		case "iface":
			switch strings.ToLower(k) {
			case "privatekey":
				hx, err := b64ToHex(v)
				if err != nil {
					return nil, fmt.Errorf("PrivateKey: %w", err)
				}
				c.Iface.PrivateKey = hx
			case "address":
				ip := strings.Split(v, "/")[0]
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					return nil, fmt.Errorf("Address: %w", err)
				}
				c.Iface.Address = addr
			case "listenport":
				n, err := strconv.Atoi(v)
				if err != nil {
					return nil, err
				}
				c.Iface.ListenPort = n
			}
		case "peer":
			if cur == nil {
				continue
			}
			switch strings.ToLower(k) {
			case "publickey":
				hx, err := b64ToHex(v)
				if err != nil {
					return nil, fmt.Errorf("PublicKey: %w", err)
				}
				cur.PublicKey = hx
			case "presharedkey":
				hx, err := b64ToHex(v)
				if err != nil {
					return nil, fmt.Errorf("PresharedKey: %w", err)
				}
				cur.PSK = hx
			case "endpoint":
				ep, err := resolveEndpoint(v)
				if err != nil {
					return nil, fmt.Errorf("Endpoint %s: %w", v, err)
				}
				cur.Endpoint = ep
			case "allowedips":
				for _, a := range strings.Split(v, ",") {
					a = strings.TrimSpace(a)
					if a != "" {
						cur.Allowed = append(cur.Allowed, a)
					}
				}
			case "persistentkeepalive":
				n, err := strconv.Atoi(v)
				if err == nil {
					cur.Keepalive = n
				}
			}
		case "riptide":
			switch strings.ToLower(k) {
			case "tag":
				c.Riptide.Tag = v
			case "mode":
				c.Riptide.Mode = v
			case "http":
				c.Riptide.HTTP = v
			case "socks":
				c.Riptide.SOCKS = v
			case "c2":
				c.Riptide.C2 = v
			case "c2via":
				c.Riptide.C2Via = v
			case "serve":
				c.Riptide.Serve = v
			case "routes":
				c.Riptide.Routes = v
			case "shields":
				c.Riptide.Shields = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
			case "allow":
				c.Riptide.Allow = v
			case "control":
				c.Riptide.Control = v
			case "exit":
				c.Riptide.Exit = v
			case "hubs":
				c.Riptide.Hubs = v
			case "failover":
				c.Riptide.Failover = v
			case "tor":
				c.Riptide.Tor = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
			case "dns":
				c.Riptide.DNS = v
			default:
				lk := strings.ToLower(k)
				if strings.HasPrefix(lk, "hubs.") {
					if c.Riptide.HubEps == nil {
						c.Riptide.HubEps = map[string]string{}
					}
					c.Riptide.HubEps[strings.TrimPrefix(lk, "hubs.")] = v
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if c.Iface.PrivateKey == "" || !c.Iface.Address.IsValid() {
		return nil, fmt.Errorf("conf missing Interface PrivateKey/Address")
	}
	if len(c.Peers) == 0 {
		return nil, fmt.Errorf("conf has no [Peer]")
	}
	return c, nil
}

func (c *cfg) ipc() string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", c.Iface.PrivateKey)
	if c.Iface.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.Iface.ListenPort)
	}
	for _, p := range c.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", p.PublicKey)
		if p.PSK != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", p.PSK)
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		for _, a := range p.Allowed {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		}
	}
	return b.String()
}

func (c *cfg) isHub() bool {
	return c.Iface.ListenPort > 0
}

func resolveEndpoint(ep string) (string, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return "", err
	}
	if net.ParseIP(host) != nil {
		return ep, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	var pick net.IP
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			pick = v4
			break
		}
	}
	if pick == nil {
		pick = ips[0]
	}
	return net.JoinHostPort(pick.String(), port), nil
}
