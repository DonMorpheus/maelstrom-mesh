//go:build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func loadConfReg(spec string) (*cfg, error) {
	spec = strings.TrimSpace(spec)
	up := strings.ToUpper(spec)
	rest := spec
	switch {
	case strings.HasPrefix(up, `HKLM\`):
		rest = spec[5:]
	case strings.HasPrefix(up, `HKEY_LOCAL_MACHINE\`):
		rest = spec[len(`HKEY_LOCAL_MACHINE\`):]
	}
	i := strings.LastIndex(rest, `\`)
	if i <= 0 {
		return nil, fmt.Errorf("reg conf path")
	}
	keyPath, val := rest[:i], rest[i+1:]
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("reg open: %w", err)
	}
	defer k.Close()
	s, _, err := k.GetStringValue(val)
	if err != nil {
		b, _, err2 := k.GetBinaryValue(val)
		if err2 != nil {
			return nil, fmt.Errorf("reg value: %w", err)
		}
		s = string(b)
	}
	return parseConf(strings.NewReader(s))
}
