//go:build !windows

package main

import "fmt"

func loadConfReg(spec string) (*cfg, error) {
	return nil, fmt.Errorf("registry conf is windows-only: %s", spec)
}
