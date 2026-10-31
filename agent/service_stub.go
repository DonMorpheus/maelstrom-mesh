//go:build !windows

package main

func maybeService(_ string) bool { return false }
