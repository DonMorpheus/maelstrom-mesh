//go:build !windows

package main

func maybeService(_, _ string) bool { return false }
