//go:build windows

package main

import (
	"golang.org/x/sys/windows/svc"
)

type riptideSvc struct {
	cfg string
}

func (s *riptideSvc) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	done := make(chan struct{})
	go func() {
		runAgent(s.cfg)
		close(done)
	}()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		case <-done:
			return false, 0
		}
	}
}

func maybeService(cfg string) bool {
	ok, err := svc.IsWindowsService()
	if err != nil || !ok {
		return false
	}
	_ = svc.Run("RiptideAgent", &riptideSvc{cfg: cfg})
	return true
}
