package main

import (
	"encoding/json"
	"net"
	"net/http"
)

func serveControl(e *engine, bind, httpBind, socksBind string, routes []string) error {
	if bind == "" || bind == "off" {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/exit", func(w http.ResponseWriter, r *http.Request) {
		cors(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]string{"exit": e.getExit()})
			return
		}
		var obj struct {
			Overlay string `json:"overlay"`
		}
		_ = json.NewDecoder(r.Body).Decode(&obj)
		e.setExit(obj.Overlay)
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "1", "exit": e.getExit()})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		cors(w)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"overlay": e.overlay.String(),
			"http":    httpBind,
			"socks":   socksBind,
			"c2":      e.c2,
			"c2_via":  e.c2Via,
			"exit":    e.getExit(),
			"routes":  routes,
			"shields": e.shields,
		})
	})
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	go func() { _ = http.Serve(ln, mux) }()
	return nil
}

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")
}
