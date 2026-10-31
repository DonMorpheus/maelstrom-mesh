.PHONY: agent agent-win bof test

agent:
	cd agent && go build -ldflags "-s -w" -o riptide-agent .

agent-win:
	cd agent && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o riptide-agent.exe .

bof:
	$(MAKE) -C bof

test:
	python3 mesh.py selftest
	python3 mesh.py init --name lab --endpoint 127.0.0.1 --out /tmp/riptide-make-test --force
	python3 mesh.py peer --out /tmp/riptide-make-test --name kali --os linux
	python3 mesh.py hub --out /tmp/riptide-make-test --name harry-hub --os windows --listen 51820 --endpoints 192.168.0.135:51820,9.9.9.9:51820
	grep -q ListenPort /tmp/riptide-make-test/hubs/harry-hub.conf
	grep -q 'Hubs.10.66.0.3' /tmp/riptide-make-test/peers/kali.conf
	grep -q Failover /tmp/riptide-make-test/peers/kali.conf
	python3 mesh.py status --out /tmp/riptide-make-test
	python3 -m py_compile mesh.py lib/*.py bof/mesh_install.py deploy/rosterd.py
	cd agent && go test ./...
	rm -rf /tmp/riptide-make-test
