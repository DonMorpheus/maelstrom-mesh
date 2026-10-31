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
	python3 mesh.py status --out /tmp/riptide-make-test
	rm -rf /tmp/riptide-make-test
