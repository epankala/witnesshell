# witnesshell build. Produces fully static Linux binaries (CGO disabled).

GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
ARCHES  ?= amd64 arm64
DIST    := dist
PKG     := witnesshell

LDFLAGS := -s -w -buildid= \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT)

export CGO_ENABLED := 0

.PHONY: all build check fmt-check vet test verify-static clean

all: check build verify-static

build: $(foreach a,$(ARCHES),$(DIST)/witnesshell-linux-$(a))

$(DIST)/witnesshell-linux-%: FORCE
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=$* $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/witnesshell

check: fmt-check vet test

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

# A static ELF has no PT_INTERP program header and no .dynamic section.
verify-static: build
	@for f in $(DIST)/witnesshell-linux-*; do \
		if readelf -lW $$f | grep -q 'Requesting program interpreter' || \
		   readelf -dW $$f | grep -q 'Dynamic section'; then \
			echo "NOT static: $$f"; exit 1; \
		fi; \
		echo "static: $$f ($$(du -h $$f | cut -f1))"; \
	done

clean:
	rm -rf $(DIST)

# Disposable test VM for anything that needs root; see scripts/vm.sh.
# Machine-specific settings (VM_DIR, VM_QEMU_ROOT, ...) may go in local.mk.
-include local.mk
export VM_DIR VM_QEMU_ROOT VM_SSH_PORT VM_MEM VM_CPUS VM_USER

# Runs the attack tests as root inside the VM, starting it if needed.
.PHONY: vm-test
vm-test: vm-start $(DIST)/witnesshell-linux-amd64
	$(GO) vet -tags vmtest ./test/vm
	GOOS=linux GOARCH=amd64 $(GO) test -c -tags vmtest -o $(DIST)/vm.test ./test/vm
	@VM_USER=vmadmin sh scripts/vm.sh ssh 'sudo sh -c "cat >/usr/local/lib/vm.test && chmod 755 /usr/local/lib/vm.test"' <$(DIST)/vm.test
	@VM_USER=vmadmin sh scripts/vm.sh ssh 'sudo sh -c "cat >/usr/local/bin/witnesshell && chmod 755 /usr/local/bin/witnesshell"' <$(DIST)/witnesshell-linux-amd64
	@tar -c deploy | VM_USER=vmadmin sh scripts/vm.sh ssh 'sudo rm -rf /usr/local/lib/deploy; sudo tar -x --no-same-owner -C /usr/local/lib'
	@VM_USER=vmadmin sh scripts/vm.sh ssh 'cd / && sudo timeout 900 /usr/local/lib/vm.test -test.v $(VMTEST_ARGS)' </dev/null

.PHONY: vm-start vm-stop vm-status vm-ssh vm-reset
vm-start vm-stop vm-status vm-ssh vm-reset: vm-%:
	@sh scripts/vm.sh $*

FORCE:
