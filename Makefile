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

build: $(foreach a,$(ARCHES),$(DIST)/witsh-linux-$(a))

$(DIST)/witsh-linux-%: FORCE
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=$* $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/witsh

check: fmt-check vet test

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

# A static ELF has no PT_INTERP program header and no .dynamic section.
verify-static: build
	@for f in $(DIST)/witsh-linux-*; do \
		if readelf -lW $$f | grep -q 'Requesting program interpreter' || \
		   readelf -dW $$f | grep -q 'Dynamic section'; then \
			echo "NOT static: $$f"; exit 1; \
		fi; \
		echo "static: $$f ($$(du -h $$f | cut -f1))"; \
	done

clean:
	rm -rf $(DIST)

# The unit tests built for arm64, run by QEMU's user-mode emulator on this
# kernel. Tests that need root are skipped, as with make test.
QEMU_AARCH64 ?= $(or $(wildcard $(VM_QEMU_ROOT)/usr/bin/qemu-aarch64),qemu-aarch64)
.PHONY: test-arm64
test-arm64:
	GOARCH=arm64 $(GO) test -exec $(QEMU_AARCH64) ./...

# Release archives, one per architecture, and their SHA-256 sums. The same
# commit gives the same bytes: files are sorted, owned by 0 and dated by the
# commit.
RELEASE_FILES := README.md PLAN.md deploy $(wildcard LICENSE)
STAMP := $(shell git log -1 --format=%cI 2>/dev/null || echo 1970-01-01T00:00:00Z)
.PHONY: release
release: all
	@case "$(VERSION)" in *dirty*) echo "warning: uncommitted changes in $(VERSION)";; esac
	@set -e; cd $(DIST); rm -f witsh-*.tar.gz SHA256SUMS; \
	for a in $(ARCHES); do \
		n=witsh-$(VERSION)-linux-$$a; rm -rf $$n; mkdir -p $$n; \
		cp witsh-linux-$$a $$n/witsh; \
		(cd ..; cp -R $(RELEASE_FILES) $(DIST)/$$n/); \
		tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='$(STAMP)' \
			--mode=go-w -c $$n | gzip -n -9 >$$n.tar.gz; \
		rm -rf $$n; \
	done; \
	sha256sum witsh-*.tar.gz >SHA256SUMS; cat SHA256SUMS

# Disposable test VM for anything that needs root; see scripts/vm.sh.
# Machine-specific settings (VM_DIR, VM_QEMU_ROOT, ...) may go in local.mk.
-include local.mk
export VM VM_DIR VM_QEMU_ROOT VM_UDP_PORT VM_SSH_PORT VM_MEM VM_CPUS VM_USER

# Runs the attack tests as root inside the VM, starting it if needed.
.PHONY: vm-test
VMTEST_BINARY ?= $(DIST)/witsh-linux-amd64
vm-test: vm-start $(VMTEST_BINARY)
	$(GO) vet -tags vmtest ./test/vm
	GOOS=linux GOARCH=amd64 $(GO) test -c -tags vmtest -o $(DIST)/vm.test ./test/vm
	@VM_USER=vmadmin sh scripts/vm.sh ssh 'sudo sh -c "cat >/usr/local/lib/vm.test && chmod 755 /usr/local/lib/vm.test"' <$(DIST)/vm.test
	@VM_USER=vmadmin sh scripts/vm.sh ssh 'sudo sh -c "cat >/usr/local/bin/witsh && chmod 755 /usr/local/bin/witsh"' <$(VMTEST_BINARY)
	@tar -c deploy | VM_USER=vmadmin sh scripts/vm.sh ssh 'sudo rm -rf /usr/local/lib/deploy; sudo tar -x --no-same-owner -C /usr/local/lib'
	@VM_USER=vmadmin sh scripts/vm.sh ssh 'cd / && sudo timeout 3600 /usr/local/lib/vm.test -test.v -test.timeout 3500s $(VMTEST_ARGS)' </dev/null

# The same with witsh built with the race detector. It needs cgo, and the VM's C
# library must be as new as the one it is linked against.
.PHONY: vm-test-race
$(DIST)/witsh-race: FORCE
	@mkdir -p $(DIST)
	CGO_ENABLED=1 $(GO) build -race -trimpath -o $@ ./cmd/witsh
vm-test-race: $(DIST)/witsh-race
	$(MAKE) vm-test VMTEST_BINARY=$(DIST)/witsh-race

.PHONY: vm-start vm-stop vm-status vm-ssh vm-reset vm-list
vm-start vm-stop vm-status vm-ssh vm-reset vm-list: vm-%:
	@sh scripts/vm.sh $*

# A VM to log in to by hand: alice, bob and carol get witsh, vmadmin bash, each
# with a key of their own. vm-test on the same VM stops its daemon; running
# vm-demo again starts it.
.PHONY: vm-demo
vm-demo: $(DIST)/witsh-linux-amd64
	@sh scripts/vm.sh demo $(DIST)/witsh-linux-amd64

FORCE:
