#!/bin/sh
# Disposable test VM. Needs QEMU, curl and ssh; no root. Uses KVM if it can.
# Test accounts have a public password: the VM is reachable on localhost only.
set -eu

DIR=${VM_DIR:-$(cd "$(dirname "$0")/.." && pwd)/.vm}
PORT=${VM_SSH_PORT:-2222}
MEM=${VM_MEM:-2048}
CPUS=${VM_CPUS:-2}
TIMEOUT=${VM_TIMEOUT:-900} # seconds to wait for boot; emulation is slow
IMG=ubuntu-26.04-server-cloudimg-amd64.img
URL=https://cloud-images.ubuntu.com/releases/26.04/release-20261108/$IMG
SHA=7b90593f5532b49b7e3fe3d2743f0d1f0d822e5b07cebcd8e00c0df8069ecab9

# VM_QEMU_ROOT points at QEMU packages unpacked without installing them.
QROOT=${VM_QEMU_ROOT:-}
if [ -n "$QROOT" ]; then
	PATH=$QROOT/usr/bin:$PATH
fi
qemu() {
	prog=$1
	shift
	if [ -n "$QROOT" ]; then
		LD_LIBRARY_PATH=$QROOT/usr/lib/x86_64-linux-gnu "$prog" "$@"
	else
		"$prog" "$@"
	fi
}

running() {
	[ -s "$DIR/pid" ] || return 1
	pid=$(cat "$DIR/pid")
	# A recycled pid must never be mistaken for our VM.
	tr '\0' ' ' 2>/dev/null <"/proc/$pid/cmdline" | grep -qF "$DIR/disk.qcow2"
}

vmssh() {
	user=${VM_USER:-vmadmin}
	ssh -q -i "$DIR/key" -p "$PORT" -o IdentitiesOnly=yes -o BatchMode=yes \
		-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$DIR/known_hosts" \
		-o ConnectTimeout=20 "$user@127.0.0.1" "$@"
}

fetch() {
	if [ ! -f "$DIR/$IMG" ]; then
		echo "downloading $IMG"
		curl -fsSL -o "$DIR/$IMG.part" "$URL"
		echo "$SHA  $DIR/$IMG.part" | sha256sum -c - >/dev/null
		mv "$DIR/$IMG.part" "$DIR/$IMG"
	fi
}

seed() {
	[ -f "$DIR/key" ] || ssh-keygen -q -t ed25519 -N '' -C witnesshell-vm -f "$DIR/key"
	mkdir -p "$DIR/seed"
	key=$(cat "$DIR/key.pub")
	printf 'instance-id: witnesshell\nlocal-hostname: witnesshell-vm\n' >"$DIR/seed/meta-data"
	{
		echo '#cloud-config'
		echo 'package_update: false'
		echo 'ssh_pwauth: false'
		echo 'users:'
		printf '  - {name: vmadmin, shell: /bin/bash, sudo: "ALL=(ALL) NOPASSWD:ALL", ssh_authorized_keys: ["%s"]}\n' "$key"
		# alice may use sudo, but only with a password, like a real actor
		printf '  - {name: alice, shell: /bin/bash, lock_passwd: false, plain_text_passwd: test, sudo: "ALL=(ALL) ALL", ssh_authorized_keys: ["%s"]}\n' "$key"
		for u in bob carol; do
			printf '  - {name: %s, shell: /bin/bash, ssh_authorized_keys: ["%s"]}\n' "$u" "$key"
		done
	} >"$DIR/seed/user-data"
}

start() {
	if running; then
		echo "already running"
		return
	fi
	command -v qemu-system-x86_64 >/dev/null || {
		echo "qemu-system-x86_64 not found; install QEMU or set VM_QEMU_ROOT" >&2
		exit 1
	}
	mkdir -p "$DIR"
	chmod 700 "$DIR"
	fetch
	seed
	if [ ! -f "$DIR/disk.qcow2" ]; then
		rm -f "$DIR/known_hosts"
		qemu qemu-img create -q -f qcow2 -F qcow2 -b "$DIR/$IMG" "$DIR/disk.qcow2" 10G
	fi
	if [ -w /dev/kvm ]; then
		accel="-accel kvm -cpu host"
	else
		echo "no KVM: using slow software emulation"
		accel="-accel tcg,thread=multi -cpu max"
	fi
	set -- -m "$MEM" -smp "$CPUS" -display none -daemonize -pidfile "$DIR/pid" \
		-serial "file:$DIR/console.log" -monitor none \
		-drive "file=$DIR/disk.qcow2,if=virtio,format=qcow2" \
		-drive "file.driver=vvfat,file.dir=$DIR/seed,file.label=CIDATA,format=raw,if=virtio,read-only=on" \
		-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22" \
		-device virtio-net-pci,netdev=n0,romfile=
	if [ -n "$QROOT" ]; then
		set -- -L "$QROOT/usr/share/qemu" -L "$QROOT/usr/share/seabios" "$@"
	fi
	# shellcheck disable=SC2086
	qemu qemu-system-x86_64 $accel "$@"
	end=$(($(date +%s) + TIMEOUT))
	# carol is created last, so all accounts exist once carol does. The test
	# users cannot run commands over ssh once the VM is hardened.
	until VM_USER=vmadmin vmssh 'id carol >/dev/null' </dev/null 2>/dev/null; do
		running || { echo "VM exited; see $DIR/console.log" >&2; exit 1; }
		[ "$(date +%s)" -lt "$end" ] || { echo "timed out; see $DIR/console.log" >&2; exit 1; }
		sleep 3
	done
	echo "VM is up: make vm-ssh"
}

stop() {
	if ! running; then
		echo "not running"
		return
	fi
	vmssh sudo poweroff </dev/null 2>/dev/null || true
	i=0
	while running && [ $i -lt 60 ]; do
		sleep 1
		i=$((i + 1))
	done
	if running; then
		echo "no clean shutdown; killing"
		kill "$(cat "$DIR/pid")"
		sleep 1
	fi
	rm -f "$DIR/pid"
	echo "stopped"
}

case ${1:-} in
start) start ;;
stop) stop ;;
status) if running; then echo "running, ssh port $PORT"; else echo "stopped"; fi ;;
ssh) shift; vmssh "$@" ;;
reset) stop; rm -f "$DIR/disk.qcow2" "$DIR/known_hosts"; echo "disk discarded" ;;
*) echo "usage: vm.sh start|stop|status|reset|ssh [command]" >&2; exit 2 ;;
esac
