#!/bin/sh
# Disposable test VM. Needs QEMU, curl and ssh; no root. Uses KVM if it can.
# Test accounts have a public password: the VM is reachable on localhost only.
set -eu

DIR=${VM_DIR:-$(cd "$(dirname "$0")/.." && pwd)/.vm}
PORT=${VM_SSH_PORT:-2222}
UDP=${VM_UDP_PORT:-60001} # forwarded to the same port in the VM
MEM=${VM_MEM:-2048}
CPUS=${VM_CPUS:-2}
TIMEOUT=${VM_TIMEOUT:-900} # seconds to wait for boot; emulation is slow
IMG=ubuntu-26.04-server-cloudimg-amd64.img
URL=https://cloud-images.ubuntu.com/releases/26.04/release-20261108/$IMG
SHA=7b90593f5532b49b7e3fe3d2743f0d1f0d822e5b07cebcd8e00c0df8069ecab9

# VM=name selects one of several VMs; without it the default VM is used. A named
# VM lives in $BASE-name and gets a slot N, a symlink $BASE/slots/N -> name. N is
# added to both base ports. The downloaded image is shared.
VM=${VM:-default}
BASE=$DIR
BASE_PORT=$PORT
BASE_UDP=$UDP

slot_of() {
	for s in "$BASE"/slots/*; do
		if [ -L "$s" ] && [ "$(readlink "$s")" = "$1" ]; then
			echo "${s##*/}"
			return
		fi
	done
}

# Sets NAME, HOST, SLOT, DIR, PORT and UDP. SLOT is empty if there is no such VM.
use() {
	NAME=$1
	if [ "$NAME" = default ]; then
		HOST=witnesshell-vm SLOT=0 DIR=$BASE
	else
		HOST=witnesshell-vm-$NAME SLOT=$(slot_of "$NAME") DIR=$BASE-$NAME
	fi
	PORT=$((BASE_PORT + ${SLOT:-0}))
	UDP=$((BASE_UDP + ${SLOT:-0}))
}

need_vm() {
	[ -n "$SLOT" ] || { echo "no VM named $NAME; see make vm-list" >&2; exit 1; }
}

claim_slot() {
	mkdir -p "$BASE/slots"
	n=1
	# ln fails if the slot is taken, so two VMs cannot share one
	until ln -sn "$NAME" "$BASE/slots/$n" 2>/dev/null; do
		n=$((n + 1))
		[ $n -lt 100 ] || { echo "cannot claim a slot in $BASE/slots" >&2; exit 1; }
	done
	use "$NAME"
}

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
	if [ ! -f "$BASE/$IMG" ]; then
		echo "downloading $IMG"
		part=$BASE/$IMG.part.$$
		curl -fsSL -o "$part" "$URL"
		echo "$SHA  $part" | sha256sum -c - >/dev/null
		mv "$part" "$BASE/$IMG"
	fi
}

seed() {
	[ -f "$DIR/key" ] || ssh-keygen -q -t ed25519 -N '' -C witnesshell-vm -f "$DIR/key"
	mkdir -p "$DIR/seed"
	key=$(cat "$DIR/key.pub")
	printf 'instance-id: witnesshell\nlocal-hostname: %s\n' "$HOST" >"$DIR/seed/meta-data"
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

# demo BINARY makes the VM a host to log in to by hand (scripts/vm-demo.sh):
# every user gets a key of their own in $DIR/users, and $DIR/ssh_config has an
# entry for each.
demo() {
	[ -f "${1:-}" ] || { echo "usage: vm.sh demo WITSH-BINARY" >&2; exit 2; }
	start
	mkdir -p "$DIR/users"
	chmod 700 "$DIR/users"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	mkdir "$tmp/keys"
	: >"$DIR/ssh_config"
	for u in vmadmin alice bob carol; do
		[ -f "$DIR/users/$u" ] || ssh-keygen -q -t ed25519 -N '' -C "$u@$HOST" -f "$DIR/users/$u"
		cp "$DIR/users/$u.pub" "$tmp/keys/"
		printf 'Host %s\n\tHostName 127.0.0.1\n\tPort %s\n\tUser %s\n\tIdentityFile %s\n\tIdentitiesOnly yes\n\tUserKnownHostsFile %s\n\tStrictHostKeyChecking accept-new\n\n' \
			"$u" "$PORT" "$u" "$DIR/users/$u" "$DIR/known_hosts" >>"$DIR/ssh_config"
	done
	cp "$1" "$tmp/witsh"
	cp -R "$(dirname "$0")/../deploy" "$(dirname "$0")/vm-demo.sh" "$tmp/"
	echo "$UDP" >"$tmp/udp_port"
	tar -c -C "$tmp" . | VM_USER=vmadmin vmssh 'd=$(mktemp -d) && sudo tar -x --no-same-owner -C "$d" && sudo sh "$d/vm-demo.sh"; s=$?; sudo rm -rf "$d"; exit $s'
	w=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
	cat <<EOF
Ready. Log in with
  ssh -F $DIR/ssh_config vmadmin                     # bash, root through sudo
  $w connect -F $DIR/ssh_config alice   # also bob, carol: witsh
Private keys are in $DIR/users.
EOF
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
	[ -n "$SLOT" ] || claim_slot
	mkdir -p "$BASE" "$DIR"
	chmod 700 "$BASE" "$DIR"
	fetch
	seed
	if [ ! -f "$DIR/disk.qcow2" ]; then
		rm -f "$DIR/known_hosts"
		qemu qemu-img create -q -f qcow2 -F qcow2 -b "$BASE/$IMG" "$DIR/disk.qcow2" 10G
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
		-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22,hostfwd=udp:127.0.0.1:$UDP-:$UDP" \
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
	if [ "$NAME" = default ]; then
		echo "VM is up: make vm-ssh"
	else
		echo "VM is up: make vm-ssh VM=$NAME (ssh port $PORT, UDP port $UDP)"
	fi
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

reset() {
	stop
	rm -f "$DIR/disk.qcow2" "$DIR/known_hosts" "$DIR/ssh_config"
	rm -rf "$DIR/users" # the keys of make vm-demo
	if [ "$NAME" != default ]; then
		rm -f "$DIR/key" "$DIR/key.pub" "$DIR/console.log" \
			"$DIR/seed/meta-data" "$DIR/seed/user-data"
		rmdir "$DIR/seed" "$DIR" 2>/dev/null || true
		rm -f "$BASE/slots/$SLOT"
	fi
	echo "disk discarded"
}

list() {
	row='%-16s %-8s %-8s %-6s %-6s %s\n'
	# shellcheck disable=SC2059
	printf "$row" NAME STATE PID SSH UDP DIR
	for link in default "$BASE"/slots/*; do
		if [ "$link" = default ]; then
			use default
		elif [ -L "$link" ]; then
			use "$(readlink "$link")"
		else
			continue
		fi
		if running; then # sets pid
			state=running
		else
			state=stopped pid=-
			[ -f "$DIR/disk.qcow2" ] || state=absent
		fi
		# shellcheck disable=SC2059
		printf "$row" "$NAME" "$state" "$pid" "$PORT" "$UDP" "$DIR"
	done
}

case $VM in
-* | *- | *[!a-z0-9-]*) echo "VM: use a-z, 0-9 and inner dashes" >&2; exit 2 ;;
esac
[ "${#VM}" -le 40 ] || { echo "VM: name too long" >&2; exit 2; }
use "$VM"
case ${1:-} in
stop | status | ssh | reset) need_vm ;;
esac

case ${1:-} in
start) start ;;
stop) stop ;;
status) if running; then echo "running, ssh port $PORT"; else echo "stopped"; fi ;;
ssh) shift; vmssh "$@" ;;
demo) shift; demo "$@" ;;
reset) reset ;;
list) list ;;
*) echo "usage: [VM=name] vm.sh start|stop|status|reset|list|ssh [command]|demo WITSH" >&2; exit 2 ;;
esac
