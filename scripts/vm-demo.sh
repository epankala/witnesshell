#!/bin/sh
# Runs as root inside the test VM (see vm.sh demo): turns it into a host where
# alice, bob and carol log in to witsh with keys of their own, and vmadmin logs
# in normally. Can be run again; it puts everything back as it should be.
#
# In the directory of this script: witsh, deploy/, keys/NAME.pub, and
# udp_port, the UDP port that is forwarded to the VM.
set -eu
D=$(cd "$(dirname "$0")" && pwd)
USERS="alice bob carol" # dropped into witsh

install -m 755 "$D/witsh" /usr/local/bin/witsh.new && mv -f /usr/local/bin/witsh.new /usr/local/bin/witsh # also while it runs
getent group witnesshell >/dev/null || groupadd -r witnesshell

# Keys: each user's own, for logging in and for signatures.
install -d -m 755 /etc/ssh/authorized_keys
install -d -m 755 /etc/witnesshell
install -d -m 711 /etc/witnesshell/public_keys
for u in vmadmin $USERS; do
	pub=$D/keys/$u.pub
	home=$(getent passwd "$u" | cut -d: -f6)
	key=$(cut -d' ' -f1,2 "$pub")
	install -d -m 700 -o "$u" -g "$u" "$home/.ssh"
	install -m 644 -o "$u" -g "$u" "$pub" "$home/.ssh/id_ed25519.pub"
	name=$(witsh keyname "$pub")
	printf '%s %s\n' "$u" "$key" >"/etc/witnesshell/public_keys/$name"
	chmod 644 "/etc/witnesshell/public_keys/$name"
done
# vmadmin keeps the VM's own key too, which vm.sh uses.
grep -qF "$(cut -d' ' -f1,2 "$D/keys/vmadmin.pub")" ~vmadmin/.ssh/authorized_keys ||
	cat "$D/keys/vmadmin.pub" >>~vmadmin/.ssh/authorized_keys
for u in $USERS; do
	home=$(getent passwd "$u" | cut -d: -f6)
	# Only their own key: sshd reads this file for them (deploy/10-witnesshell.conf).
	install -m 644 "$D/keys/$u.pub" "/etc/ssh/authorized_keys/$u"
	install -m 600 -o "$u" -g "$u" "$D/keys/$u.pub" "$home/.ssh/authorized_keys"
	usermod -s /usr/local/bin/witsh -aG witnesshell "$u"
done

# Host requirements, applied at every boot before the daemon starts.
install -d /usr/local/lib/witnesshell-demo
cat >/usr/local/lib/witnesshell-demo/harden.sh <<EOF
#!/bin/sh
sysctl -qw vm.memfd_noexec=2 kernel.yama.ptrace_scope=1
for d in /home /tmp /var/tmp /dev/shm /run/lock /var/crash /dev/mqueue /run/screen /run/cloud-init/tmp; do
	[ -d \$d ] || continue
	mountpoint -q \$d || mount --bind \$d \$d
	mount -o remount,bind,noexec,nosuid,nodev \$d
done
for u in $USERS; do
	for t in cron at; do grep -qsx \$u /etc/\$t.deny || echo \$u >>/etc/\$t.deny; done
	rm -f /var/lib/systemd/linger/\$u
done
rm -f /etc/cron.allow /etc/at.allow
EOF
chmod 755 /usr/local/lib/witnesshell-demo/harden.sh
cat >/etc/systemd/system/witnesshell-harden.service <<'EOF'
[Unit]
Description=Host requirements of witnesshell (test VM)
Before=witnesshell.service ssh.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/lib/witnesshell-demo/harden.sh

[Install]
WantedBy=multi-user.target
EOF
ln -sf /dev/null /etc/systemd/system/user@.service
ln -sf /dev/null /etc/systemd/system/user-runtime-dir@.service
for u in $USERS; do
	systemctl stop "user@$(id -u "$u").service" 2>/dev/null || true
	umount -l "/run/user/$(id -u "$u")" 2>/dev/null || true
	rmdir "/run/user/$(id -u "$u")" 2>/dev/null || true
done

# The daemon, as a service, listening on the forwarded UDP port.
printf 'approvals_required = 1\nudp_port = %s\n' "$(cat "$D/udp_port")" >/etc/witnesshell/config.toml
# The suggested commands without approval (README).
cat >>/etc/witnesshell/config.toml <<'EOF'
free_commands = [
  "cd", "jobs",                                                # shell builtins
  "ls", "pwd", "cat", "head", "tail", "wc", "stat", "du", "df", # files
  "realpath", "readlink", "basename", "dirname",
  "grep", "cut", "tr", "nl", "cmp", "diff",                    # text
  "sha256sum", "sha1sum", "md5sum", "b2sum",
  "id", "whoami", "groups", "uname", "date", "uptime", "free", # the system
  "ps", "w", "who", "nproc", "lsblk", "findmnt",
  "printenv", "echo", "printf", "tty", "locale",
]
EOF
cp "$D/deploy/witnesshell.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable -q witnesshell-harden.service witnesshell.service
systemctl restart witnesshell-harden.service
systemctl restart witnesshell.service

# Forced login for the witnesshell group; a mistake here locks them out.
cp "$D/deploy/10-witnesshell.conf" /etc/ssh/sshd_config.d/10-witnesshell.conf
sshd -t
systemctl reload ssh

sleep 1
systemctl is-active -q witnesshell.service || {
	journalctl -u witnesshell.service -n 20 --no-pager
	exit 1
}
