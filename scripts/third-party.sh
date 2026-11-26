#!/bin/sh
# Prints the licenses of the code compiled into witsh for the given
# architectures: every module it uses, and Go's standard library and runtime.
# Their licenses ask for these notices to go with the binaries.
# Usage: third-party.sh ARCH... (GO names the go command)
set -eu
GO=${GO:-go}
[ $# -gt 0 ] || { echo "usage: third-party.sh ARCH..." >&2; exit 2; }
cd "$(dirname "$0")/.."
mods=$(for a in "$@"; do
	GOOS=linux GOARCH=$a $GO list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' ./cmd/witsh
done | sort -u)

echo "Third-party code in the witsh binaries ($*), with its licenses."
echo
echo "$mods" | while read -r path ver dir; do
	echo "  $path $ver"
done
echo "  Go standard library and runtime $($GO env GOVERSION)"

notice() {
	echo
	echo "================================================================================"
	echo "$1"
	echo "================================================================================"
	echo
	cat "$2"
}
echo "$mods" | while read -r path ver dir; do
	found=
	for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
		[ -f "$f" ] || continue
		notice "$path $ver (${f##*/})" "$f"
		found=1
	done
	[ -n "$found" ] || { echo "third-party.sh: no license file in $path $ver" >&2; exit 1; }
done
notice "Go standard library and runtime $($GO env GOVERSION)" "$($GO env GOROOT)/LICENSE"
