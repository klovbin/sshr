#!/bin/sh
# An example extension: sshr hello [greeting] says hello to every saved host
#
# sshr passes SSHR_BIN, the sshr binary, "$SSHR_BIN" list --json prints the
# hosts without any secret, the extension never sees a password or a key
set -eu

[ "${SSHR_EXT_PROTOCOL:-}" = 1 ] || {
	echo "hello: run me with sshr hello, not by hand" >&2
	exit 2
}

greeting="${1:-hello}"
"$SSHR_BIN" list --json | sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' | while read -r name; do
	echo "$greeting, $name"
done
