#!/bin/sh
# sshr ext import putty [folder...] reads the saved sessions of PuTTY on
# Linux and macOS and prints them as {"hosts": [...]} for sshr
#
# The sessions folder is found the way PuTTY finds it (unix/storage.c),
# $PUTTYSESSIONS, else $PUTTYDIR/sessions, else ~/.config/putty/sessions
# when ~/.config/putty exists, else ~/.putty/sessions, each file is one
# session, its name is the session name with %XX escapes, its lines are
# Key=Value, PuTTY saves no password, OpenSSH cannot read a .ppk key, so
# it is left out with a note, an SSH proxy (ProxyMethod 6) becomes a jump
# host, other proxies are not carried
set -eu

[ "${SSHR_EXT_PROTOCOL:-}" = 1 ] || {
	echo "putty: run me with sshr ext import putty, not by hand" >&2
	exit 2
}

if [ $# -eq 0 ]; then
	if [ -n "${PUTTYSESSIONS:-}" ]; then
		set -- "$PUTTYSESSIONS"
	elif [ -n "${PUTTYDIR:-}" ]; then
		set -- "$PUTTYDIR/sessions"
	elif [ -e "${XDG_CONFIG_HOME:-$HOME/.config}/putty" ]; then
		set -- "${XDG_CONFIG_HOME:-$HOME/.config}/putty/sessions"
	else
		set -- "$HOME/.putty/sessions"
	fi
	if [ ! -d "$1" ]; then
		echo '{"hosts":[]}'
		exit 0
	fi
fi

files=""
for dir in "$@"; do
	[ -d "$dir" ] || {
		echo "putty: $dir is not a folder" >&2
		exit 1
	}
	for f in "$dir"/*; do
		# a name with a line break would split into two in the list awk
		# reads, the second half a path relative to the working directory
		case $f in
		*'
'*)
			echo "putty: a file name with a line break is skipped" >&2
			continue
			;;
		esac
		# a link in a synced folder can point at any file, a huge file
		# would be read into awk at once
		if [ -L "$f" ]; then
			echo "putty: $f is a link, it is skipped" >&2
		elif [ -f "$f" ] && [ "$(wc -c <"$f")" -gt 1048576 ]; then
			echo "putty: $f is over 1 MiB, it is skipped" >&2
		elif [ -f "$f" ]; then
			files="$files
$f"
		fi
	done
done

# bytes, not characters: %XX of a UTF-8 name decode one byte at a time,
# gawk in a UTF-8 locale would turn each into a character of its own
printf '%s\n' "$files" | LC_ALL=C awk '
function esc(s,   out, i, c, n) {
	out = ""
	n = length(s)
	for (i = 1; i <= n; i++) {
		c = substr(s, i, 1)
		if (c == "\\") out = out "\\\\"
		else if (c == "\"") out = out "\\\""
		else if (c == "\t") out = out "\\t"
		else if (c < " ") continue
		else out = out c
	}
	return out
}
function str(k, v) { return "\"" k "\":\"" esc(v) "\"" }
# okport tells a port sshr takes, 1 to 65535 written in digits only
function okport(p) { return p ~ /^[0-9]+$/ && p + 0 >= 1 && p + 0 <= 65535 }
function hexval(c) { return index("0123456789ABCDEF", toupper(c)) - 1 }
# decode turns the %XX escapes of a session file name back into bytes
function decode(s,   out, i, a, b) {
	out = ""
	for (i = 1; i <= length(s); i++) {
		if (substr(s, i, 1) == "%" && i + 2 <= length(s)) {
			a = hexval(substr(s, i + 1, 1)); b = hexval(substr(s, i + 2, 1))
			if (a >= 0 && b >= 0) { out = out sprintf("%c", a * 16 + b); i += 2; continue }
		}
		out = out substr(s, i, 1)
	}
	return out
}
function flush(   name, host, user, port, obj, at, jump, proto) {
	name = file; sub(/^.*\//, "", name); name = decode(name)
	if (name == "Default Settings") return
	proto = tolower(v["Protocol"])
	if (proto != "" && proto != "ssh" && proto != "default") return
	host = v["HostName"]; user = v["UserName"]
	if (host == "") return
	at = index(host, "@")
	if (at > 0) {
		if (user == "") user = substr(host, 1, at - 1)
		host = substr(host, at + 1)
	}
	port = v["PortNumber"]
	obj = "{" str("key", name) "," str("name", name) "," str("host", host)
	if (okport(port)) obj = obj ",\"port\":" (port + 0)
	if (user != "") obj = obj "," str("user", user)
	if (v["PublicKeyFile"] ~ /\.[pP][pP][kK]$/) {
		printf "putty: %s: the key %s is a PuTTY key, convert it with puttygen key.ppk -O private-openssh -o key and set it in sshr\n", name, v["PublicKeyFile"] > "/dev/stderr"
	} else if (v["PublicKeyFile"] != "") {
		obj = obj "," str("key_file", v["PublicKeyFile"])
	}
	if (v["ProxyMethod"] == "6" && v["ProxyHost"] != "") {
		jump = v["ProxyHost"]
		if (v["ProxyUsername"] != "") jump = v["ProxyUsername"] "@" jump
		if (okport(v["ProxyPort"]) && v["ProxyPort"] + 0 != 22) jump = jump ":" (v["ProxyPort"] + 0)
		obj = obj "," str("jump", jump)
	} else if (v["ProxyMethod"] != "" && v["ProxyMethod"] != "0") {
		printf "putty: %s: its proxy (ProxyMethod %s) is not carried, sshr goes direct or through jump hosts\n", name, v["ProxyMethod"] > "/dev/stderr"
	}
	obj = obj "}"
	out = out (out == "" ? "" : ",") obj
}
function readfile(path,   line, eq) {
	split("", v); file = path
	while ((getline line < path) > 0) {
		sub(/\r$/, "", line)
		eq = index(line, "="); if (eq == 0) continue
		v[substr(line, 1, eq - 1)] = substr(line, eq + 1)
	}
	close(path)
	flush()
}
NF { readfile($0) }
END { print "{\"hosts\":[" out "]}" }
'
