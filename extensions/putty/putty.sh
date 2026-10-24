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

# bytes, not characters: a session file may hold any byte and gawk in a
# UTF-8 locale would stop matching on one that is no UTF-8
printf '%s\n' "$files" | LC_ALL=C awk '
BEGIN { ascii = " !\"#$%&\047()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~" }
function esc(s,   out, i, c, n) {
	out = ""
	n = length(s)
	for (i = 1; i <= n; i++) {
		c = substr(s, i, 1)
		if (c == "\\") out = out "\\\\"
		else if (c == "\"") out = out "\\\""
		else if (c == "\t") out = out "\\t"
		else if (c < " " || c == "\177") continue
		else if (c == "\302" && substr(s, i + 1, 1) >= "\200" && substr(s, i + 1, 1) <= "\237") i++
		else out = out c
	}
	return out
}
function str(k, v) { return "\"" k "\":\"" esc(v) "\"" }
# shown is s for a note on the terminal: control characters, DEL and the
# C1 controls a session file may carry would drive the terminal
function shown(s,   out, i, c) {
	out = ""
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (c < " " || c == "\177") continue
		if (c == "\302" && substr(s, i + 1, 1) >= "\200" && substr(s, i + 1, 1) <= "\237") { i++; continue }
		out = out c
	}
	return out
}
# okport tells a port sshr takes, 1 to 65535 written in digits only
function okport(p) { return p ~ /^[0-9]+$/ && p + 0 >= 1 && p + 0 <= 65535 }
function hexval(c) { return index("0123456789ABCDEF", toupper(c)) - 1 }
# hex4 writes n as four lower case hex digits, for a JSON \u escape
function hex4(n,   out, i) {
	out = ""
	for (i = 0; i < 4; i++) { out = substr("0123456789abcdef", n % 16 + 1, 1) out; n = int(n / 16) }
	return out
}
# jsonname is the session name of a file name for a JSON string: the %XX
# escapes PuTTY writes are decoded as UTF-8 and every character past
# ASCII becomes a \u escape, so no awk turns a byte into a character of
# its own, control characters are dropped, empty when the name is not
# valid UTF-8 or holds a byte PuTTY would have escaped
function jsonname(s,   n, b, i, c, a, h, out, cp, need, k) {
	n = 0
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (c == "%" && i + 2 <= length(s)) {
			a = hexval(substr(s, i + 1, 1)); h = hexval(substr(s, i + 2, 1))
			if (a < 0 || h < 0) return ""
			b[++n] = a * 16 + h; i += 2
		} else if (index(ascii, c) > 0) {
			b[++n] = index(ascii, c) + 31
		} else return ""
	}
	out = ""
	for (i = 1; i <= n; i++) {
		cp = b[i]
		if (cp < 128) need = 0
		else if (cp >= 194 && cp <= 223) { need = 1; cp -= 192 }
		else if (cp >= 224 && cp <= 239) { need = 2; cp -= 224 }
		else if (cp >= 240 && cp <= 244) { need = 3; cp -= 240 }
		else return ""
		for (k = 1; k <= need; k++) {
			if (i + k > n || b[i + k] < 128 || b[i + k] > 191) return ""
			cp = cp * 64 + b[i + k] - 128
		}
		i += need
		if ((need == 2 && cp < 2048) || (need == 3 && (cp < 65536 || cp > 1114111)) || (cp >= 55296 && cp <= 57343)) return ""
		if (cp < 32 || (cp >= 127 && cp <= 159)) continue
		if (cp == 34) out = out "\\\""
		else if (cp == 92) out = out "\\\\"
		else if (cp < 127) out = out substr(ascii, cp - 31, 1)
		else if (cp < 65536) out = out "\\u" hex4(cp)
		else { cp -= 65536; out = out "\\u" hex4(55296 + int(cp / 1024)) "\\u" hex4(56320 + cp % 1024) }
	}
	return out
}
function flush(   name, title, host, user, port, obj, at, jump, jhost, juser, proto) {
	# the file name as it is on disk is the key, two names that decode the
	# same (A and %41) stay two hosts
	name = file; sub(/^.*\//, "", name)
	if (name == "Default%20Settings") return
	title = jsonname(name)
	if (title == "") title = esc(name)
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
	obj = "{" str("key", name) ",\"name\":\"" title "\"," str("host", host)
	if (okport(port)) obj = obj ",\"port\":" (port + 0)
	if (user != "") obj = obj "," str("user", user)
	if (v["PublicKeyFile"] ~ /\.[pP][pP][kK]$/) {
		printf "putty: %s: the key %s is a PuTTY key, convert it with puttygen key.ppk -O private-openssh -o key and set it in sshr\n", shown(name), shown(v["PublicKeyFile"]) > "/dev/stderr"
	} else if (v["PublicKeyFile"] != "") {
		obj = obj "," str("key_file", v["PublicKeyFile"])
	}
	# cleaned before the test, a host or user of control characters only
	# would give an empty jump or "@gw"
	jhost = shown(v["ProxyHost"]); juser = shown(v["ProxyUsername"])
	if (v["ProxyMethod"] == "6" && jhost != "") {
		jump = jhost
		if (juser != "") jump = juser "@" jump
		if (okport(v["ProxyPort"]) && v["ProxyPort"] + 0 != 22) jump = jump ":" (v["ProxyPort"] + 0)
		obj = obj "," str("jump", jump)
	} else if (v["ProxyMethod"] != "" && v["ProxyMethod"] != "0") {
		printf "putty: %s: its proxy (ProxyMethod %s) is not carried, sshr goes direct or through jump hosts\n", shown(name), shown(v["ProxyMethod"]) > "/dev/stderr"
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
