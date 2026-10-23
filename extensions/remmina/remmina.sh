#!/bin/sh
# sshr ext import remmina [folder...] reads the SSH profiles of Remmina,
# the *.remmina files in ~/.local/share/remmina or the folders given, and
# prints them as {"hosts": [...]} for sshr
#
# Remmina keeps passwords in the system keyring, not in these files, so
# nothing secret is read, a profile of another protocol is skipped, the
# file name is the key, so a second import updates the same hosts
set -eu

[ "${SSHR_EXT_PROTOCOL:-}" = 1 ] || {
	echo "remmina: run me with sshr ext import remmina, not by hand" >&2
	exit 2
}

if [ $# -eq 0 ]; then
	set -- "${XDG_DATA_HOME:-$HOME/.local/share}/remmina"
fi

files=""
for dir in "$@"; do
	[ -d "$dir" ] || {
		echo "remmina: $dir is not a folder" >&2
		exit 1
	}
	for f in "$dir"/*.remmina; do
		# a name with a line break would split into two in the list awk
		# reads, the second half a path relative to the working directory
		case $f in
		*'
'*)
			echo "remmina: a file name with a line break is skipped" >&2
			continue
			;;
		esac
		# a link in a synced folder can point at any file, a huge file
		# would be read into awk at once
		if [ -L "$f" ]; then
			echo "remmina: $f is a link, it is skipped" >&2
		elif [ -f "$f" ] && [ "$(wc -c <"$f")" -gt 1048576 ]; then
			echo "remmina: $f is over 1 MiB, it is skipped" >&2
		elif [ -f "$f" ]; then
			files="$files
$f"
		fi
	done
done

# awk reads the [remmina] group of each file and prints one JSON object
# per SSH profile, the strings are escaped for JSON
printf '%s\n' "$files" | awk '
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
function flush(   host, port, key, i, tags, t, n, obj) {
	if (file == "" || tolower(f["protocol"]) != "ssh" || f["server"] == "") return
	host = f["server"]; port = 0
	if (host ~ /^\[.*\]:[0-9]+$/) {
		i = index(host, "]:"); port = substr(host, i + 2); host = substr(host, 2, i - 2)
	} else if (host ~ /^[^:]+:[0-9]+$/) {
		i = index(host, ":"); port = substr(host, i + 1); host = substr(host, 1, i - 1)
	}
	key = file; sub(/^.*\//, "", key); sub(/\.remmina$/, "", key)
	obj = "{" str("key", key) "," str("name", f["name"] != "" ? f["name"] : host) "," str("host", host)
	if (okport(port)) obj = obj ",\"port\":" (port + 0)
	if (f["username"] != "") obj = obj "," str("user", f["username"])
	if (f["ssh_privatekey"] != "") obj = obj "," str("key_file", f["ssh_privatekey"])
	tags = ""
	n = split(f["group"], t, "/")
	for (i = 1; i <= n; i++) if (t[i] != "") tags = tags (tags == "" ? "" : ",") "\"" esc(t[i]) "\""
	if (tags != "") obj = obj ",\"tags\":[" tags "]"
	obj = obj "}"
	out = out (out == "" ? "" : ",") obj
}
function readfile(path,   line, group, eq, k) {
	split("", f); file = path; group = ""
	while ((getline line < path) > 0) {
		sub(/\r$/, "", line)
		if (line ~ /^\[.*\]$/) { group = substr(line, 2, length(line) - 2); continue }
		if (group != "remmina" || line ~ /^[#;]/) continue
		eq = index(line, "="); if (eq == 0) continue
		k = substr(line, 1, eq - 1); gsub(/[ \t]+$/, "", k)
		f[k] = substr(line, eq + 1); sub(/^[ \t]+/, "", f[k])
	}
	close(path)
	flush()
}
NF { readfile($0) }
END { print "{\"hosts\":[" out "]}" }
'
