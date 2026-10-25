#!/bin/sh
# sshr ext import royalts <file.rtsz>... reads the SSH connections of Royal
# TS or Royal TSX documents and prints them as {"hosts": [...]} for sshr
#
# A document is XML (.rtsx, or .rtsz saved without a zip) or a zip that
# holds the XML as Document.rtsz, the root RTSZDocument holds a flat list
# of objects (RoyalDocument, RoyalFolder, RoyalSSHConnection,
# RoyalCredential, RoyalTrash, ...) linked by ID and ParentID, every
# property is a child element, the names come from the scripting reference
# of Royal Apps (objects/connections/royalsshconnection), the folders
# above a connection become tags, a connection in the trash, a template or
# a telnet connection is left out, passwords stay encrypted in the
# document and are never read, a key embedded in the document is left out
# with a note
set -eu

[ "${SSHR_EXT_PROTOCOL:-}" = 1 ] || {
	echo "royalts: run me with sshr ext import royalts, not by hand" >&2
	exit 2
}
[ $# -gt 0 ] || {
	echo "royalts: give the Royal TS documents to read, sshr ext import royalts ~/Documents/servers.rtsz" >&2
	exit 1
}

xml() {
	if [ "$(head -c 2 "$1")" = PK ]; then
		command -v unzip >/dev/null 2>&1 || {
			echo "royalts: $1 is a zip, unzip is needed to read it" >&2
			return 1
		}
		if unzip -Z1 "$1" 2>/dev/null | grep -qx Document.rtsz; then
			unzip -p "$1" Document.rtsz
		else
			unzip -p "$1" "$(unzip -Z1 "$1" | head -n 1)"
		fi
	else
		cat "$1"
	fi
}

for f in "$@"; do
	[ -f "$f" ] || {
		echo "royalts: $f is no file" >&2
		exit 1
	}
	if [ "$(wc -c <"$f")" -gt 33554432 ]; then
		echo "royalts: $f is over 32 MiB, it is skipped" >&2
		continue
	fi
	xml "$f"
	# a document ends, the next one starts with its own objects
	printf '\n<!--sshr-end-of-document-->\n'
done | LC_ALL=C awk '
BEGIN { RS = "<"; doc = 0 }
function esc(s,   out, i, c, n) {
	out = ""
	n = length(s)
	for (i = 1; i <= n; i++) {
		c = substr(s, i, 1)
		if (c == "\\") out = out "\\\\"
		else if (c == "\"") out = out "\\\""
		else if (c < " " || c == "\177") continue
		else if (c == "\302" && substr(s, i + 1, 1) >= "\200" && substr(s, i + 1, 1) <= "\237") i++
		else out = out c
	}
	return out
}
function str(k, v) { return "\"" k "\":\"" esc(v) "\"" }
# shown is s for a note on the terminal, without control characters
function shown(s,   out, i, c) {
	out = ""
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (c < " " || c == "\177") continue
		out = out c
	}
	return out
}
function okport(p) { return p ~ /^[0-9]+$/ && p + 0 >= 1 && p + 0 <= 65535 }
# unxml decodes the entities of XML text, a numeric one past ASCII is left
# out, Royal writes UTF-8 bytes for those
function unxml(s,   out, i, j, e, n) {
	out = ""
	while ((i = index(s, "&")) > 0) {
		out = out substr(s, 1, i - 1)
		s = substr(s, i)
		j = index(s, ";")
		if (j == 0 || j > 10) { out = out "&"; s = substr(s, 2); continue }
		e = substr(s, 2, j - 2)
		s = substr(s, j + 1)
		if (e == "lt") out = out "<"
		else if (e == "gt") out = out ">"
		else if (e == "amp") out = out "&"
		else if (e == "quot") out = out "\""
		else if (e == "apos") out = out "\047"
		else if (e ~ /^#[0-9]+$/) { n = substr(e, 2) + 0; if (n >= 32 && n < 127) out = out sprintf("%c", n) }
		else if (e ~ /^#x[0-9a-fA-F]+$/) { n = hexnum(substr(e, 3)); if (n >= 32 && n < 127) out = out sprintf("%c", n) }
	}
	return out s
}
function hexnum(h,   n, i) { n = 0; for (i = 1; i <= length(h); i++) n = n * 16 + index("0123456789abcdef", tolower(substr(h, i, 1))) - 1; return n }
function trim(s) { gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s); return s }
# a record is the text after one "<": a tag up to ">" and the text after it
{
	rec = $0
	if (rec ~ /^!--sshr-end-of-document-->/) { doc++; depth = 0; next }
	if (rec ~ /^[?!]/) next
	gt = index(rec, ">")
	if (gt == 0) next
	tag = substr(rec, 1, gt - 1); text = substr(rec, gt + 1)
	if (substr(tag, 1, 1) == "/") {
		if (depth == 2 && cur != "") end_object()
		depth--
		next
	}
	self = substr(tag, length(tag), 1) == "/"
	sub(/\/$/, "", tag); split(tag, tw, /[ \t\r\n]/); name = tw[1]
	depth++
	if (depth == 2) { cur = name; split("", p) }
	else if (depth == 3) p[name] = trim(unxml(text))
	if (self) { if (depth == 2) end_object(); depth-- }
}
function end_object(   id) {
	id = doc ":" p["ID"]
	if (p["ID"] == "") { cur = ""; return }
	type[id] = cur; parent[id] = doc ":" p["ParentID"]; oname[id] = p["Name"]
	if (cur == "RoyalCredential") {
		if (p["UserName"] != "") { cuser[id] = p["UserName"]; if (p["Name"] != "") cbyname[doc ":" p["Name"]] = p["UserName"] }
		if (p["Password"] != "") secrets++
		cur = ""
		return
	}
	cmode[id] = p["CredentialMode"]; cfrom[id] = p["CredentialFromParent"]
	cname[id] = p["CredentialName"]; cid[id] = doc ":" p["CredentialId"]
	ucred[id] = p["CredentialUsername"]
	if (p["CredentialPassword"] != "") secrets++
	if (cur == "RoyalSSHConnection") {
		order[++n] = id
		uri[id] = p["URI"]; port[id] = p["Port"]
		telnet[id] = p["IsTelnetConnection"]; template[id] = p["IsConnectionTemplate"]
		keyfile[id] = p["CredentialKeyFile"]; keymode[id] = p["CredentialKeyMode"]
		embedded[id] = p["CredentialKeyContent"] != ""
	}
	cur = ""
}
# user is the user name the credentials of object id give, a folder above
# for "from the parent", a shared credential by ID or name, the part after
# DOMAIN\ only, ssh logs in with a plain user name
function user(id, hops,   u, d) {
	if (hops > 32 || !(id in type)) return ""
	if (cfrom[id] == "True" || cmode[id] == "1") return user(parent[id], hops + 1)
	if (cmode[id] == "2") u = ucred[id]
	else if (cmode[id] == "3") u = cuser[cid[id]]
	else if (cmode[id] == "4") u = cbyname[substr(id, 1, index(id, ":")) cname[id]]
	else u = ucred[id]
	d = index(u, "\\")
	if (d > 0) u = substr(u, d + 1)
	return u
}
# tags are the folders above object id, TRASH when it is in the trash
function tags(id,   pid, hops, out) {
	out = ""
	pid = parent[id]
	for (hops = 0; hops < 64 && (pid in type); hops++) {
		if (type[pid] == "RoyalTrash") return "TRASH"
		if (type[pid] == "RoyalFolder" && oname[pid] != "") out = "\"" esc(oname[pid]) "\"" (out == "" ? "" : ",") out
		pid = parent[pid]
	}
	return out
}
END {
	if (secrets > 0) printf "royalts: %d saved passwords stay in Royal TS, they are encrypted in the document and are not read\n", secrets > "/dev/stderr"
	out = ""
	for (i = 1; i <= n; i++) {
		id = order[i]
		if (telnet[id] == "True" || template[id] == "True") continue
		t = tags(id)
		if (t == "TRASH") continue
		host = uri[id]; pt = port[id]; u = user(id, 0)
		sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", host); sub(/\/.*$/, "", host)
		at = index(host, "@")
		if (at > 0) { if (u == "") u = substr(host, 1, at - 1); host = substr(host, at + 1) }
		if (host ~ /^[^:]+:[0-9]+$/) { if (pt == "") pt = substr(host, index(host, ":") + 1); sub(/:[0-9]+$/, "", host) }
		if (host == "") continue
		nm = oname[id]; if (nm == "") nm = host
		obj = "{" str("key", "royalts:" substr(id, index(id, ":") + 1)) "," str("name", nm) "," str("host", host)
		if (okport(pt)) obj = obj ",\"port\":" (pt + 0)
		if (u != "") obj = obj "," str("user", u)
		if (keymode[id] == "1" || embedded[id]) printf "royalts: %s: its key is embedded in the document, save it as a file and set it in sshr\n", shown(nm) > "/dev/stderr"
		else if (keyfile[id] != "") obj = obj "," str("key_file", keyfile[id])
		if (t != "") obj = obj ",\"tags\":[" t "]"
		out = out (out == "" ? "" : ",") obj "}"
	}
	print "{\"hosts\":[" out "]}"
}
'
