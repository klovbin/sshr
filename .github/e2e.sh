#!/usr/bin/env bash
# Connects sshr to a real sshd on 127.0.0.1:2222 of the CI runner: a key
# host, a host behind a saved jump host, an upload and, where the system
# keychain works, a saved password through askpass
set -euxo pipefail

sshr="$PWD/cli/sshr"
w="${RUNNER_TEMP:-/tmp}/sshr-e2e"
pw='Pw-1234-sshr'
user="${USER:-$USERNAME}"
authkeys=.ssh/authorized_keys
# lines only the sshd of MSYS2 knows, the one of the Linux runner is older
extra=""

os="$(uname -s)"
usepam="UsePAM yes"
case "$os" in
MINGW* | MSYS*)
	# the sshd of MSYS2 has no PAM
	usepam=""
	# the ssh sshr runs is the one of Windows, the case #135 is about, its
	# ssh-keygen also makes the keys: the OpenSSH of Windows refuses a
	# private key whose ACL lets others read it, and a file the ssh-keygen
	# of Git Bash writes gets the ACL of the folder
	export PATH="/c/Windows/System32/OpenSSH:$PATH"
	# one path both Git Bash and MSYS2 read
	w="$(cygpath -u "$w")"
	# the home of MSYS2 is not the one of Windows, sshd gets the file of
	# the Windows user by its full path
	authkeys="$(cygpath -u "$HOME/.ssh/authorized_keys")"
	# Git Bash turns arguments that look like POSIX paths into Windows
	# paths for sshr.exe, /tmp/... are paths on the server and stay
	export MSYS2_ARG_CONV_EXCL=/tmp
	# OpenSSH 10 penalises an address for connections that do not log in,
	# ssh-keyscan and the banner check of sshr ping are such connections
	extra="PerSourcePenalties no"
	;;
esac
mkdir -p "$w"

ssh-keygen -q -t ed25519 -N '' -f "$w/hostkey"
ssh-keygen -q -t ed25519 -N '' -f "$w/userkey"
mkdir -p ~/.ssh
chmod 700 ~/.ssh
cat "$w/userkey.pub" >>~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

cat >"$w/sshd_config" <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $w/hostkey
PidFile $w/sshd.pid
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
$usepam
AuthorizedKeysFile $authkeys
$extra
Subsystem sftp internal-sftp
EOF

case "$os" in
Linux)
	sudo apt-get install -y -qq openssh-server >/dev/null
	sudo mkdir -p /run/sshd
	sudo useradd -m -s /bin/sh sshrpw
	echo "sshrpw:$pw" | sudo chpasswd
	;;
Darwin)
	sudo sysadminctl -addUser sshrpw -password "$pw" -home /Users/sshrpw
	sudo createhomedir -c -u sshrpw >/dev/null || true
	;;
esac
case "$os" in
MINGW* | MSYS*)
	# the sshd of MSYS2 (on the runner at C:\msys64) runs as the runner
	# user and logs in only that user, which is all the key and jump
	# checks need, its shell is POSIX like the other runners, the sshd of
	# Windows would run the commands through cmd.exe, it is started and
	# stopped through the bash of MSYS2, the pid in sshd.pid is one of
	# MSYS2, the trap is set first so a failed start shows its log, a
	# daemon started from Git Bash keeps the call waiting, so sshd stays in
	# the foreground (-D) in a background job of Git Bash
	msys() { MSYSTEM=MSYS /c/msys64/usr/bin/bash -lc "$1"; }
	msys 'pacman -Sy --noconfirm --needed openssh' >/dev/null
	trap 'msys "kill \$(cat $w/sshd.pid)" || true; cat "$w/sshd.log" || true' EXIT
	msys "/usr/bin/sshd -t -f $w/sshd_config"
	msys "exec /usr/bin/sshd -D -f $w/sshd_config -E $w/sshd.log" &
	;;
*)
	trap 'sudo kill "$(cat "$w/sshd.pid")" || true; sudo cat "$w/sshd.log" || true' EXIT
	sudo /usr/sbin/sshd -f "$w/sshd_config" -E "$w/sshd.log"
	;;
esac
for _ in 1 2 3 4 5 6 7 8 9 10; do
	# only the ed25519 key the server has, every other type would be one
	# more connection that does not log in
	ssh-keyscan -t ed25519 -p 2222 127.0.0.1 >"$w/known" 2>/dev/null || true
	[ -s "$w/known" ] && break
	sleep 1
done
cat "$w/known" >>~/.ssh/known_hosts

# run_command through the MCP server, the output of the command is in the
# JSON answer
mcp() {
	printf '%s\n' \
		'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ci","version":"1"}}}' \
		'{"jsonrpc":"2.0","method":"notifications/initialized"}' \
		"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"run_command\",\"arguments\":{\"host\":\"$1\",\"command\":\"$2\"}}}" |
		"$sshr" mcp --allow-commands
}

"$sshr" add 127.0.0.1 -u "$user" -n key -p 2222 -k "$w/userkey"
"$sshr" add 127.0.0.1 -u "$user" -n inner -p 2222 -k "$w/userkey" -J key

"$sshr" ping key
# the arithmetic runs on the server, the answer proves the command ran there
# shellcheck disable=SC2016
mcp key 'echo sshr-ok-$((40+2))' | tee "$w/out1" | grep 'sshr-ok-42'
# shellcheck disable=SC2016
mcp inner 'echo via-jump-$((40+2))' | tee "$w/out2" | grep 'via-jump-42'

# both hosts by tag, through sshr run
"$sshr" tag key +e2e
"$sshr" tag inner +e2e
# shellcheck disable=SC2016
test "$("$sshr" run -t e2e -- 'echo run-$((40+2))' | grep -c '^run-42$')" = 2
# Tab completion offers saved hosts, the bash script parses
"$sshr" __complete connect ke | grep -qx key
"$sshr" completion bash | bash -n
# a command stopped by --timeout still shows what it printed before
"$sshr" run --timeout 2 key -- 'echo started-run; sleep 20' >"$w/out3" || true
grep -q '^started-run$' "$w/out3"

# send a folder through the jump host and get it back
mkdir -p "$w/tree/sub"
echo one >"$w/tree/a.txt"
echo two >"$w/tree/sub/b.txt"
"$sshr" send inner "$w/tree" --to /tmp/sshr-e2e-copy </dev/null
mkdir -p "$w/back"
"$sshr" get --legacy key /tmp/sshr-e2e-copy --to "$w/back" </dev/null
diff -r "$w/tree" "$w/back/sshr-e2e-copy"

echo "hello from ci" >"$w/up.txt"
remote="$("$sshr" paste -f "$w/up.txt" key | tail -n 1)"
mcp key "cat $remote" | grep 'hello from ci'

# a saved password needs the system keychain, macOS runners have the login
# keychain, Linux runners have no Secret Service
if [ "$os" = Darwin ]; then
	printf '%s\n' "$pw" | "$sshr" add 127.0.0.1 -u sshrpw -n pw -p 2222 --no-key
	mcp pw 'id -un' | tee "$w/out3" | grep 'sshrpw'
fi
echo "end to end checks passed"
