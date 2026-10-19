#!/bin/sh
# Installs sshr on Linux or macOS into ~/.local/bin (or --prefix) and adds
# that directory to PATH in the shell startup file
#
#   curl -fsSL https://raw.githubusercontent.com/klovbin/sshr/main/install.sh | sh
#   sh install.sh --help
#
# A release binary is downloaded when one exists for this system and its
# checksum matches, otherwise sshr is built from source with Go, the GUI
# needs cgo and a C compiler, without them the CLI is built and the script
# says so
set -eu

REPO="klovbin/sshr"
PREFIX="${SSHR_PREFIX:-$HOME/.local/bin}"
VERSION="latest"
MODIFY_PATH=1
FROM_SOURCE=0
CLI_ONLY=0
UNINSTALL=0
GUI=0
COMPLETION=1
PATH_MARK="# added by the sshr installer"

usage() {
	cat <<'EOF'
Usage: install.sh [options]

  --prefix <dir>      install into <dir> (default ~/.local/bin, or $SSHR_PREFIX)
  --version <tag>     release to download (default latest)
  --from-source       build from source even if a release binary exists
  --cli-only          build without the GUI (no cgo, no C compiler needed)
  --no-modify-path    do not touch shell startup files
  --no-completion     do not install Tab completion for bash and fish
  --uninstall         remove sshr, its menu entry and the PATH line this
                      script added
  -h, --help          show this help
EOF
}

say() { printf 'sshr install: %s\n' "$*"; }
die() { printf 'sshr install: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--prefix) [ $# -ge 2 ] || die "--prefix needs a directory"; PREFIX="$2"; shift ;;
	--prefix=*) PREFIX="${1#*=}" ;;
	--version) [ $# -ge 2 ] || die "--version needs a tag"; VERSION="$2"; shift ;;
	--version=*) VERSION="${1#*=}" ;;
	--from-source) FROM_SOURCE=1 ;;
	--cli-only) CLI_ONLY=1 ;;
	--no-modify-path) MODIFY_PATH=0 ;;
	--no-completion) COMPLETION=0 ;;
	--uninstall) UNINSTALL=1 ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown option $1" ;;
	esac
	shift
done

case "$(uname -s)" in
Linux) OS=linux ;;
Darwin) OS=darwin ;;
MINGW* | MSYS* | CYGWIN*) die "on Windows build with: go build -o sshr.exe ./cmd/sshr (a Windows installer is planned)" ;;
*) die "unsupported system $(uname -s), Linux and macOS are supported" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported CPU $(uname -m), amd64 and arm64 are supported" ;;
esac

# rc_files lists the startup files of the user's shell that get the PATH line
rc_files() {
	case "${SHELL:-}" in
	*/fish) echo "${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/sshr.fish" ;;
	*/zsh) echo "${ZDOTDIR:-$HOME}/.zshrc" ;;
	*/bash)
		if [ "$OS" = darwin ]; then echo "$HOME/.bash_profile"; else echo "$HOME/.bashrc"; fi ;;
	*) echo "$HOME/.profile" ;;
	esac
}

# remove_path_line deletes the line this script added, other lines stay
remove_path_line() {
	f="$1"
	[ -f "$f" ] || return 0
	grep -qF "$PATH_MARK" "$f" || return 0
	tmp="$f.sshr-tmp"
	grep -vF "$PATH_MARK" "$f" >"$tmp" || true
	cat "$tmp" >"$f"
	rm -f "$tmp"
	say "removed the PATH line from $f"
}

bash_completion_file() { echo "${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/sshr"; }
fish_completion_file() { echo "${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/sshr.fish"; }

if [ "$UNINSTALL" = 1 ]; then
	if [ -x "$PREFIX/sshr" ]; then "$PREFIX/sshr" desktop-entry --remove >/dev/null 2>&1 && say "removed the application menu entry"; fi
	rm -f "$PREFIX/sshr"
	say "removed $PREFIX/sshr"
	for f in "$(bash_completion_file)" "$(fish_completion_file)"; do
		if [ -f "$f" ] && grep -qF "sshr completion" "$f"; then rm -f "$f"; say "removed $f"; fi
	done
	# the fish file holds only our line, it goes whole
	fish_rc="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/sshr.fish"
	if [ -f "$fish_rc" ] && grep -qF "$PATH_MARK" "$fish_rc"; then rm -f "$fish_rc"; say "removed $fish_rc"; fi
	for f in "${ZDOTDIR:-$HOME}/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do remove_path_line "$f"; done
	say "your hosts in ~/.sshr are kept, delete that folder to remove them"
	exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sshr-install.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM

fetch() {
	if have curl; then curl -fsSL "$1" -o "$2"
	elif have wget; then wget -q "$1" -O "$2"
	else return 1
	fi
}

sha256() {
	if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
	elif have shasum; then shasum -a 256 "$1" | cut -d' ' -f1
	else return 1
	fi
}

# download_release fetches sshr_<os>_<arch> and checks it against
# sha256sums.txt of the same release, any failure means building from source
download_release() {
	asset="sshr_${OS}_${ARCH}"
	if [ "$VERSION" = latest ]; then
		base="https://github.com/$REPO/releases/latest/download"
	else
		base="https://github.com/$REPO/releases/download/$VERSION"
	fi
	if ! fetch "$base/$asset" "$WORK/sshr" 2>/dev/null; then
		say "no release binary $asset ($VERSION), building from source"
		return 1
	fi
	if ! fetch "$base/sha256sums.txt" "$WORK/sums" 2>/dev/null; then
		say "the release has no sha256sums.txt, not using an unchecked binary"
		return 1
	fi
	want="$(awk -v a="$asset" '$2 == a || $2 == "*"a {print $1}' "$WORK/sums")"
	got="$(sha256 "$WORK/sshr")" || { say "no sha256sum or shasum to check the download"; return 1; }
	if [ -z "$want" ] || [ "$want" != "$got" ]; then
		say "checksum of $asset does not match, not installing it"
		return 1
	fi
	chmod 755 "$WORK/sshr"
	GUI=1
	say "downloaded release $VERSION for $OS/$ARCH"
}

# go_ok checks for Go 1.21 or newer, newer toolchains named in go.mod are
# fetched by go itself
go_ok() {
	have go || return 1
	v="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
	major="${v%%.*}"
	rest="${v#*.}"
	minor="${rest%%.*}"
	[ "${major:-0}" -gt 1 ] || { [ "${major:-0}" -eq 1 ] && [ "${minor:-0}" -ge 21 ]; }
}

# build_source builds from this checkout when the script runs inside one,
# otherwise from a fresh copy of the main branch
build_source() {
	go_ok || die "no checked release binary for $OS/$ARCH and no Go 1.21+ to build one, install Go from https://go.dev/dl/ and run this again"
	here="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
	if [ -n "$here" ] && [ -f "$here/go.mod" ] && grep -q '^module sshr.dev' "$here/go.mod"; then
		src="$here"
	elif have git; then
		git clone -q --depth 1 "https://github.com/$REPO.git" "$WORK/src" || die "git clone failed"
		src="$WORK/src"
	else
		fetch "https://github.com/$REPO/archive/refs/heads/main.tar.gz" "$WORK/src.tgz" || die "cannot download the source, install curl, wget or git"
		mkdir "$WORK/src" && tar -xzf "$WORK/src.tgz" -C "$WORK/src" --strip-components 1
		src="$WORK/src"
	fi
	say "building from source in $src"
	if [ "$CLI_ONLY" = 0 ] && (cd "$src" && CGO_ENABLED=1 go build -o "$WORK/sshr" ./cmd/sshr) 2>"$WORK/gui.log"; then
		say "built with the GUI"
		GUI=1
		return 0
	fi
	if [ "$CLI_ONLY" = 0 ]; then
		say "the GUI did not build (it needs a C compiler and, on Linux, Wayland/X11 and Vulkan headers), building the CLI only:"
		sed 's/^/    /' "$WORK/gui.log" | tail -n 5
	fi
	(cd "$src" && CGO_ENABLED=0 go build -tags nocgo -o "$WORK/sshr" ./cmd/sshr) || die "go build failed"
	say "built the CLI"
}

if [ "$FROM_SOURCE" = 1 ] || [ "$CLI_ONLY" = 1 ] || ! download_release; then
	build_source
fi

mkdir -p "$PREFIX"
# a copy next to the old binary, then a rename, a running sshr keeps working
cp "$WORK/sshr" "$PREFIX/.sshr.new"
mv -f "$PREFIX/.sshr.new" "$PREFIX/sshr"
say "installed $PREFIX/sshr"

# the GUI goes to the application menu with its icon, sshr carries the
# icons and writes the entry itself (an app bundle on macOS)
if [ "$GUI" = 1 ]; then
	"$PREFIX/sshr" desktop-entry || say "could not add sshr to the application menu"
fi

# Tab completion for the shells that are here, written by sshr itself so
# it always matches the installed version, zsh needs a line in .zshrc
if [ "$COMPLETION" = 1 ]; then
	if have bash; then
		f="$(bash_completion_file)"
		mkdir -p "$(dirname "$f")" && "$PREFIX/sshr" completion bash >"$f" && say "Tab completion for bash in $f"
	fi
	if have fish; then
		f="$(fish_completion_file)"
		mkdir -p "$(dirname "$f")" && "$PREFIX/sshr" completion fish >"$f" && say "Tab completion for fish in $f"
	fi
	if have zsh; then
		say "for Tab completion in zsh add to ~/.zshrc: source <(sshr completion zsh)"
	fi
fi

case ":$PATH:" in
*":$PREFIX:"*) exit 0 ;;
esac
if [ "$MODIFY_PATH" = 0 ]; then
	say "$PREFIX is not in PATH, add it to run sshr by name"
	exit 0
fi
rc="$(rc_files)"
if [ -f "$rc" ] && grep -qF "$PATH_MARK" "$rc"; then
	say "$rc already adds $PREFIX to PATH, open a new terminal"
	exit 0
fi
mkdir -p "$(dirname "$rc")"
case "$rc" in
*.fish)
	printf 'fish_add_path %s %s\n' "'$PREFIX'" "$PATH_MARK" >>"$rc"
	say "added $PREFIX to PATH in $rc, open a new terminal or run: fish_add_path '$PREFIX'"
	exit 0
	;;
*) # shellcheck disable=SC2016 # $PATH expands in the shell that reads rc
	printf 'export PATH="%s:$PATH" %s\n' "$PREFIX" "$PATH_MARK" >>"$rc" ;;
esac
say "added $PREFIX to PATH in $rc, open a new terminal or run: export PATH=\"$PREFIX:\$PATH\""
