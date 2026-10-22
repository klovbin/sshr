#!/bin/sh
# Builds the release files of sshr into a folder: the CLI for linux, darwin
# and windows on amd64 and arm64, named sshr_<os>_<arch> (.exe on Windows),
# and sha256sums.txt next to them, install.sh looks for exactly these names
#
#   scripts/release.sh v1.2.3 [out-dir]
#
# The version goes into the binary through app.Version, the MCP server
# reports it. The CLI is built without cgo (-tags nocgo), so it needs no C
# compiler and no Wayland, X11 or Vulkan headers, the GUI is not part of
# these files
set -eu

die() {
	echo "release.sh: $*" >&2
	exit 1
}

[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: scripts/release.sh <tag> [out-dir]"
TAG="$1"
OUT="${2:-dist}"
case "$TAG" in
v[0-9]*) ;;
*) die "the tag $TAG should look like v1.2.3" ;;
esac

cd "$(dirname "$0")/.."
rm -rf "$OUT"
mkdir -p "$OUT"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
	os="${target%/*}"
	arch="${target#*/}"
	name="sshr_${os}_${arch}"
	[ "$os" = windows ] && name="$name.exe"
	echo "building $name"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -tags nocgo -trimpath \
		-ldflags "-s -w -X sshr.dev/internal/app.Version=$TAG" \
		-o "$OUT/$name" ./cmd/sshr
done

# two spaces between hash and name, the format sha256sum -c reads and
# install.sh picks the hash from
(
	cd "$OUT"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum sshr_* >sha256sums.txt
	else
		shasum -a 256 sshr_* >sha256sums.txt
	fi
)
echo "wrote $OUT/sha256sums.txt"
