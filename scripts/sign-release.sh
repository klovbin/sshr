#!/bin/sh
# Signs the line "sshr-release <tag>" followed by <dir>/sha256sums.txt with
# the release key in $SSHR_RELEASE_KEY into sha256sums.txt.sig and checks
# the signature against the key pinned in install.sh, the tag in the signed
# text keeps an old signed release from passing for a newer one, a release
# without the key or with another key than the one install.sh trusts stops
# here instead of going out
#
#   SSHR_RELEASE_KEY="$(cat sshr-release)" scripts/sign-release.sh dist v1.2.3
set -eu

DIR="${1:?usage: sign-release.sh <dir> <tag>}"
TAG="${2:?usage: sign-release.sh <dir> <tag>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
NS="sshr-release"

[ -n "${SSHR_RELEASE_KEY:-}" ] || { echo "SSHR_RELEASE_KEY is empty, set the repository secret, see issue #146" >&2; exit 1; }
pinned="$(sed -n 's/^RELEASE_KEY="\(.*\)"$/\1/p' "$HERE/../install.sh")"
[ -n "$pinned" ] || { echo "install.sh pins no RELEASE_KEY, paste the public key there, see issue #146" >&2; exit 1; }
# one ed25519 key, a second line would make either key pass
case "$pinned" in
*"
"* | *[!A-Za-z0-9+/=\ -]*) echo "RELEASE_KEY in install.sh is not one key line" >&2; exit 1 ;;
ssh-ed25519\ *) ;;
*) echo "RELEASE_KEY in install.sh is not an ssh-ed25519 key" >&2; exit 1 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
umask 077
printf '%s\n' "$SSHR_RELEASE_KEY" >"$tmp/key"
{ printf '%s %s\n' "$NS" "$TAG"; cat "$DIR/sha256sums.txt"; } >"$tmp/signed"
# ssh-keygen asks before it writes over an old signature
rm -f "$tmp/signed.sig" "$DIR/sha256sums.txt.sig"
ssh-keygen -q -Y sign -f "$tmp/key" -n "$NS" "$tmp/signed"
mv "$tmp/signed.sig" "$DIR/sha256sums.txt.sig"
printf '%s %s\n' "$NS" "$pinned" >"$tmp/allowed"
ssh-keygen -q -Y verify -f "$tmp/allowed" -I "$NS" -n "$NS" -s "$DIR/sha256sums.txt.sig" <"$tmp/signed" >/dev/null ||
	{ echo "the signature does not check with the key pinned in install.sh, the secret holds another key" >&2; exit 1; }
echo "signed $DIR/sha256sums.txt for $TAG"
