# Packaging

How to put the sshr CLI into AUR, Homebrew, Scoop and nixpkgs (#17). The GUI is not packaged yet, every package below installs the one `sshr` binary built with `-tags nocgo`.

Everything here starts from a release: a tag `vX.Y.Z` runs `.github/workflows/release.yml`, which uploads `sshr_<os>_<arch>` for linux, darwin and windows on amd64 and arm64 (`.exe` on Windows) and `sha256sums.txt`, plus a build provenance attestation. No package can be written before the first tag, the URLs and hashes below come from it.

Sources: the research on release automation of 17.10.2026 and the docs of each project, named at each rule.

## Order

1. Tag `v0.1.0` and check the release page has the six files and `sha256sums.txt`.
2. AUR `sshr-bin`: no review, live within minutes.
3. Homebrew: a tap of our own, `brew install klovbin/tap/sshr`, no review.
4. Scoop: a bucket of our own, `scoop bucket add sshr https://github.com/klovbin/scoop-bucket`, no review.
5. nixpkgs: a pull request, reviewed by people, takes days to weeks.

homebrew-core and the official Scoop buckets come later, they want a popular project (see their sections). At the time of writing the repository has 2 stars and 0 forks. The names are free: AUR has no `sshr` or `sshr-bin`, Homebrew has no `sshr` formula, nixpkgs has no `sshr` attribute (checked 23.10.2026).

## AUR

**Rule.** A package built from release binaries while the source is public must end in `-bin` (AUR submission guidelines). Files go to `/usr`, never `/usr/local` (Arch package guidelines). The AUR holds only the PKGBUILD and `.SRCINFO`, never a binary.

**Once.** An account on aur.archlinux.org with an SSH public key in its settings, then `git clone ssh://aur@aur.archlinux.org/sshr-bin.git` (an empty repository is created on the first push).

**PKGBUILD** for `sshr-bin`:

```bash
# Maintainer: <name> <email>
pkgname=sshr-bin
pkgver=0.1.0
pkgrel=1
pkgdesc='SSH host manager with an encrypted vault, device sync and an MCP server'
arch=('x86_64' 'aarch64')
url='https://github.com/klovbin/sshr'
license=('AGPL-3.0-only')
depends=('openssh')
optdepends=('libfido2: a security key that opens the vault (sshr vault add-token)')
provides=('sshr')
conflicts=('sshr')
source=("LICENSE-$pkgver::https://raw.githubusercontent.com/klovbin/sshr/v$pkgver/LICENSE")
source_x86_64=("sshr-$pkgver-x86_64::$url/releases/download/v$pkgver/sshr_linux_amd64")
source_aarch64=("sshr-$pkgver-aarch64::$url/releases/download/v$pkgver/sshr_linux_arm64")
sha256sums=('SKIP')
sha256sums_x86_64=('SKIP')
sha256sums_aarch64=('SKIP')

package() {
  install -Dm755 "sshr-$pkgver-$CARCH" "$pkgdir/usr/bin/sshr"
  install -Dm644 "LICENSE-$pkgver" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
```

Replace every `SKIP` with real hashes before the push: `updpkgsums` fills them in, they must match `sha256sums.txt` of the release.

**Check and push:**

```sh
updpkgsums
makepkg -si          # builds and installs, sshr help must work
namcap PKGBUILD
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO
git commit -m 'sshr-bin 0.1.0'
git push
```

**New tag.** Raise `pkgver`, set `pkgrel=1`, `updpkgsums`, regenerate `.SRCINFO`, commit, push.

A source package `sshr` (builds with `go build` on the user's machine) can follow later, under the Go package guidelines of Arch.

## Homebrew

**Rule.** A formula builds from source, a cask installs a binary built and signed upstream (Homebrew Formula Cookbook, Acceptable Formulae). sshr's macOS binaries are not signed or notarized yet, that needs an Apple Developer account, so the tap gets a formula that builds from the source tarball. It works on macOS and Linux and needs no signature.

homebrew-core takes a project with at least 30 forks, 30 watchers or 75 stars, and at least 90 forks, 90 watchers or 225 stars when the owner submits it himself (`docs/Package-Acceptance-Policy.md`, Notability). Until then the tap.

**Once.** Create the public repository `klovbin/homebrew-tap` (the `homebrew-` prefix makes `brew tap klovbin/tap` find it), or `brew tap-new klovbin/tap` locally and push it.

**`Formula/sshr.rb`:**

```ruby
class Sshr < Formula
  desc "SSH host manager with an encrypted vault, device sync and an MCP server"
  homepage "https://github.com/klovbin/sshr"
  url "https://github.com/klovbin/sshr/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "<sha256 of the tarball>"
  license "AGPL-3.0-only"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X sshr.dev/internal/app.Version=v#{version}", tags: "nocgo"), "./cmd/sshr"
  end

  test do
    assert_match "sshr", shell_output("#{bin}/sshr help")
  end
end
```

`std_go_args` sets the output path and takes `ldflags` and `tags` (Formula Cookbook). The tarball hash: `curl -sL <url> | shasum -a 256`.

**Check and publish:**

```sh
brew install --build-from-source ./Formula/sshr.rb
brew test sshr
brew audit --strict --new sshr
git add Formula/sshr.rb && git commit -m 'sshr 0.1.0' && git push
```

Users run `brew install klovbin/tap/sshr`.

**New tag.** `brew bump-formula-pr --url <new tarball url> klovbin/tap/sshr` or edit `url` and `sha256` by hand.

## Scoop

**Rule.** A bucket is a git repository of JSON manifests, anyone can add one. The Main bucket wants "a reasonably well-known and widely used developer tool", for a GitHub project at least 500 stars and 150 forks (`wiki/Criteria-for-including-apps-in-the-main-bucket.md`), Extras takes what does not fit Main (`extras/README.md`). Start with a bucket of our own.

**Once.** Create the public repository `klovbin/scoop-bucket` with a folder `bucket/`.

**`bucket/sshr.json`:**

```json
{
    "version": "0.1.0",
    "description": "SSH host manager with an encrypted vault, device sync and an MCP server",
    "homepage": "https://github.com/klovbin/sshr",
    "license": "AGPL-3.0-only",
    "architecture": {
        "64bit": {
            "url": "https://github.com/klovbin/sshr/releases/download/v0.1.0/sshr_windows_amd64.exe#/sshr.exe",
            "hash": "<sha256 from sha256sums.txt>"
        },
        "arm64": {
            "url": "https://github.com/klovbin/sshr/releases/download/v0.1.0/sshr_windows_arm64.exe#/sshr.exe",
            "hash": "<sha256 from sha256sums.txt>"
        }
    },
    "bin": "sshr.exe",
    "checkver": "github",
    "autoupdate": {
        "architecture": {
            "64bit": {
                "url": "https://github.com/klovbin/sshr/releases/download/v$version/sshr_windows_amd64.exe#/sshr.exe"
            },
            "arm64": {
                "url": "https://github.com/klovbin/sshr/releases/download/v$version/sshr_windows_arm64.exe#/sshr.exe"
            }
        },
        "hash": {
            "url": "$baseurl/sha256sums.txt"
        }
    }
}
```

`#/sshr.exe` renames the download, `$baseurl` is the URL without the file name, so the hashes come from `sha256sums.txt` of the same release (`wiki/App-Manifests.md`, `wiki/App-Manifest-Autoupdate.md`). sshr needs `ssh.exe` on PATH, Windows 10 and 11 ship OpenSSH.

**Check and publish** (on Windows):

```powershell
scoop install .\bucket\sshr.json
sshr help
git add bucket/sshr.json; git commit -m 'sshr: Add version 0.1.0'; git push
```

Users run `scoop bucket add sshr https://github.com/klovbin/scoop-bucket` and `scoop install sshr`.

**New tag.** `checkver` and `autoupdate` let the bucket's update script raise the version and the hashes.

## nixpkgs

**Rule.** nixpkgs builds Go programs from source with `buildGoModule`, a pull request to NixOS/nixpkgs adds the package (nixpkgs manual, CONTRIBUTING.md). There is no popularity threshold, the package needs a maintainer listed in `maintainers/maintainer-list.nix`. GoReleaser's nix output only writes a NUR binary package, not a nixpkgs one.

**Once.** A GitHub fork of NixOS/nixpkgs, an entry for yourself in `maintainers/maintainer-list.nix` (its own commit, `maintainers: add <handle>`).

**`pkgs/by-name/ss/sshr/package.nix`:**

```nix
{
  lib,
  buildGoModule,
  fetchFromGitHub,
}:

buildGoModule (finalAttrs: {
  pname = "sshr";
  version = "0.1.0";

  src = fetchFromGitHub {
    owner = "klovbin";
    repo = "sshr";
    tag = "v${finalAttrs.version}";
    hash = lib.fakeHash;
  };

  vendorHash = lib.fakeHash;

  subPackages = [ "cmd/sshr" ];
  tags = [ "nocgo" ];
  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
    "-X sshr.dev/internal/app.Version=v${finalAttrs.version}"
  ];

  meta = {
    description = "SSH host manager with an encrypted vault, device sync and an MCP server";
    homepage = "https://github.com/klovbin/sshr";
    license = lib.licenses.mit;
    mainProgram = "sshr";
    maintainers = with lib.maintainers; [ ];
  };
})
```

Build once with `lib.fakeHash`, nix prints the real `hash`, put it in, build again for `vendorHash`. `go.mod` asks for Go 1.27, if the default Go of nixpkgs is older the build stops and the package needs the matching `buildGo1XXModule`. If a test needs something the build sandbox does not have, skip only that test with `checkFlags = [ "-skip=^TestName$" ];`, not the whole suite.

**Check and submit:**

```sh
nix-build -A sshr
./result/bin/sshr help
nix-shell -p nixpkgs-review --run 'nixpkgs-review wip'
git commit -m 'sshr: init at 0.1.0'
```

Open the pull request against `master` and fill in its checklist.

**New tag.** A pull request `sshr: 0.1.0 -> 0.2.0` with the new `version`, `hash` and `vendorHash`.

## Not now

- winget: one version per pull request, reviews take 2 to 5.5 weeks, worth it once there is a Windows installer
- Flathub: sshr calls the host's `ssh` and reads the keychain, 1Password and Bitwarden, the Flatpak sandbox blocks all of that and Flathub says terminal and developer tools fit poorly
- a Homebrew cask: needs a signed and notarized macOS binary
