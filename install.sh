#!/bin/sh
# Install whatsrisky. The same shape as Trivy's and gitleaks' installers, because
# the whole point of the Go rewrite is that this is all it takes.
#
#   curl -sSfL https://raw.githubusercontent.com/smagew/whatsrisky/main/install.sh | sh
#   ... | sh -s -- -b /usr/local/bin -v 0.3.0
#
# Downloads a release archive, verifies its checksum, and puts the binary on PATH.
set -eu

REPO="smagew/whatsrisky"
BIN_DIR="${BIN_DIR:-./bin}"
VERSION="${VERSION:-latest}"

usage() {
	cat <<'USAGE'
Usage: install.sh [-b <dir>] [-v <version>]
  -b  where to put the binary (default ./bin, or $BIN_DIR)
  -v  version to install (default the latest release)
USAGE
	exit 1
}

while getopts "b:v:h" opt; do
	case "$opt" in
	b) BIN_DIR="$OPTARG" ;;
	v) VERSION="$OPTARG" ;;
	*) usage ;;
	esac
done

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "install.sh needs $1" >&2
		exit 1
	}
}
need curl
need tar

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
x86_64 | amd64) arch="amd64" ;;
arm64 | aarch64) arch="arm64" ;;
*)
	echo "unsupported architecture: $arch" >&2
	exit 1
	;;
esac
case "$os" in
darwin | linux) ;;
*)
	echo "unsupported system: $os — on Windows, download the archive from" >&2
	echo "https://github.com/$REPO/releases" >&2
	exit 1
	;;
esac

if [ "$VERSION" = "latest" ]; then
	VERSION=$(curl -sSfL "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)
	[ -n "$VERSION" ] || {
		echo "could not determine the latest version" >&2
		exit 1
	}
fi

name="whatsrisky_${VERSION}_${os}_${arch}"
base="https://github.com/$REPO/releases/download/v${VERSION}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "downloading whatsrisky ${VERSION} for ${os}/${arch}"
curl -sSfL "$base/${name}.tar.gz" -o "$work/${name}.tar.gz"

# A security tool that installs itself unverified is not much of an argument.
if curl -sSfL "$base/checksums.txt" -o "$work/checksums.txt" 2>/dev/null; then
	expected=$(grep " ${name}.tar.gz\$" "$work/checksums.txt" | awk '{print $1}')
	if [ -n "$expected" ]; then
		if command -v sha256sum >/dev/null 2>&1; then
			actual=$(sha256sum "$work/${name}.tar.gz" | awk '{print $1}')
		elif command -v shasum >/dev/null 2>&1; then
			actual=$(shasum -a 256 "$work/${name}.tar.gz" | awk '{print $1}')
		else
			actual=""
			echo "no sha256 tool found; skipping verification" >&2
		fi
		if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then
			echo "checksum mismatch for ${name}.tar.gz" >&2
			echo "  expected $expected" >&2
			echo "  got      $actual" >&2
			exit 1
		fi
		[ -n "$actual" ] && echo "checksum verified"
	fi
else
	echo "no checksums published for this release; skipping verification" >&2
fi

tar -xzf "$work/${name}.tar.gz" -C "$work"
mkdir -p "$BIN_DIR"
install -m 0755 "$work/whatsrisky" "$BIN_DIR/whatsrisky"

echo "installed $("$BIN_DIR/whatsrisky" --version) to $BIN_DIR/whatsrisky"
case ":$PATH:" in
*":$BIN_DIR:"*) ;;
*) echo "add $BIN_DIR to your PATH, or move the binary somewhere already on it" ;;
esac

echo
echo "The scanners it orchestrates are separate binaries. Check what you have:"
echo "  $BIN_DIR/whatsrisky doctor"
