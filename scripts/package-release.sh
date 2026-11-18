#!/usr/bin/env bash
# Builds plugin-store release archives into dist/: key-access_<version>_<goos>_<goarch>.zip and checksums.txt.
# Linux targets are built in manylinux2014 containers (needs Docker), so the library needs only GLIBC 2.17
# and loads on the official CPA Linux images. darwin targets build natively on macOS.
#
# Usage: scripts/package-release.sh <version> [target ...]
#   targets: linux/amd64 linux/arm64 darwin/arm64 darwin/amd64 (default: both Linux targets)
# Environment: GOPROXY (passed to builds), GO_VERSION (default: from go.mod).
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION="${1:?usage: scripts/package-release.sh <version> [target ...]}"
VERSION="${VERSION#v}"
shift
if ! [[ "$VERSION" =~ ^[0-9]+([.][0-9]+)*$ ]]; then
  echo "version must be dotted numeric such as 0.1.0, got: $VERSION" >&2
  exit 1
fi
TARGETS=("$@")
[ ${#TARGETS[@]} -gt 0 ] || TARGETS=(linux/amd64 linux/arm64)
GO_VERSION="${GO_VERSION:-$(sed -n 's/^go //p' go.mod)}"
GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
LDFLAGS="-s -w -X main.pluginVersion=${VERSION}"
DIST=dist

build_linux() {
  local arch="$1" image
  case "$arch" in
    amd64) image=quay.io/pypa/manylinux2014_x86_64 ;;
    arm64) image=quay.io/pypa/manylinux2014_aarch64 ;;
    *) echo "unsupported linux arch $arch" >&2; exit 1 ;;
  esac
  local args=(--rm --platform "linux/${arch}" -v "$PWD:/src" -w /src
    -e "GO_VERSION=$GO_VERSION" -e "GOPROXY=$GOPROXY" -e "LDFLAGS=$LDFLAGS" -e "GOARCH_TARGET=$arch"
    -e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)")
  docker run "${args[@]}" "$image" bash -euo pipefail -c '
    git config --global --add safe.directory /src
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH_TARGET}.tar.gz" -o /tmp/go.tgz
    tar -C /usr/local -xzf /tmp/go.tgz
    export PATH="/usr/local/go/bin:$PATH" GOFLAGS=-mod=readonly GOTOOLCHAIN=local
    out="dist/build/linux_${GOARCH_TARGET}"
    mkdir -p "$out"
    CGO_ENABLED=1 go build -trimpath -buildmode=c-shared -ldflags="$LDFLAGS" -o "$out/key-access.so" .
    rm -f "$out/key-access.h"
    max_glibc="$(readelf --version-info "$out/key-access.so" | grep -o "GLIBC_[0-9.]*" | sed "s/GLIBC_//" | sort -V | tail -n 1)"
    if [ -n "$max_glibc" ] && [ "$(printf "2.17\n%s\n" "$max_glibc" | sort -V | tail -n 1)" != "2.17" ]; then
      echo "key-access.so requires GLIBC_${max_glibc}, expected 2.17 or older" >&2
      exit 1
    fi
    bash scripts/verify-abi.sh "$out/key-access.so"
    chown -R "$HOST_UID:$HOST_GID" dist
  '
}

build_darwin() {
  local arch="$1"
  local out="dist/build/darwin_${arch}"
  local cc=(clang)
  mkdir -p "$out"
  [ "$arch" = "$(go env GOHOSTARCH)" ] || cc=(clang -arch "$([ "$arch" = amd64 ] && echo x86_64 || echo arm64)")
  CC="${cc[*]}" CGO_ENABLED=1 GOOS=darwin GOARCH="$arch" GOFLAGS=-mod=readonly go build -trimpath -buildmode=c-shared -ldflags="$LDFLAGS" -o "$out/key-access.dylib" .
  rm -f "$out/key-access.h"
  # A library built for the other architecture cannot be loaded here, so only verify native builds.
  if [ "$arch" = "$(go env GOHOSTARCH)" ]; then
    bash scripts/verify-abi.sh "$out/key-access.dylib"
  fi
}

rm -rf "$DIST/build"
mkdir -p "$DIST"
SUMS=()
for target in "${TARGETS[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  echo "==> ${goos}/${goarch}"
  case "$goos" in
    linux) build_linux "$goarch"; lib="$DIST/build/linux_${goarch}/key-access.so" ;;
    darwin) build_darwin "$goarch"; lib="$DIST/build/darwin_${goarch}/key-access.dylib" ;;
    *) echo "unsupported target $target" >&2; exit 1 ;;
  esac
  go run ./scripts/packager -lib "$lib" -version "$VERSION" -goos "$goos" -goarch "$goarch" -out "$DIST"
  SUMS+=("$DIST/key-access_${VERSION}_${goos}_${goarch}.zip.sha256")
done
cat "${SUMS[@]}" | sort -k2 > "$DIST/checksums.txt"
echo "==> $DIST/"
ls -l "$DIST"/*.zip
cat "$DIST/checksums.txt"
