#!/usr/bin/env bash
# Installs the pinned toolchain for scanner on Ubuntu 24.04 (native or WSL2).
# Needs root for apt and setcap. Idempotent; records exact versions in
# ~/.scanner/BUILD_INFO, which the preflight reads.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # resolve before any cd

GO_VERSION=1.25.8   # ZDNS v2.1.1 needs Go 1.25; pinned so no other toolchain is downloaded silently
ZMAP_COMMIT=651ed713759a12e283c449259b2f6fa027ccf9b5   # v4.4.0
ZMAP_PREFIX=/opt/scanner/zmap-4.4.0
ZGRAB2_COMMIT=ea734bcf60ef2921684cb522dfb87a07a322afa6   # v1.0.0
ZDNS_TAG=v2.1.1

if [ "$(id -u)" -ne 0 ]; then echo "run as root: sudo $0" >&2; exit 2; fi
[ "$(uname -m)" = "x86_64" ] || { echo "amd64 (x86_64) only: the Go toolchain download below is linux-amd64" >&2; exit 3; }
TARGET_USER=${SUDO_USER:-root}
[ "$TARGET_USER" != "root" ] || echo "WARNING: no SUDO_USER, so the venv and BUILD_INFO go to root's home. Run this as 'sudo $0' from the account that will run the scan." >&2
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git build-essential curl ca-certificates \
  python3 python3-pip python3-venv libcap2-bin iproute2 iputils-ping \
  cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev libjudy-dev
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || { echo "Python 3.11 or newer is required (Ubuntu 24.04, Debian 13 or newer); found $(python3 --version)" >&2; exit 3; }

# Install alongside any system ZMap. RESPECT_INSTALL_PREFIX_CONFIG also prevents
# CMake's configure step from rewriting /etc/zmap/zmap.conf used by old versions.
mkdir -p /opt/src
[ -d /opt/src/scanner-zmap-4.4.0 ] || git clone -q https://github.com/zmap/zmap.git /opt/src/scanner-zmap-4.4.0
git -C /opt/src/scanner-zmap-4.4.0 fetch -q origin "$ZMAP_COMMIT"
git -C /opt/src/scanner-zmap-4.4.0 checkout -q "$ZMAP_COMMIT"
cmake -S /opt/src/scanner-zmap-4.4.0 -B /opt/src/scanner-zmap-4.4.0/build \
  -DCMAKE_INSTALL_PREFIX="$ZMAP_PREFIX" -DRESPECT_INSTALL_PREFIX_CONFIG=ON \
  -DENABLE_DEVELOPMENT=OFF -DENABLE_LOG_TRACE=OFF
cmake --build /opt/src/scanner-zmap-4.4.0/build -j 4
cmake --install /opt/src/scanner-zmap-4.4.0/build
ZMAP_BIN="$ZMAP_PREFIX/sbin/zmap"
"$ZMAP_BIN" -C /dev/null --version | grep -Eq '^zmap v?4\.4\.0$'

GO_ROOT="/opt/scanner/go-$GO_VERSION"
if ! "$GO_ROOT/go/bin/go" version 2>/dev/null | grep -q "go${GO_VERSION} "; then
  mkdir -p "$GO_ROOT"
  GO_ARCHIVE=$(mktemp /tmp/scanner-go.XXXXXX.tar.gz)
  curl --fail -sSL -o "$GO_ARCHIVE" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  tar -C "$GO_ROOT" -xzf "$GO_ARCHIVE"
  rm -f "$GO_ARCHIVE"
fi
export PATH="$GO_ROOT/go/bin:$PATH" GOPATH=/opt/gopath GOFLAGS=-buildvcs=false GOTOOLCHAIN=local

mkdir -p /opt/src && cd /opt/src
[ -d zgrab2 ] || git clone -q https://github.com/zmap/zgrab2.git
(cd zgrab2 && git fetch -q --all && git checkout -q "$ZGRAB2_COMMIT" && make -s && cp -f cmd/zgrab2/zgrab2 /usr/local/bin/zgrab2)
[ -d zdns ] || git clone -q https://github.com/zmap/zdns.git
(cd zdns && git fetch -q --all --tags && git checkout -q "$ZDNS_TAG" && make -s && cp -f zdns /usr/local/bin/zdns)

# Raw-socket capability on zmap so the pipeline itself never has to run as root.
setcap cap_net_raw,cap_net_admin+ep "$ZMAP_BIN"

VENV="$TARGET_HOME/scanner-venv"
sudo -u "$TARGET_USER" python3 -m venv "$VENV"
sudo -u "$TARGET_USER" "$VENV/bin/pip" -q install -r "$REPO_ROOT/scanner/requirements.lock" "pytest==9.1.1"

mkdir -p "$TARGET_HOME/.scanner"
{
  echo "zmap: $("$ZMAP_BIN" -C /dev/null --version 2>&1 | grep -E '^zmap v?[0-9]' | head -1) ($ZMAP_COMMIT)"
  echo "zmap_sha256: $(sha256sum "$ZMAP_BIN" | cut -d ' ' -f1)"
  echo "zgrab2_commit: $ZGRAB2_COMMIT"
  echo "zdns: $(zdns --version 2>&1 | head -1) ($(cd /opt/src/zdns && git rev-parse HEAD))"
  echo "go: $(go version)"
  echo "python: $("$VENV/bin/python" --version)"
  echo "installed_at: $(date -u +%FT%TZ)"
} > "$TARGET_HOME/.scanner/BUILD_INFO"
chown -R "$TARGET_USER" "$TARGET_HOME/.scanner"
cat "$TARGET_HOME/.scanner/BUILD_INFO"
echo "OK: python venv at $VENV ; run scripts with: $VENV/bin/python -m scanner.internet ..."
