# scanner image. Build from the root of the extracted release package:
#   docker build -f run/Dockerfile -t scanner:1 .
# Every tool is pinned; nothing is fetched when the container runs.
# Run it with host networking (see run/scanner): ZMap sends raw packets and must see the host's NIC.

# ZDNS v2.1.1 needs Go 1.25. The toolchain is pinned here and never downloaded at build time.
ARG GO_IMAGE=golang:1.25.8-bookworm
ARG BASE_IMAGE=ubuntu:24.04

# ---- ZGrab2 and ZDNS ----------------------------------------------------------------------
FROM ${GO_IMAGE} AS gotools
ARG ZGRAB2_COMMIT=ea734bcf60ef2921684cb522dfb87a07a322afa6
ARG ZDNS_TAG=v2.1.1
ENV GOFLAGS=-buildvcs=false GOTOOLCHAIN=local
RUN git clone -q https://github.com/zmap/zgrab2.git /src/zgrab2 \
 && git -C /src/zgrab2 checkout -q "$ZGRAB2_COMMIT" \
 && make -C /src/zgrab2 -s \
 && git clone -q https://github.com/zmap/zdns.git /src/zdns \
 && git -C /src/zdns checkout -q "$ZDNS_TAG" \
 && make -C /src/zdns -s \
 && install -m 0755 /src/zgrab2/cmd/zgrab2/zgrab2 /out-zgrab2 \
 && install -m 0755 /src/zdns/zdns /out-zdns \
 && git -C /src/zgrab2 rev-parse HEAD > /out-zgrab2.commit \
 && git -C /src/zdns rev-parse HEAD > /out-zdns.commit \
 && go version > /out-go.version

# ---- ZMap ---------------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS zmap
ARG ZMAP_COMMIT=651ed713759a12e283c449259b2f6fa027ccf9b5
ARG ZMAP_PREFIX=/opt/scanner/zmap-4.4.0
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      git build-essential ca-certificates cmake libgmp3-dev gengetopt libpcap-dev flex byacc \
      libjson-c-dev pkg-config libunistring-dev libjudy-dev \
 && git clone -q https://github.com/zmap/zmap.git /src/zmap \
 && git -C /src/zmap checkout -q "$ZMAP_COMMIT" \
 && cmake -S /src/zmap -B /src/zmap/build -DCMAKE_INSTALL_PREFIX="$ZMAP_PREFIX" \
      -DRESPECT_INSTALL_PREFIX_CONFIG=ON -DENABLE_DEVELOPMENT=OFF -DENABLE_LOG_TRACE=OFF \
 && cmake --build /src/zmap/build -j 4 \
 && cmake --install /src/zmap/build \
 && "$ZMAP_PREFIX/sbin/zmap" -C /dev/null --version | grep -Eq '^zmap v?4\.4\.0$'

# ---- runtime ------------------------------------------------------------------------------
FROM ${BASE_IMAGE}
ARG ZMAP_COMMIT=651ed713759a12e283c449259b2f6fa027ccf9b5
ARG ZMAP_PREFIX=/opt/scanner/zmap-4.4.0
ARG PACKAGE_VERSION=unversioned
LABEL org.opencontainers.image.title="scanner hostname-resolution scanner" \
      org.opencontainers.image.version="${PACKAGE_VERSION}"
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      python3 python3-venv python3-pip ca-certificates libcap2-bin iproute2 iputils-ping \
      libpcap0.8t64 libgmp10 libjson-c5 libunistring5 libjudydebian1 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --home-dir /home/scanner scanner

COPY --from=zmap ${ZMAP_PREFIX} ${ZMAP_PREFIX}
COPY --from=gotools /out-zgrab2 /usr/local/bin/zgrab2
COPY --from=gotools /out-zdns /usr/local/bin/zdns
COPY --from=gotools /out-zgrab2.commit /out-zdns.commit /out-go.version /tmp/

# Raw-socket capability on the ZMap binary only, so the pipeline itself never runs as root.
RUN setcap cap_net_raw+ep "${ZMAP_PREFIX}/sbin/zmap"

# Exact Python pins (tested on this base image) plus the test runner for `verify`.
COPY scanner/requirements.lock /tmp/requirements.lock
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install -q --no-cache-dir -r /tmp/requirements.lock "pytest==9.1.1" \
 && rm -f /tmp/requirements.lock

COPY . /opt/app
RUN { \
      echo "zmap: $(${ZMAP_PREFIX}/sbin/zmap -C /dev/null --version 2>&1 | grep -E '^zmap v?[0-9]' | head -1) (${ZMAP_COMMIT})"; \
      echo "zmap_sha256: $(sha256sum ${ZMAP_PREFIX}/sbin/zmap | cut -d ' ' -f1)"; \
      echo "zgrab2_commit: $(cat /tmp/out-zgrab2.commit)"; \
      echo "zdns: $(zdns --version 2>&1 | head -1) ($(cat /tmp/out-zdns.commit))"; \
      echo "go: $(cat /tmp/out-go.version)"; \
      echo "python: $(/opt/venv/bin/python --version)"; \
      echo "image_package_version: ${PACKAGE_VERSION}"; \
      echo "installed_at: $(date -u +%FT%TZ)"; \
    } > /opt/scanner/BUILD_INFO \
 && rm -f /tmp/out-zgrab2.commit /tmp/out-zdns.commit /tmp/out-go.version\
 && chmod -R a+rX /opt/app /opt/scanner /opt/venv

ENV SCANNER_BUILD_INFO=/opt/scanner/BUILD_INFO \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/app \
    HOME=/home/scanner \
    PATH=/opt/venv/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER scanner
WORKDIR /work
ENTRYPOINT ["python", "-m", "scanner.internet"]
