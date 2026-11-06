# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# dss-server from a release package (docs/server.md, "Docker"). The build context is a folder holding
# dss-native-<VERSION>-linux-<x64|aarch64>.tar.gz: dist/ after scripts/package.sh, or the GitHub release's assets.
#
#   docker build -f docker/dss-server/Dockerfile --build-arg VERSION=1.2.0 -t dss-server:1.2.0 dist/
#
# The library needs glibc 2.34+ and zlib (docs/native-library.md), so the base is Debian, not Alpine.
FROM debian:trixie-slim

ARG VERSION
ARG TARGETARCH
# The package keeps its licences in /opt/dss-native (LICENSE, LICENSING.md, licenses/); the Debian base keeps its
# own in /usr/share/doc/*/copyright.
LABEL org.opencontainers.image.title="dss-server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/codingduck/dss-native" \
      org.opencontainers.image.licenses="LGPL-2.1-or-later" \
      org.opencontainers.image.vendor="Coding Duck"
COPY dss-native-${VERSION}-linux-*.tar.gz /tmp/
RUN set -eu; \
    case "${TARGETARCH}" in amd64) arch=x64 ;; arm64) arch=aarch64 ;; *) echo "no package for ${TARGETARCH}" >&2; exit 1 ;; esac; \
    mkdir -p /opt/dss-native; \
    tar -xzf "/tmp/dss-native-${VERSION}-linux-${arch}.tar.gz" -C /opt/dss-native --strip-components=1 --no-same-owner; \
    rm /tmp/dss-native-*.tar.gz; \
    useradd --system --home-dir /var/lib/dss --create-home dss; \
    mkdir /var/lib/dss/cache; \
    chown dss: /var/lib/dss/cache

# Every option is an environment variable: dss-server --help. The OJ keystore comes from the package.
ENV DSS_LISTEN=0.0.0.0:8484 \
    DSS_CACHE_DIR=/var/lib/dss/cache
# The trusted-list cache: kept across restarts, the engine starts from it offline in seconds.
VOLUME /var/lib/dss/cache
USER dss
EXPOSE 8484
# Healthy once the engine is up; with an empty cache, loading the EU trusted lists online takes a while longer.
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s CMD ["/opt/dss-native/bin/dss-server", "--health-check"]
ENTRYPOINT ["/opt/dss-native/bin/dss-server"]
