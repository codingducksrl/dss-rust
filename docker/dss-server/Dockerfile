# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# dss-server from a release package (docs/server.md, "Docker"). The build context is a folder holding
# dss-native-<VERSION>-linux-<x64|aarch64>.tar.gz and its .sha256: dist/ after scripts/package.sh, or the GitHub
# release's assets. Needs BuildKit (Docker 23+ uses it by default): TARGETARCH and RUN --mount.
#
#   docker build -f docker/dss-server/Dockerfile --build-arg VERSION=1.2.0 -t dss-server:1.2.0 dist/
#
# The package is checked against its .sha256 and read through a bind mount, so the tarball is never copied into
# an image layer. CI builds the image and waits for its health check before a release is published.
#
# The library needs glibc 2.34+ and zlib (docs/native-library.md), so the base is Debian, not Alpine. The base is
# pinned by digest (debian:trixie-slim; Dependabot proposes updates).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ARG VERSION
ARG TARGETARCH
# The package keeps its licences in /opt/dss-native (LICENSE, LICENSING.md, licenses/); the Debian base keeps its
# own in /usr/share/doc/*/copyright.
LABEL org.opencontainers.image.title="dss-server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/codingducksrl/dss-rust" \
      org.opencontainers.image.licenses="LGPL-2.1-or-later" \
      org.opencontainers.image.vendor="Coding Duck"
# A fixed, numeric user (10001:10001): the cache volume keeps its owner across image rebuilds, and Kubernetes'
# runAsNonRoot can verify it.
RUN --mount=type=bind,target=/ctx,readonly \
    set -eu; \
    [ -n "${VERSION}" ] || { echo "--build-arg VERSION=<version> is required" >&2; exit 1; }; \
    case "${TARGETARCH}" in amd64) arch=x64 ;; arm64) arch=aarch64 ;; *) echo "no package for ${TARGETARCH}" >&2; exit 1 ;; esac; \
    pkg="dss-native-${VERSION}-linux-${arch}.tar.gz"; \
    [ -f "/ctx/${pkg}.sha256" ] || { echo "${pkg}.sha256 is missing from the build context" >&2; exit 1; }; \
    (cd /ctx && sha256sum -c "${pkg}.sha256"); \
    mkdir -p /opt/dss-native; \
    tar -xzf "/ctx/${pkg}" -C /opt/dss-native --strip-components=1 --no-same-owner; \
    groupadd --system --gid 10001 dss; \
    useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/dss --create-home --shell /usr/sbin/nologin dss; \
    mkdir /var/lib/dss/cache; \
    chown 10001:10001 /var/lib/dss/cache

# Every option is an environment variable: dss-server --help. The OJ keystore comes from the package.
# Change the address with DSS_LISTEN, not with a --listen argument: the HEALTHCHECK runs a separate
# `dss-server --health-check`, which sees the environment but not the server's arguments, so after
# `--listen 0.0.0.0:9000` it would keep probing 8484 and the container would never turn healthy.
ENV DSS_LISTEN=0.0.0.0:8484 \
    DSS_CACHE_DIR=/var/lib/dss/cache
# The trusted-list cache: kept across restarts, the engine starts from it offline in seconds.
VOLUME /var/lib/dss/cache
USER 10001:10001
EXPOSE 8484
# Healthy once the engine is up and the trusted lists are loaded (unless DSS_ALLOW_WITHOUT_TRUSTED_LISTS is set):
# from the cache volume in seconds; with an empty cache only after the first online refresh of the EU lists, which
# can take minutes. Failed probes during the start period do not count, and a passing one marks the container
# healthy at once, so the long start period delays nothing.
HEALTHCHECK --interval=10s --timeout=5s --start-period=300s CMD ["/opt/dss-native/bin/dss-server", "--health-check"]
ENTRYPOINT ["/opt/dss-native/bin/dss-server"]
