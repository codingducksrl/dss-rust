#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Builds the dss-server image from a Linux package and checks it, offline:
#
#   scripts/ci/docker-smoke.sh <context_dir> <version>
#
# <context_dir> holds dss-native-<version>-linux-<arch>.tar.gz and its .sha256 for the Docker host's
# architecture. The script
# 1. builds docker/dss-server/Dockerfile (which verifies the checksum);
# 2. starts the server without network and without trusted lists, and waits for the image's own HEALTHCHECK to
#    report healthy (at most 120 s);
# 3. checks it runs as UID 10001;
# 4. runs scripts/ci/package-smoke.sh inside the image against /opt/dss-native and the committed fixtures.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
ctx="${1:?usage: docker-smoke.sh <context_dir> <version>}"
version="${2:?usage: docker-smoke.sh <context_dir> <version>}"
image="dss-server-smoke:$version"
name="dss-server-smoke-$$"
docker build -f "$root/docker/dss-server/Dockerfile" --build-arg "VERSION=$version" -t "$image" "$ctx"
trap 'docker logs "$name" 2>&1 | tail -20 || true; docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" --network none \
  -e DSS_REFRESH_HOURS=0 -e DSS_ALLOW_WITHOUT_TRUSTED_LISTS=true "$image" >/dev/null
status=starting
for _ in $(seq 1 60); do
  status="$(docker inspect --format '{{.State.Health.Status}}' "$name")"
  [[ "$status" == healthy || "$status" == unhealthy ]] && break
  [[ "$(docker inspect --format '{{.State.Running}}' "$name")" == true ]] || break
  sleep 2
done
[[ "$status" == healthy ]] || { echo "the container is $status, not healthy" >&2; exit 1; }
echo "container healthy"
uid="$(docker exec "$name" id -u)"
[[ "$uid" == 10001 ]] || { echo "the server runs as UID $uid, expected 10001" >&2; exit 1; }
docker run --rm --network none --entrypoint bash \
  -v "$root/scripts/ci:/ci:ro" -v "$root/testdata/fixtures:/fixtures:ro" \
  "$image" /ci/package-smoke.sh /opt/dss-native /fixtures "$version"
echo "image OK"
