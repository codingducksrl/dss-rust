#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Copies the documentation a package ships into <out_dir>, in the repository's layout, so that README.md's and
# docs/'s relative links keep working there: README.md, LICENSE, LICENSING.md, docs/*.md, docs/openapi.yaml,
# trust/README.md, php/ (without vendor/ and dot files) and docker/dss-server/Dockerfile.
#
#   scripts/ci/copy-package-docs.sh <out_dir>
#
# Used by scripts/package.sh, and by scripts/ci/test-scripts.sh, which runs check-md-links.py on the result on
# every push and pull request, so a link that would break in the package fails there rather than at release time.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
[[ $# -eq 1 ]] || { echo "usage: $0 <out_dir>" >&2; exit 64; }
out="$1"
mkdir -p "$out/docs" "$out/trust" "$out/docker/dss-server"
cp "$root/LICENSE" "$root/LICENSING.md" "$root/README.md" "$out/"
cp "$root/docs/"*.md "$root/docs/openapi.yaml" "$out/docs/"
cp "$root/trust/README.md" "$out/trust/"
cp "$root/docker/dss-server/Dockerfile" "$out/docker/dss-server/"
(cd "$root" && find php -type f ! -path '*/vendor/*' ! -name '.*' -print) | while IFS= read -r f; do
  mkdir -p "$out/$(dirname "$f")" && cp "$root/$f" "$out/$f"
done
