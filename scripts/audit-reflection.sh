#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Lists reflection/resource/provider call sites in the sources of every runtime dependency.
# Output: one line per call site, "<artifact>\t<pattern>\t<file>:<line>\t<code>", to stdout.
# Input for docs/reflection-audit.md; the classification there is done by reading each site.
#
#   scripts/audit-reflection.sh [work_dir] > audit.tsv
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="${1:-$root/java/target/reflection-audit}"
mkdir -p "$work/jars" "$work/src"
(cd "$root/java" && ./mvnw -q -B dependency:copy-dependencies -Dclassifier=sources -DincludeScope=runtime \
  -DoutputDirectory="$work/jars" -Dmdep.failOnMissingClassifierArtifact=false >&2)
patterns='Class\.forName|\.getDeclared(Field|Method|Constructor)s?\(|\.getField\(|\.getMethod\(|\.getConstructor\(|\.newInstance\(|ServiceLoader\.load|\.getResource(AsStream)?\(|getSystemResource|ResourceBundle\.getBundle|Proxy\.newProxyInstance|JAXBContext\.newInstance|Security\.(addProvider|insertProviderAt)|MethodHandles\.lookup|\.loadClass\('
for jar in "$work"/jars/*-sources.jar; do
  name="$(basename "$jar" -sources.jar)"
  dir="$work/src/$name"
  [[ -d "$dir" ]] || { mkdir -p "$dir"; (cd "$dir" && unzip -qo "$jar" '*.java' 2>/dev/null || true); }
  grep -rnE "$patterns" --include='*.java' "$dir" 2>/dev/null \
    | grep -vE '^\S+:[0-9]+:\s*(\*|//)' \
    | while IFS= read -r hit; do
        file="${hit%%:*}"; rest="${hit#*:}"; line="${rest%%:*}"; code="${rest#*:}"
        pat="$(grep -oE "$patterns" <<<"$code" | head -1)"
        printf '%s\t%s\t%s:%s\t%s\n' "$name" "$pat" "${file#$dir/}" "$line" "$(sed -E 's/^\s+//' <<<"$code" | cut -c1-200)"
      done || true
done
