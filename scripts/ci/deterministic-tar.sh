#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Writes <parent>/<name> as a reproducible .tar.gz: entries sorted by name, owner and group 0 with no names,
# permissions normalised (u+rw, go-w, others as the owner can read/execute), every mtime SOURCE_DATE_EPOCH
# (default 0), gzip without name or timestamp. The same files give the same bytes on the same tar (GNU tar on
# Linux, bsdtar on macOS).
#
#   SOURCE_DATE_EPOCH=<seconds> scripts/ci/deterministic-tar.sh <parent> <name> <out.tar.gz>
#
# It changes the mtimes and permissions of the files it packs.
set -euo pipefail
parent="${1:?usage: deterministic-tar.sh <parent> <name> <out.tar.gz>}"
name="${2:?usage: deterministic-tar.sh <parent> <name> <out.tar.gz>}"
out="${3:?usage: deterministic-tar.sh <parent> <name> <out.tar.gz>}"
epoch="${SOURCE_DATE_EPOCH:-0}"
[[ "$epoch" =~ ^[0-9]+$ ]] || { echo "SOURCE_DATE_EPOCH must be a number of seconds: $epoch" >&2; exit 1; }
[[ -d "$parent/$name" ]] || { echo "no directory $parent/$name" >&2; exit 1; }
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac

if stamp="$(date -u -d "@$epoch" +%Y%m%d%H%M.%S 2>/dev/null)"; then :; else stamp="$(date -u -r "$epoch" +%Y%m%d%H%M.%S)"; fi
list="$(mktemp)"
trap 'rm -f "$list"' EXIT
cd "$parent"
chmod -R u+rw,go-w,go+rX "$name"
find "$name" -exec env TZ=UTC touch -h -t "$stamp" {} +
find "$name" -print | LC_ALL=C sort > "$list"
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  tar --format=gnu --no-recursion --numeric-owner --owner=0 --group=0 -cf - -T "$list" | gzip -n -9 > "$out"
else
  # bsdtar (macOS): no extended attributes or AppleDouble ._ entries either.
  COPYFILE_DISABLE=1 tar --format gnutar --no-mac-metadata --no-xattrs --no-acls -n --numeric-owner --uid 0 --gid 0 \
    -cf - -T "$list" | gzip -n -9 > "$out"
fi
