#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Gate on the health of every trusted list in a `dss-cli tl status --json` document.

  scripts/ci/check-tl-status.py <status.json> [--max-problems N]

The same rule as the JVM seeder (java/.../engine/CacheSeeder.java): a LOTL or national list has a problem when its
download failed, its signature is not TOTAL_PASSED, it is expired, or it is not used as a trust source. Exit
status 0 when there are at most N problems (default 0) and the lists are loaded, 1 otherwise. Alerts are printed
as warnings (GitHub annotations in CI) without failing.

CI runs it on the seed trusted-list cache before a release is published: `dss-cli tl refresh` itself succeeds as
soon as one certificate is loaded, so a release could otherwise ship a seed cache with missing or bad countries.
"""
import argparse
import json
import os
import sys


def problems(status):
    for key in ("lotls", "tls"):
        for tl in status.get(key) or []:
            reasons = []
            download = tl.get("download") or {}
            validation = tl.get("validation") or {}
            if download.get("error"):
                reasons.append(f"download failed: {download['error']}")
            if validation.get("indication") != "TOTAL_PASSED":
                sub = validation.get("sub_indication")
                reasons.append(f"signature {validation.get('indication')}" + (f"/{sub}" if sub else ""))
            if tl.get("expired"):
                reasons.append(f"expired (next update {tl.get('next_update')})")
            if tl.get("used_for_trust") is False:
                reasons.append("not used for trust")
            if reasons:
                yield f"{tl.get('territory') or key} {tl.get('url')}: " + "; ".join(reasons)


def annotate(level, message):
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{message}")
    else:
        print(f"{level}: {message}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("status")
    parser.add_argument("--max-problems", type=int, default=0)
    args = parser.parse_args()
    with open(args.status, encoding="utf-8") as f:
        status = json.load(f)
    for alert in status.get("alerts") or []:
        annotate("warning", f"trusted-list alert {alert.get('type')}: {alert.get('message')} ({alert.get('url')})")
    found = list(problems(status))
    for p in found:
        annotate("error", p)
    lists = len(status.get("tls") or [])
    print(f"{lists} national lists, {status.get('trusted_certificates')} trusted certificates, "
          f"{len(found)} lists with problems (at most {args.max_problems} allowed)")
    if not status.get("loaded") or lists == 0:
        annotate("error", "no trusted list is loaded")
        sys.exit(1)
    if len(found) > args.max_problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
