<!--
SPDX-FileCopyrightText: 2026 Coding Duck
SPDX-License-Identifier: LGPL-2.1-or-later
-->

# Security policy

dss-native decides whether electronic signatures are valid and which certificates are trusted, so a defect can
make a forged or revoked signature pass. Please report anything that could do that, or that lets input crash or
take over the process, privately first.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on
<https://github.com/codingducksrl/dss-rust/security/advisories/new>. Do not open a public issue, pull request or
discussion for it.

Please include:
- the version (`dss-cli version`, or `dss_version` / `GET /version`) and platform;
- what you did (a minimal document, `config_json` and `options_json`, or the HTTP request), what happened and what
  you expected;
- whether real signed documents or personal data are involved: do not attach them; describe them, or build a
  synthetic reproduction with the test PKI in `testdata/fixtures/pki/`.

You get an acknowledgement in the advisory thread, and a disclosure date is agreed with you once the cause is
understood. A fix ships as a new release (a pushed version tag, see `CONTRIBUTING.md`); the advisory names the
fixed version and credits you unless you ask otherwise.

## Supported versions

Only the latest release receives security fixes. Until 1.0, a fix may come with contract changes, listed in
`CHANGELOG.md`.

The library embeds the GraalVM CE runtime (JDK class library and CA bundle) and DSS. A security release of either
reaches users only through a new dss-native release; `.github/workflows/security.yml` fails every week while a
newer GraalVM CE release is out, so the project notices (docs/DECISIONS.md, "Dependency monitoring").

## Scope

In scope: the Java engine and the C API (`java/`), the Rust crates (`rust/`, including `dss-server`), the PHP
client (`php/`), the build and release scripts and the Docker image.

Report upstream instead, and tell us if dss-native is affected:
- defects in DSS itself: <https://github.com/esig/dss> (dss-native uses DSS unmodified);
- defects in GraalVM / Substrate VM: <https://github.com/oracle/graal/security/policy>.

Documented design limits, not vulnerabilities (see README.md and docs/DECISIONS.md before reporting):
- a trusted-list snapshot is trusted as given: whoever can write the file chooses the trust anchors; the
  application vouches for it;
- trusted-list downloads do not verify TLS (`http.tl_verify_tls: false`); integrity comes from the lists' XML
  signatures, and rollback to older lists is refused;
- a Java heap exhausted while DSS processes a document can abort the process (docs/native-library.md, "Heap
  size"); bound document sizes and concurrency;
- `dss-server` has no TLS and is meant for the same host or a private network; without `--token-file` it refuses
  browser-originated requests but accepts any other local client.
