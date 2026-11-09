<!--
SPDX-FileCopyrightText: 2026 Coding Duck
SPDX-License-Identifier: LGPL-2.1-or-later
-->

# Contributing

Thank you for helping. dss-native wraps the EU DSS validation engine, so changes are judged first by whether
signatures still validate exactly as plain DSS validates them, and whether the trust decisions stay safe.

Security problems: do not open an issue, follow `SECURITY.md`.

## Before you start

- Read README.md (the contract: C API, `config_json`, `options_json`, results, error codes) and the parts of
  docs/DECISIONS.md that touch your change. A change that goes against a recorded decision needs a reason, and the
  decision text is updated in the same pull request.
- For anything beyond a small fix, open an issue first and describe the behaviour you want.

## Building and testing

Requirements and commands are in README.md, "Building and testing". In short:

```bash
cd java && ./mvnw test                     # JDK 21+; no network
scripts/build-native.sh                    # GraalVM CE (the release java/pom.xml pins) as JAVA_HOME
scripts/smoke-test-c.sh
cd rust && cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings \
  && cargo test --workspace --all-features
python3 scripts/ci/check-repo.py           # SPDX headers, testdata/private, GraalVM pin
```

Rules for tests:
- The default suites use no network: trusted lists, CRLs, OCSP responders and TSAs are synthetic and served in
  memory or on 127.0.0.1. Tests that need the real EU lists are tagged `online` (Java) or `#[ignore]`d (Rust) and
  run only with `-Pintegration` / `scripts/test-rust.sh --online`.
- New behaviour comes with a test that fails without it. Java changes are checked natively too: run
  `cd java && ./mvnw -Pnative test` when you touch reflection, resources, serialization or a new library path,
  and refresh the metadata as docs/reflection-audit.md describes.
- Never commit real signed documents: `testdata/private/` is for local runs only, and `check-repo.py` refuses it.
  Install it as a pre-commit hook: `ln -s ../../scripts/ci/check-repo.py .git/hooks/pre-commit`.

## Changing the contract

The JSON contract is additive: new keys and fields are fine, renaming or removing one is a breaking change. With
a contract change, update in the same pull request:
- README.md (the reference; keep relative links to files that release packages contain: `docs/`, `trust/`,
  `php/`, `docker/`, `LICENSE`, `LICENSING.md`; mention anything else in a code span);
- `docs/openapi.yaml` and docs/server.md when the HTTP sidecar exposes it;
- the Rust mirror (`rust/dss/src/config.rs`, `types.rs`; `rust/dss/tests/config_keys.rs` compares the config keys
  with Java's);
- `CHANGELOG.md`, under "Unreleased".

## Code style

- Java: the existing style (4 spaces, 120 columns), no new runtime dependency without a licence check
  (LICENSING.md) and a reachability-metadata check.
- Rust: `cargo fmt` (`rust/rustfmt.toml`) and clippy with `-D warnings`.
- Every new file starts with `SPDX-FileCopyrightText: 2026 Coding Duck` and `SPDX-License-Identifier:
  LGPL-2.1-or-later`, or is annotated in `REUSE.toml` when it cannot carry a header. Contributions are accepted
  under the project's licence, LGPL-2.1-or-later.

## Commits and pull requests

- One topic per commit, with a message that says what changes and why, in the imperative ("Refuse a negative
  online_cache_expiration_ms"), not the phase or date it belongs to. Reference the issue or audit finding when
  there is one.
- A pull request describes the behaviour change, the tests that cover it and the documentation updated; the
  checks workflow (`.github/workflows/checks.yml`) must pass.

## Releases

Releases are cut only by pushing a version tag on main: `git tag v1.2.0 && git push origin v1.2.0` (README.md, "CI
and packages"). The tag is the version everywhere; the committed files keep `0.0.0-dev`. Before tagging, move the
"Unreleased" entries of `CHANGELOG.md` under the new version and date. The release workflow publishes the
release only when every job passed.
