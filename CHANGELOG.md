<!--
SPDX-FileCopyrightText: 2026 Coding Duck
SPDX-License-Identifier: LGPL-2.1-or-later
-->

# Changelog

Changes that integrators see: the C API and its JSON contract (README.md), the Rust crates, `dss-cli`,
`dss-server`'s HTTP API and the release packages. The reasons are in docs/DECISIONS.md. No version has been
released yet; the first tag will move "Unreleased" under its version.

## Unreleased

### Security

- Trusted-list refreshes are fail-safe: downloads are pre-checked and staged, only usable lists reach
  `<cache_dir>/tl` (written atomically), and a refresh whose result is unusable is not published (the previous
  lists stay in use). A forged or garbled response can no longer empty the trust pool or overwrite the cache.
- Rollback protection: a list older than the one published for its URL is refused (`tl_rollback` alert,
  `<cache_dir>/tl-sequence-numbers.json`).
- Every outbound request (trusted lists, CRL, OCSP, AIA, TSA) runs behind one policy: scheme allow-list,
  private-address blocking, response size cap, per-request deadline, redirects checked hop by hop.
- Timestamp tokens are verified before they are embedded (imprint, nonce, TSA certificate, EKU, algorithm
  strength, clock skew and, by default, a chain to the trust anchors).
- The external CMS of `dss_sign_complete` (`"cms"` mode) is checked completely: signing-certificate reference,
  signature algorithm, one value per attribute, no unsigned attribute but one verified signature timestamp.
  Signing certificates are checked for suitability (no CA, key usage, extended key usage), not only for dates.
- Visible signatures bound caller-supplied images, fonts and text, so a small input can no longer exhaust the
  heap.
- `dss-cli` and `dss-server` no longer take the OJ keystore or the cache from the current directory; both log or
  print the keystore in use.
- `http.block_private_addresses` defaults to `true`: a TSA, LOTL/TL mirror or CRL/OCSP/AIA server on a loopback or
  private address is refused unless the configuration sets it to `false` (air-gapped deployments, test setups).
- `dss-server` refuses browser-originated requests when it has no token, requires tokens of at least 16 bytes,
  bounds header reads, connections, requests in flight and request time.
- C strings are decoded strictly (malformed UTF-8 is `INVALID_ARGUMENT`), and a call with another thread's
  `graal_isolatethread_t*` stops the process instead of corrupting it.
- The library is built with GraalVM CE 25.5.5.0.3 (JDK 25.0.5 security fixes, updated CA bundle).

### Added

- Error code `TSA_FAILED` (Rust `ErrorCode::TsaFailed`, HTTP 502): the TSA could not be reached or returned a
  token the engine refuses. `TL_REFRESH_FAILED` is now raised when an online refresh published nothing.
- `config_json`: `limits` (`max_pdf_pages`, `max_pdf_signatures`, `max_pdf_annotations_per_page`,
  `max_cms_certificates`); `http.allowed_schemes`, `http.block_private_addresses`, `http.max_response_bytes`,
  `http.request_deadline_ms`, `http.follow_redirects`, `http.proxy`, `http.use_system_proxy`, `http.cache_ms`;
  `tsa.require_trusted`, `tsa.max_clock_skew_ms`; `tl_sync.accept_structure_errors`.
- Validation result: `all_passed`, top-level `timestamps`, and per signature `trust_anchor`,
  `qualification_errors`, `qualification_warnings`, `info`, `policy`, `modified_after_signing`,
  `changes_after_signing` (PDF) and `timestamps`. `nested` also covers a signed PDF inside a CAdES envelope
  (`.pdf.p7m`).
- Trusted-list status: `oj_keystore`, `extra_trusted_certificates`, `countries_unmatched`, per list
  `structure_messages` and `last_published_sequence_number`, alerts with `first_seen`, `last_seen`, `count`, and
  the alert types `lotl_signature_error`, `lotl_expired`, `lotl_structure_error`, `tl_structure_error`,
  `countries_unmatched`, `refresh_not_published`, `cache_write_error`, `tl_rollback`.
- `dss_init` reports `log_level`; `dss_shutdown` reports `trusted_list_threads_stopped`; `dss_version` reports
  `api_version`, the version of the C/JSON contract (1).
- C API: `dss_validate_with_contents`, detached contents as binary buffers (at most 1024), binary end to end: the
  library keeps no base64 copy, and a content too large for the heap is `INTERNAL_ERROR`.
- `dss_init` reports `oj_keystore` (`path`, `sha256`), as `dss_tl_status` does.
- Rust: `ErrorCode::Unknown(name)` keeps the wire name, `Error::Argument`, `Error::Thread`, `dss::API_VERSION`,
  `DetachedContent::bytes`, `Limits`, `Proxy`, `RefreshScheduler::try_spawn`/`request_refresh`/`is_running`;
  `dss::library_version()` (no engine); `Engine::validate_with_contents` and `validate_with_contents_json` with
  `DetachedBytes::named`/`unnamed`; `dss::CancelToken`, `Engine::cancellable(&token)` (the document calls, whose
  queued calls a cancelled token skips) and `Error::Cancelled`; `InitInfo.oj_keystore` and
  `TrustedListStatus.oj_keystore` (`OjKeystoreInfo { path, sha256 }`); `ListStatus.last_published_sequence_number`;
  `Alert.previous_sequence_number`, `previous_issue_date`, `sequence_number`, `issue_date` (`tl_rollback`).
- `dss-cli`: `--tl-threads`; `--tsa-password-file` (`DSS_TSA_PASSWORD_FILE`; `DSS_TSA_PASSWORD` stays the
  fallback); `--help` documents the exit status; `version` prints `API version <n> (dss-cli expects <n>)`.
- `dss-server`: `--max-in-flight` (503 `SERVER_BUSY`), `--request-timeout` (504 `TIMEOUT`), `--max-connections`,
  `--oj-url`, `--lotl-url`, `--tl-snapshot`, `--tl-threads`, `--tsa-password-file`, `--allow-private-addresses`
  (`DSS_ALLOW_PRIVATE_ADDRESSES`: sets `http.block_private_addresses` to `false`; excluded by `--config`); 403
  `FORBIDDEN` and 405 `METHOD_NOT_ALLOWED` JSON errors; `/health` reports `last_online_refresh`, `in_flight`,
  `max_in_flight`; a start-up log line naming the keystore (or config file) and cache directory;
  `dss_server::parse_rfc3339` in the crate's library API.
- PHP client: `DssClient::API_VERSION` (1); error codes `INCOMPATIBLE_API_VERSION` (`version()` found a server
  `api_version` other than 1; a missing or null one is accepted) and `SINK_FAILED` (status 0: the document could
  not be written to the sink).
- Release packages: `docs/`, `trust/README.md`, `php/`, `docker/`, CycloneDX SBOMs in `sbom/`, and the source
  archives attached to each release.

### Changed

- Validation `errors` and `warnings` hold AdES messages only; qualification messages moved to
  `qualification_errors` / `qualification_warnings`.
- Input normalisation removes up to three nested transport encodings (the third used to be discarded); text that
  is not a CMS structure is `UNSUPPORTED_DOCUMENT` instead of `VALIDATION_FAILED`.
- A PDF encrypted with a user password is `UNSUPPORTED_DOCUMENT` for every operation.
- `dss_extend`: a signature already above the target level no longer blocks the others; only "every signature is
  above the target" is refused. With `revocation: "offline"`, B/T→LT/LTA is refused before a timestamp is spent.
- `dss_sign_prepare` refuses, before an external signature is spent: an unsuitable signing certificate, a PDF
  whose existing signatures `complete` could not extend, and (in `"signature_value"` mode) a too small
  `pades.content_size` (`INVALID_ARGUMENT`; it used to fail at `complete` with `SIGNING_FAILED`).
- Visible signatures: images at most 16384 pixels a side, JPEGs with an Exif rotation refused, fonts checked at
  `prepare` (font failures are `INVALID_ARGUMENT` there instead of `SIGNING_FAILED` later), text at most 10,000
  characters, NoRotate fields drawn upright, Hidden/NoView fields refused, a DefaultRGB colour space on PDFs with a
  non-RGB output intent.
- `config_json`/`options_json` are parsed strictly (duplicate keys, malformed numbers and escapes are errors), and
  more values are range-checked (`online_cache_expiration_ms`, timeouts, `log_level`, `countries` without `GR`,
  TSA credentials only over https).
- With `tl_snapshot`, an unwritable `cache_dir` is a warning instead of `INVALID_CONFIG`.
- Rust: every result struct is `#[non_exhaustive]`; `DetachedContent` is an enum; `Error::Api` prints
  `CODE: message` with the wire code; `EngineBuilder` refuses malformed heap sizes and isolate options.
- `dss-cli`: the default cache is `dss-native` in the user cache directory (was `./dss-cache`); `--config`
  conflicts with the flags it replaces; `version` needs no engine; outputs are written atomically and `-o` may
  name the input; `validate-batch` prints wire error codes and exits 2 on an invalid `--validation-time`.
- `dss-server`: `/health` is ready only once the trusted lists are loaded (unless
  `--allow-without-trusted-lists`); the first refresh depends on the age of the cached lists, failed refreshes
  are retried with backoff; the Docker image runs as UID/GID 10001 (chown existing cache volumes once).
- PHP client: `refreshTrustedLists()` returns `false` when a refresh is already running or requested (409)
  instead of throwing; the Laravel configuration takes the token as a file path (`DSS_TOKEN_FILE`), read at each
  request; an unreadable or empty token file is `TOKEN_FILE_UNREADABLE`.
- Refresh records measure `duration_ms` on a monotonic clock.
- Validation result: `changes_after_signing.pages_differ` is the array of pages (from 1) added or removed after
  the signed revision (it was a boolean); the OpenAPI description's `Changes.pages_differ` now says so too (it
  documented a boolean).
- Rust: `dss::API_VERSION` is checked against the library's `api_version` (`Error::Protocol` on another version);
  `DetachedContent::bytes` in `Options` reaches the library as binary buffers through `Engine::validate`; at most
  256 distinct unknown error-code names are kept per process, further ones are `ErrorCode::Unknown("UNKNOWN")` with
  the real name at the start of the `Error::Api` message; `RefreshScheduler`'s `stop()` versus drop semantics are
  documented.
- `dss-cli` output targets (`-o`, `--request`, `--out-dir`): an existing write-protected file is refused (exit 2,
  `<path>: Permission denied`) instead of replaced; a FIFO, `/dev/stdout`, a process substitution or any path under
  `/dev` or `/proc` is opened before the engine runs and written directly. An empty `DSS_*` variable counts as
  unset. `--config` conflicts are enforced wherever the flag is placed; `--tsa-user` needs `--tsa-url` and
  `--tsa-password-file` needs `--tsa-user`, checked after parsing, so `DSS_TSA_USER` with `--tsa-url` works.
  `tl status` shows each list's `published` sequence number, pivots under their LOTL, the refused and published
  sequence numbers of `tl_rollback` alerts, and the keystore's SHA-256. `version` uses `dss::library_version()`.
- `dss-server`: a wrong-method request on a guarded path answers 401 without the token (405 with `Allow` only with
  it); `/health` and `/openapi.yaml` answer 405 without one. `--cache-dir` defaults to `dss-native` in the user
  cache directory (was `./dss-cache`; an error without `HOME`). Detached parts go to the library as binary
  buffers, before the options' own `detached_contents`. A request abandoned before its engine call ran (deadline,
  client disconnect) is skipped. The Docker image's health-check start period is 300 s: with an empty cache the
  container turns healthy only after the first online refresh, unless `DSS_ALLOW_WITHOUT_TRUSTED_LISTS` is set.
- PHP client: a path sink is written through `<path>.<hex>.part` in the same directory and renamed over the path
  (the directory must be writable; on an error an existing file is left untouched, it used to be deleted); a
  resource sink only needs to be writable (a read-only one is refused) and receives the document at its current
  position, only on success; resources passed as documents or sinks are never closed by the client.
  `BAD_RESPONSE` messages no longer quote non-textual bodies, only their Content-Type and size. `composer.json`
  requires `guzzlehttp/psr7` ^2.0 (with `guzzlehttp/guzzle` ^7.2).
- Releases are created by pushing a `v<semver>` tag, after every gate passed; repackaging the same built library
  gives byte-identical tarballs.
