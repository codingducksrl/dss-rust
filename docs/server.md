# dss-server: the HTTP sidecar

`dss-server` runs one engine and serves it over HTTP, for applications written in other languages (PHP/Laravel
in particular). Every client process shares that engine: the trusted lists are loaded once, kept in one heap and
refreshed on a schedule. Clients need no native code. Why a sidecar rather than PHP FFI or a PHP extension:
[DECISIONS.md](DECISIONS.md#after-phase-6-http-sidecar-2026-11-03).

## Running

From the repository (a development build knows the repository's `trust/oj-keystore.p12` by its absolute path,
so the current directory does not matter):

```bash
rust/target/release/dss-server --country IT
```

From a package, `bin/dss-server` finds the library and the OJ keystore itself (next to the executable or in
`../share/dss-native/`). The keystore is the root of trust of the trusted lists, so it is never looked up in the
current directory, and neither is the cache: without `--cache-dir` it is `dss-native` in the user cache
directory. The paths in use are the first line of the log.

- **Starting.** The server listens at once. Until the engine is up, `/health` answers 503 (`starting`) and every
  endpoint that needs the engine answers `NOT_INITIALIZED`. That takes seconds with a cached copy of the trusted
  lists (docs/native-library.md, "Performance"). If the engine cannot start (bad configuration, missing
  keystore), the server exits with status 2 and relies on its supervisor (Compose `restart:`, systemd,
  Kubernetes) to start it again.
- **Readiness.** `/health` answers 200 only once the server can validate: the engine is up and, unless
  `--allow-without-trusted-lists`, the trusted lists are loaded. Until then it answers 503
  (`waiting_for_trusted_lists`), so an orchestrator does not route traffic to an instance whose every
  validation would fail with `TRUSTED_LISTS_NOT_LOADED`. `--health-check` follows the same rule.
- **First start.** With an empty cache, an online refresh starts right away (about 15 s for the full EU list),
  unless `--refresh-hours` is `0`: then nothing is loaded until `POST /tl/refresh`. Until the lists are loaded,
  validation, and extension or signing at LT/LTA, fail with `TRUSTED_LISTS_NOT_LOADED` (not with
  `--allow-without-trusted-lists`). To skip that wait, extract a seed cache (`dss-native-tl-cache-<date>.tar.gz`,
  from the releases) into the cache directory, or start from a trusted-list snapshot (`--tl-snapshot`, or
  `"tl_snapshot"` in the `--config` file; README.md, "Trusted-list snapshots"). A snapshot that cannot be used
  stops the server with status 2, like any other engine start failure.
- **Refreshes** run every `--refresh-hours` and on `POST /tl/refresh`. The age of what was loaded counts: lists
  downloaded (or a snapshot written) longer ago than the period are refreshed at start, younger ones when they
  reach that age, so restarting more often than the period does not keep the lists from ever being refreshed.
  A refresh whose result is unusable (the LOTL unreachable once a snapshot or cache got the engine started,
  a badly signed LOTL, every national list failing) is not applied: the previous lists stay in use,
  `/tl/status` shows `last_online_refresh.completed: false` with the reason in `error`, and a
  `refresh_not_published` alert. Such a refresh, like one that fails outright, is retried after 1, 2, 4, …
  minutes (at most the period) instead of waiting a whole period. Requests keep being served during a refresh,
  against the previous lists. Give each server its own `--cache-dir`, or at least do not expect a
  `dss-cli tl refresh` on the same directory to update a running server: it writes safely, but the server's
  lists change only on its own refresh.
- **Stopping.** On SIGTERM or Ctrl-C the server stops accepting connections, finishes the requests in progress
  (bounded by `--request-timeout`) and a running refresh, then exits with status 0. A second SIGTERM or Ctrl-C
  stops it at once, dropping the connections still open.
- **Logs** go to stderr: the OJ keystore (or `--config` file) and cache directory in use, start-up, each refresh
  and retry, who asked for a refresh, every 5xx error (a `SERVER_BUSY` or `TIMEOUT` line per refused request),
  and the library's own messages at `--log-level`.

### Options

Every option can also be set with an environment variable; an empty variable is the same as an unset one (so
Compose's `${VAR:-}` is safe). A boolean variable takes `true`/`false`, `1`/`0`, `yes`/`no` or `on`/`off`.

| Option | Variable | Default | |
|---|---|---|---|
| `--listen` | `DSS_LISTEN` | `127.0.0.1:8484` | Address and port. `0.0.0.0:8484` in a container |
| `--token-file` | `DSS_TOKEN_FILE` | none | File holding a bearer token (at least 16 bytes) that every endpoint but `/health` and `/openapi.yaml` requires |
| `--refresh-hours` | `DSS_REFRESH_HOURS` | `6` | Hours between online refreshes; `0`: only on `POST /tl/refresh` |
| `--max-request-mb` | `DSS_MAX_REQUEST_MB` | `100` | Largest request, all parts together |
| `--max-in-flight` | `DSS_MAX_IN_FLIGHT` | 2 × `--workers` | Document requests read and processed at the same time; the next one is answered 503 `SERVER_BUSY` at once. At most 256 |
| `--request-timeout` | `DSS_REQUEST_TIMEOUT` | `300` | Seconds a request may take, upload included, before 504 `TIMEOUT`; `0`: no limit |
| `--max-connections` | `DSS_MAX_CONNECTIONS` | `1024` | Open connections accepted at the same time; further clients wait in the listen queue |
| `--workers` | `DSS_WORKERS` | CPUs | Requests the engine runs at the same time; more wait in a queue |
| `--max-heap` | `DSS_MAX_HEAP` | grows with RAM | Engine heap, e.g. `1g`. Set it in containers |
| `--cache-dir` | `DSS_CACHE_DIR` | `dss-native` in the user cache directory (`$XDG_CACHE_HOME` or `~/.cache`, `~/Library/Caches` on macOS) | Trusted-list cache; it also holds the rollback protection's `tl-sequence-numbers.json`. Never the current directory; an error without `HOME` |
| `--config` | `DSS_CONFIG` | none | A full `config_json` file (README.md). Giving it together with one of the options below (as a flag or a variable) is an error, not a silent override |
| `--oj-keystore` | `DSS_OJ_KEYSTORE` | the package's (next to the executable or in `../share/dss-native/`); a development build also knows the repository's `trust/oj-keystore.p12` | OJ keystore with the LOTL signing certificates. Never looked up in the current directory |
| `--oj-url`, `--lotl-url` | `DSS_OJ_URL`, `DSS_LOTL_URL` | the EU's | For a mirror or a test (on a private address: with `--allow-private-addresses`) |
| `--tl-snapshot` | `DSS_TL_SNAPSHOT` | none | Start from this trusted-list snapshot instead of the cache |
| `--country` | `DSS_COUNTRIES` | every list | National lists to load, e.g. `IT`; comma-separated in the variable. See the note below |
| `--offline-revocation` | `DSS_OFFLINE_REVOCATION` | off | Only revocation data embedded in the signatures |
| `--trust` | `DSS_TRUST` | none | Extra trusted certificates (PEM/DER); comma-separated in the variable |
| `--allow-without-trusted-lists` | `DSS_ALLOW_WITHOUT_TRUSTED_LISTS` | off | Validate with no trusted list loaded (private PKI); `/health` is then ready as soon as the engine is up |
| `--tsa-url`, `--tsa-user` | `DSS_TSA_URL`, `DSS_TSA_USER` | none | TSA for extension and signing at T/LTA |
| `--tsa-password-file` | `DSS_TSA_PASSWORD_FILE` | none | File holding the TSA password (else the `DSS_TSA_PASSWORD` variable, which `docker inspect` shows) |
| `--allow-private-addresses` | `DSS_ALLOW_PRIVATE_ADDRESSES` | off | Let the engine fetch from loopback, private and link-local addresses. By default a TSA, LOTL/TL mirror, CRL or OCSP responder there is refused (see "Security") |
| `--tl-threads` | `DSS_TL_THREADS` | CPUs, at most 16 | Threads that download and validate the trusted lists (1–64) |
| `--log-level` | `DSS_LOG_LEVEL` | `warn` | Library log level: `off`, `error`, `warn`, `info`, `debug`, `trace` |
| `--health-check` | | | Instead of serving: exit 0 if the server at `--listen` is ready, 1 if not |

`--country` limits the trust anchors to the lists named: a signature anchored in another member state's list
(a German or Spanish qualified signature with `--country IT`) then validates `INDETERMINATE` with
`NO_CERTIFICATE_CHAIN_FOUND`, and nothing in the result says the scope is the reason (`/tl/status` shows the
lists loaded in `tls[].territory`). Load every list (the default) wherever cross-border signatures may arrive;
the option is for a single-country deployment that wants a faster start and a smaller heap.

### Sizing

Admission control bounds what the server holds: at most `--max-in-flight` requests are read and processed at
once, each held in memory whole (the body, plus a copy handed to the engine; `detached` parts travel the same
way, as binary buffers, never as base64) and then copied into the engine's heap. The memory the server itself needs is therefore about `--max-in-flight` × `--max-request-mb` × 2, and
the engine heap (`--max-heap`) about the largest document × `--workers` × 3 for validation, more for signing
and extension. `--max-heap` caps the engine's own memory but is not a safety boundary: a document that
exhausts it is usually refused with `INTERNAL_ERROR`, but an `OutOfMemoryError` raised deep inside DSS can
stop the whole process (docs/native-library.md), so keep the admission and size caps well inside the memory
available. A request refused with `SERVER_BUSY` costs nothing: its body is never read.

`--request-timeout` bounds how long a request may take, upload included; over it, the client gets 504
`TIMEOUT`. Every engine call is bound to a cancellation token that the server sets when the request is
abandoned: when the deadline fires, and when the client closes its connection before the answer. A call still
queued for one of the engine's `--workers` is then skipped by the worker that takes it, so a queue of requests
whose callers are gone (clients that timed out on their side, a restarted application) costs no engine time.
The library cannot cancel a call that is already running: it finishes in the background and keeps its admission
slot until then, so set the timeout above the longest legitimate request and keep clients from retrying a
timed-out upload at once.

## API

The OpenAPI 3.1 description is [`openapi.yaml`](openapi.yaml). Every server also serves it at `/openapi.yaml`, with
`info.version` set to its own version, so it always matches the binary answering.

Requests that carry a document are `multipart/form-data`, with these parts:

| Part | Used by | Content |
|---|---|---|
| `document` | `/validate`, `/extend`, `/sign/*` | The document. For `/validate` and `/extend` its filename becomes `filename` in the options, unless they set one |
| `options` | the same; optional for `/validate` | A JSON object: the library's `options_json` (README.md, "API") |
| `detached` | `/validate`, repeatable | Detached content (for a `.p7s`); its filename is the content's name, `detached-<n>` without one. Passed to the library as binary buffers (`dss_validate_with_contents`), never as base64, and placed before any `detached_contents` entry of the options; at most 1024 parts, none empty. A CAdES signature covers one content: send exactly that one (given two, DSS finds no signed data: `SIGNED_DATA_NOT_FOUND`) |
| `signature` | `/sign/complete` | What the external signer returned |

A part an endpoint does not take, or a second `document`, `options` or `signature`, is `INVALID_ARGUMENT`. So
is `detached_contents[].path` in the options: the server never reads its own files for a client. Send the file
as a `detached` part, or as a `base64` entry.

| Endpoint | Response |
|---|---|
| `POST /validate` | The library's validation result (JSON) |
| `POST /extend` | The extended PDF as the body; the result JSON in the `Dss-Result` header |
| `POST /sign/prepare` | The library's result (JSON): `digest`, `signing_time`, … |
| `POST /sign/complete` | The signed document as the body; the result JSON in `Dss-Result` |
| `GET /tl/status` | The library's trusted-list status (JSON; README.md, "Trusted-list status"): what is loaded, `oj_keystore` (the root of trust in use: its `path` and `sha256`, a digest over its certificates that a trusted-list snapshot records as `settings.oj_keystore_sha256`, so a snapshot's provenance can be checked against the running server), the last refreshes (their `duration_ms` is measured on a monotonic clock and never negative; `started_at`/`finished_at` are wall-clock times), each list's state with `last_published_sequence_number` (the rollback protection's floor for that list), and `alerts`, among them `tl_rollback` (an older list than the one last published was refused: `download.status` `ERROR`, "rollback refused: …") and `cache_write_error` (one per list that could not be stored) |
| `POST /tl/refresh` | 202 `{"ok":true}`: an online refresh starts as soon as possible. `/tl/status` shows it (`refresh_in_progress`, then `last_online_refresh`); it can lag the 202 by a few milliseconds |
| `GET /version` | `{"ok":true,"server":…,"library":…,"dss":…,"runtime":…,"api_version":…}` |
| `GET /health` | 200 `{"ok":true,"status":"ready","trusted_lists_loaded":…,"refresh_in_progress":…,"last_online_refresh":…,"in_flight":…,"max_in_flight":…}`, or 503 `{"ok":false,"status":"starting"}` / `{"ok":false,"status":"waiting_for_trusted_lists",…}`. Needs no token |
| `GET /openapi.yaml` | This API's OpenAPI document. Needs no token |

- **A failed signature is not an error.** A tampered or untrusted signature is a 200 result; check `all_passed`
  (true only when the document has at least one signature and every one, nested ones included, is
  `TOTAL_PASSED`), or each `signatures[].indication`.
- **Documents** come back as the raw body, not as base64 in JSON:
  - `application/pdf` for PAdES;
  - `application/pkcs7-signature` for a detached CAdES `.p7s`;
  - `application/pkcs7-mime` for an enveloping `.p7m`.

  `Dss-Result` holds the compact result JSON, with any non-ASCII character escaped as `\uXXXX`.
- **Signing** passes the options through unchanged, and adds no filename. `complete` must get the same document
  and options as `prepare`, plus the `signing_time` that `prepare` returned. Anything else gives another digest,
  and the signature is refused. In mode `signature_value` a `pades.content_size` the CMS cannot fit is
  `INVALID_ARGUMENT` from `prepare` already (before the signer is asked), and from `complete`; a CMS that does
  not fit for a reason outside that estimate (the level-T timestamp) is `SIGNING_FAILED`.
- **Rollback protection.** The cache directory holds `tl-sequence-numbers.json`, the highest sequence number
  the engine has published per list, written after each publication (and a snapshot import) and never lowered;
  an older list, downloaded or restored from a backup of the cache, is refused (README.md, "Rollback
  protection"). `/tl/status` shows it as described above.

### Errors

The body is always `{"ok":false,"error":{"code":"…","message":"…"}}`: the library's code, or one of the
server's own (`UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `METHOD_NOT_ALLOWED`, `REQUEST_TOO_LARGE`,
`SERVER_BUSY`, `TIMEOUT`).

| Status | Codes |
|---|---|
| 400 | `INVALID_ARGUMENT`: not `multipart/form-data`, a malformed or broken-off body, a bad part or option (a `pades.content_size` the signature's CMS cannot fit included) |
| 401 | `UNAUTHORIZED`: missing or wrong bearer token (with a `WWW-Authenticate: Bearer` challenge) |
| 403 | `FORBIDDEN`: the server runs without a token and the request carries an `Origin` header (a web page) |
| 404 | `NOT_FOUND` |
| 405 | `METHOD_NOT_ALLOWED`: an endpoint that exists, with the wrong method, e.g. `GET /validate`; `Allow` lists the methods it takes. With a token, a guarded endpoint checks the token first (401 before 405) |
| 409 | `REFRESH_IN_PROGRESS`: a refresh is already running or requested |
| 413 | `REQUEST_TOO_LARGE`: over `--max-request-mb` |
| 422 | `UNSUPPORTED_DOCUMENT`, `VALIDATION_FAILED`, `EXTENSION_FAILED`, `SIGNING_FAILED` |
| 500 | `INTERNAL_ERROR`: anything unexpected in the library (an engine out of heap), or a refresh schedule that has died |
| 502 | `TSA_FAILED`: the TSA could not be reached or returned a token the engine refuses; retry later. `TL_REFRESH_FAILED` is never a response: a refresh runs after its 202 |
| 503 | `NOT_INITIALIZED` (the engine is starting), `TRUSTED_LISTS_NOT_LOADED`, `SERVER_BUSY` (`--max-in-flight` reached; `Retry-After: 1`) |
| 504 | `TIMEOUT`: over `--request-timeout`; the engine call, if still queued, is skipped |

A configuration the engine refuses (`INVALID_CONFIG`, `TL_SNAPSHOT_REJECTED`) stops the server at start-up, so
no request ever gets those codes. A failed online refresh is no error either: `POST /tl/refresh` has already
answered 202, and the outcome is in the log and in `/tl/status` (`last_online_refresh`).

### With curl

```bash
curl -F document=@contract.pdf.p7m -F 'options={"reports":["detailed"]}' http://127.0.0.1:8484/validate
```

```bash
curl -F document=@signature.p7s -F detached=@contract.pdf http://127.0.0.1:8484/validate
```

```bash
curl -D - -o signed-lt.pdf -F document=@signed-t.pdf -F 'options={"level":"LT"}' http://127.0.0.1:8484/extend
```

## PHP and Laravel

[`php/DssClient.php`](../php/DssClient.php) and [`php/DssException.php`](../php/DssException.php) are a client
built on Laravel's HTTP client (PHP 8.1 and Laravel 10 or later). That client needs `guzzlehttp/guzzle`,
which a Laravel application already has; a project that uses `illuminate/http` 10 on its own must require it
(`composer require guzzlehttp/guzzle:^7.2`). Copy the two files into `app/Services/Dss/`, then configure the
server's address and token file in `config/services.php`:

```php
'dss' => [
    'url' => env('DSS_URL', 'http://dss:8484'),
    // The same file as the server's --token-file; unset or empty when the server runs without one.
    'token_file' => env('DSS_TOKEN_FILE'),
],
```

Keep only the path in the configuration, never the token: `php artisan config:cache` (and `optimize`) store the
evaluated configuration in a file, often at image build time, before the secret is mounted. The client reads
the file at each request and throws `DssException` `TOKEN_FILE_UNREADABLE` when it is missing, unreadable or
empty, rather than silently sending no token. Then register the client in a service provider:

```php
use App\Services\Dss\DssClient;
use Illuminate\Http\Client\Factory;

$this->app->singleton(DssClient::class, fn ($app) => new DssClient(
    $app->make(Factory::class),
    config('services.dss.url'),
    timeoutSeconds: 120,   // keep it at or above the server's --request-timeout
    tokenFile: config('services.dss.token_file'),
));
```

(`token:` takes the token itself instead, for one that comes from elsewhere; not both.) The client keeps no
per-request state, so a singleton is safe under Octane.

```php
$result = $dss->validate($request->file('document')->get(), 'contract.pdf.p7m', ['reports' => ['detailed']]);
if (DssClient::allPassed($result) && ! DssClient::modifiedAfterSigning($result)) {
    // every signature (nested ones included) is TOTAL_PASSED, and no PDF was changed after it was signed
}
foreach ($result['signatures'] as $signature) {
    // $signature['indication']: TOTAL_PASSED, TOTAL_FAILED or INDETERMINATE; signed_by, signing_time,
    // modified_after_signing (PAdES), … when known
}

[$pdf, $result] = $dss->extend($signedPdf, 'LT');        // $result['level'] === 'PAdES-BASELINE-LT'

$options = ['mode' => 'cms', 'level' => 'LT'];
$prepared = $dss->prepareSignature($pdf, $options);       // send $prepared['digest'] to the remote signer
$options['signing_time'] = $prepared['signing_time'];
[$signed, $result] = $dss->completeSignature($pdf, $options, $cmsFromTheSigner);

$dss->health();                 // ['ok' => true, 'status' => 'ready', …], or ok false (503) while starting
$dss->version();                // server, library, dss, runtime, api_version (see Errors)
$dss->trustedListStatus();      // oj_keystore (path, sha256), last_offline_refresh, last_online_refresh, …
$dss->refreshTrustedLists();    // true: started; false: one is already running or requested (409)
```

**Memory.** A document given as a string, and one returned as a string, is held in PHP's memory whole: an
extension or a signature needs about twice the document's size at the peak, so a 60 MB PDF exhausts the default
`memory_limit` of 128M (the server accepts up to `--max-request-mb`, 100 by default). For large documents, pass
a stream instead of a string (`fopen($request->file('document')->getRealPath(), 'rb')`), which is
sent without being read into memory, and give `extend()` / `completeSignature()` a `sink`, a file path or a
writable resource (`wb` is enough), which receives the returned document; the first element of the pair is
then `null`:

```php
[, $result] = $dss->extend(fopen($in, 'rb'), 'LT', 'contract.pdf', sink: $out);
```

The sink receives the answer only once it is known to be a document, so it never holds an error answer: a
path sink is written whole or not at all (the answer goes to a `.part` file next to it, renamed over it at the
end; on an error an existing file is left as it was), and a resource sink gets the document appended at its
current position. A resource given as a document or as a sink is never closed by the client: close it
yourself.

**Options** are the library's `options_json` as an array. An empty array under `pades` or `pades.visible` is
sent as a JSON object (`{}`), so `['pades' => []]` filled conditionally works; elsewhere an empty array is a
JSON list. Upload file names (`validate()`'s `$filename` and the keys of `$detached`) have quotes, backslashes
and control characters replaced with `_`, so they cannot break the multipart body.

**Errors.** Every `{"ok":false}` answer throws `DssException`, with `errorCode`, the HTTP `status` and, for
503 `SERVER_BUSY`, `retryAfter` (seconds, from `Retry-After`; retry after it). `TSA_FAILED` (502) is worth
retrying later; after a 504 `TIMEOUT` do not resend the upload at once, since the engine call keeps running. A
non-2xx answer that is not the server's JSON (a proxy's error page) throws it with `errorCode` `HTTP_<status>`;
a 2xx answer that is not the server's (a wrong `DSS_URL`, or a proxy that strips the `Dss-Result` header)
throws `BAD_RESPONSE`. Either message holds at most the first 1000 bytes of a textual body (`text/*`, JSON,
XML); for any other body, a returned document for instance, it gives only the Content-Type and the size. Options
that cannot be encoded as JSON (invalid UTF-8) throw `INVALID_ARGUMENT` with `status` 0, before any request is
sent; a document that cannot be written to the sink throws `SINK_FAILED` with `status` 0. `version()` throws
`INCOMPATIBLE_API_VERSION` when the server reports an `api_version` other than `DssClient::API_VERSION` (1),
the version of the contract the client was written for; a server without the field predates it and is accepted.
Calling `version()` from a deploy or readiness check catches a server upgraded past the client. A connection
that fails or times out throws Laravel's `ConnectionException`.

**Tests.** `php/` has a `composer.json` for the client's own tests, which use Laravel's fake HTTP client, plus
a few that run Guzzle's real handler against a stand-in server (`tests/fixtures/router.php` under `php -S` on
127.0.0.1); none needs dss-server or the network: `cd php && composer install && composer lint && composer test`.
CI runs them on PHP 8.1 (Laravel 10), 8.2 and 8.4 (newest Laravel); they also pass with the lowest versions
`composer.json` allows (`composer update --prefer-lowest`: `illuminate/http` 10.0, `guzzlehttp/guzzle` 7.3,
`guzzlehttp/psr7` 2.0, `psr/http-message` 1.0).

## Docker

[`docker/dss-server/Dockerfile`](../docker/dss-server/Dockerfile) builds an image from a Linux release package.
The build context is the folder holding `dss-native-<VERSION>-linux-<x64|aarch64>.tar.gz` **and its `.sha256`**
(`dist/` after `scripts/package.sh`, or the release's assets): the build verifies the checksum and stops without
the `.sha256` file. `--build-arg VERSION` is required, and the build needs BuildKit (the default since Docker 23):

```bash
docker build -f docker/dss-server/Dockerfile --build-arg VERSION=1.2.0 -t dss-server:1.2.0 dist/
```

The base is `debian:trixie-slim`, pinned by digest (Dependabot proposes updates), because the library needs
glibc. The image runs as a non-root user (uid 10001), keeps the cache in a volume (`/var/lib/dss/cache`; give
each container its own), and its health check is `dss-server --health-check`, which passes only once the trusted
lists are loaded: from the cache volume in seconds, with an empty cache only after the first online refresh of
the EU lists, which can take minutes (the `--start-period` of 300 s covers it: failed probes during that period
do not count, and a passing one marks the container healthy at once), unless `DSS_ALLOW_WITHOUT_TRUSTED_LISTS`
is set. Change the listening address with `DSS_LISTEN` (default `0.0.0.0:8484`), not with a `--listen` argument
in `command:`: the health check runs a separate `dss-server --health-check`, which sees the environment but not
the server's arguments, so after `--listen 0.0.0.0:9000` it would keep probing 8484 and the container would
never turn healthy. Next to a Laravel app in Compose:

```yaml
services:
  dss:
    image: dss-server:1.2.0
    restart: unless-stopped      # the server exits with status 2 on a failed start and expects to be restarted
    environment:
      DSS_MAX_HEAP: 1g
      DSS_TOKEN_FILE: /run/secrets/dss_token
      # DSS_COUNTRIES: IT        # only when every signature is Italian: others then validate INDETERMINATE
    volumes:
      - dss-cache:/var/lib/dss/cache
    secrets: [dss_token]
  app:
    depends_on:
      dss:
        condition: service_healthy
    environment:
      DSS_URL: http://dss:8484
      DSS_TOKEN_FILE: /run/secrets/dss_token
    secrets: [dss_token]
volumes:
  dss-cache:
secrets:
  dss_token:
    file: ./secrets/dss_token
```

Do not publish the port: the app reaches the sidecar over the Compose network. Create the token with
`openssl rand -base64 32 > secrets/dss_token`. On a Linux host, Compose bind-mounts the secret file with the
host's owner and mode: the server (uid 10001) cannot read a `0600` file owned by you, and exits with status 2
(`token file /run/secrets/dss_token: Permission denied`). Make it readable by that uid (`chmod 0640` and
`chown :10001`, or `0644` on a host where only trusted users can read the directory). Docker Desktop remaps the
owner, so the problem shows up only on Linux.

## Security

- **No TLS.** Run the sidecar on the same host or on a private network, as above, and never expose it publicly.
  The token stops other containers on the same network from using it.
- **The token is read from a file**, so it does not show up in `ps` or `docker inspect`. It must be at least 16
  bytes: generate it (`openssl rand -base64 32`), do not choose it. The comparison is constant-time, and there
  is no lockout, so a short token could be guessed by any process on the network.
- **Without a token, requests from web pages are refused** (403 `FORBIDDEN` when the request carries an
  `Origin` header, which browsers add to every cross-site POST): a page could otherwise submit documents to, or
  start refreshes on, a sidecar on localhost. Run with a token wherever a browser can reach the server.
- **Signing keys never reach the server.** `prepare` and `complete` handle documents and digests; the key stays
  with the external signer.
- **The TSA password** is read from a file too (`--tsa-password-file`); the `DSS_TSA_PASSWORD` variable is
  accepted for compatibility but is visible to `docker inspect` and in `/proc/<pid>/environ`.
- **Outbound requests stay on the public network by default.** The engine refuses to fetch from loopback,
  private, link-local (cloud metadata), CGNAT and multicast addresses, literal or as resolved when the request
  starts (`http.block_private_addresses`, README.md): a TSA, LOTL/TL mirror, CRL or OCSP responder there fails
  with `outbound request to <url> refused by policy: <address> is a loopback address` in the log (a refresh then
  ends with 0 trusted certificates, a timestamp with 502 `TSA_FAILED`). A TSA or mirror on this host or on the
  Compose network (service names resolve to private addresses) needs `--allow-private-addresses`, or
  `"http": {"block_private_addresses": false}` in the `--config` file; the two exclude each other like the
  other engine options. The check is a first layer, not a defence against DNS rebinding.
- **Size and time.** `--max-request-mb` caps one request, `--max-in-flight` how many are held at once,
  `--request-timeout` how long one may take, and `--max-connections` how many clients are connected; a client
  that sends no complete request line and headers within 30 s is disconnected. See "Sizing" above.
