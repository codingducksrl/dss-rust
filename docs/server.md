# dss-server: the HTTP sidecar

`dss-server` runs one engine and serves it over HTTP, for applications written in other languages (PHP/Laravel
in particular). Every client process shares that engine: the trusted lists are loaded once, kept in one heap and
refreshed on a schedule. Clients need no native code. Why a sidecar rather than PHP FFI or a PHP extension:
[DECISIONS.md](DECISIONS.md#after-phase-6-http-sidecar-2026-11-03).

## Running

```bash
rust/target/release/dss-server --country IT
```

From a package, `bin/dss-server` runs from the unpacked folder and finds the library and the OJ keystore itself.

- **Starting.** The server listens at once. `/health` answers 503, and every other endpoint `NOT_INITIALIZED`,
  until the engine is up. That takes seconds with a cached copy of the trusted lists (docs/native-library.md,
  "Performance"). If the engine cannot start (bad configuration, missing keystore), the server exits with
  status 2.
- **First start.** With an empty cache, an online refresh starts right away (about 15 s for the full EU list).
  Until it finishes, validations fail with `TRUSTED_LISTS_NOT_LOADED`. To skip that wait, extract a seed cache
  (`dss-native-tl-cache-<date>.tar.gz`, from the releases) into the cache directory, or start from a
  trusted-list snapshot: `"tl_snapshot"` in the `--config` file (README.md, "Trusted-list snapshots"). A snapshot
  that cannot be used stops the server with status 2, like any other engine start failure.
- **Refreshes** run every `--refresh-hours` and on `POST /tl/refresh`. Requests keep being served during a
  refresh, against the previous lists.
- **Stopping.** On SIGTERM or Ctrl-C the server stops accepting connections, finishes the requests in progress
  (and a running refresh), then exits with status 0.
- **Logs** go to stderr: start-up, each refresh, every 5xx error, and the library's own messages at
  `--log-level`.

### Options

Every option can also be set with an environment variable. For a boolean variable, `true` turns it on.

| Option | Variable | Default | |
|---|---|---|---|
| `--listen` | `DSS_LISTEN` | `127.0.0.1:8484` | Address and port. `0.0.0.0:8484` in a container |
| `--token-file` | `DSS_TOKEN_FILE` | none | File holding a bearer token that every endpoint but `/health` and `/openapi.yaml` requires |
| `--refresh-hours` | `DSS_REFRESH_HOURS` | `6` | Hours between online refreshes; `0`: only on `POST /tl/refresh` |
| `--max-request-mb` | `DSS_MAX_REQUEST_MB` | `100` | Largest request, all parts together |
| `--workers` | `DSS_WORKERS` | CPUs | Requests the engine runs at the same time; more wait in a queue |
| `--max-heap` | `DSS_MAX_HEAP` | grows with RAM | Engine heap, e.g. `1g`. Set it in containers |
| `--cache-dir` | `DSS_CACHE_DIR` | `dss-cache` | Trusted-list cache |
| `--config` | `DSS_CONFIG` | none | A full `config_json` file (README.md); replaces the options below |
| `--oj-keystore` | `DSS_OJ_KEYSTORE` | the package's | OJ keystore with the LOTL signing certificates |
| `--country` | `DSS_COUNTRIES` | every list | National lists to load, e.g. `IT`; comma-separated in the variable |
| `--offline-revocation` | `DSS_OFFLINE_REVOCATION` | off | Only revocation data embedded in the signatures |
| `--trust` | `DSS_TRUST` | none | Extra trusted certificates (PEM/DER); comma-separated in the variable |
| `--allow-without-trusted-lists` | `DSS_ALLOW_WITHOUT_TRUSTED_LISTS` | off | Validate with no trusted list loaded (private PKI) |
| `--tsa-url`, `--tsa-user` | `DSS_TSA_URL`, `DSS_TSA_USER` | none | TSA for extension and signing at T/LTA; password in `DSS_TSA_PASSWORD` |
| `--log-level` | `DSS_LOG_LEVEL` | `warn` | Library log level |
| `--health-check` | | | Instead of serving: exit 0 if the server at `--listen` is ready, 1 if not |

## API

The OpenAPI 3.1 description is [`openapi.yaml`](openapi.yaml). Every server also serves it at `/openapi.yaml`, with
`info.version` set to its own version, so it always matches the binary answering.

Requests that carry a document are `multipart/form-data`, with these parts:

| Part | Used by | Content |
|---|---|---|
| `document` | `/validate`, `/extend`, `/sign/*` | The document. For `/validate` and `/extend` its filename becomes `filename` in the options, unless they set one |
| `options` | the same; optional for `/validate` | A JSON object: the library's `options_json` (README.md, "API") |
| `detached` | `/validate`, repeatable | Detached content (for a `.p7s`); its filename is the content's name |
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
| `GET /tl/status` | The library's trusted-list status (JSON) |
| `POST /tl/refresh` | 202 `{"ok":true}`: an online refresh started. `/tl/status` shows its outcome |
| `GET /version` | `{"ok":true,"server":…,"library":…,"dss":…,"runtime":…}` |
| `GET /health` | 200 `{"ok":true,"status":"ready","trusted_lists_loaded":…,"refresh_in_progress":…}`, or 503 `{"ok":false,"status":"starting"}`. Needs no token |
| `GET /openapi.yaml` | This API's OpenAPI document. Needs no token |

- **A failed signature is not an error.** A tampered or untrusted signature is a 200 result; check each
  `signatures[].indication`.
- **Documents** come back as the raw body, not as base64 in JSON:
  - `application/pdf` for PAdES;
  - `application/pkcs7-signature` for a detached CAdES `.p7s`;
  - `application/pkcs7-mime` for an enveloping `.p7m`.

  `Dss-Result` holds the compact result JSON, with any non-ASCII character escaped as `\uXXXX`.
- **Signing** passes the options through unchanged, and adds no filename. `complete` must get the same document
  and options as `prepare`, plus the `signing_time` that `prepare` returned. Anything else gives another digest,
  and the signature is refused.

### Errors

The body is always `{"ok":false,"error":{"code":"…","message":"…"}}`: the library's code, or one of the server's
own codes (`UNAUTHORIZED`, `NOT_FOUND`, `REQUEST_TOO_LARGE`).

| Status | Codes |
|---|---|
| 400 | `INVALID_ARGUMENT`: malformed request, part or option |
| 401 | `UNAUTHORIZED`: missing or wrong bearer token |
| 404 | `NOT_FOUND` |
| 409 | `REFRESH_IN_PROGRESS` |
| 413 | `REQUEST_TOO_LARGE`: over `--max-request-mb` |
| 422 | `UNSUPPORTED_DOCUMENT`, `VALIDATION_FAILED`, `EXTENSION_FAILED`, `SIGNING_FAILED` |
| 500 | `INVALID_CONFIG`, `INTERNAL_ERROR` (including an engine out of heap) |
| 502 | `TL_REFRESH_FAILED` |
| 503 | `NOT_INITIALIZED` (the engine is starting), `TRUSTED_LISTS_NOT_LOADED` |

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
built on Laravel's HTTP client. Copy them into `app/Services/Dss/`, then configure the server's address and token
in `config/services.php`:

```php
'dss' => [
    'url' => env('DSS_URL', 'http://dss:8484'),
    // The same file as the server's --token-file; null when the server runs without one.
    'token' => is_readable($file = env('DSS_TOKEN_FILE', '')) ? trim(file_get_contents($file)) : null,
],
```

Then register the client in a service provider:

```php
use App\Services\Dss\DssClient;
use Illuminate\Http\Client\Factory;

$this->app->singleton(DssClient::class, fn ($app) => new DssClient(
    $app->make(Factory::class),
    config('services.dss.url'),
    config('services.dss.token'),
));
```

The client keeps no per-request state, so a singleton is safe under Octane.

```php
$result = $dss->validate($request->file('document')->get(), 'contract.pdf.p7m', ['reports' => ['detailed']]);
foreach ($result['signatures'] as $signature) {
    // $signature['indication']: TOTAL_PASSED, TOTAL_FAILED or INDETERMINATE; also signed_by, signing_time, …
}

[$pdf, $result] = $dss->extend($signedPdf, 'LT');        // $result['level'] === 'PAdES-BASELINE-LT'

$options = ['mode' => 'cms', 'level' => 'LT'];
$prepared = $dss->prepareSignature($pdf, $options);       // send $prepared['digest'] to the remote signer
$options['signing_time'] = $prepared['signing_time'];
[$signed, $result] = $dss->completeSignature($pdf, $options, $cmsFromTheSigner);
```

Every `{"ok":false}` answer throws `DssException`, with `errorCode` and the HTTP `status`. A connection that
fails throws Laravel's `ConnectionException`.

## Docker

[`docker/dss-server/Dockerfile`](../docker/dss-server/Dockerfile) builds an image from a Linux release package.
The build context is the folder holding the `.tar.gz`:

```bash
docker build -f docker/dss-server/Dockerfile --build-arg VERSION=1.2.0 -t dss-server:1.2.0 dist/
```

The image is Debian slim, because the library needs glibc. It runs as a non-root user, keeps the cache in a
volume, and its health check is `dss-server --health-check`. Next to a Laravel app in Compose:

```yaml
services:
  dss:
    image: dss-server:1.2.0
    environment:
      DSS_COUNTRIES: IT            # only the Italian list: faster start, less memory
      DSS_MAX_HEAP: 1g
      DSS_TOKEN_FILE: /run/secrets/dss_token
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

Do not publish the port: the app reaches the sidecar over the Compose network.

## Security

- **No TLS.** Run the sidecar on the same host or on a private network, as above, and never expose it publicly.
  The token stops other containers on the same network from using it.
- **The token is read from a file**, so it does not show up in `ps` or `docker inspect`.
- **Signing keys never reach the server.** `prepare` and `complete` handle documents and digests; the key stays
  with the external signer.
- **Size.** A request is held in memory whole, and the engine copies it into its own heap. `--max-request-mb`
  and `--max-heap` bound both.
