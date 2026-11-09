<?php

// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

declare(strict_types=1);

namespace App\Services\Dss;

use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use InvalidArgumentException;
use JsonException;
use Psr\Http\Message\StreamInterface;
use stdClass;

/**
 * Laravel client for dss-server (docs/server.md). Copy this file and DssException.php into the application.
 * Requires PHP 8.1 and Laravel 10 or later (Illuminate\Http\Client).
 *
 * Results are the library's JSON as arrays (README.md, "API"). A failed signature is a result, not an exception:
 * check `all_passed` (allPassed()) and each signature's `modified_after_signing` (modifiedAfterSigning()).
 * Every `{"ok":false}` answer throws DssException with the error code; so does an answer that is not
 * dss-server's (BAD_RESPONSE).
 *
 * Documents can be given as a string, a stream resource (fopen) or a PSR-7 stream: a stream is sent without
 * being read into memory, and a resource is left open (the caller closes it). extend() and completeSignature()
 * take a `$sink` (a file path or a writable resource) that receives the returned document instead of a string,
 * only once the answer is known to be a document. Without them, a document is held in memory whole, twice at
 * the peak (what is sent and what comes back): size PHP's memory_limit accordingly.
 */
final class DssClient
{
    /**
     * The version of the C/JSON contract this client speaks (`api_version` of /version). It changes only on an
     * incompatible change; version() refuses a server reporting another one.
     */
    public const API_VERSION = 1;

    /** Bytes copied at a time from a returned document to a resource sink. */
    private const CHUNK = 65536;

    /**
     * Options keys whose value is a JSON object: an empty PHP array there is sent as `{}`, not as `[]`.
     * Nested arrays are the object keys below.
     */
    private const OBJECT_KEYS = ['pades' => ['visible' => []]];

    /**
     * @param  ?string  $token  the bearer token itself
     * @param  ?string  $tokenFile  a file holding the token (the server's --token-file), read at each request, so
     *                              that `php artisan config:cache` never stores the token; '' is the same as null
     */
    public function __construct(
        private readonly Factory $http,
        private readonly string $baseUrl = 'http://dss:8484',
        private readonly ?string $token = null,
        private readonly int $timeoutSeconds = 120,
        private readonly ?string $tokenFile = null,
    ) {
        if ($token !== null && $tokenFile !== null && $tokenFile !== '') {
            throw new InvalidArgumentException('give either a token or a token file, not both');
        }
    }

    /**
     * Validates a PDF or CMS/CAdES document.
     *
     * @param  string|resource|StreamInterface  $document
     * @param  array<string, mixed>  $options  options_json, e.g. ['reports' => ['detailed']]
     * @param  array<string, string|resource|StreamInterface>  $detached  detached contents, file name => bytes
     * @return array<string, mixed>
     */
    public function validate(mixed $document, string $filename, array $options = [], array $detached = []): array
    {
        $request = $this->request()->attach('document', self::content($document), self::filename($filename));
        foreach ($detached as $name => $content) {
            $request = $request->attach('detached', self::content($content), self::filename((string) $name));
        }

        return $this->result($request->post('/validate', $this->options($options)));
    }

    /**
     * Extends every signature of a PDF to PAdES-BASELINE-T, -LT or -LTA.
     *
     * @param  string|resource|StreamInterface  $pdf
     * @param  string|resource|null  $sink  where to write the extended PDF instead of returning it: a path (written
     *                                    whole or not at all) or a writable resource (written at its position)
     * @return array{0: ?string, 1: array<string, mixed>} the extended PDF (null with a sink), and the result
     */
    public function extend(mixed $pdf, string $level, string $filename = 'document.pdf', mixed $sink = null): array
    {
        $request = $this->request()->attach('document', self::content($pdf), self::filename($filename));

        return $this->document($request, '/extend', $this->options(['level' => $level]), $sink);
    }

    /**
     * Signing with an external signer, step 1: the digest to sign, and the signing time to pass to step 2.
     *
     * @param  string|resource|StreamInterface  $document
     * @param  array<string, mixed>  $options  mode, level, signing_certificate, pades, …
     * @return array<string, mixed>
     */
    public function prepareSignature(mixed $document, array $options): array
    {
        $request = $this->request()->attach('document', self::content($document), 'document');

        return $this->result($request->post('/sign/prepare', $this->options($options)));
    }

    /**
     * Step 2: the same document and options as step 1, with 'signing_time' set to the one it returned.
     *
     * @param  string|resource|StreamInterface  $document
     * @param  array<string, mixed>  $options
     * @param  string|resource|null  $sink  where to write the signed document instead of returning it, as for
     *                                    extend()
     * @return array{0: ?string, 1: array<string, mixed>} the signed document (null with a sink), and the result
     */
    public function completeSignature(mixed $document, array $options, string $signature, mixed $sink = null): array
    {
        $request = $this->request()
            ->attach('document', self::content($document), 'document')
            ->attach('signature', $signature, 'signature');

        return $this->document($request, '/sign/complete', $this->options($options), $sink);
    }

    /**
     * The trusted lists' state, as the library reports it (README.md, "Trusted lists"): `oj_keystore` (`path`,
     * `sha256`), `last_offline_refresh`, `last_online_refresh` (each with `duration_ms`, never negative), …
     *
     * @return array<string, mixed>
     */
    public function trustedListStatus(): array
    {
        return $this->result($this->request()->get('/tl/status'));
    }

    /**
     * Starts an online refresh of the trusted lists; trustedListStatus() shows how it went.
     *
     * @return bool true when a refresh was started, false when one was already running or requested
     */
    public function refreshTrustedLists(): bool
    {
        try {
            $this->result($this->request()->post('/tl/refresh'));
        } catch (DssException $e) {
            if ($e->errorCode === 'REFRESH_IN_PROGRESS') {
                return false;
            }
            throw $e;
        }

        return true;
    }

    /**
     * The server's, the library's and DSS's versions: `server`, `library`, `dss`, `runtime`, `api_version`.
     * Throws DssException INCOMPATIBLE_API_VERSION when the server reports an `api_version` other than
     * API_VERSION; a server without one (or with null) predates the field and is accepted as version 1.
     *
     * @return array<string, mixed>
     */
    public function version(): array
    {
        $response = $this->request()->get('/version');
        $version = $this->result($response);
        $api = $version['api_version'] ?? null;
        if ($api !== null && ! is_int($api)) {
            throw DssException::badResponse($response, 'api_version is not an integer');
        }
        if ($api !== null && $api !== self::API_VERSION) {
            $library = is_string($version['library'] ?? null) ? $version['library'] : 'unknown';
            throw new DssException('INCOMPATIBLE_API_VERSION', "the server speaks API version {$api} (library "
                ."{$library}), this client ".self::API_VERSION, $response->status());
        }

        return $version;
    }

    /**
     * Readiness: `ok` is true (HTTP 200) once the server can validate, false (503) with `status` `starting` or
     * `waiting_for_trusted_lists` until then. Neither is an exception; anything else throws DssException.
     *
     * @return array<string, mixed>
     */
    public function health(): array
    {
        // No token: /health needs none, and a missing token file must not hide whether the server is up.
        $response = $this->http->baseUrl($this->baseUrl)->timeout($this->timeoutSeconds)->acceptJson()->get('/health');
        $body = $response->json();
        if (($response->status() === 200 || $response->status() === 503)
            && is_array($body) && is_bool($body['ok'] ?? null) && is_string($body['status'] ?? null)) {
            return $body;
        }

        throw DssException::fromResponse($response);
    }

    /**
     * Whether every signature of a validation result, nested ones included, is TOTAL_PASSED (`all_passed`):
     * false for an unsigned document. It ignores modifiedAfterSigning(): check both.
     *
     * @param  array<string, mixed>  $result
     */
    public static function allPassed(array $result): bool
    {
        return ($result['all_passed'] ?? false) === true;
    }

    /**
     * Whether a PDF was changed after any of its signatures (`signatures[*].modified_after_signing`, nested
     * results included). Details are in each signature's `changes_after_signing`, whose `pages_differ` and
     * `annotations_overlap` are lists of 1-based page numbers (empty when nothing changed), not booleans.
     *
     * @param  array<string, mixed>  $result
     */
    public static function modifiedAfterSigning(array $result): bool
    {
        foreach ($result['signatures'] ?? [] as $signature) {
            if (is_array($signature) && ($signature['modified_after_signing'] ?? false) === true) {
                return true;
            }
        }
        // `nested` is a list of results, one per document found inside this one (a PDF inside a CAdES envelope).
        foreach ($result['nested'] ?? [] as $nested) {
            if (is_array($nested) && self::modifiedAfterSigning($nested)) {
                return true;
            }
        }

        return false;
    }

    private function request(): PendingRequest
    {
        $request = $this->http->baseUrl($this->baseUrl)->timeout($this->timeoutSeconds)->acceptJson();
        $token = $this->token ?? $this->readTokenFile();

        return $token === null ? $request : $request->withToken($token);
    }

    private function readTokenFile(): ?string
    {
        if ($this->tokenFile === null || $this->tokenFile === '') {
            return null;
        }
        $token = is_file($this->tokenFile) && is_readable($this->tokenFile)
            ? @file_get_contents($this->tokenFile)
            : false;
        if ($token === false) {
            throw new DssException('TOKEN_FILE_UNREADABLE', "token file {$this->tokenFile} cannot be read", 0);
        }
        $token = trim($token);
        if ($token === '') {
            throw new DssException('TOKEN_FILE_UNREADABLE', "token file {$this->tokenFile} is empty", 0);
        }

        return $token;
    }

    /**
     * The 'options' multipart part. An empty one is left out: it would encode as a JSON list.
     *
     * @param  array<string, mixed>  $options
     * @return array<string, string>
     */
    private function options(array $options): array
    {
        if ($options === []) {
            return [];
        }

        try {
            $json = json_encode(self::objects($options, self::OBJECT_KEYS), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            throw new DssException('INVALID_ARGUMENT', 'options cannot be encoded as JSON: '.$e->getMessage(), 0);
        }

        return ['options' => $json];
    }

    /**
     * Turns the empty arrays found under object-valued keys into objects, so that ['pades' => []] is sent as
     * {"pades":{}} and not as {"pades":[]}, which the library refuses.
     *
     * @param  array<array-key, mixed>  $values
     * @param  array<string, array<string, mixed>>  $objectKeys
     * @return array<array-key, mixed>
     */
    private static function objects(array $values, array $objectKeys): array
    {
        foreach ($objectKeys as $key => $children) {
            if (! array_key_exists($key, $values) || ! is_array($values[$key])) {
                continue;
            }
            $values[$key] = $values[$key] === [] ? new stdClass : self::objects($values[$key], $children);
        }

        return $values;
    }

    /**
     * A JSON answer: `{"ok":true,…}` is the result; anything else throws, a non-JSON 2xx as BAD_RESPONSE.
     *
     * @return array<string, mixed>
     */
    private function result(Response $response): array
    {
        $result = $response->json();
        if (! $response->successful() || ! is_array($result) || ($result['ok'] ?? false) !== true) {
            throw DssException::fromResponse($response);
        }

        return $result;
    }

    /** @return string|StreamInterface */
    private static function content(mixed $content): mixed
    {
        if (is_string($content) || $content instanceof StreamInterface) {
            return $content;
        }
        if (is_resource($content)) {
            return self::borrowed($content);
        }

        throw new InvalidArgumentException('a document must be a string, a stream resource or a PSR-7 stream');
    }

    /**
     * The caller's resource as a PSR-7 stream that never closes it. Guzzle's own Stream fcloses its resource in
     * its destructor, and wrapping one in a decorator that detaches it first is not enough: when the request
     * objects end up in a reference cycle, PHP's cycle collector destroys them in no fixed order and may close
     * the caller's handle through the inner Stream first (seen with the lowest Laravel 10 dependency set). So
     * this stream talks to the resource directly and has no destructor at all.
     *
     * Parameters are untyped and return types declared, so the class fits both psr/http-message 1.x and 2.x.
     *
     * @param  resource  $resource
     */
    private static function borrowed($resource): StreamInterface
    {
        return new class($resource) implements StreamInterface
        {
            /** @var resource|null */
            private $resource;

            /** @param resource $resource */
            public function __construct($resource)
            {
                $this->resource = $resource;
            }

            /** @return resource */
            private function handle()
            {
                if ($this->resource === null || ! is_resource($this->resource)) {
                    throw new \RuntimeException('the document stream is detached or closed');
                }

                return $this->resource;
            }

            public function __toString(): string
            {
                try {
                    if ($this->isSeekable()) {
                        $this->rewind();
                    }

                    return $this->getContents();
                } catch (\Throwable) {
                    return '';
                }
            }

            /** Lets go of the resource without closing it: the caller owns it. */
            public function close(): void
            {
                $this->resource = null;
            }

            public function detach()
            {
                $resource = $this->resource;
                $this->resource = null;

                return $resource;
            }

            public function getSize(): ?int
            {
                if ($this->resource === null || ! is_resource($this->resource)) {
                    return null;
                }
                $stat = fstat($this->resource);

                return is_array($stat) && isset($stat['size']) ? (int) $stat['size'] : null;
            }

            public function tell(): int
            {
                $position = ftell($this->handle());
                if ($position === false) {
                    throw new \RuntimeException('cannot tell the position of the document stream');
                }

                return $position;
            }

            public function eof(): bool
            {
                return $this->resource === null || ! is_resource($this->resource) || feof($this->resource);
            }

            public function isSeekable(): bool
            {
                return $this->resource !== null && is_resource($this->resource)
                    && (bool) (stream_get_meta_data($this->resource)['seekable'] ?? false);
            }

            public function seek($offset, $whence = SEEK_SET): void
            {
                if (fseek($this->handle(), (int) $offset, (int) $whence) !== 0) {
                    throw new \RuntimeException('cannot seek the document stream');
                }
            }

            public function rewind(): void
            {
                $this->seek(0);
            }

            public function isWritable(): bool
            {
                return false;
            }

            public function write($string): int
            {
                throw new \RuntimeException('the document stream is read-only');
            }

            public function isReadable(): bool
            {
                if ($this->resource === null || ! is_resource($this->resource)) {
                    return false;
                }
                $mode = (string) (stream_get_meta_data($this->resource)['mode'] ?? '');

                return str_contains($mode, 'r') || str_contains($mode, '+');
            }

            public function read($length): string
            {
                $length = (int) $length;
                if ($length < 0) {
                    throw new \RuntimeException('cannot read a negative length');
                }
                if ($length === 0) {
                    return '';
                }
                $data = fread($this->handle(), $length);
                if ($data === false) {
                    throw new \RuntimeException('cannot read the document stream');
                }

                return $data;
            }

            public function getContents(): string
            {
                $data = stream_get_contents($this->handle());
                if ($data === false) {
                    throw new \RuntimeException('cannot read the document stream');
                }

                return $data;
            }

            public function getMetadata($key = null): mixed
            {
                if ($this->resource === null || ! is_resource($this->resource)) {
                    return $key === null ? [] : null;
                }
                $meta = stream_get_meta_data($this->resource);

                return $key === null ? $meta : ($meta[$key] ?? null);
            }
        };
    }

    /**
     * A file name that is safe in a Content-Disposition header: quotes, backslashes and control characters
     * (CR and LF would break the multipart body) become '_'.
     */
    private static function filename(string $name): string
    {
        $name = preg_replace('/[\x00-\x1f\x7f"\\\\]/', '_', $name) ?? '';

        return $name === '' ? 'document' : $name;
    }

    /**
     * Posts a request whose answer is a document, with the result JSON in the Dss-Result header.
     *
     * With a sink, Guzzle writes the answer to a file of the client's (next to a path sink, or a temporary
     * stream for a resource sink); the sink itself receives it only once the answer is known to be a document,
     * so an error answer never reaches it, and the caller's resource is never handed to Guzzle (which would
     * fclose it).
     *
     * @param  array<string, string>  $data
     * @param  string|resource|null  $sink
     * @return array{0: ?string, 1: array<string, mixed>}
     */
    private function document(PendingRequest $request, string $url, array $data, mixed $sink): array
    {
        $part = null;
        if (is_resource($sink)) {
            $mode = stream_get_meta_data($sink)['mode'];
            if (strpbrk($mode, 'waxc+') === false) {
                throw new InvalidArgumentException("a sink resource must be writable (e.g. 'wb'), not '{$mode}'");
            }
            $request = $request->sink(fopen('php://temp', 'w+b'));
        } elseif (is_string($sink) && $sink !== '') {
            $part = $sink.'.'.bin2hex(random_bytes(6)).'.part';
            $request = $request->sink($part);
        } elseif ($sink !== null) {
            throw new InvalidArgumentException('a sink must be a file path or a stream resource');
        }

        try {
            $response = $request->post($url, $data);
            if (! $response->successful()) {
                throw DssException::fromResponse($response);
            }
            $header = $response->header('Dss-Result');
            if ($header === '') {
                throw DssException::badResponse($response, 'no Dss-Result header in the answer');
            }
            $result = json_decode($header, true);
            if (! is_array($result) || ($result['ok'] ?? null) === false) {
                throw DssException::badResponse($response, 'the Dss-Result header is not a result');
            }

            if ($sink === null) {
                return [$response->body(), $result];
            }
            $body = $response->toPsrResponse()->getBody();
            if ($part !== null) {
                $body->close();
                if (! is_file($part)) {
                    touch($part);   // an empty document: Guzzle opens its sink at the first byte only
                }
                if (! @rename($part, $sink)) {
                    throw new DssException('SINK_FAILED', "cannot move the document to {$sink}", 0);
                }
                $part = null;
            } else {
                self::copy($body, $sink);
            }

            return [null, $result];
        } finally {
            if ($part !== null && is_file($part)) {
                @unlink($part);
            }
        }
    }

    /**
     * Appends a returned document to a resource sink at its position; on a failed write, what was written is
     * cut off again (when the resource can seek), so the sink never holds part of a document.
     *
     * @param  resource  $sink
     */
    private static function copy(StreamInterface $body, $sink): void
    {
        if ($body->isSeekable()) {
            $body->rewind();
        }
        $start = ftell($sink);
        while (! $body->eof()) {
            $chunk = $body->read(self::CHUNK);
            $written = $chunk === '' ? 0 : @fwrite($sink, $chunk);
            if ($written !== strlen($chunk)) {
                if (is_int($start)) {
                    @ftruncate($sink, $start);
                    @fseek($sink, $start);
                }
                throw new DssException('SINK_FAILED', 'cannot write the document to the sink resource', 0);
            }
        }
    }
}
