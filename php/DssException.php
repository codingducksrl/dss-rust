<?php

// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

declare(strict_types=1);

namespace App\Services\Dss;

use GuzzleHttp\Psr7\Utils;
use Illuminate\Http\Client\Response;
use RuntimeException;

/**
 * An `{"ok":false}` answer from dss-server: the library's error code (INVALID_ARGUMENT, UNSUPPORTED_DOCUMENT,
 * VALIDATION_FAILED, EXTENSION_FAILED, SIGNING_FAILED, TSA_FAILED, TRUSTED_LISTS_NOT_LOADED, …) or the server's
 * (UNAUTHORIZED, FORBIDDEN, NOT_INITIALIZED while it starts, REQUEST_TOO_LARGE, SERVER_BUSY, TIMEOUT, …).
 * docs/server.md lists them with their HTTP status.
 *
 * The client raises a few codes of its own, with `status` 0 when no answer was involved:
 * - BAD_RESPONSE: an answer that is not dss-server's (a proxy's page, a wrong DSS_URL, a missing `Dss-Result`
 *   header); `status` is the HTTP status received. The message quotes the start of a textual body only; for
 *   any other body (a document) it gives the Content-Type and the size.
 * - INCOMPATIBLE_API_VERSION: version() found a server speaking another `api_version` than the client's.
 * - SINK_FAILED (status 0): the returned document could not be written to the sink.
 * - INVALID_ARGUMENT (status 0): options that cannot be encoded as JSON (invalid UTF-8, for instance).
 * - TOKEN_FILE_UNREADABLE (status 0): the configured token file is missing, unreadable or empty.
 *
 * `retryAfter` is the `Retry-After` header in seconds when the server sent one (503 SERVER_BUSY).
 */
final class DssException extends RuntimeException
{
    /** Longest part of a body that is not dss-server's JSON copied into the message, in bytes. */
    public const MAX_BODY_IN_MESSAGE = 1000;

    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly int $status,
        public readonly ?int $retryAfter = null,
    ) {
        parent::__construct("{$errorCode}: {$message}", $status);
    }

    public static function fromResponse(Response $response): self
    {
        $error = $response->json('error');
        $retryAfter = self::retryAfter($response);

        if (is_array($error) && isset($error['code']) && is_string($error['code'])) {
            return new self($error['code'], (string) ($error['message'] ?? ''), $response->status(), $retryAfter);
        }

        // Not the server's error JSON: a proxy or another service answered.
        $code = $response->successful() ? 'BAD_RESPONSE' : 'HTTP_'.$response->status();

        return new self($code, self::excerpt($response), $response->status(), $retryAfter);
    }

    public static function badResponse(Response $response, string $reason): self
    {
        $type = $response->header('Content-Type');
        if (self::isText($type)) {
            $detail = self::excerpt($response);
        } else {
            // A document (PDF, CMS): its bytes do not belong in a message or a log.
            $size = $response->toPsrResponse()->getBody()->getSize();
            $detail = ($type === '' ? 'a body without Content-Type' : "a {$type} body")
                .' of '.($size === null ? 'unknown size' : "{$size} bytes");
        }

        return new self('BAD_RESPONSE', "{$reason}: {$detail}", $response->status());
    }

    private static function isText(string $contentType): bool
    {
        $type = strtolower(trim(explode(';', $contentType, 2)[0]));

        return str_starts_with($type, 'text/') || preg_match('~^[a-z0-9.+-]+/([a-z0-9.-]+\+)?(json|xml)$~', $type) === 1;
    }

    /**
     * The start of the body, cut on a UTF-8 boundary, so that a large page does not flood the logs. Reads at
     * most MAX_BODY_IN_MESSAGE + 1 bytes of it.
     */
    private static function excerpt(Response $response): string
    {
        $stream = $response->toPsrResponse()->getBody();
        if ($stream->isSeekable()) {
            $stream->rewind();
        }
        $head = Utils::copyToString($stream, self::MAX_BODY_IN_MESSAGE + 1);
        $size = $stream->getSize();
        if (strlen($head) <= self::MAX_BODY_IN_MESSAGE) {
            return $head;
        }

        return mb_strcut($head, 0, self::MAX_BODY_IN_MESSAGE, 'UTF-8')
            .'… ('.($size === null ? 'more than '.self::MAX_BODY_IN_MESSAGE : $size).' bytes)';
    }

    private static function retryAfter(Response $response): ?int
    {
        $value = trim($response->header('Retry-After'));

        return ctype_digit($value) ? (int) $value : null;
    }
}
