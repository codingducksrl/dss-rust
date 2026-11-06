<?php

// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

declare(strict_types=1);

namespace App\Services\Dss;

use Illuminate\Http\Client\Response;
use RuntimeException;

/**
 * An `{"ok":false}` answer from dss-server: the library's error code (INVALID_ARGUMENT, UNSUPPORTED_DOCUMENT,
 * EXTENSION_FAILED, SIGNING_FAILED, TRUSTED_LISTS_NOT_LOADED, …) or the server's (UNAUTHORIZED, NOT_INITIALIZED
 * while it starts, REQUEST_TOO_LARGE). docs/server.md lists them with their HTTP status.
 */
final class DssException extends RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly int $status,
    ) {
        parent::__construct("{$errorCode}: {$message}", $status);
    }

    public static function fromResponse(Response $response): self
    {
        $error = $response->json('error');

        return is_array($error)
            ? new self((string) ($error['code'] ?? 'UNKNOWN'), (string) ($error['message'] ?? ''), $response->status())
            : new self('HTTP_'.$response->status(), $response->body(), $response->status());
    }
}
