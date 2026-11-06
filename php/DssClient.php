<?php

// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

declare(strict_types=1);

namespace App\Services\Dss;

use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;

/**
 * Laravel client for dss-server (docs/server.md). Copy this file and DssException.php into the application.
 *
 * Results are the library's JSON as arrays (README.md, "API"). A failed signature is a result, not an exception:
 * check `signatures[*].indication`. Every `{"ok":false}` answer throws DssException with the error code.
 */
final class DssClient
{
    public function __construct(
        private readonly Factory $http,
        private readonly string $baseUrl = 'http://dss:8484',
        private readonly ?string $token = null,
        private readonly int $timeoutSeconds = 120,
    ) {}

    /**
     * Validates a PDF or CMS/CAdES document.
     *
     * @param  array<string, mixed>  $options  options_json, e.g. ['reports' => ['detailed']]
     * @param  array<string, string>  $detached  detached contents, file name => bytes
     * @return array<string, mixed>
     */
    public function validate(string $document, string $filename, array $options = [], array $detached = []): array
    {
        $request = $this->request()->attach('document', $document, $filename);
        foreach ($detached as $name => $content) {
            $request = $request->attach('detached', $content, $name);
        }

        return $this->result($request->post('/validate', $this->options($options)));
    }

    /**
     * Extends every signature of a PDF to PAdES-BASELINE-T, -LT or -LTA.
     *
     * @return array{0: string, 1: array<string, mixed>} the extended PDF, and the result
     */
    public function extend(string $pdf, string $level, string $filename = 'document.pdf'): array
    {
        $request = $this->request()->attach('document', $pdf, $filename);

        return $this->document($request->post('/extend', $this->options(['level' => $level])));
    }

    /**
     * Signing with an external signer, step 1: the digest to sign, and the signing time to pass to step 2.
     *
     * @param  array<string, mixed>  $options  mode, level, signing_certificate, pades, …
     * @return array<string, mixed>
     */
    public function prepareSignature(string $document, array $options): array
    {
        $request = $this->request()->attach('document', $document, 'document');

        return $this->result($request->post('/sign/prepare', $this->options($options)));
    }

    /**
     * Step 2: the same document and options as step 1, with 'signing_time' set to the one it returned.
     *
     * @param  array<string, mixed>  $options
     * @return array{0: string, 1: array<string, mixed>} the signed document, and the result
     */
    public function completeSignature(string $document, array $options, string $signature): array
    {
        $request = $this->request()
            ->attach('document', $document, 'document')
            ->attach('signature', $signature, 'signature');

        return $this->document($request->post('/sign/complete', $this->options($options)));
    }

    /** @return array<string, mixed> */
    public function trustedListStatus(): array
    {
        return $this->result($this->request()->get('/tl/status'));
    }

    /** Starts an online refresh of the trusted lists; trustedListStatus() shows how it went. */
    public function refreshTrustedLists(): void
    {
        $this->result($this->request()->post('/tl/refresh'));
    }

    private function request(): PendingRequest
    {
        $request = $this->http->baseUrl($this->baseUrl)->timeout($this->timeoutSeconds)->acceptJson();

        return $this->token === null ? $request : $request->withToken($this->token);
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

        return ['options' => json_encode($options, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)];
    }

    /** @return array<string, mixed> */
    private function result(Response $response): array
    {
        $result = $response->json();
        if (! is_array($result) || ($result['ok'] ?? false) !== true) {
            throw DssException::fromResponse($response);
        }

        return $result;
    }

    /** @return array{0: string, 1: array<string, mixed>} */
    private function document(Response $response): array
    {
        if (! $response->successful()) {
            throw DssException::fromResponse($response);
        }

        return [$response->body(), json_decode($response->header('Dss-Result'), true, flags: JSON_THROW_ON_ERROR)];
    }
}
