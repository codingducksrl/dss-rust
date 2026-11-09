<?php

// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

declare(strict_types=1);

namespace App\Services\Dss\Tests;

use App\Services\Dss\DssClient;
use App\Services\Dss\DssException;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * The client against dss-server's contract (docs/server.md, docs/openapi.yaml), with Laravel's fake HTTP client:
 * no server, no network.
 */
final class DssClientTest extends TestCase
{
    private const RESULT = ['ok' => true, 'level' => 'PAdES-BASELINE-LT', 'format' => 'PAdES'];

    private Factory $http;

    private string $dir;

    protected function setUp(): void
    {
        $this->http = new Factory;
        $this->dir = sys_get_temp_dir().'/dss-client-test-'.bin2hex(random_bytes(6));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir.'/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }

    private function client(?string $token = null, ?string $tokenFile = null): DssClient
    {
        return new DssClient($this->http, 'http://dss.test:8484', $token, 30, $tokenFile);
    }

    /** @return list<Request> */
    private function sent(): array
    {
        return $this->http->recorded()->map(fn (array $pair) => $pair[0])->values()->all();
    }

    private static function json(array $body, int $status = 200, array $headers = []): \GuzzleHttp\Promise\PromiseInterface
    {
        return Factory::response($body, $status, $headers + ['Content-Type' => 'application/json']);
    }

    private static function error(string $code, int $status, array $headers = []): \GuzzleHttp\Promise\PromiseInterface
    {
        return self::json(['ok' => false, 'error' => ['code' => $code, 'message' => 'm']], $status, $headers);
    }

    private static function capture(callable $call): DssException
    {
        try {
            $call();
        } catch (DssException $e) {
            return $e;
        }
        self::fail('no DssException');
    }

    // ---- results and errors

    public function test_validate_sends_multipart_and_returns_the_result(): void
    {
        $this->http->fake(['*/validate' => self::json(['ok' => true, 'all_passed' => true, 'signatures' => []])]);

        $result = $this->client('t0ken-t0ken-t0ken')->validate('%PDF', 'contract.pdf', ['reports' => ['detailed']], ['a.txt' => 'A']);

        $this->assertTrue(DssClient::allPassed($result));
        $request = $this->sent()[0];
        $this->assertSame('http://dss.test:8484/validate', $request->url());
        $this->assertTrue($request->hasHeader('Authorization', 'Bearer t0ken-t0ken-t0ken'));
        $body = $request->body();
        $this->assertStringContainsString('name="document"; filename="contract.pdf"', $body);
        $this->assertStringContainsString('name="detached"; filename="a.txt"', $body);
        $this->assertStringContainsString('{"reports":["detailed"]}', $body);
    }

    public function test_error_json_becomes_dss_exception_with_retry_after(): void
    {
        $this->http->fake(['*' => self::error('SERVER_BUSY', 503, ['Retry-After' => '1'])]);

        $e = self::capture(fn () => $this->client()->validate('x', 'x.pdf'));

        $this->assertSame('SERVER_BUSY', $e->errorCode);
        $this->assertSame(503, $e->status);
        $this->assertSame(1, $e->retryAfter);
    }

    // F-105: a proxy page is cut, and a 2xx that is not the server's JSON is BAD_RESPONSE, not HTTP_200.
    public function test_foreign_error_body_is_truncated(): void
    {
        $page = '<html>'.str_repeat('é', 30000).'</html>';
        $this->http->fake(['*' => Factory::response($page, 502, ['Content-Type' => 'text/html'])]);

        $e = self::capture(fn () => $this->client()->validate('x', 'x.pdf'));

        $this->assertSame('HTTP_502', $e->errorCode);
        $this->assertLessThan(1100, strlen($e->getMessage()));
        $this->assertTrue(mb_check_encoding($e->getMessage(), 'UTF-8'));
    }

    public function test_2xx_foreign_body_is_bad_response(): void
    {
        $this->http->fake(['*' => Factory::response('<html>welcome</html>', 200, ['Content-Type' => 'text/html'])]);

        $e = self::capture(fn () => $this->client()->trustedListStatus());

        $this->assertSame('BAD_RESPONSE', $e->errorCode);
        $this->assertSame(200, $e->status);
    }

    // F-100: a document answer without (or with a broken) Dss-Result is DssException BAD_RESPONSE, not JsonException.
    public function test_document_without_result_header_is_bad_response(): void
    {
        $this->http->fake(['*' => Factory::response('%PDF-1.7', 200, ['Content-Type' => 'application/pdf'])]);

        $e = self::capture(fn () => $this->client()->extend('%PDF', 'LT'));

        $this->assertSame('BAD_RESPONSE', $e->errorCode);
        // The body is a document: its type and size, not its bytes.
        $this->assertStringNotContainsString('%PDF-1.7', $e->getMessage());
        $this->assertStringContainsString('application/pdf body of 8 bytes', $e->getMessage());
    }

    public function test_bad_response_quotes_a_textual_body(): void
    {
        $this->http->fake(['*' => Factory::response('<html>proxy says hi</html>', 200, ['Content-Type' => 'text/html; charset=utf-8'])]);

        $e = self::capture(fn () => $this->client()->extend('%PDF', 'LT'));

        $this->assertSame('BAD_RESPONSE', $e->errorCode);
        $this->assertStringContainsString('proxy says hi', $e->getMessage());
    }

    public function test_document_with_garbled_result_header_is_bad_response(): void
    {
        $this->http->fake(['*' => Factory::response('%PDF-1.7', 200, ['Dss-Result' => '{not json'])]);

        $e = self::capture(fn () => $this->client()->extend('%PDF', 'LT'));

        $this->assertSame('BAD_RESPONSE', $e->errorCode);
    }

    public function test_extend_returns_document_and_result(): void
    {
        $this->http->fake(['*/extend' => Factory::response('%PDF-LT', 200, [
            'Content-Type' => 'application/pdf',
            'Dss-Result' => json_encode(self::RESULT),
        ])]);

        [$pdf, $result] = $this->client()->extend('%PDF', 'LT', 'in.pdf');

        $this->assertSame('%PDF-LT', $pdf);
        $this->assertSame('PAdES-BASELINE-LT', $result['level']);
        $this->assertStringContainsString('{"level":"LT"}', $this->sent()[0]->body());
    }

    // ---- F-102: streams in, sink out

    public function test_stream_document_and_path_sink(): void
    {
        $this->http->fake(['*' => Factory::response('%PDF-LT', 200, ['Dss-Result' => json_encode(self::RESULT)])]);
        $in = fopen('php://temp', 'w+b');
        fwrite($in, '%PDF-streamed');
        rewind($in);
        $out = $this->dir.'/out.pdf';

        [$pdf, $result] = $this->client()->extend($in, 'LT', 'in.pdf', $out);

        $this->assertNull($pdf);
        $this->assertSame('PAdES-BASELINE-LT', $result['level']);
        $this->assertSame('%PDF-LT', file_get_contents($out));
        $this->assertStringContainsString('%PDF-streamed', $this->sent()[0]->body());
    }

    public function test_borrowed_resource_stream_never_closes_the_resource(): void
    {
        $in = fopen('php://temp', 'w+b');
        fwrite($in, 'abcdef');
        rewind($in);
        $borrow = new \ReflectionMethod(DssClient::class, 'borrowed');

        $stream = $borrow->invoke(null, $in);
        $this->assertSame(6, $stream->getSize());
        $this->assertTrue($stream->isReadable() && $stream->isSeekable() && ! $stream->isWritable());
        $this->assertSame('ab', $stream->read(2));
        $this->assertSame(2, $stream->tell());
        $this->assertSame('cdef', $stream->getContents());
        $this->assertTrue($stream->eof());
        $stream->rewind();
        $this->assertSame('abcdef', (string) $stream);
        $stream->close();
        unset($stream);

        // a stream in a reference cycle, destroyed by the cycle collector, must not close it either
        $cycle = new stdClass;
        $cycle->stream = $borrow->invoke(null, $in);
        $cycle->self = $cycle;
        unset($cycle);
        gc_collect_cycles();

        $this->assertTrue(is_resource($in) && get_resource_type($in) === 'stream');
        $this->assertSame('abcdef', (rewind($in) ? stream_get_contents($in) : ''));
        $this->assertTrue(fclose($in));
    }

    public function test_sink_is_cleared_on_error(): void
    {
        $this->http->fake(['*' => self::error('SIGNING_FAILED', 422)]);
        $out = $this->dir.'/signed.pdf';

        $e = self::capture(fn () => $this->client()->completeSignature('%PDF', ['mode' => 'cms'], 'sig', $out));

        $this->assertSame('SIGNING_FAILED', $e->errorCode);
        $this->assertFileDoesNotExist($out);
    }

    public function test_error_never_reaches_a_resource_sink(): void
    {
        $this->http->fake(['*' => self::error('EXTENSION_FAILED', 422)]);
        $sink = fopen('php://temp', 'w+b');
        fwrite($sink, 'PRIOR');

        $e = self::capture(fn () => $this->client()->extend('%PDF', 'LT', 'x.pdf', $sink));

        $this->assertSame('EXTENSION_FAILED', $e->errorCode);
        rewind($sink);
        $this->assertSame('PRIOR', stream_get_contents($sink));
    }

    public function test_resource_sink_receives_the_document_at_its_position(): void
    {
        $this->http->fake(['*' => Factory::response('%PDF-LT', 200, ['Dss-Result' => json_encode(self::RESULT)])]);
        $file = $this->dir.'/w.pdf';
        $sink = fopen($file, 'wb');   // write-only is enough: nothing is read back from the sink
        fwrite($sink, 'PRIOR|');

        [$pdf] = $this->client()->extend('%PDF', 'LT', 'x.pdf', $sink);
        fclose($sink);

        $this->assertNull($pdf);
        $this->assertSame('PRIOR|%PDF-LT', file_get_contents($file));
    }

    public function test_read_only_sink_is_refused(): void
    {
        $sink = fopen(__FILE__, 'rb');

        $this->expectException(InvalidArgumentException::class);
        $this->client()->extend('%PDF', 'LT', 'x.pdf', $sink);
    }

    // ---- F-103: file names cannot break the multipart body

    public function test_filename_is_sanitised(): void
    {
        $this->http->fake(['*' => self::json(['ok' => true])]);

        $this->client()->validate('DATA', "a\"b\r\nContent-Type: x\r\n\r\n.pdf", [], ["d\"\n.txt" => 'D']);

        $body = $this->sent()[0]->body();
        $this->assertStringContainsString('filename="a_b__Content-Type: x____.pdf"', $body);
        $this->assertStringContainsString('filename="d__.txt"', $body);
        $this->assertStringNotContainsString("a\"b", $body);
    }

    // ---- F-104: options encoding

    public function test_empty_object_options_are_sent_as_objects(): void
    {
        $this->http->fake(['*' => self::json(['ok' => true, 'digest' => 'AA=='])]);

        $this->client()->prepareSignature('%PDF', ['mode' => 'cms', 'reports' => [], 'pades' => []]);
        $this->client()->prepareSignature('%PDF', ['mode' => 'cms', 'pades' => ['reason' => 'r', 'visible' => []]]);

        [$first, $second] = $this->sent();
        $this->assertStringContainsString('{"mode":"cms","reports":[],"pades":{}}', $first->body());
        $this->assertStringContainsString('{"mode":"cms","pades":{"reason":"r","visible":{}}}', $second->body());
    }

    public function test_options_that_are_not_utf8_throw_dss_exception(): void
    {
        $this->http->fake();

        $e = self::capture(fn () => $this->client()->prepareSignature('%PDF', ['pades' => ['reason' => "\xff"]]));

        $this->assertSame('INVALID_ARGUMENT', $e->errorCode);
        $this->assertSame(0, $e->status);
        $this->assertSame([], $this->sent());
    }

    // ---- F-099: the token file is read at each request, and an unreadable one is an error, not "no token"

    public function test_token_file_is_read_lazily(): void
    {
        $this->http->fake(['*' => self::json(['ok' => true])]);
        $file = $this->dir.'/token';
        $client = $this->client(tokenFile: $file);   // the file does not exist yet: no error at construction

        file_put_contents($file, "first-token-0123456\n");
        $client->version();
        file_put_contents($file, "second-token-012345\n");
        $client->version();

        [$a, $b] = $this->sent();
        $this->assertTrue($a->hasHeader('Authorization', 'Bearer first-token-0123456'));
        $this->assertTrue($b->hasHeader('Authorization', 'Bearer second-token-012345'));
    }

    public function test_missing_token_file_throws(): void
    {
        $this->http->fake();

        $e = self::capture(fn () => $this->client(tokenFile: $this->dir.'/absent')->trustedListStatus());

        $this->assertSame('TOKEN_FILE_UNREADABLE', $e->errorCode);
        $this->assertSame([], $this->sent());
    }

    public function test_empty_token_file_throws(): void
    {
        file_put_contents($this->dir.'/token', "\n");

        $e = self::capture(fn () => $this->client(tokenFile: $this->dir.'/token')->trustedListStatus());

        $this->assertSame('TOKEN_FILE_UNREADABLE', $e->errorCode);
    }

    public function test_empty_token_file_setting_means_no_token(): void
    {
        $this->http->fake(['*' => self::json(['ok' => true])]);

        $this->client(tokenFile: '')->version();

        $this->assertFalse($this->sent()[0]->hasHeader('Authorization'));
    }

    public function test_token_and_token_file_together_are_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->client('t', '/run/secrets/dss_token');
    }

    // ---- F-109: health(), version(), refresh

    public function test_health_returns_ready_and_not_ready_without_token(): void
    {
        $this->http->fake(['*/health' => $this->http->sequence()
            ->push(['ok' => true, 'status' => 'ready', 'trusted_lists_loaded' => true], 200)
            ->push(['ok' => false, 'status' => 'waiting_for_trusted_lists'], 503)
            ->push('<html>bad gateway</html>', 502)]);
        $client = $this->client(tokenFile: $this->dir.'/absent');

        $this->assertTrue($client->health()['ok']);
        $this->assertSame('waiting_for_trusted_lists', $client->health()['status']);
        $this->assertSame('HTTP_502', self::capture(fn () => $client->health())->errorCode);
        $this->assertFalse($this->sent()[0]->hasHeader('Authorization'));
    }

    public function test_version(): void
    {
        $this->http->fake(['*/version' => self::json(['ok' => true, 'server' => '1.0.0', 'api_version' => DssClient::API_VERSION])]);

        $this->assertSame('1.0.0', $this->client()->version()['server']);
    }

    // F-196: a server speaking another API version is refused; one without the field predates it and is accepted.
    public function test_version_checks_the_api_version(): void
    {
        $this->http->fake(['*/version' => $this->http->sequence()
            ->push(['ok' => true, 'library' => '0.9.0'], 200)
            ->push(['ok' => true, 'library' => '0.9.0', 'api_version' => null], 200)
            ->push(['ok' => true, 'library' => '2.0.0', 'api_version' => DssClient::API_VERSION + 1], 200)
            ->push(['ok' => true, 'api_version' => '1'], 200)]);
        $client = $this->client();

        $this->assertArrayNotHasKey('api_version', $client->version());
        $this->assertNull($client->version()['api_version']);
        $e = self::capture(fn () => $client->version());
        $this->assertSame('INCOMPATIBLE_API_VERSION', $e->errorCode);
        $this->assertStringContainsString('2.0.0', $e->getMessage());
        $this->assertSame('BAD_RESPONSE', self::capture(fn () => $client->version())->errorCode);
    }

    // F-064: the status is passed through as the library's JSON, new fields included.
    public function test_trusted_list_status_passes_new_fields_through(): void
    {
        $keystore = ['path' => '/etc/dss/oj.p12', 'sha256' => str_repeat('ab', 32)];
        $this->http->fake(['*/tl/status' => self::json([
            'ok' => true,
            'oj_keystore' => $keystore,
            'last_offline_refresh' => ['duration_ms' => 12],
        ])]);

        $status = $this->client()->trustedListStatus();

        $this->assertSame($keystore, $status['oj_keystore']);
        $this->assertSame(12, $status['last_offline_refresh']['duration_ms']);
    }

    public function test_refresh_returns_false_when_one_is_running(): void
    {
        $this->http->fake(['*/tl/refresh' => $this->http->sequence()
            ->push(['ok' => true], 202)
            ->push(['ok' => false, 'error' => ['code' => 'REFRESH_IN_PROGRESS', 'message' => 'm']], 409)
            ->push(['ok' => false, 'error' => ['code' => 'UNAUTHORIZED', 'message' => 'm']], 401)]);
        $client = $this->client();

        $this->assertTrue($client->refreshTrustedLists());
        $this->assertFalse($client->refreshTrustedLists());
        $this->assertSame('UNAUTHORIZED', self::capture(fn () => $client->refreshTrustedLists())->errorCode);
    }

    // ---- result helpers

    public function test_modified_after_signing_looks_at_every_signature_and_nested_results(): void
    {
        $clean = ['all_passed' => true, 'signatures' => [['modified_after_signing' => false], ['modified_after_signing' => null]]];
        $this->assertFalse(DssClient::modifiedAfterSigning($clean));
        $this->assertTrue(DssClient::allPassed($clean));

        $modified = $clean;
        $modified['signatures'][] = ['modified_after_signing' => true];
        $this->assertTrue(DssClient::modifiedAfterSigning($modified));

        // `nested` is a list of results (docs/openapi.yaml, Reports.nested), e.g. a PDF inside a CAdES envelope.
        $nested = ['signatures' => [], 'nested' => [['signatures' => [['modified_after_signing' => true]]]]];
        $this->assertTrue(DssClient::modifiedAfterSigning($nested));
        $second = ['signatures' => [], 'nested' => [
            ['signatures' => [['modified_after_signing' => false]]],
            ['signatures' => [], 'nested' => [['signatures' => [['modified_after_signing' => true]]]]],
        ]];
        $this->assertTrue(DssClient::modifiedAfterSigning($second));
        $second['nested'][1]['nested'][0]['signatures'][0]['modified_after_signing'] = false;
        $this->assertFalse(DssClient::modifiedAfterSigning($second));
        $this->assertFalse(DssClient::allPassed(['signatures' => []]));
    }
    public function test_changes_after_signing_page_lists_pass_through(): void
    {
        // The library reports changes_after_signing.pages_differ (and annotations_overlap) as lists of 1-based
        // page numbers, not booleans; the client passes them through untouched, and modifiedAfterSigning()
        // reads only the modified_after_signing flag.
        $signature = ['indication' => 'TOTAL_PASSED', 'modified_after_signing' => true, 'changes_after_signing' => [
            'pages_differ' => [2, 3], 'annotations_overlap' => [], 'modified_after_signing' => true,
        ]];
        $this->http->fake(['*/validate' => self::json(['ok' => true, 'all_passed' => true, 'signatures' => [$signature]])]);

        $result = $this->client()->validate('%PDF', 'a.pdf');

        $this->assertSame([2, 3], $result['signatures'][0]['changes_after_signing']['pages_differ']);
        $this->assertTrue(DssClient::modifiedAfterSigning($result));

        $unchanged = ['signatures' => [['modified_after_signing' => false, 'changes_after_signing' => ['pages_differ' => []]]]];
        $this->assertFalse(DssClient::modifiedAfterSigning($unchanged));
    }
}
