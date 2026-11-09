<?php

// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

declare(strict_types=1);

namespace App\Services\Dss\Tests;

use App\Services\Dss\DssClient;
use App\Services\Dss\DssException;
use Illuminate\Http\Client\Factory;
use PHPUnit\Framework\TestCase;

/**
 * Streams and sinks through Guzzle's real handler, against fixtures/router.php under `php -S` on 127.0.0.1.
 * Laravel's fake client writes to a sink itself and never wraps resources, so it cannot show what Guzzle does
 * with them (F-102: Guzzle's stream wrapper fcloses a raw resource it was given).
 */
final class RealHandlerTest extends TestCase
{
    /** @var resource|null */
    private static $server = null;

    private static string $url = '';

    private string $dir;

    public static function setUpBeforeClass(): void
    {
        $probe = stream_socket_server('tcp://127.0.0.1:0');
        $address = stream_socket_get_name($probe, false);
        fclose($probe);
        self::$server = proc_open(
            [PHP_BINARY, '-S', $address, __DIR__.'/fixtures/router.php'],
            [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
        );
        self::$url = "http://{$address}";
        for ($i = 0; $i < 100; $i++) {
            $socket = @stream_socket_client("tcp://{$address}", $errno, $error, 0.1);
            if ($socket !== false) {
                fclose($socket);

                return;
            }
            usleep(50_000);
        }
        self::fail("php -S did not start on {$address}");
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$server)) {
            proc_terminate(self::$server);
            proc_close(self::$server);
        }
    }

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/dss-client-real-'.bin2hex(random_bytes(6));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir.'/{,.}*', GLOB_BRACE) ?: [] as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        rmdir($this->dir);
    }

    private static function client(string $mode): DssClient
    {
        return new DssClient(new Factory, self::$url.'/'.$mode, timeoutSeconds: 10);
    }

    public function test_resource_sink_and_document_stay_open(): void
    {
        $in = fopen('php://temp', 'w+b');
        fwrite($in, '%PDF-in');
        rewind($in);
        $sink = fopen($this->dir.'/out.pdf', 'w+b');

        [$pdf, $result] = self::client('ok')->extend($in, 'LT', 'in.pdf', $sink);
        gc_collect_cycles();

        $this->assertNull($pdf);
        $this->assertSame('PAdES-BASELINE-LT', $result['level']);
        $this->assertTrue(is_resource($sink) && get_resource_type($sink) === 'stream', 'the sink was closed');
        $this->assertTrue(is_resource($in) && get_resource_type($in) === 'stream', 'the document was closed');
        rewind($sink);
        $this->assertSame('EXTENDED:%PDF-in', stream_get_contents($sink));
        $this->assertTrue(fclose($sink));
        $this->assertTrue(fclose($in));
    }

    public function test_write_only_resource_sink_receives_the_document_after_prior_content(): void
    {
        $file = $this->dir.'/out.pdf';
        $sink = fopen($file, 'wb');
        fwrite($sink, 'PRIOR|');

        self::client('ok')->extend('%PDF-in', 'LT', 'in.pdf', $sink);
        fclose($sink);

        $this->assertSame('PRIOR|EXTENDED:%PDF-in', file_get_contents($file));
    }

    public function test_error_answer_keeps_its_code_and_never_reaches_a_resource_sink(): void
    {
        $sink = fopen('php://temp', 'w+b');
        fwrite($sink, 'PRIOR');

        try {
            self::client('error')->extend('%PDF', 'LT', 'x.pdf', $sink);
            $this->fail('no DssException');
        } catch (DssException $e) {
            $this->assertSame('EXTENSION_FAILED', $e->errorCode);
            $this->assertSame(422, $e->status);
        }
        gc_collect_cycles();

        rewind($sink);
        $this->assertSame('PRIOR', stream_get_contents($sink));
    }

    public function test_path_sink_is_written_whole_or_not_at_all(): void
    {
        $out = $this->dir.'/out.pdf';
        file_put_contents($out, 'OLD');

        try {
            self::client('error')->extend('%PDF', 'LT', 'x.pdf', $out);
            $this->fail('no DssException');
        } catch (DssException $e) {
            $this->assertSame('EXTENSION_FAILED', $e->errorCode);
        }
        $this->assertSame('OLD', file_get_contents($out));

        self::client('ok')->extend('%PDF-in', 'LT', 'x.pdf', $out);
        $this->assertSame('EXTENDED:%PDF-in', file_get_contents($out));
        $this->assertSame([$out], glob($this->dir.'/*'), 'a .part file was left behind');
    }

    public function test_bad_response_does_not_quote_the_document(): void
    {
        $out = $this->dir.'/out.pdf';

        try {
            self::client('nohdr')->extend('%PDF', 'LT', 'x.pdf', $out);
            $this->fail('no DssException');
        } catch (DssException $e) {
            $this->assertSame('BAD_RESPONSE', $e->errorCode);
            $this->assertStringNotContainsString('secret', $e->getMessage());
            $this->assertStringContainsString('application/pdf', $e->getMessage());
        }
        $this->assertSame([], glob($this->dir.'/*'));
    }

    public function test_resource_document_for_validate_stays_open(): void
    {
        $in = fopen('php://temp', 'w+b');
        fwrite($in, str_repeat('A', 100_000));
        rewind($in);

        $result = self::client('ok')->validate($in, 'a.pdf');
        gc_collect_cycles();

        $this->assertSame(100_000, $result['size']);
        $this->assertTrue(is_resource($in) && get_resource_type($in) === 'stream');
        $this->assertTrue(fclose($in));
    }
}
