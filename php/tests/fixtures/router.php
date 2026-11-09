<?php

// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

// A stand-in for dss-server under `php -S`, for RealHandlerTest: the first path segment picks the answer.

declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
[, $mode, $endpoint] = array_pad(explode('/', $path, 3), 3, '');

if ($endpoint === 'validate') {
    header('Content-Type: application/json');
    echo json_encode(['ok' => true, 'size' => filesize($_FILES['document']['tmp_name'])]);

    return;
}

switch ($mode) {
    case 'ok':
        header('Content-Type: application/pdf');
        header('Dss-Result: '.json_encode(['ok' => true, 'level' => 'PAdES-BASELINE-LT']));
        echo 'EXTENDED:', file_get_contents($_FILES['document']['tmp_name']);
        break;
    case 'error':
        http_response_code(422);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'error' => ['code' => 'EXTENSION_FAILED', 'message' => 'no revocation data']]);
        break;
    case 'nohdr':
        header('Content-Type: application/pdf');
        echo "%PDF-1.7\n%\xe2\xe3\xcf\xd3 secret document body";
        break;
    default:
        http_response_code(404);
}
