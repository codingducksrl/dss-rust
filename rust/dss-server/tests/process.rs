// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! The `dss-server` executable: listening before the engine is up, readiness, SIGTERM, and a failed start.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// `dss-server` with an offline engine, on a free port.
fn dss_server(name: &str, oj_keystore: &Path) -> Command {
    let root = repo_root();
    let cache = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dss-server"));
    cmd.args(["--listen", "127.0.0.1:0", "--refresh-hours", "0"])
        .arg("--cache-dir")
        .arg(&cache)
        .arg("--oj-keystore")
        .arg(oj_keystore)
        .arg("--trust")
        .arg(root.join("testdata/fixtures/pki/root-ca.pem"))
        .args(["--allow-without-trusted-lists", "--offline-revocation"])
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd
}

/// The server's stderr, line by line.
fn stderr_lines(child: &mut Child) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    let stderr = BufReader::new(child.stderr.take().unwrap());
    std::thread::spawn(move || {
        for line in stderr.lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    rx
}

fn wait_for(lines: &mpsc::Receiver<String>, needle: &str) -> String {
    loop {
        let line = lines
            .recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|e| panic!("no '{needle}' on stderr: {e}"));
        if line.contains(needle) {
            return line;
        }
    }
}

fn http_get(addr: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn serves_until_sigterm() {
    let mut child = dss_server("process-cache", &repo_root().join("trust/oj-keystore.p12"))
        .spawn()
        .expect("spawn dss-server");
    let lines = stderr_lines(&mut child);
    let addr = wait_for(&lines, "listening on ").rsplit(' ').next().unwrap().to_owned();

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let response = http_get(&addr, "/health");
        if response.starts_with("HTTP/1.1 200") {
            assert!(response.contains(r#""status":"ready""#), "{response}");
            break;
        }
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(Instant::now() < deadline, "not ready after 60 s");
        std::thread::sleep(Duration::from_millis(100));
    }

    let check = |addr: &str| {
        Command::new(env!("CARGO_BIN_EXE_dss-server"))
            .args(["--health-check", "--listen", addr])
            .status()
            .unwrap()
            .code()
    };
    assert_eq!(check(&addr), Some(0));
    let port = addr.rsplit(':').next().unwrap();
    assert_eq!(
        check(&format!("0.0.0.0:{port}")),
        Some(0),
        "an unspecified address means this host"
    );

    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    wait_for(&lines, "stopping");
    let status = child.wait().unwrap();
    assert!(status.success(), "{status}");
    assert_eq!(check(&addr), Some(1), "nothing listens any more");
}

#[test]
fn exits_when_the_engine_cannot_start() {
    let mut child = dss_server("process-fail", Path::new("/nonexistent/oj-keystore.p12"))
        .spawn()
        .expect("spawn dss-server");
    let lines = stderr_lines(&mut child);
    wait_for(&lines, "the engine did not start");
    assert_eq!(child.wait().unwrap().code(), Some(2));
}
