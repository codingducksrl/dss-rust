// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! The `dss-server` executable: listening before the engine is up, readiness, the token file, environment
//! variables, the refresh schedule, SIGTERM (graceful and forced) and a failed start.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// A fresh directory under cargo's per-target temp dir, removed when dropped (after the server using it has
/// exited).
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        // The library may still create the cache directory from a background thread for a moment after
        // the server's shutdown: remove it again until it stays gone.
        for _ in 0..40 {
            let _ = std::fs::remove_dir_all(&self.0);
            std::thread::sleep(std::time::Duration::from_millis(25));
            if !self.0.exists() {
                break;
            }
        }
    }
}

fn temp_dir(name: &str) -> TempDir {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "process-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    TempDir(dir)
}

/// `dss-server` on a free port, caching in `dir`, with no engine option yet.
fn bare_server(dir: &TempDir, refresh_hours: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dss-server"));
    cmd.args(["--listen", "127.0.0.1:0", "--refresh-hours", refresh_hours])
        .arg("--cache-dir")
        .arg(dir.0.join("cache"))
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd
}

/// `dss-server` with an offline engine, on a free port, caching in `dir`.
fn dss_server(dir: &TempDir, oj_keystore: &Path) -> Command {
    dss_server_refreshing_every(dir, oj_keystore, "0")
}

fn dss_server_refreshing_every(dir: &TempDir, oj_keystore: &Path, refresh_hours: &str) -> Command {
    let root = repo_root();
    let mut cmd = bare_server(dir, refresh_hours);
    cmd.arg("--oj-keystore")
        .arg(oj_keystore)
        .arg("--trust")
        .arg(root.join("testdata/fixtures/pki/root-ca.pem"))
        .args(["--allow-without-trusted-lists", "--offline-revocation"]);
    cmd
}

/// A running server: its process, its stderr lines and its address.
struct Running {
    child: Child,
    lines: mpsc::Receiver<String>,
    addr: String,
}

impl Running {
    fn start(mut cmd: Command) -> Self {
        let mut child = cmd.spawn().expect("spawn dss-server");
        let lines = stderr_lines(&mut child);
        let addr = wait_for(&lines, "listening on ").rsplit(' ').next().unwrap().to_owned();
        Running { child, lines, addr }
    }

    fn wait_until_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let response = http_get(&self.addr, "/health");
            if response.starts_with("HTTP/1.1 200") {
                assert!(response.contains(r#""status":"ready""#), "{response}");
                return;
            }
            assert!(response.starts_with("HTTP/1.1 503"), "{response}");
            assert!(Instant::now() < deadline, "not ready after 60 s");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn signal(&self, name: &str) {
        let killed = Command::new("kill")
            .args([name, &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(killed.success());
    }

    /// A connection that has sent the request line and headers of an upload and part of its body, and then
    /// stalls.
    fn stalled_upload(&self) -> TcpStream {
        let mut stream = TcpStream::connect(&self.addr).unwrap();
        write!(
            stream,
            "POST /validate HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; \
             boundary=xyz\r\nContent-Length: 1000000\r\n\r\n--xyz\r\nContent-Disposition: form-data; \
             name=\"document\"\r\n\r\n%PDF-"
        )
        .unwrap();
        stream.flush().unwrap();
        stream
    }
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
    drain_until(lines, needle).pop().unwrap()
}

/// Every stderr line up to and including the first one containing `needle`.
fn drain_until(lines: &mpsc::Receiver<String>, needle: &str) -> Vec<String> {
    let mut seen = vec![];
    loop {
        let line = lines
            .recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|e| panic!("no '{needle}' on stderr: {e}"));
        let found = line.contains(needle);
        seen.push(line);
        if found {
            return seen;
        }
    }
}

fn http_get(addr: &str, path: &str) -> String {
    http_get_with(addr, path, "")
}

fn http_get_with(addr: &str, path: &str, headers: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

/// A `POST /validate` of the fixture `rel` asking for every report, as raw HTTP/1.1 with `Connection: close`.
fn validate_request(rel: &str) -> Vec<u8> {
    let document = std::fs::read(repo_root().join("testdata/fixtures").join(rel)).unwrap();
    let mut body = b"--xyz\r\nContent-Disposition: form-data; name=\"options\"\r\n\r\n\
         {\"reports\":[\"detailed\",\"etsi\",\"diagnostic\"]}\r\n\
         --xyz\r\nContent-Disposition: form-data; name=\"document\"; filename=\"document.pdf\"\r\n\r\n"
        .to_vec();
    body.extend_from_slice(&document);
    body.extend_from_slice(b"\r\n--xyz--\r\n");
    let mut request = format!(
        "POST /validate HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: multipart/form-data; boundary=xyz\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    request
}

/// Sends `request` and returns the whole response.
fn http_send(addr: &str, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(request).unwrap();
    stream.flush().unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn health_check(addr: &str) -> Option<i32> {
    Command::new(env!("CARGO_BIN_EXE_dss-server"))
        .args(["--health-check", "--listen", addr])
        .env_clear()
        .status()
        .unwrap()
        .code()
}

#[test]
fn serves_until_sigterm() {
    let dir = temp_dir("sigterm");
    let server = Running::start(dss_server(&dir, &repo_root().join("trust/oj-keystore.p12")));
    server.wait_until_ready();

    assert_eq!(health_check(&server.addr), Some(0));
    let port = server.addr.rsplit(':').next().unwrap();
    assert_eq!(
        health_check(&format!("0.0.0.0:{port}")),
        Some(0),
        "an unspecified address means this host"
    );

    server.signal("-TERM");
    wait_for(&server.lines, "stopping");
    let Running { mut child, addr, .. } = server;
    let status = child.wait().unwrap();
    assert!(status.success(), "{status}");
    assert_eq!(health_check(&addr), Some(1), "nothing listens any more");
}

#[test]
fn exits_when_the_engine_cannot_start() {
    let dir = temp_dir("fail");
    let mut child = dss_server(&dir, Path::new("/nonexistent/oj-keystore.p12"))
        .spawn()
        .expect("spawn dss-server");
    let lines = stderr_lines(&mut child);
    wait_for(&lines, "the engine did not start");
    assert_eq!(child.wait().unwrap().code(), Some(2));
}

/// Start-up failures name the file or option at fault.
#[test]
fn start_failures_name_their_cause() {
    let dir = temp_dir("causes");
    let keystore = repo_root().join("trust/oj-keystore.p12");
    let run = |configure: &dyn Fn(&mut Command)| -> (Option<i32>, String) {
        let mut cmd = dss_server(&dir, &keystore);
        configure(&mut cmd);
        let output = cmd.output().unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };

    let missing = dir.0.join("no-such-token");
    let (code, err) = run(&|c| {
        c.arg("--token-file").arg(&missing);
    });
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("token file") && err.contains("no-such-token"), "{err}");

    let empty = dir.0.join("empty-token");
    std::fs::write(&empty, " \n").unwrap();
    let (code, err) = run(&|c| {
        c.arg("--token-file").arg(&empty);
    });
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("the token file is empty"), "{err}");

    let short = dir.0.join("short-token");
    std::fs::write(&short, "s3cret\n").unwrap();
    let (code, err) = run(&|c| {
        c.arg("--token-file").arg(&short);
    });
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("6 bytes long") && err.contains("at least 16"), "{err}");

    let bare = |configure: &dyn Fn(&mut Command)| -> (Option<i32>, String) {
        let mut cmd = bare_server(&dir, "0");
        configure(&mut cmd);
        let output = cmd.output().unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let (code, err) = bare(&|c| {
        c.arg("--config").arg(dir.0.join("no-such-config.json"));
    });
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("config file") && err.contains("no-such-config.json"),
        "{err}"
    );

    let (code, err) = bare(&|c| {
        c.arg("--config").arg(dir.0.join("x.json")).arg("--country").arg("IT");
    });
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("--config") && err.contains("--country"),
        "an option a config file replaces is refused with it, not dropped: {err}"
    );
    let (code, err) = bare(&|c| {
        c.arg("--config").arg(dir.0.join("x.json")).env("DSS_COUNTRIES", "IT");
    });
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("--config") && err.contains("--country"),
        "also from the environment: {err}"
    );
    let (code, err) = bare(&|c| {
        c.arg("--config")
            .arg(dir.0.join("x.json"))
            .arg("--allow-private-addresses");
    });
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("--config") && err.contains("--allow-private-addresses"),
        "a config file sets http.block_private_addresses itself: {err}"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_dss-server"))
        .args(["--listen", "127.0.0.1:0", "--refresh-hours", "0"])
        .env_clear()
        .env("DSS_CACHE_DIR", "/nonexistent-root/x/cache")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{err}");
    assert!(err.contains("cache directory /nonexistent-root/x/cache"), "{err}");

    let (code, err) = run(&|c| {
        c.args(["--tsa-url", "https://tsa.example", "--tsa-user", "bob"]);
    });
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("--tsa-password-file"), "{err}");

    // Out-of-range sizes are usage errors naming the option, never a silent overflow (2^44 MiB wrapped to 0
    // bytes once, so that every request was 413).
    for (option, value) in [
        ("--max-request-mb", "0"),
        ("--max-request-mb", "17592186044416"),
        ("--max-in-flight", "300"),
        ("--refresh-hours", "1000001"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_dss-server"))
            .args(["--listen", "127.0.0.1:0", option, value])
            .arg("--cache-dir")
            .arg(dir.0.join("cache"))
            .arg("--oj-keystore")
            .arg(&keystore)
            .env_clear()
            .output()
            .unwrap();
        let code = output.status.code();
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        assert_eq!(code, Some(2), "{option} {value}: {err}");
        assert!(
            err.contains(option) && err.contains(value),
            "{option} {value} is refused as a usage error naming it: {err}"
        );
        assert!(
            !err.contains("listening on"),
            "{option} {value}: the server did not start: {err}"
        );
    }

    // No cache directory can be derived without HOME (the current directory is never the default).
    let output = Command::new(env!("CARGO_BIN_EXE_dss-server"))
        .args(["--listen", "127.0.0.1:0", "--refresh-hours", "0"])
        .arg("--oj-keystore")
        .arg(&keystore)
        .env_clear()
        .current_dir(&dir.0)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{err}");
    assert!(err.contains("no cache directory: HOME is not set"), "{err}");
    assert!(
        !dir.0.join("dss-cache").exists(),
        "no cache directory was created in the current directory"
    );
}

/// The OJ keystore is the root of trust: without `--oj-keystore` it comes from the installation (next to the
/// executable, `../share/dss-native/`, or for a development build the repository's by its absolute path), never
/// from the current directory, and the path used is logged at start-up with the cache directory.
#[test]
fn keystore_comes_from_the_installation_not_the_current_directory() {
    let Some(dev_keystore) = option_env!("DSS_SERVER_DEV_OJ_KEYSTORE") else {
        eprintln!("release build: no development keystore to find, skipping");
        return;
    };
    let dir = temp_dir("keystore");
    // A planted keystore where the old lookup ended: it must not be the one used.
    std::fs::create_dir_all(dir.0.join("trust")).unwrap();
    std::fs::write(dir.0.join("trust/oj-keystore.p12"), b"not a keystore").unwrap();
    let mut cmd = bare_server(&dir, "0");
    cmd.args(["--allow-without-trusted-lists", "--log-level", "error"])
        .current_dir(&dir.0);
    // The paths are the first line of the log, before "listening on" (which Running::start would consume).
    let mut child = cmd.spawn().expect("spawn dss-server");
    let lines = stderr_lines(&mut child);
    let line = wait_for(&lines, "OJ keystore ");
    let keystore = line
        .split("OJ keystore ")
        .nth(1)
        .and_then(|rest| rest.split(", cache directory ").next())
        .unwrap();
    assert_eq!(
        Path::new(keystore).canonicalize().unwrap(),
        Path::new(dev_keystore).canonicalize().unwrap(),
        "{line}"
    );
    assert!(!keystore.contains("keystore-"), "not the planted one: {line}");
    assert!(
        line.ends_with(&format!(", cache directory {}", dir.0.join("cache").display())),
        "{line}"
    );
    let addr = wait_for(&lines, "listening on ").rsplit(' ').next().unwrap().to_owned();
    let server = Running { child, lines, addr };
    server.wait_until_ready();

    server.signal("-TERM");
    let Running { mut child, .. } = server;
    assert!(child.wait().unwrap().success());
}

/// A token file guards the API; environment variables set the options, and empty ones mean unset (Compose
/// `${VAR:-}` idioms), booleans in any usual spelling.
#[test]
fn token_file_and_environment_variables() {
    let dir = temp_dir("env");
    let root = repo_root();
    let token_file = dir.0.join("token");
    std::fs::write(&token_file, "0123456789abcdefXYZ\n").unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dss-server"));
    cmd.env_clear()
        .env("DSS_LISTEN", "127.0.0.1:0")
        .env("DSS_REFRESH_HOURS", "0")
        .env("DSS_CACHE_DIR", dir.0.join("cache"))
        .env("DSS_OJ_KEYSTORE", root.join("trust/oj-keystore.p12"))
        .env("DSS_TRUST", root.join("testdata/fixtures/pki/root-ca.pem"))
        .env("DSS_TOKEN_FILE", &token_file)
        .env("DSS_ALLOW_WITHOUT_TRUSTED_LISTS", "1")
        .env("DSS_OFFLINE_REVOCATION", "yes")
        .env("DSS_COUNTRIES", "")
        .env("DSS_TSA_URL", "")
        .env("DSS_CONFIG", "")
        .env("DSS_MAX_HEAP", "")
        .env("DSS_LOG_LEVEL", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let server = Running::start(cmd);
    server.wait_until_ready();

    let response = http_get(&server.addr, "/version");
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    assert!(
        response.to_ascii_lowercase().contains("www-authenticate: bearer"),
        "{response}"
    );
    let response = http_get_with(
        &server.addr,
        "/version",
        "Authorization: Bearer 0123456789abcdefXYZ\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains(r#""ok":true"#), "{response}");
    assert_eq!(health_check(&server.addr), Some(0), "/health needs no token");

    server.signal("-TERM");
    let Running { mut child, .. } = server;
    assert!(child.wait().unwrap().success());
}

/// A port on 127.0.0.1 that nothing listens on: a connection to it is refused at once, without any network.
fn closed_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port() // now closed
}

/// With a period, the schedule runs: nothing is cached, so the first refresh starts at once (here against a
/// closed port, reached with --allow-private-addresses: it fails without any network), is logged, and a retry
/// is scheduled with a backoff.
#[test]
fn refresh_schedule_runs_logs_and_retries() {
    let dir = temp_dir("schedule");
    let port = closed_loopback_port();
    let mut cmd = dss_server_refreshing_every(&dir, &repo_root().join("trust/oj-keystore.p12"), "1");
    cmd.arg("--allow-private-addresses")
        .arg("--lotl-url")
        .arg(format!("http://127.0.0.1:{port}/eu-lotl.xml"));
    let server = Running::start(cmd);
    wait_for(&server.lines, "trusted lists not cached yet");
    let lines = drain_until(&server.lines, "dss-server: online trusted-list refresh");
    let outcome = lines.last().unwrap();
    assert!(
        // A library that still reports an empty refresh as completed counts as failed too (0 certificates).
        outcome.contains("failed")
            || outcome.contains("published nothing")
            || outcome.contains("0 trusted certificates"),
        "{outcome}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("refused by policy")),
        "with --allow-private-addresses the loopback LOTL is attempted, not refused by policy: {lines:#?}"
    );
    let retry = wait_for(&server.lines, "retrying the online trusted-list refresh in");
    assert!(retry.ends_with("in 60 s"), "{retry}");
    server.wait_until_ready();
    assert!(
        http_get(&server.addr, "/health").contains(r#""trusted_lists_loaded":false"#),
        "no list could be loaded"
    );

    server.signal("-TERM");
    wait_for(&server.lines, "stopping");
    let Running { mut child, .. } = server;
    assert!(child.wait().unwrap().success());
}

/// By default the engine refuses outbound requests to loopback and private addresses: a LOTL URL on
/// 127.0.0.1 is not even attempted, the library says why, and the refresh ends without lists. The server
/// relaxes it only with --allow-private-addresses (above).
#[test]
fn private_addresses_are_refused_by_default() {
    let dir = temp_dir("private");
    let port = closed_loopback_port();
    let mut cmd = dss_server_refreshing_every(&dir, &repo_root().join("trust/oj-keystore.p12"), "1");
    cmd.arg("--lotl-url")
        .arg(format!("http://127.0.0.1:{port}/eu-lotl.xml"));
    let server = Running::start(cmd);
    let refused = wait_for(&server.lines, "refused by policy");
    assert!(
        refused.contains(&format!("http://127.0.0.1:{port}/eu-lotl.xml")) && refused.contains("loopback"),
        "{refused}"
    );
    let outcome = wait_for(&server.lines, "dss-server: online trusted-list refresh");
    assert!(
        outcome.contains("failed")
            || outcome.contains("published nothing")
            || outcome.contains("0 trusted certificates"),
        "{outcome}"
    );
    server.wait_until_ready();
    assert!(
        http_get(&server.addr, "/health").contains(r#""trusted_lists_loaded":false"#),
        "no list could be loaded"
    );

    server.signal("-TERM");
    wait_for(&server.lines, "stopping");
    let Running { mut child, .. } = server;
    assert!(child.wait().unwrap().success());
}

/// SIGTERM finishes the requests in progress, and --request-timeout bounds how long that takes: a stalled
/// upload gets 504 and the server exits, instead of waiting for the client until SIGKILL.
#[test]
fn graceful_stop_is_bounded_by_the_request_timeout() {
    let dir = temp_dir("drain");
    let mut cmd = dss_server(&dir, &repo_root().join("trust/oj-keystore.p12"));
    cmd.args(["--request-timeout", "2"]);
    let server = Running::start(cmd);
    server.wait_until_ready();
    let mut stalled = server.stalled_upload();
    std::thread::sleep(Duration::from_millis(200));

    let signalled = Instant::now();
    server.signal("-TERM");
    wait_for(&server.lines, "finishing the request");
    let mut response = String::new();
    stalled.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 504"), "{response}");
    assert!(response.contains("TIMEOUT"), "{response}");
    wait_for(&server.lines, "dss-server: stopping");
    let Running { mut child, .. } = server;
    assert!(child.wait().unwrap().success());
    assert!(
        signalled.elapsed() < Duration::from_secs(20),
        "stopped after {:?}",
        signalled.elapsed()
    );
}

/// A client that closes its connection before the answer does not keep the engine busy: hyper drops the
/// request's future on the EOF, which cancels the queued engine call. With one worker, a client arriving after
/// many that disconnected is answered after the request running, not after all of them.
#[test]
fn clients_that_disconnect_do_not_keep_the_engine_busy() {
    const ABANDONED: usize = 200;
    let dir = temp_dir("disconnect");
    let mut cmd = dss_server(&dir, &repo_root().join("trust/oj-keystore.p12"));
    cmd.args(["--workers", "1", "--max-in-flight", "256"]);
    let server = Running::start(cmd);
    server.wait_until_ready();
    let request = validate_request("pades/b-lta.pdf");
    // Warm up, then measure one validation.
    assert!(http_send(&server.addr, &request).starts_with("HTTP/1.1 200"));
    let started = Instant::now();
    assert!(http_send(&server.addr, &request).starts_with("HTTP/1.1 200"));
    let one = started.elapsed();

    let running = std::thread::spawn({
        let (addr, request) = (server.addr.clone(), request.clone());
        move || http_send(&addr, &request)
    });
    let abandoned: Vec<TcpStream> = (0..ABANDONED)
        .map(|_| {
            let mut stream = TcpStream::connect(&server.addr).unwrap();
            stream.write_all(&request).unwrap();
            stream.flush().unwrap();
            stream
        })
        .collect();
    // Let the server read them and queue their calls behind the running one (a few of them run meanwhile),
    // then close them all.
    std::thread::sleep(Duration::from_millis(300));
    drop(abandoned);
    let started = Instant::now();
    let last = http_send(&server.addr, &request);
    let elapsed = started.elapsed();
    assert!(last.starts_with("HTTP/1.1 200"), "{last}");
    assert!(running.join().unwrap().starts_with("HTTP/1.1 200"));
    assert!(
        elapsed < one * 20,
        "the last request took {elapsed:?} with {ABANDONED} disconnected clients queued; one takes {one:?}"
    );

    server.signal("-TERM");
    wait_for(&server.lines, "stopping");
    let Running { mut child, .. } = server;
    assert!(child.wait().unwrap().success());
}

/// Without a request timeout a stalled upload holds the graceful stop; a second SIGTERM ends the server at once.
#[test]
fn a_second_signal_stops_at_once() {
    let dir = temp_dir("force");
    let mut cmd = dss_server(&dir, &repo_root().join("trust/oj-keystore.p12"));
    cmd.args(["--request-timeout", "0"]);
    let server = Running::start(cmd);
    server.wait_until_ready();
    let _stalled = server.stalled_upload();
    std::thread::sleep(Duration::from_millis(200));

    server.signal("-TERM");
    wait_for(&server.lines, "finishing the request");
    assert!(
        server.lines.recv_timeout(Duration::from_secs(2)).is_err(),
        "the stalled upload keeps the server alive"
    );
    server.signal("-TERM");
    let line = wait_for(&server.lines, "stopping now");
    assert!(line.contains("1 connection(s) dropped"), "{line}");
    let Running { mut child, .. } = server;
    assert!(child.wait().unwrap().success());
}
