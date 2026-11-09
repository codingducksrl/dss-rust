// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! The HTTP API against the library in build/native/<os>-<arch>/, in process. Offline: no trusted lists, the
//! synthetic test root trusted directly, embedded revocation only (as the dss crate's tests). Each test has its
//! own engine in a cache directory that removes itself.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body::Frame;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use dss::schedule::RefreshScheduler;
use dss::{Config, Engine, EngineBuilder, Http, RefreshRecord, Revocation};
use dss_server::{AppState, RESULT_HEADER, Settings, describe_refresh, refresh_failed, router};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn read_fixture(rel: &str) -> Vec<u8> {
    let path = repo_root().join("testdata/fixtures").join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
}

/// A fresh directory under cargo's per-target temp dir, removed when dropped. Declared before the engine that
/// uses it, so that the engine is dropped first.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        // The library may still create the cache directory from a background thread for a moment after
        // the engine's shutdown: remove it again until it stays gone.
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
        "server-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    TempDir(dir)
}

fn offline_config() -> Config {
    let root = repo_root();
    let mut config = Config::new(root.join("trust/oj-keystore.p12"));
    config.require_trusted_lists = Some(false);
    config.extra_trusted_certificates = vec![root.join("testdata/fixtures/pki/root-ca.pem")];
    config.revocation = Some(Revocation::Offline);
    config.log_level = Some("error".into());
    config
}

/// An engine for one test, and the routers built on it. Fields drop in order: the engine (which still writes
/// to its cache while it tears down) before the directory.
struct Server {
    engine: Arc<Engine>,
    _cache: TempDir,
}

impl Server {
    fn new(name: &str) -> Self {
        Self::with_config(name, offline_config())
    }

    fn with_config(name: &str, config: Config) -> Self {
        Self::with_config_and_workers(name, config, 2)
    }

    fn with_config_and_workers(name: &str, config: Config, workers: usize) -> Self {
        let cache = temp_dir(name);
        let engine = Arc::new(
            EngineBuilder::new(&cache.0, &config)
                .workers(workers)
                .build()
                .expect("engine"),
        );
        Server { engine, _cache: cache }
    }

    /// An engine with one worker: document requests run one after the other.
    fn single_worker(name: &str) -> Self {
        Self::with_config_and_workers(name, offline_config(), 1)
    }

    /// An engine whose online refresh fails at once: its LOTL URL is a closed port on 127.0.0.1 (no network).
    /// The library refuses loopback addresses by default, so the policy is relaxed for the connection to be
    /// attempted and refused by the closed port.
    fn refreshing(name: &str) -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port(); // now closed
        let mut config = offline_config();
        config.lotl_url = Some(format!("http://127.0.0.1:{port}/eu-lotl.xml"));
        config.http = Some(Http {
            block_private_addresses: Some(false), // the closed port is on 127.0.0.1
            ..Http::default()
        });
        Self::with_config(name, config)
    }

    fn app(&self) -> Router {
        self.app_with(None, 64 * 1024 * 1024)
    }

    fn app_with(&self, token: Option<&str>, max_request_bytes: usize) -> Router {
        self.app_settings(
            Settings {
                token: token.map(str::to_owned),
                ..Settings::default()
            },
            max_request_bytes,
        )
    }

    fn app_settings(&self, settings: Settings, max_request_bytes: usize) -> Router {
        let state = AppState::with(settings);
        state.set_engine(Arc::clone(&self.engine), None);
        router(state, max_request_bytes)
    }
}

/// A multipart/form-data body, as PHP's HTTP clients send it.
struct Form(Vec<u8>);

const BOUNDARY: &str = "dss-server-test-3b9f1c07e2d45a68";

impl Form {
    fn new() -> Self {
        Form(vec![])
    }

    fn file(mut self, name: &str, filename: Option<&str>, bytes: &[u8]) -> Self {
        let filename = filename.map(|f| format!("; filename=\"{f}\"")).unwrap_or_default();
        self.0.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"{filename}\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        self.0.extend_from_slice(bytes);
        self.0.extend_from_slice(b"\r\n");
        self
    }

    fn document(self, rel: &str) -> Self {
        let name = Path::new(rel).file_name().unwrap().to_str().unwrap().to_owned();
        self.file("document", Some(&name), &read_fixture(rel))
    }

    fn options(self, options: &Value) -> Self {
        self.file("options", None, options.to_string().as_bytes())
    }

    fn post(mut self, uri: &str) -> Request<Body> {
        self.0.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        Request::post(uri)
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .body(Body::from(self.0))
            .unwrap()
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&self.body)))
    }

    fn result_header(&self) -> Value {
        serde_json::from_str(self.headers[RESULT_HEADER].to_str().unwrap()).unwrap()
    }

    /// The error code of an `{"ok":false}` body.
    fn code(&self) -> String {
        let json = self.json();
        assert_eq!(json["ok"], false, "{json}");
        json["error"]["code"].as_str().unwrap().to_owned()
    }

    fn message(&self) -> String {
        self.json()["error"]["message"].as_str().unwrap().to_owned()
    }
}

async fn send(app: Router, request: Request<Body>) -> Reply {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes().to_vec();
    Reply { status, headers, body }
}

async fn get(app: Router, uri: &str) -> Reply {
    send(app, Request::get(uri).body(Body::empty()).unwrap()).await
}

async fn post(app: Router, uri: &str) -> Reply {
    send(app, Request::post(uri).body(Body::empty()).unwrap()).await
}

fn indication(result: &Value) -> &str {
    result["signatures"][0]["indication"].as_str().unwrap()
}

#[tokio::test]
async fn health_and_requests_wait_for_the_engine() {
    let server = Server::new("health");
    let state = AppState::new(None);
    let app = router(Arc::clone(&state), 1024 * 1024);

    let r = get(app.clone(), "/health").await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.json(), json!({"ok": false, "status": "starting"}));
    let r = send(app.clone(), Form::new().document("pades/b-lta.pdf").post("/validate")).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "NOT_INITIALIZED")
    );

    state.set_engine(Arc::clone(&server.engine), None);
    let r = get(app, "/health").await;
    assert_eq!(r.status, StatusCode::OK);
    let h = r.json();
    assert_eq!(h["status"], "ready");
    assert_eq!(h["trusted_lists_loaded"], false);
    assert_eq!(h["refresh_in_progress"], false);
    assert_eq!(h["in_flight"], 0);
    assert_eq!(h["max_in_flight"], Settings::default().max_in_flight);
    assert!(h.get("last_online_refresh").is_some(), "{h}");
}

/// When validation needs the trusted lists, an engine without them is not ready: `--health-check` and
/// orchestrators must not route traffic to an instance that answers TRUSTED_LISTS_NOT_LOADED.
#[tokio::test]
async fn health_waits_for_the_trusted_lists_when_they_are_required() {
    let server = Server::new("readiness");
    let app = server.app_settings(
        Settings {
            trusted_lists_required: true,
            ..Settings::default()
        },
        1024 * 1024,
    );
    let r = get(app, "/health").await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    let h = r.json();
    assert_eq!(h["ok"], false);
    assert_eq!(h["status"], "waiting_for_trusted_lists");
    assert_eq!(h["trusted_lists_loaded"], false);

    let r = get(server.app(), "/health").await;
    assert_eq!(r.status, StatusCode::OK, "not required: ready without lists");
}

#[tokio::test]
async fn validate_returns_the_library_result() {
    let server = Server::new("validate");
    let r = send(
        server.app(),
        Form::new()
            .document("pades/b-lta.pdf")
            .options(&json!({"reports": ["detailed"]}))
            .post("/validate"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers[header::CONTENT_TYPE], "application/json");
    let result = r.json();
    assert_eq!(result["ok"], true);
    assert_eq!(result["container"], "PDF");
    assert_eq!(indication(&result), "TOTAL_PASSED", "{result}");
    assert!(result["detailed_report_xml"].is_string());
    assert!(
        result["simple_report_xml"].as_str().unwrap().contains("b-lta.pdf"),
        "the uploaded file's name is the document's name in the reports"
    );

    // An explicit filename in the options wins over the part's.
    let r = send(
        server.app(),
        Form::new()
            .document("pades/b-lta.pdf")
            .options(&json!({"filename": "contract-2026.pdf"}))
            .post("/validate"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let xml = r.json()["simple_report_xml"].as_str().unwrap().to_owned();
    assert!(xml.contains("contract-2026.pdf"), "options.filename is the name: {xml}");
    assert!(!xml.contains("b-lta.pdf"), "the part's filename is not used: {xml}");

    let r = send(
        server.app(),
        Form::new().document("tampered/pades/b-lta.pdf").post("/validate"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "a failed signature is a result, not an error");
    assert_eq!(indication(&r.json()), "TOTAL_FAILED");
}

/// A B-level signature: offline it lacks revocation data, so the content is what the sub-indication tells.
#[tokio::test]
async fn validate_takes_detached_content_as_parts() {
    let server = Server::new("detached");
    let outcome = |result: Value| {
        let s = &result["signatures"][0];
        (
            s["indication"].as_str().unwrap().to_owned(),
            s["sub_indication"].as_str().unwrap_or_default().to_owned(),
        )
    };
    let with_content = Form::new()
        .document("cades/detached.txt.p7s")
        .file("detached", Some("document.txt"), &read_fixture("content/document.txt"))
        .post("/validate");
    assert_eq!(
        outcome(send(server.app(), with_content).await.json()),
        ("INDETERMINATE".into(), "CERTIFICATE_CHAIN_GENERAL_FAILURE".into())
    );

    let r = send(
        server.app(),
        Form::new().document("cades/detached.txt.p7s").post("/validate"),
    )
    .await;
    assert_eq!(
        outcome(r.json()),
        ("INDETERMINATE".into(), "SIGNED_DATA_NOT_FOUND".into())
    );

    let tampered = Form::new()
        .document("cades/detached.txt.p7s")
        .file(
            "detached",
            Some("document.txt"),
            &read_fixture("tampered/content/document.txt"),
        )
        .post("/validate");
    assert_eq!(
        outcome(send(server.app(), tampered).await.json()),
        ("TOTAL_FAILED".into(), "HASH_FAILURE".into())
    );

    // A detached part without a filename is named detached-<n>, which the diagnostic data shows.
    let unnamed = Form::new()
        .document("cades/detached.txt.p7s")
        .options(&json!({"reports": ["diagnostic"]}))
        .file("detached", None, &read_fixture("content/document.txt"))
        .post("/validate");
    let r = send(server.app(), unnamed).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let result = r.json();
    assert_eq!(
        outcome(result.clone()).1,
        "CERTIFICATE_CHAIN_GENERAL_FAILURE",
        "the content was used"
    );
    let diagnostic = result["diagnostic_data_xml"].as_str().unwrap();
    assert!(
        diagnostic.contains("detached-1"),
        "no detached-1 in the diagnostic data"
    );

    // The server never reads its own files for a client.
    let by_path = Form::new()
        .document("cades/detached.txt.p7s")
        .options(&json!({"detached_contents": [{"name": "x", "path": "/etc/hosts"}]}))
        .post("/validate");
    let r = send(server.app(), by_path).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT")
    );

    // The parts go to the library as binary buffers (dss_validate_with_contents), which refuses an empty one.
    let empty = Form::new()
        .document("cades/detached.txt.p7s")
        .file("detached", Some("empty.txt"), b"")
        .post("/validate");
    let r = send(server.app(), empty).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT"),
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    assert!(r.message().contains("empty"), "{}", r.message());

    // A base64 entry in the options still works: the library decodes it.
    let encoded = base64_of(&read_fixture("content/document.txt"));
    let by_base64 = Form::new()
        .document("cades/detached.txt.p7s")
        .options(&json!({"detached_contents": [{"name": "document.txt", "base64": encoded}]}))
        .post("/validate");
    let r = send(server.app(), by_base64).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(outcome(r.json()).1, "CERTIFICATE_CHAIN_GENERAL_FAILURE");

    // A CAdES signature covers one content: given two (a part and an entry, or two parts), DSS cannot tell
    // which one is signed and finds no signed data, so clients must send exactly the one.
    let two = Form::new()
        .document("cades/detached.txt.p7s")
        .options(&json!({"detached_contents": [{"name": "other.txt", "base64": "bm90IHRoZSBzaWduZWQgY29udGVudA=="}]}))
        .file("detached", Some("document.txt"), &read_fixture("content/document.txt"))
        .post("/validate");
    let r = send(server.app(), two).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(outcome(r.json()).1, "SIGNED_DATA_NOT_FOUND");
}

/// Standard base64 without a dependency: the server no longer needs one.
fn base64_of(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A body that delivers some bytes and then fails, as a client that disconnects mid-upload.
struct BrokenBody(bool);

impl http_body::Body for BrokenBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if !self.0 {
            self.0 = true;
            let head = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"document\"\r\n\r\n%PDF-1.7");
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(head)))));
        }
        Poll::Ready(Some(Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))))
    }
}

#[tokio::test]
async fn request_errors() {
    let server = Server::new("errors");
    for (form, status, code) in [
        (
            Form::new().file("document", Some("x.pdf"), b"not a signed document"),
            StatusCode::UNPROCESSABLE_ENTITY,
            "UNSUPPORTED_DOCUMENT",
        ),
        (
            Form::new().options(&json!({})),
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
        ),
        (
            Form::new().document("pades/b-lta.pdf").file("unexpected", None, b"x"),
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
        ),
        (
            Form::new()
                .document("pades/b-lta.pdf")
                .file("options", None, b"{not json"),
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
        ),
        (
            Form::new()
                .document("pades/b-lta.pdf")
                .options(&json!({"no_such_option": true})),
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
        ),
        (
            Form::new().document("pades/b-lta.pdf").document("pades/b-lt.pdf"),
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
        ),
    ] {
        let r = send(server.app(), form.post("/validate")).await;
        assert_eq!((r.status, r.code().as_str()), (status, code), "{}", r.json());
    }

    // Not multipart: the message names the problem, not a boundary.
    for (content_type, expected) in [
        (Some("application/pdf"), "its Content-Type is application/pdf"),
        (Some("application/json"), "its Content-Type is application/json"),
        (None, "it has no Content-Type"),
    ] {
        let mut request = Request::post("/validate");
        if let Some(ct) = content_type {
            request = request.header(header::CONTENT_TYPE, ct);
        }
        let request = request.body(Body::from(read_fixture("pades/b-lta.pdf"))).unwrap();
        let r = send(server.app(), request).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT")
        );
        assert!(
            r.message().starts_with("the request must be multipart/form-data") && r.message().contains(expected),
            "{content_type:?}: {}",
            r.message()
        );
    }
    let no_boundary = Request::post("/validate")
        .header(header::CONTENT_TYPE, "multipart/form-data")
        .body(Body::from("x"))
        .unwrap();
    let r = send(server.app(), no_boundary).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT")
    );
    assert!(r.message().contains("boundary"), "{}", r.message());

    // A body that breaks off is the client's problem (400), not a server error.
    let broken = Request::post("/validate")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::new(BrokenBody(false)))
        .unwrap();
    let r = send(server.app(), broken).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT"),
        "{}",
        r.message()
    );

    let r = send(
        server.app_with(None, 4096),
        Form::new().document("pades/b-lta.pdf").post("/validate"),
    )
    .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, "REQUEST_TOO_LARGE")
    );

    let r = get(server.app(), "/no/such/endpoint").await;
    assert_eq!((r.status, r.code().as_str()), (StatusCode::NOT_FOUND, "NOT_FOUND"));

    // A known path with the wrong method is a JSON error like every other, with the Allow header.
    for (request, allow) in [
        (Request::get("/validate").body(Body::empty()).unwrap(), "POST"),
        (Request::post("/version").body(Body::empty()).unwrap(), "GET,HEAD"),
        (Request::delete("/health").body(Body::empty()).unwrap(), "GET,HEAD"),
    ] {
        let r = send(server.app(), request).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED")
        );
        assert_eq!(r.headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(r.headers[header::ALLOW], allow);
    }
}

#[tokio::test]
async fn extend_returns_the_pdf_and_the_result_in_a_header() {
    let server = Server::new("extend");
    let original = read_fixture("pades/b-lt.pdf");
    let r = send(
        server.app(),
        Form::new()
            .document("pades/b-lt.pdf")
            .options(&json!({"level": "LT"}))
            .post("/extend"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.headers[header::CONTENT_TYPE], "application/pdf");
    let result = r.result_header();
    assert_eq!(result["ok"], true);
    assert_eq!(result["level"], "PAdES-BASELINE-LT");
    assert!(r.body.starts_with(&original), "an incremental update of the input");

    let revalidated = send(
        server.app(),
        Form::new()
            .file("document", Some("extended.pdf"), &r.body)
            .post("/validate"),
    )
    .await;
    assert_eq!(indication(&revalidated.json()), "TOTAL_PASSED");

    // Offline revocation: T to LT has nothing to embed, and DSS refuses.
    let r = send(
        server.app(),
        Form::new()
            .document("pades/b-t.pdf")
            .options(&json!({"level": "LT"}))
            .post("/extend"),
    )
    .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "EXTENSION_FAILED")
    );
    assert!(r.headers.get(RESULT_HEADER).is_none());

    let r = send(server.app(), Form::new().document("pades/b-lt.pdf").post("/extend")).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT")
    );
}

/// testdata/fixtures/signing/ stands in for the external signer, as in the dss crate's tests.
#[tokio::test]
async fn sign_prepare_then_complete() {
    let server = Server::new("sign");
    for (case, document, level, content_type) in [
        (
            "pades-cms",
            "content/document.pdf",
            "PAdES-BASELINE-T",
            "application/pdf",
        ),
        (
            "cades-cms",
            "content/document.txt",
            "CAdES-BASELINE-T",
            "application/pkcs7-signature",
        ),
        (
            "cades-signature-value",
            "content/document.txt",
            "CAdES-BASELINE-B",
            "application/pkcs7-mime",
        ),
    ] {
        let options: Value = serde_json::from_slice(&read_fixture(&format!("signing/{case}.json"))).unwrap();
        let r = send(
            server.app(),
            Form::new().document(document).options(&options).post("/sign/prepare"),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{case}: {}", r.json());
        assert!(r.json()["digest"].is_string(), "{case}");
        assert_eq!(r.json()["signing_time"], options["signing_time"], "{case}");

        let r = send(
            server.app(),
            Form::new()
                .document(document)
                .options(&options)
                .file("signature", None, &read_fixture(&format!("signing/{case}.sig")))
                .post("/sign/complete"),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{case}: {}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.headers[header::CONTENT_TYPE], content_type, "{case}");
        assert_eq!(r.result_header()["level"], level, "{case}");
        assert!(!r.body.is_empty(), "{case}");
    }

    // The upload's filename never enters the signing options: a PDF prepared under one name completes under
    // another with the same digest (a server-added filename would change it between the two steps).
    let options: Value = serde_json::from_slice(&read_fixture("signing/pades-cms.json")).unwrap();
    let pdf = read_fixture("content/document.pdf");
    let r = send(
        server.app(),
        Form::new()
            .file("document", Some("a.pdf"), &pdf)
            .options(&options)
            .post("/sign/prepare"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json());
    let r = send(
        server.app(),
        Form::new()
            .file("document", Some("b.pdf"), &pdf)
            .options(&options)
            .file("signature", None, &read_fixture("signing/pades-cms.sig"))
            .post("/sign/complete"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.result_header()["level"], "PAdES-BASELINE-T");

    // Another document's signature does not complete this one.
    let r = send(
        server.app(),
        Form::new()
            .document("content/document.pdf")
            .options(&options)
            .file("signature", None, &read_fixture("signing/cades-cms.sig"))
            .post("/sign/complete"),
    )
    .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "SIGNING_FAILED")
    );
}

#[tokio::test]
async fn trusted_list_status_and_version() {
    let server = Server::new("status");
    let r = get(server.app(), "/tl/status").await;
    assert_eq!(r.status, StatusCode::OK);
    let s = r.json();
    assert_eq!(s["ok"], true);
    assert_eq!(s["loaded"], false);
    // The root of trust in use, reported before any refresh: the keystore as configured and a digest over its
    // certificates (64 lowercase hex digits), the value a trusted-list snapshot records as
    // settings.oj_keystore_sha256.
    let keystore = &s["oj_keystore"];
    assert_eq!(
        keystore["path"].as_str(),
        repo_root().join("trust/oj-keystore.p12").to_str(),
        "{s}"
    );
    let sha256 = keystore["sha256"]
        .as_str()
        .unwrap_or_else(|| panic!("no oj_keystore.sha256 in {s}"));
    assert!(
        sha256.len() == 64 && sha256.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "oj_keystore.sha256 {sha256:?}"
    );
    assert_eq!(s["last_online_refresh"], Value::Null, "{s}");
    for list in s["lotls"]
        .as_array()
        .unwrap()
        .iter()
        .chain(s["tls"].as_array().unwrap())
    {
        // The rollback protection's floor per list: absent or null until a list was published from its URL.
        let floor = &list["last_published_sequence_number"];
        assert!(floor.is_null() || floor.is_u64(), "{list}");
    }

    let r = get(server.app(), "/version").await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v["server"], env!("CARGO_PKG_VERSION"));
    assert!(v["dss"].as_str().is_some_and(|s| !s.is_empty()), "{v}");
    assert!(v["library"].as_str().is_some_and(|s| !s.is_empty()), "{v}");
    assert_eq!(v["api_version"].as_u64(), Some(u64::from(dss::API_VERSION)), "{v}");
}

/// `POST /tl/refresh` without a schedule runs the refresh itself: 202 at once, 409 while it runs. The LOTL
/// URL is a closed port, so the refresh fails in milliseconds without touching the network.
#[tokio::test]
async fn tl_refresh_without_a_scheduler() {
    let server = Server::refreshing("refresh-direct");
    let app = server.app();
    let r = post(app.clone(), "/tl/refresh").await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json(), json!({"ok": true}));
    let r = post(app.clone(), "/tl/refresh").await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::CONFLICT, "REFRESH_IN_PROGRESS")
    );
    // Once it has finished, the status shows the attempt and a new one is accepted.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = get(app.clone(), "/tl/status").await.json();
        if status["refresh_in_progress"] == false && !status["last_online_refresh"].is_null() {
            assert_eq!(status["loaded"], false, "{status}");
            break;
        }
        assert!(std::time::Instant::now() < deadline, "refresh never finished: {status}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let r = post(app.clone(), "/tl/refresh").await;
        if r.status == StatusCode::ACCEPTED {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "still busy");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// With a schedule, `POST /tl/refresh` hands the request to it: 202 when it is taken, 409 when one is
/// already waiting (the refresh in progress serves it), and an error when the schedule has died.
#[tokio::test(flavor = "multi_thread")]
async fn tl_refresh_with_a_scheduler() {
    let server = Server::refreshing("refresh-scheduled");
    let scheduler = RefreshScheduler::spawn(Arc::clone(&server.engine), Duration::from_secs(3600), false);
    let mut outcomes = scheduler.subscribe();
    let state = AppState::new(None);
    state.set_engine(Arc::clone(&server.engine), Some(scheduler));
    let app = router(state, 1024 * 1024);

    let first = post(app.clone(), "/tl/refresh").await;
    assert_eq!(
        first.status,
        StatusCode::ACCEPTED,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    // While a refresh runs, one request waits and the next is refused. A refresh against a closed port (or one
    // the library refuses by policy) can end between two requests, so they are repeated until the 409 is seen:
    // each 202 starts or queues a refresh, and the one queued behind a running refresh leaves no room for the
    // request after it.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut accepted = 1;
    loop {
        let (a, b, c) = tokio::join!(
            post(app.clone(), "/tl/refresh"),
            post(app.clone(), "/tl/refresh"),
            post(app.clone(), "/tl/refresh")
        );
        let statuses = [a.status, b.status, c.status];
        accepted += statuses.iter().filter(|s| **s == StatusCode::ACCEPTED).count();
        if statuses.contains(&StatusCode::CONFLICT) {
            break;
        }
        assert!(
            statuses.iter().all(|s| *s == StatusCode::ACCEPTED),
            "202 or 409 only: {statuses:?}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "no request was ever refused while a refresh ran"
        );
    }
    assert!(accepted >= 1);
    tokio::time::timeout(Duration::from_secs(30), outcomes.changed())
        .await
        .expect("the requested refresh ran")
        .unwrap();
    let outcome = outcomes.borrow_and_update().clone().expect("an outcome");
    assert!(
        refresh_failed(&outcome.result),
        "a closed port cannot publish lists: {:?}",
        outcome.result
    );

    // A schedule whose task is gone (here: its runtime was shut down) cannot take requests.
    let engine = Arc::clone(&server.engine);
    let dead = tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let scheduler = runtime.block_on(async { RefreshScheduler::spawn(engine, Duration::from_secs(3600), false) });
        drop(runtime);
        scheduler
    })
    .await
    .unwrap();
    assert!(!dead.is_running());
    let state = AppState::new(None);
    state.set_engine(Arc::clone(&server.engine), Some(dead));
    let r = post(router(state, 1024 * 1024), "/tl/refresh").await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
        "{}",
        r.message()
    );
    assert!(r.message().contains("stopped"), "{}", r.message());
}

#[test]
fn refresh_outcomes_are_described_and_classified() {
    let record = |completed: bool, certificates: u64, error: Option<&str>| -> RefreshRecord {
        serde_json::from_value(json!({
            "mode": "online", "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:10Z",
            "duration_ms": 10_000, "completed": completed, "error": error, "trusted_certificates": certificates,
        }))
        .unwrap()
    };
    let ok = Ok(record(true, 4905, None));
    assert!(!refresh_failed(&ok));
    assert_eq!(
        describe_refresh(&ok),
        "online trusted-list refresh completed in 10000 ms, 4905 trusted certificates"
    );
    let empty = Ok(record(true, 0, None));
    assert!(
        refresh_failed(&empty),
        "no certificate at all: nothing to validate against"
    );
    let kept = Ok(record(false, 4905, Some("LOTL unreachable")));
    assert!(refresh_failed(&kept));
    assert!(describe_refresh(&kept).contains("the lists loaded before are kept: LOTL unreachable"));
    let failed: dss::Result<RefreshRecord> = Err(dss::Error::Api {
        code: dss::ErrorCode::TlRefreshFailed,
        message: "nothing published".into(),
    });
    assert!(refresh_failed(&failed));
    assert_eq!(
        describe_refresh(&failed),
        "online trusted-list refresh failed: TL_REFRESH_FAILED: nothing published"
    );
    let busy: dss::Result<RefreshRecord> = Err(dss::Error::Api {
        code: dss::ErrorCode::RefreshInProgress,
        message: "already running".into(),
    });
    assert!(!refresh_failed(&busy), "another refresh is doing the work");
}

#[tokio::test]
async fn token_guards_everything_but_health() {
    let server = Server::new("token");
    let app = server.app_with(Some("s3cret"), 1024 * 1024);
    let version = |auth: Option<&str>| {
        let mut request = Request::get("/version");
        if let Some(auth) = auth {
            request = request.header(header::AUTHORIZATION, auth);
        }
        request.body(Body::empty()).unwrap()
    };
    for (auth, challenge) in [
        (None, "Bearer"),
        (Some("Bearer wrong!"), "Bearer error=\"invalid_token\""),
        (Some("Bearer s3cre"), "Bearer error=\"invalid_token\""),
        (Some("s3cret"), "Bearer error=\"invalid_token\""),
        (Some("Basic s3cret"), "Bearer error=\"invalid_token\""),
        (Some("Bearer"), "Bearer error=\"invalid_token\""),
    ] {
        let r = send(app.clone(), version(auth)).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            "{auth:?}"
        );
        assert_eq!(r.headers[header::WWW_AUTHENTICATE], challenge, "{auth:?}");
    }
    // The scheme is case-insensitive and may be followed by more than one space (RFC 7235).
    for auth in [
        "Bearer s3cret",
        "bearer s3cret",
        "BEARER s3cret",
        "Bearer   s3cret ",
        "Bearer\ts3cret",
    ] {
        assert_eq!(
            send(app.clone(), version(Some(auth))).await.status,
            StatusCode::OK,
            "{auth:?}"
        );
    }
    assert_eq!(get(app, "/health").await.status, StatusCode::OK);
}

/// A wrong-method request on a guarded endpoint meets the token check first: the 405 (with its `Allow` header)
/// is for callers that hold the token. Only `/health` and `/openapi.yaml` answer 405 without one.
#[tokio::test]
async fn method_not_allowed_is_behind_the_token() {
    let server = Server::new("token-405");
    let app = server.app_with(Some("s3cret"), 1024 * 1024);
    for (uri, allow) in [("/validate", "POST"), ("/version", "GET,HEAD")] {
        let wrong_method = |auth: Option<&str>| {
            let mut request = if uri == "/validate" {
                Request::get(uri)
            } else {
                Request::post(uri)
            };
            if let Some(auth) = auth {
                request = request.header(header::AUTHORIZATION, auth);
            }
            request.body(Body::empty()).unwrap()
        };
        let r = send(app.clone(), wrong_method(None)).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            "{uri}"
        );
        let r = send(app.clone(), wrong_method(Some("Bearer s3cret"))).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED"),
            "{uri}"
        );
        assert_eq!(r.headers[header::ALLOW], allow, "{uri}");
    }
    let r = send(app, Request::delete("/health").body(Body::empty()).unwrap()).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED, "/health needs no token");
}

#[test]
fn rfc3339_instants_are_parsed() {
    use std::time::{Duration, SystemTime};
    let at = |secs: u64, nanos: u32| SystemTime::UNIX_EPOCH + Duration::new(secs, nanos);
    assert_eq!(dss_server::parse_rfc3339("1970-01-01T00:00:00Z"), Some(at(0, 0)));
    assert_eq!(
        dss_server::parse_rfc3339("2026-01-31T12:00:00Z"),
        Some(at(1_769_860_800, 0))
    );
    assert_eq!(
        dss_server::parse_rfc3339("2026-01-31T12:00:00.123456789Z"),
        Some(at(1_769_860_800, 123_456_789)),
        "as java.time.Instant prints it"
    );
    assert_eq!(
        dss_server::parse_rfc3339("2026-01-31T13:00:00.5+01:00"),
        Some(at(1_769_860_800, 500_000_000))
    );
    assert_eq!(
        dss_server::parse_rfc3339("2026-01-31T07:00:00-05:00"),
        Some(at(1_769_860_800, 0))
    );
    assert_eq!(
        dss_server::parse_rfc3339("2024-02-29T00:00:00Z"),
        Some(at(1_709_164_800, 0)),
        "leap day"
    );
    for bad in [
        "",
        "2026-01-31",
        "2026-01-31T12:00:00",
        "yesterday",
        "2026-13-01T00:00:00Z",
        "1960-01-01T00:00:00Z",
    ] {
        assert_eq!(dss_server::parse_rfc3339(bad), None, "{bad:?}");
    }
}

/// Without a token, a request a browser makes (it carries an Origin header) is refused: a web page could
/// otherwise submit documents to, or trigger refreshes on, a sidecar on localhost. With a token, the token
/// decides.
#[tokio::test]
async fn requests_from_web_pages_need_a_token() {
    let server = Server::new("origin");
    let from_page = |auth: Option<&str>| {
        let mut request = Request::get("/version").header(header::ORIGIN, "https://evil.example");
        if let Some(auth) = auth {
            request = request.header(header::AUTHORIZATION, auth);
        }
        request.body(Body::empty()).unwrap()
    };
    let r = send(server.app(), from_page(None)).await;
    assert_eq!((r.status, r.code().as_str()), (StatusCode::FORBIDDEN, "FORBIDDEN"));
    let r = send(server.app(), Form::new().document("pades/b-lta.pdf").post("/validate")).await;
    assert_eq!(r.status, StatusCode::OK, "no Origin: a server-side client");
    let mut multipart = Form::new().document("pades/b-lta.pdf").post("/validate");
    multipart
        .headers_mut()
        .insert(header::ORIGIN, "http://localhost:8484".parse().unwrap());
    let r = send(server.app(), multipart).await;
    assert_eq!((r.status, r.code().as_str()), (StatusCode::FORBIDDEN, "FORBIDDEN"));

    let app = server.app_with(Some("s3cret"), 1024 * 1024);
    assert_eq!(
        send(app.clone(), from_page(None)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(app, from_page(Some("Bearer s3cret"))).await.status,
        StatusCode::OK,
        "a page that holds the token may call"
    );
}

/// Only `max_in_flight` document requests are read and processed at once; the next is refused at once, before
/// its body is read, and the slot is held until the engine call returns.
#[tokio::test]
async fn admission_control_refuses_the_request_over_the_limit() {
    let server = Server::new("admission");
    let app = server.app_settings(
        Settings {
            max_in_flight: 1,
            ..Settings::default()
        },
        64 * 1024 * 1024,
    );
    let first = send(
        app.clone(),
        Form::new()
            .document("pades/b-lta.pdf")
            .options(&json!({"reports": ["detailed", "etsi", "diagnostic"]}))
            .post("/validate"),
    );
    let second = send(app.clone(), Form::new().document("pades/b-lta.pdf").post("/validate"));
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first.status, StatusCode::OK, "{}", String::from_utf8_lossy(&first.body));
    assert_eq!(
        (second.status, second.code().as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "SERVER_BUSY"),
        "{}",
        String::from_utf8_lossy(&second.body)
    );
    assert_eq!(second.headers[header::RETRY_AFTER], "1");

    // Slots are released: the next request is served, and status endpoints never need one.
    let r = send(app.clone(), Form::new().document("pades/b-lta.pdf").post("/validate")).await;
    assert_eq!(r.status, StatusCode::OK);
    let h = get(app, "/health").await.json();
    assert_eq!(
        (h["in_flight"].as_u64(), h["max_in_flight"].as_u64()),
        (Some(0), Some(1))
    );
}

/// A request over `request_timeout` is answered 504.
#[tokio::test]
async fn requests_over_the_timeout_are_answered_504() {
    let server = Server::new("timeout");
    let app = server.app_settings(
        Settings {
            request_timeout: Some(Duration::from_millis(1)),
            ..Settings::default()
        },
        64 * 1024 * 1024,
    );
    let r = send(
        app.clone(),
        Form::new()
            .document("pades/b-lta.pdf")
            .options(&json!({"reports": ["detailed", "etsi", "diagnostic"]}))
            .post("/validate"),
    )
    .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::GATEWAY_TIMEOUT, "TIMEOUT"),
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    // Status endpoints are under the same deadline, but a generous one serves them.
    let app = server.app_settings(
        Settings {
            request_timeout: Some(Duration::from_secs(30)),
            ..Settings::default()
        },
        64 * 1024 * 1024,
    );
    assert_eq!(get(app, "/version").await.status, StatusCode::OK);
}

/// A request abandoned before its answer (its deadline passed, its client gone: the handler's future is dropped
/// either way) does not keep the engine busy: its token is cancelled, and the worker skips the queued call. With
/// one worker, a request sent after many abandoned ones is answered after the one running, not after all of them.
#[tokio::test]
async fn abandoned_requests_are_skipped_by_the_engine() {
    const ABANDONED: usize = 200;
    let server = Server::single_worker("cancel");
    let app = server.app_settings(
        Settings {
            max_in_flight: ABANDONED + 2,
            ..Settings::default()
        },
        64 * 1024 * 1024,
    );
    let request = || {
        Form::new()
            .document("pades/b-lta.pdf")
            .options(&json!({"reports": ["detailed", "etsi", "diagnostic"]}))
            .post("/validate")
    };
    // Warm up, then measure one validation.
    assert_eq!(send(app.clone(), request()).await.status, StatusCode::OK);
    let started = Instant::now();
    assert_eq!(send(app.clone(), request()).await.status, StatusCode::OK);
    let one = started.elapsed();

    let running = tokio::spawn(send(app.clone(), request()));
    let abandoned: Vec<_> = (0..ABANDONED)
        .map(|_| tokio::spawn(send(app.clone(), request())))
        .collect();
    // Let them be read and queued in the engine behind the running one (a few of them run meanwhile), then
    // drop their futures.
    tokio::time::sleep(Duration::from_millis(50)).await;
    for task in &abandoned {
        task.abort();
    }
    let started = Instant::now();
    let last = send(app.clone(), request()).await;
    let elapsed = started.elapsed();
    assert_eq!(last.status, StatusCode::OK, "{}", String::from_utf8_lossy(&last.body));
    assert_eq!(running.await.unwrap().status, StatusCode::OK);
    assert!(
        elapsed < one * 20,
        "the last request took {elapsed:?} with {ABANDONED} abandoned requests queued; one takes {one:?}"
    );
    // The few answered before the abort got a 200; the rest were dropped (and their engine calls skipped).
    let mut cancelled = 0;
    for task in abandoned {
        match task.await {
            Ok(reply) => assert_eq!(reply.status, StatusCode::OK),
            Err(e) => {
                assert!(e.is_cancelled(), "{e}");
                cancelled += 1;
            }
        }
    }
    assert!(
        cancelled > ABANDONED / 2,
        "{cancelled} of {ABANDONED} were still pending at the abort"
    );
    // Every slot is back: the skipped calls returned.
    let h = get(app, "/health").await.json();
    assert_eq!(h["in_flight"].as_u64(), Some(0), "{h}");
}

/// Every operation of docs/openapi.yaml is routed, and the token guards exactly those the document says it does:
/// unauthenticated, a guarded route answers 401, an open one 200; with the token, a route the router lacks
/// would answer 404, and one with another method 405.
#[tokio::test]
async fn openapi_document_matches_the_router() {
    // With the token, POST /tl/refresh starts a refresh: this engine's LOTL URL is a closed port, so it fails
    // at once without any network.
    let server = Server::refreshing("openapi");
    let source = dss_server::OPENAPI_SOURCE;
    let lines: Vec<&str> = source.lines().collect();
    let start = lines.iter().position(|l| *l == "paths:").unwrap() + 1;
    let end = start
        + lines[start..]
            .iter()
            .take_while(|l| l.is_empty() || l.starts_with(' '))
            .count();
    let paths = &lines[start..end];
    let mut operations = vec![];
    let mut path = None;
    for (i, line) in paths.iter().enumerate() {
        // Paths at two spaces, their methods at four, an operation's keys at six.
        if let Some(p) = line.strip_prefix("  /").and_then(|l| l.strip_suffix(':')) {
            path = Some(format!("/{p}"));
        } else if let Some(method) = line.strip_prefix("    ").and_then(|l| l.strip_suffix(':'))
            && ["get", "post", "put", "patch", "delete"].contains(&method)
        {
            let open = paths[i + 1..]
                .iter()
                .take_while(|l| l.starts_with("      "))
                .any(|l| *l == "      security: []");
            operations.push((path.clone().unwrap(), method.to_uppercase(), open));
        }
    }
    assert_eq!(operations.len(), 9, "{operations:?}");

    let app = server.app_with(Some("s3cret"), 1024 * 1024);
    for (path, method, open) in operations {
        let request = Request::builder()
            .method(method.as_str())
            .uri(&path)
            .body(Body::empty())
            .unwrap();
        let expected = if open { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        assert_eq!(send(app.clone(), request).await.status, expected, "{method} {path}");

        let request = Request::builder()
            .method(method.as_str())
            .uri(&path)
            .header(header::AUTHORIZATION, "Bearer s3cret")
            .body(Body::empty())
            .unwrap();
        let status = send(app.clone(), request).await.status;
        assert!(
            status != StatusCode::NOT_FOUND && status != StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} is not routed: {status}"
        );
    }
}

#[tokio::test]
async fn serves_the_openapi_document_with_its_version() {
    let server = Server::new("openapi-version");
    let source = dss_server::OPENAPI_SOURCE;
    assert_eq!(
        source.matches(dss_server::OPENAPI_VERSION_LINE).count(),
        1,
        "docs/openapi.yaml keeps the version placeholder in info.version"
    );
    let r = get(server.app_with(Some("s3cret"), 1024 * 1024), "/openapi.yaml").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers[header::CONTENT_TYPE], "application/yaml");
    let served = String::from_utf8(r.body).unwrap();
    assert!(served.starts_with("openapi: 3.1."));
    assert!(served.contains(&format!("\n  version: {}\n", env!("CARGO_PKG_VERSION"))));
}
