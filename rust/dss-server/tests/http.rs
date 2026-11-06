// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! The HTTP API against the library in build/native/<os>-<arch>/, in process. Offline: no trusted lists, the
//! synthetic test root trusted directly, embedded revocation only (as the dss crate's tests).

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use dss::{Config, Engine, EngineBuilder, Revocation};
use dss_server::{AppState, RESULT_HEADER, router};

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

/// One engine for every test in this binary.
fn engine() -> Arc<Engine> {
    static ENGINE: OnceLock<Arc<Engine>> = OnceLock::new();
    let engine = ENGINE.get_or_init(|| {
        let root = repo_root();
        let mut config = Config::new(root.join("trust/oj-keystore.p12"));
        config.require_trusted_lists = Some(false);
        config.extra_trusted_certificates = vec![root.join("testdata/fixtures/pki/root-ca.pem")];
        config.revocation = Some(Revocation::Offline);
        config.log_level = Some("error".into());
        let cache = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("server-cache-{}", std::process::id()));
        Arc::new(EngineBuilder::new(cache, &config).workers(2).build().expect("engine"))
    });
    Arc::clone(engine)
}

fn app_with(token: Option<&str>, max_request_bytes: usize) -> Router {
    let state = AppState::new(token.map(str::to_owned));
    state.set_engine(engine(), None);
    router(state, max_request_bytes)
}

fn app() -> Router {
    app_with(None, 64 * 1024 * 1024)
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

fn indication(result: &Value) -> &str {
    result["signatures"][0]["indication"].as_str().unwrap()
}

#[tokio::test]
async fn health_and_requests_wait_for_the_engine() {
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

    state.set_engine(engine(), None);
    let r = get(app, "/health").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["status"], "ready");
    assert_eq!(r.json()["trusted_lists_loaded"], false);
}

#[tokio::test]
async fn validate_returns_the_library_result() {
    let r = send(
        app(),
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

    let r = send(
        app(),
        Form::new().document("tampered/pades/b-lta.pdf").post("/validate"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "a failed signature is a result, not an error");
    assert_eq!(indication(&r.json()), "TOTAL_FAILED");
}

/// A B-level signature: offline it lacks revocation data, so the content is what the sub-indication tells.
#[tokio::test]
async fn validate_takes_detached_content_as_parts() {
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
        outcome(send(app(), with_content).await.json()),
        ("INDETERMINATE".into(), "CERTIFICATE_CHAIN_GENERAL_FAILURE".into())
    );

    let r = send(app(), Form::new().document("cades/detached.txt.p7s").post("/validate")).await;
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
        outcome(send(app(), tampered).await.json()),
        ("TOTAL_FAILED".into(), "HASH_FAILURE".into())
    );

    // The server never reads its own files for a client.
    let by_path = Form::new()
        .document("cades/detached.txt.p7s")
        .options(&json!({"detached_contents": [{"name": "x", "path": "/etc/hosts"}]}))
        .post("/validate");
    let r = send(app(), by_path).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT")
    );
}

#[tokio::test]
async fn request_errors() {
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
        let r = send(app(), form.post("/validate")).await;
        assert_eq!((r.status, r.code().as_str()), (status, code), "{}", r.json());
    }

    let not_multipart = Request::post("/validate")
        .header(header::CONTENT_TYPE, "application/pdf")
        .body(Body::from(read_fixture("pades/b-lta.pdf")))
        .unwrap();
    let r = send(app(), not_multipart).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT")
    );

    let r = send(
        app_with(None, 4096),
        Form::new().document("pades/b-lta.pdf").post("/validate"),
    )
    .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, "REQUEST_TOO_LARGE")
    );

    let r = get(app(), "/no/such/endpoint").await;
    assert_eq!((r.status, r.code().as_str()), (StatusCode::NOT_FOUND, "NOT_FOUND"));
}

#[tokio::test]
async fn extend_returns_the_pdf_and_the_result_in_a_header() {
    let original = read_fixture("pades/b-lt.pdf");
    let r = send(
        app(),
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
        app(),
        Form::new()
            .file("document", Some("extended.pdf"), &r.body)
            .post("/validate"),
    )
    .await;
    assert_eq!(indication(&revalidated.json()), "TOTAL_PASSED");

    // Offline revocation: T to LT has nothing to embed, and DSS refuses.
    let r = send(
        app(),
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

    let r = send(app(), Form::new().document("pades/b-lt.pdf").post("/extend")).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT")
    );
}

/// testdata/fixtures/signing/ stands in for the external signer, as in the dss crate's tests.
#[tokio::test]
async fn sign_prepare_then_complete() {
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
            app(),
            Form::new().document(document).options(&options).post("/sign/prepare"),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{case}: {}", r.json());
        assert!(r.json()["digest"].is_string(), "{case}");
        assert_eq!(r.json()["signing_time"], options["signing_time"], "{case}");

        let r = send(
            app(),
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

    // Another document's signature does not complete this one.
    let options: Value = serde_json::from_slice(&read_fixture("signing/pades-cms.json")).unwrap();
    let r = send(
        app(),
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
    let r = get(app(), "/tl/status").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["ok"], true);
    assert_eq!(r.json()["loaded"], false);

    let r = get(app(), "/version").await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v["server"], env!("CARGO_PKG_VERSION"));
    assert!(v["dss"].as_str().is_some_and(|s| !s.is_empty()), "{v}");
}

#[tokio::test]
async fn token_guards_everything_but_health() {
    let app = app_with(Some("s3cret"), 1024 * 1024);
    let version = |auth: Option<&str>| {
        let mut request = Request::get("/version");
        if let Some(auth) = auth {
            request = request.header(header::AUTHORIZATION, auth);
        }
        request.body(Body::empty()).unwrap()
    };
    for auth in [None, Some("Bearer wrong!"), Some("Bearer s3cre"), Some("s3cret")] {
        let r = send(app.clone(), version(auth)).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            "{auth:?}"
        );
    }
    assert_eq!(
        send(app.clone(), version(Some("Bearer s3cret"))).await.status,
        StatusCode::OK
    );
    assert_eq!(get(app, "/health").await.status, StatusCode::OK);
}

/// Every operation of docs/openapi.yaml is routed, and the token guards exactly those the document says it does:
/// unauthenticated, a guarded route answers 401, an open one 200, and one the router lacks 404 or 405.
#[tokio::test]
async fn openapi_document_matches_the_router() {
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

    let app = app_with(Some("s3cret"), 1024 * 1024);
    for (path, method, open) in operations {
        let request = Request::builder()
            .method(method.as_str())
            .uri(&path)
            .body(Body::empty())
            .unwrap();
        let expected = if open { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        assert_eq!(send(app.clone(), request).await.status, expected, "{method} {path}");
    }
}

#[tokio::test]
async fn serves_the_openapi_document_with_its_version() {
    let source = dss_server::OPENAPI_SOURCE;
    assert_eq!(
        source.matches(dss_server::OPENAPI_VERSION_LINE).count(),
        1,
        "docs/openapi.yaml keeps the version placeholder in info.version"
    );
    let r = get(app_with(Some("s3cret"), 1024 * 1024), "/openapi.yaml").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers[header::CONTENT_TYPE], "application/yaml");
    let served = String::from_utf8(r.body).unwrap();
    assert!(served.starts_with("openapi: 3.1."));
    assert!(served.contains(&format!("\n  version: {}\n", env!("CARGO_PKG_VERSION"))));
}
