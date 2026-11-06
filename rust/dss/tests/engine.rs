// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! The safe API against the real native library (build it first: scripts/build-native.sh).
//!
//! Tests marked #[ignore] need extra setup and run through scripts/test-rust.sh: `synthetic_*` need a seeded
//! synthetic trusted-list cache (DSS_TEST_SYNTHETIC_DIR), `online_*` need internet access.

mod common;

use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use common::*;
use dss::{
    Config, DetachedContent, Engine, EngineBuilder, ErrorCode, ExtendOptions, Http, ImagePosition, Indication, Level,
    Options, PadesOptions, Placement, PreparedSignature, RefreshRecord, Report, SignOptions, SignatureFormat,
    SigningMode, TrustedListStatus, Tsa, VisibleSignature,
};

#[test]
fn version() {
    let v = offline_engine(1).version().unwrap();
    assert_eq!(v.dss, "6.5.1");
    assert!(v.runtime.contains("Substrate VM"), "{}", v.runtime);
}

#[test]
fn pades_fixtures() {
    let engine = offline_engine(1);
    for (fixture, format) in [
        ("pades/b-lt.pdf", "PAdES-BASELINE-LT"),
        ("pades/b-lta.pdf", "PAdES-BASELINE-LTA"),
    ] {
        let r = engine.validate(&read_fixture(fixture), &Options::default()).unwrap();
        assert_eq!(r.container, "PDF");
        assert_eq!(r.signatures.len(), 1);
        let s = &r.signatures[0];
        assert_eq!(s.indication, Indication::TotalPassed, "{fixture}: {s:?}");
        assert_eq!(s.format.as_deref(), Some(format));
        assert_eq!(s.signed_by.as_deref(), Some("Mario Rossi (TEST)"));
        let dn = s.signer_dn.as_deref().unwrap_or_default();
        assert!(dn.contains("CN=Mario Rossi (TEST)") && dn.contains("C=IT"), "{dn}");
        assert!(r.simple_report_xml.contains("SimpleReport"));
        assert!(r.all_passed());
    }
    let tampered = engine
        .validate(&read_fixture("tampered/pades/b-lta.pdf"), &Options::default())
        .unwrap();
    assert_eq!(tampered.signatures[0].indication, Indication::TotalFailed);
    assert_eq!(tampered.signatures[0].sub_indication.as_deref(), Some("HASH_FAILURE"));
    assert!(!tampered.all_passed());
}

#[test]
fn cades_variants() {
    let engine = offline_engine(1);
    let b64 = engine
        .validate(&read_fixture("cades/attached-base64.p7m"), &Options::default())
        .unwrap();
    assert_eq!(b64.container, "CMS");
    assert_eq!(b64.transformations, vec!["base64"]);

    let multi = engine
        .validate(&read_fixture("cades/multi-signer.p7m"), &Options::default())
        .unwrap();
    let mut signers: Vec<_> = multi.signatures.iter().filter_map(|s| s.signed_by.clone()).collect();
    signers.sort();
    assert_eq!(signers, vec!["Giulia Bianchi (TEST)", "Mario Rossi (TEST)"]);

    let nested = engine
        .validate(&read_fixture("cades/nested.p7m.p7m"), &Options::default())
        .unwrap();
    assert_eq!(nested.nested.len(), 1);
    assert_eq!(nested.signatures[0].signed_by.as_deref(), Some("Giulia Bianchi (TEST)"));
    assert_eq!(
        nested.nested[0].signatures[0].signed_by.as_deref(),
        Some("Mario Rossi (TEST)")
    );
    assert_eq!(nested.all_signatures().len(), 2);

    let tampered = engine
        .validate(&read_fixture("tampered/cades/attached-ber.p7m"), &Options::default())
        .unwrap();
    assert_eq!(tampered.signatures[0].sub_indication.as_deref(), Some("HASH_FAILURE"));
}

#[test]
fn detached_content_and_reports() {
    let engine = offline_engine(1);
    let p7s = read_fixture("cades/detached.txt.p7s");
    let with = |content: &str| Options {
        detached_contents: vec![DetachedContent::file(fixture(content))],
        reports: Some(vec![Report::Detailed, Report::Etsi]),
        ..Default::default()
    };
    // B-B with offline revocation is INDETERMINATE, but the content must match.
    let ok = engine.validate(&p7s, &with("content/document.txt")).unwrap();
    assert_ne!(ok.signatures[0].sub_indication.as_deref(), Some("HASH_FAILURE"));
    assert!(ok.detailed_report_xml.as_deref().unwrap().contains("DetailedReport"));
    assert!(ok.etsi_report_xml.is_some());
    assert!(ok.diagnostic_data_xml.is_none());

    let bad = engine.validate(&p7s, &with("tampered/content/document.txt")).unwrap();
    assert_eq!(bad.signatures[0].sub_indication.as_deref(), Some("HASH_FAILURE"));

    let missing = engine.validate(&p7s, &Options::default()).unwrap();
    assert_eq!(
        missing.signatures[0].sub_indication.as_deref(),
        Some("SIGNED_DATA_NOT_FOUND")
    );
}

#[test]
fn errors_are_typed() {
    let engine = offline_engine(1);
    fn code<T>(r: dss::Result<T>) -> Option<ErrorCode> {
        r.err().and_then(|e| e.code())
    }
    assert_eq!(
        code(engine.validate(b"hello", &Options::default())),
        Some(ErrorCode::UnsupportedDocument)
    );
    assert_eq!(
        code(engine.validate(b"", &Options::default())),
        Some(ErrorCode::InvalidArgument)
    );
    assert_eq!(
        code(engine.validate_json(b"%PDF-1.7", "{bad")),
        Some(ErrorCode::InvalidArgument)
    );

    let mut config = offline_config();
    config.countries = vec!["Italy".into()];
    let err = EngineBuilder::new(temp_dir("cache"), &config).build().unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::InvalidConfig), "{err}");

    let err = Engine::builder(temp_dir("cache"), &Config::new("/nonexistent.p12"))
        .build()
        .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::InvalidConfig), "{err}");
}

/// Offline, an LT signature can be extended to LT again (its revocation data is embedded); everything else that
/// needs fetching or a TSA is refused as ExtensionFailed.
#[test]
fn extend_pades() {
    let engine = offline_engine(1);
    let lt = read_fixture("pades/b-lt.pdf");
    let e = engine.extend(&lt, &ExtendOptions::new(Level::Lt)).unwrap();
    assert_eq!(e.container, "PDF");
    assert!(e.transformations.is_empty());
    assert_eq!(e.level, "PAdES-BASELINE-LT");
    assert!(e.document.len() > lt.len());
    assert_eq!(
        &e.document[..lt.len()],
        &lt[..],
        "an incremental update keeps the original bytes"
    );
    let r = engine.validate(&e.document, &Options::default()).unwrap();
    assert!(r.all_passed(), "{:?}", r.signatures);
    assert_eq!(r.signatures[0].format.as_deref(), Some("PAdES-BASELINE-LT"));

    let (json, pdf) = engine
        .extend_json(&lt, r#"{"level":"lt","filename":"contract.pdf"}"#)
        .unwrap();
    assert!(json.contains(r#""level":"PAdES-BASELINE-LT""#), "{json}");
    assert!(pdf.starts_with(b"%PDF"));

    fn code<T>(r: dss::Result<T>) -> Option<ErrorCode> {
        r.err().and_then(|e| e.code())
    }
    let lt_options = ExtendOptions::new(Level::Lt);
    // B-T has no revocation data, and this engine fetches none.
    assert_eq!(
        code(engine.extend(&read_fixture("pades/b-t.pdf"), &lt_options)),
        Some(ErrorCode::ExtensionFailed)
    );
    let no_tsa = engine.extend(&lt, &ExtendOptions::new(Level::Lta)).unwrap_err();
    assert_eq!(no_tsa.code(), Some(ErrorCode::ExtensionFailed));
    assert!(no_tsa.to_string().contains("no TSA is configured"), "{no_tsa}");
    assert_eq!(
        code(engine.extend(&read_fixture("pades/b-lta.pdf"), &lt_options)),
        Some(ErrorCode::ExtensionFailed),
        "already above the target level"
    );
    assert_eq!(
        code(engine.extend(&read_fixture("tampered/pades/b-lt.pdf"), &lt_options)),
        Some(ErrorCode::ExtensionFailed)
    );
    assert_eq!(
        code(engine.extend(&read_fixture("cades/attached-der.p7m"), &lt_options)),
        Some(ErrorCode::UnsupportedDocument)
    );
    assert_eq!(code(engine.extend(b"", &lt_options)), Some(ErrorCode::InvalidArgument));
    assert_eq!(code(engine.extend_json(&lt, "{}")), Some(ErrorCode::InvalidArgument));
}

/// The committed signing fixtures (testdata/fixtures/signing/): options with a fixed signing time, and what an
/// external signer returned for the digest prepare gave on the JVM. Completing them proves the native library
/// prepares the same data.
#[test]
fn sign_with_recorded_external_signatures() {
    let engine = offline_engine(1);
    for (case, document, level, packaging) in [
        (
            "pades-signature-value",
            "content/document.pdf",
            "PAdES-BASELINE-B",
            "ENVELOPED",
        ),
        ("pades-cms", "content/document.pdf", "PAdES-BASELINE-T", "ENVELOPED"),
        ("cades-cms", "content/document.txt", "CAdES-BASELINE-T", "DETACHED"),
        (
            "cades-signature-value",
            "content/document.txt",
            "CAdES-BASELINE-B",
            "ENVELOPING",
        ),
        // Visible signatures: the native library must draw the appearance exactly as the JVM did, without AWT.
        (
            "pades-visible-cms",
            "content/document.pdf",
            "PAdES-BASELINE-B",
            "ENVELOPED",
        ),
        (
            "pades-visible-field-signature-value",
            "content/form.pdf",
            "PAdES-BASELINE-B",
            "ENVELOPED",
        ),
    ] {
        let content = read_fixture(document);
        let options = String::from_utf8(read_fixture(&format!("signing/{case}.json"))).unwrap();
        let prepared: PreparedSignature =
            serde_json::from_str(&engine.prepare_signature_json(&content, &options).unwrap()).unwrap();
        assert_eq!(prepared.digest.len(), 32, "{case}");
        assert_eq!(
            prepared.data_to_sign.is_some(),
            case.ends_with("signature-value"),
            "{case}"
        );
        assert!(
            options.contains(&prepared.signing_time),
            "{case}: the given signing time is kept"
        );

        let (json, signed) = engine
            .complete_signature_json(&content, &options, &read_fixture(&format!("signing/{case}.sig")))
            .unwrap_or_else(|e| panic!("{case}: {e}"));
        assert!(json.contains(&format!(r#""level":"{level}""#)), "{case}: {json}");
        assert!(
            json.contains(&format!(r#""packaging":"{packaging}""#)),
            "{case}: {json}"
        );
        if packaging == "ENVELOPED" {
            assert!(signed.starts_with(&content), "{case}: signing appends to the PDF");
        }

        // Embedded revocation only: B and T are not TOTAL_PASSED here, but must be intact.
        let detached = if packaging == "DETACHED" {
            vec![DetachedContent::file(fixture(document))]
        } else {
            vec![]
        };
        let r = engine
            .validate(
                &signed,
                &Options {
                    detached_contents: detached,
                    ..Default::default()
                },
            )
            .unwrap();
        let s = &r.signatures[0];
        assert_eq!(s.format.as_deref(), Some(level), "{case}");
        assert_eq!(s.signed_by.as_deref(), Some("Mario Rossi (TEST)"), "{case}");
        assert_eq!(s.indication, Indication::Indeterminate, "{case}: {s:?}");
    }
}

/// The typed `VisibleSignature` serializes to the same options as the recorded JSON: same digest, and the recorded
/// CMS completes it.
#[test]
fn sign_visible_typed_api() {
    let engine = offline_engine(1);
    let pdf = read_fixture("content/document.pdf");
    let recorded = String::from_utf8(read_fixture("signing/pades-visible-cms.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&recorded).unwrap();
    let v = &json["pades"]["visible"];

    let mut visible = VisibleSignature::new(Placement::Rect {
        page: 1,
        x: 300.0,
        y: 650.0,
        width: 240.0,
        height: 80.0,
    });
    visible.text = Some("Firmato digitalmente da {signer_name}\n{signing_time}".into());
    visible.time_zone = Some("Europe/Rome".into());
    visible.image = Some(
        base64::engine::general_purpose::STANDARD
            .decode(v["image"].as_str().unwrap())
            .unwrap(),
    );
    visible.background_color = Some("#F0F4FF".into());
    let mut options = SignOptions::new(SigningMode::Cms, Level::B);
    options.signing_time = Some(json["signing_time"].as_str().unwrap().to_owned());
    options.pades = Some(PadesOptions {
        signer_name: Some("Mario Rossi".into()),
        visible: Some(visible),
        ..Default::default()
    });
    let typed = serde_json::to_value(&options).unwrap();
    assert_eq!(
        typed["pades"]["visible"]["page"], 1,
        "the placement is flattened into the object"
    );
    assert_eq!(typed["pades"]["visible"]["image"], v["image"], "bytes go as base64");

    let prepared = engine.prepare_signature(&pdf, &options).unwrap();
    let from_json: PreparedSignature =
        serde_json::from_str(&engine.prepare_signature_json(&pdf, &recorded).unwrap()).unwrap();
    assert_eq!(prepared.digest, from_json.digest);
    let signed = engine
        .complete_signature(&pdf, &options, &read_fixture("signing/pades-visible-cms.sig"))
        .unwrap();
    assert!(signed.document.starts_with(&pdf));

    // Options that do not fit the document fail before anything is signed.
    let mut field = VisibleSignature::new(Placement::Field { field: "Firma1".into() });
    field.text = Some("x".into());
    field.image_position = Some(ImagePosition::Behind);
    let mut wrong = SignOptions::new(SigningMode::Cms, Level::B);
    wrong.pades = Some(PadesOptions {
        visible: Some(field),
        ..Default::default()
    });
    let err = engine.prepare_signature(&pdf, &wrong).unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::InvalidArgument), "{err}");
    assert!(err.to_string().contains("no field 'Firma1'"), "{err}");
}

#[test]
fn sign_typed_api() {
    let engine = offline_engine(1);
    let pdf = read_fixture("content/document.pdf");
    let recorded: serde_json::Value = serde_json::from_slice(&read_fixture("signing/pades-cms.json")).unwrap();

    let mut options = SignOptions::new(SigningMode::Cms, Level::B);
    options.signing_time = Some(recorded["signing_time"].as_str().unwrap().to_owned());
    let prepared = engine.prepare_signature(&pdf, &options).unwrap();
    assert_eq!(prepared.format, "PAdES");
    assert_eq!(prepared.digest_algorithm, "SHA256");
    assert_eq!(prepared.digest_base64().len(), 44);
    assert!(prepared.data_to_sign.is_none());
    let signed = engine
        .complete_signature(&pdf, &options, &read_fixture("signing/pades-cms.sig"))
        .unwrap();
    assert_eq!(signed.format, "PAdES");
    assert_eq!(
        signed.level, "PAdES-BASELINE-T",
        "the recorded CMS has a signature timestamp"
    );
    assert_eq!(signed.packaging, "ENVELOPED");
    assert!(signed.document.starts_with(&pdf));

    fn code<T>(r: dss::Result<T>) -> Option<ErrorCode> {
        r.err().and_then(|e| e.code())
    }
    // Another signing time prepares another PDF: the recorded CMS no longer matches.
    let mut later = SignOptions::new(SigningMode::Cms, Level::B);
    later.signing_time = Some("2030-01-01T00:00:00Z".into());
    let err = engine
        .complete_signature(&pdf, &later, &read_fixture("signing/pades-cms.sig"))
        .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::SigningFailed), "{err}");
    assert!(err.to_string().contains("same document and options"), "{err}");

    let fresh = SignOptions::new(SigningMode::Cms, Level::B);
    assert_eq!(
        code(engine.complete_signature(&pdf, &fresh, b"x")),
        Some(ErrorCode::InvalidArgument)
    );
    assert_eq!(
        code(engine.complete_signature(&pdf, &options, b"not a cms")),
        Some(ErrorCode::SigningFailed)
    );
    assert_eq!(
        code(engine.prepare_signature(&pdf, &SignOptions::new(SigningMode::SignatureValue, Level::B))),
        Some(ErrorCode::InvalidArgument),
        "signature_value needs the signing certificate"
    );
    let mut pades = SignOptions::new(SigningMode::Cms, Level::B);
    pades.format = Some(SignatureFormat::Pades);
    assert_eq!(
        code(engine.prepare_signature(b"hello", &pades)),
        Some(ErrorCode::UnsupportedDocument)
    );
    assert_eq!(
        code(engine.complete_signature(&pdf, &SignOptions::new(SigningMode::Cms, Level::T), b"x")),
        Some(ErrorCode::InvalidArgument)
    );
    assert_eq!(
        code(engine.extend(&read_fixture("pades/b-lt.pdf"), &ExtendOptions::new(Level::B))),
        Some(ErrorCode::InvalidArgument),
        "B is a signing level only"
    );
}

#[test]
fn extensions_and_validations_from_many_threads() {
    let engine = Arc::new(offline_engine(3));
    let lt = Arc::new(read_fixture("pades/b-lt.pdf"));
    let handles: Vec<_> = (0..6)
        .map(|i| {
            let (engine, lt) = (Arc::clone(&engine), Arc::clone(&lt));
            thread::spawn(move || {
                for _ in 0..4 {
                    if i % 2 == 0 {
                        let e = engine.extend(&lt, &ExtendOptions::new(Level::Lt)).unwrap();
                        assert_eq!(&e.document[..lt.len()], &lt[..]);
                    } else {
                        assert!(engine.validate(&lt, &Options::default()).unwrap().all_passed());
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn tsa_config_is_checked() {
    let mut config = offline_config();
    config.tsa = Some(Tsa::new("https://tsa.example.test/tsr"));
    assert!(EngineBuilder::new(temp_dir("cache"), &config).build().is_ok());
    for tsa in [
        Tsa::new("ftp://tsa.example.test"),
        Tsa {
            username: Some("user".into()),
            ..Tsa::new("https://tsa.example.test/tsr")
        },
    ] {
        config.tsa = Some(tsa);
        let err = EngineBuilder::new(temp_dir("cache"), &config).build().unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::InvalidConfig), "{err}");
    }
}

#[test]
fn tl_snapshot_errors_are_typed() {
    // Nothing loaded: nothing to export.
    let engine = offline_engine(1);
    let err = engine.export_tl_snapshot().unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::TrustedListsNotLoaded), "{err}");

    let mut config = offline_config();
    config.tl_snapshot = Some(temp_dir("snapshot").join("missing.tlsnap"));
    let err = EngineBuilder::new(temp_dir("cache"), &config).build().unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::TlSnapshotRejected), "{err}");

    let not_a_snapshot = temp_dir("snapshot").join("other.tlsnap");
    std::fs::write(&not_a_snapshot, b"%PDF-1.7 hello").unwrap();
    config.tl_snapshot = Some(not_a_snapshot);
    let err = EngineBuilder::new(temp_dir("cache"), &config).build().unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::TlSnapshotRejected), "{err}");
    assert!(err.to_string().contains("not a trusted-list snapshot"), "{err}");
}

#[test]
fn empty_cache_refuses_to_validate() {
    let mut config = offline_config();
    config.require_trusted_lists = None; // the default: true
    let engine = EngineBuilder::new(temp_dir("cache"), &config).build().unwrap();
    assert!(!engine.init_info().trusted_lists_loaded);
    let status = engine.trusted_list_status().unwrap();
    assert!(!status.loaded);
    assert_eq!(status.trusted_certificates, 0);
    let err = engine
        .validate(&read_fixture("pades/b-lta.pdf"), &Options::default())
        .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::TrustedListsNotLoaded));
}

#[test]
fn concurrent_validations_from_many_threads() {
    let engine = Arc::new(offline_engine(4));
    let lta = Arc::new(read_fixture("pades/b-lta.pdf"));
    let tampered = Arc::new(read_fixture("tampered/cades/attached-der.p7m"));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let (engine, lta, tampered) = (Arc::clone(&engine), Arc::clone(&lta), Arc::clone(&tampered));
            thread::spawn(move || {
                for j in 0..10 {
                    let (doc, want) = if (i + j) % 2 == 0 {
                        (&*lta, Indication::TotalPassed)
                    } else {
                        (&*tampered, Indication::TotalFailed)
                    };
                    let r = engine.validate(doc, &Options::default()).unwrap();
                    assert_eq!(r.signatures[0].indication, want);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

/// A document that does not fit the isolate's heap is an error result; the engine stays usable.
#[test]
fn heap_limit_is_an_error_not_a_crash() {
    let engine = EngineBuilder::new(temp_dir("cache"), &offline_config())
        .max_heap("64m")
        .build()
        .unwrap();
    let big = vec![0u8; 128 * 1024 * 1024];
    let err = engine.validate(&big, &Options::default()).unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::InternalError), "{err}");
    assert!(err.to_string().contains("OutOfMemoryError"), "{err}");
    let r = engine
        .validate(&read_fixture("pades/b-lta.pdf"), &Options::default())
        .unwrap();
    assert_eq!(r.signatures[0].indication, Indication::TotalPassed);
}

#[test]
fn invalid_isolate_option_fails_cleanly() {
    let err = EngineBuilder::new(temp_dir("cache"), &offline_config())
        .isolate_arg("-Xmx-nonsense")
        .build()
        .unwrap_err();
    assert!(matches!(err, dss::Error::Isolate(_)), "{err}");
}

#[test]
fn engines_are_independent_and_drop_cleanly() {
    for _ in 0..3 {
        let a = offline_engine(2);
        let b = offline_engine(1);
        let doc = read_fixture("pades/b-lta.pdf");
        assert!(a.validate(&doc, &Options::default()).unwrap().all_passed());
        drop(a);
        assert!(b.validate(&doc, &Options::default()).unwrap().all_passed());
    }
}

/// A trusted-list server on 127.0.0.1 that accepts connections and never answers: an online refresh then
/// lasts until the response timeout, long enough to validate during it and to try a second refresh.
#[test]
fn validation_keeps_working_during_a_refresh() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let mut held = vec![];
        while !stop2.load(Ordering::Relaxed) {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = s.set_nonblocking(true);
                let _ = s.read(&mut buf);
                held.push(s); // never respond
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    let mut config = offline_config();
    config.lotl_url = Some(format!("http://127.0.0.1:{port}/eu-lotl.xml"));
    config.http = Some(Http {
        connect_timeout_ms: Some(1000),
        response_timeout_ms: Some(2500),
        ..Default::default()
    });
    let engine = Arc::new(
        EngineBuilder::new(temp_dir("cache"), &config)
            .workers(2)
            .build()
            .unwrap(),
    );

    let refresher = {
        let engine = Arc::clone(&engine);
        thread::spawn(move || engine.refresh_trusted_lists())
    };
    // Wait until the library reports the refresh as running.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !engine.trusted_list_status().unwrap().refresh_in_progress {
        assert!(Instant::now() < deadline, "refresh never started");
        thread::sleep(Duration::from_millis(20));
    }
    let second = engine.refresh_trusted_lists().unwrap_err();
    assert_eq!(second.code(), Some(ErrorCode::RefreshInProgress));

    let doc = read_fixture("pades/b-lta.pdf");
    let mut during = 0;
    while engine.trusted_list_status().unwrap().refresh_in_progress {
        assert!(engine.validate(&doc, &Options::default()).unwrap().all_passed());
        during += 1;
    }
    let record = refresher.join().unwrap().unwrap();
    assert!(record.completed);
    assert!(during >= 3, "only {during} validations ran during the refresh");
    let status = engine.trusted_list_status().unwrap();
    assert!(status.lotls[0].download.error.is_some(), "{:?}", status.lotls[0]);

    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
}

// ------------------------------------------------------------------------------------------ need setup

fn synthetic_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("DSS_TEST_SYNTHETIC_DIR").expect(
            "DSS_TEST_SYNTHETIC_DIR not set: run scripts/test-rust.sh, which seeds a synthetic trusted-list cache",
        ),
    )
}

/// Trust from the (synthetic) trusted lists in the cache, not from an extra anchor.
#[test]
#[ignore = "needs DSS_TEST_SYNTHETIC_DIR (scripts/test-rust.sh)"]
fn synthetic_trusted_lists_from_cache() {
    let dir = synthetic_dir();
    let config = std::fs::read_to_string(dir.join("config.json")).unwrap();
    let started = Instant::now();
    let engine = EngineBuilder::with_config_json(dir.join("cache"), config)
        .build()
        .unwrap();
    assert!(engine.init_info().trusted_lists_loaded);
    assert!(started.elapsed() < Duration::from_secs(10));
    let status = engine.trusted_list_status().unwrap();
    assert_eq!(status.trusted_certificates, 3);
    let mut territories: Vec<_> = status.tls.iter().filter_map(|t| t.territory.clone()).collect();
    territories.sort();
    assert_eq!(territories, vec!["DE", "IT"]);
    assert!(status.tls.iter().all(|t| t.used_for_trust == Some(true)));
    let r = engine
        .validate(&read_fixture("pades/b-lta.pdf"), &Options::default())
        .unwrap();
    assert!(r.all_passed(), "{:?}", r.signatures);
}

/// A snapshot of the synthetic lists starts a second engine, with an empty cache, that trusts the same.
#[test]
#[ignore = "needs DSS_TEST_SYNTHETIC_DIR (scripts/test-rust.sh)"]
fn synthetic_tl_snapshot_round_trip() {
    let dir = synthetic_dir();
    let config = std::fs::read_to_string(dir.join("config.json")).unwrap();
    let source = EngineBuilder::with_config_json(dir.join("cache"), config.clone())
        .build()
        .unwrap();
    let snapshot = source.export_tl_snapshot().unwrap();
    assert_eq!(snapshot.info.format, 1);
    assert_eq!(snapshot.info.size, snapshot.bytes.len() as u64);
    assert_eq!(snapshot.info.trusted_certificates, 3);
    assert_eq!(snapshot.info.lists_loaded.as_ref().unwrap().mode, "offline");
    assert!(snapshot.info.settings["oj_keystore_sha256"].is_string());
    let file = temp_dir("snapshot").join("lists.tlsnap");
    std::fs::write(&file, &snapshot.bytes).unwrap();

    let mut with_snapshot: serde_json::Value = serde_json::from_str(&config).unwrap();
    with_snapshot["tl_snapshot"] = file.to_string_lossy().into();
    let empty_cache = temp_dir("cache");
    let started = Instant::now();
    let loaded = EngineBuilder::with_config_json(&empty_cache, with_snapshot.to_string())
        .build()
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(loaded.init_info().initial_load.mode, "snapshot");
    assert!(loaded.init_info().trusted_lists_loaded);
    let status = loaded.trusted_list_status().unwrap();
    assert_eq!(status.trusted_certificates, 3);
    let info = status.tl_snapshot.expect("tl_snapshot in the status");
    assert_eq!(info.path.as_deref(), Some(file.to_string_lossy().as_ref()));
    assert_eq!(info.created_at, snapshot.info.created_at);
    assert_eq!(
        std::fs::read_dir(empty_cache.join("tl")).unwrap().count(),
        0,
        "the cache stays untouched"
    );
    eprintln!("engine from snapshot in {elapsed:?}");

    // Both engines reach the same verdicts. The synthetic config uses embedded revocation only, so B-level
    // signatures are INDETERMINATE on both; LTA carries its revocation data and passes.
    let verdicts = |r: &dss::Reports| {
        r.signatures
            .iter()
            .map(|s| (s.indication, s.sub_indication.clone(), s.qualification.clone()))
            .collect::<Vec<_>>()
    };
    for fixture in [
        "pades/b-lta.pdf",
        "pades/b-b.pdf",
        "cades/attached-der.p7m",
        "cades/multi-signer.p7m",
    ] {
        let a = source.validate(&read_fixture(fixture), &Options::default()).unwrap();
        let b = loaded.validate(&read_fixture(fixture), &Options::default()).unwrap();
        assert_eq!(verdicts(&a), verdicts(&b), "{fixture}");
    }
    let lta = loaded
        .validate(&read_fixture("pades/b-lta.pdf"), &Options::default())
        .unwrap();
    assert!(lta.all_passed(), "{:?}", lta.signatures);

    // The same file under other trusted-list settings is refused.
    with_snapshot["countries"] = serde_json::json!(["IT"]);
    let err = EngineBuilder::with_config_json(temp_dir("cache"), with_snapshot.to_string())
        .build()
        .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::TlSnapshotRejected), "{err}");
    assert!(err.to_string().contains("countries"), "{err}");
}

/// The real servers have hiccups: AgID's TSL-IT.xml has answered HTTP 504 in CI. Refreshes again, at most 3 times
/// 30 s apart, while a list failed to *download*. A list that downloads but fails parsing or validation is left
/// to the assertions.
fn refresh_until_downloaded(engine: &Engine) -> (RefreshRecord, TrustedListStatus) {
    let mut attempt = 1;
    loop {
        let record = engine.refresh_trusted_lists().unwrap();
        let status = engine.trusted_list_status().unwrap();
        if attempt == 3 || !download_failed(&status) {
            return (record, status);
        }
        eprintln!("a list failed to download (attempt {attempt}), refreshing again in 30 s");
        thread::sleep(Duration::from_secs(30));
        attempt += 1;
    }
}

/// A list whose download failed has no territory yet (it comes from parsing), so look at every list.
fn download_failed(status: &TrustedListStatus) -> bool {
    status
        .lotls
        .iter()
        .chain(&status.tls)
        .any(|l| l.download.status.as_deref() == Some("ERROR"))
}

/// Real EU LOTL (IT only): first refresh, then a second refresh while threads keep validating.
#[test]
#[ignore = "online"]
fn online_refresh_while_validating() {
    let mut config = offline_config();
    config.require_trusted_lists = None;
    config.countries = vec!["IT".into()];
    let engine = Arc::new(
        EngineBuilder::new(temp_dir("online"), &config)
            .workers(2)
            .build()
            .unwrap(),
    );
    let (first, _) = refresh_until_downloaded(&engine);
    assert!(first.completed && first.trusted_certificates > 0, "{first:?}");

    let done = Arc::new(AtomicBool::new(false));
    let validators: Vec<_> = (0..2)
        .map(|_| {
            let (engine, done) = (Arc::clone(&engine), Arc::clone(&done));
            thread::spawn(move || {
                let doc = read_fixture("pades/b-lta.pdf");
                let mut n = 0;
                while !done.load(Ordering::Relaxed) {
                    assert!(engine.validate(&doc, &Options::default()).unwrap().all_passed());
                    n += 1;
                }
                n
            })
        })
        .collect();
    let second = engine.refresh_trusted_lists().unwrap();
    done.store(true, Ordering::Relaxed);
    let total: usize = validators.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(second.completed);
    assert!(total > 0);
    let mut status = engine.trusted_list_status().unwrap();
    if download_failed(&status) {
        status = refresh_until_downloaded(&engine).1;
    }
    let it = status
        .tls
        .iter()
        .find(|t| t.territory.as_deref() == Some("IT"))
        .expect("IT list");
    assert_eq!(it.validation.indication.as_deref(), Some("TOTAL_PASSED"));
}
