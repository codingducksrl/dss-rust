// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! `dss::Config` mirrors the library's `config_json` key for key: every key the Java side allows (the
//! `allowOnly(Set.of(...))` lists of EngineConfig.java and DocumentLimits.java) is a field here, and every field
//! here is a key there. Runs against the Java sources of this checkout, no library needed.

mod common;

use std::collections::BTreeSet;

use common::repo_root;
use dss::{Config, Http, Limits, OjKeystore, Proxy, Report, Revocation, TlSync, TrustStore, Tsa};

/// Every quoted string inside every `allowOnly(Set.of(...))` of the given Java sources.
fn java_allowed_keys() -> BTreeSet<String> {
    let dir = repo_root().join("java/src/main/java/it/codingduck/dssnative/engine");
    let mut keys = BTreeSet::new();
    for file in ["EngineConfig.java", "DocumentLimits.java"] {
        let source = std::fs::read_to_string(dir.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let mut rest = source.as_str();
        while let Some(at) = rest.find("allowOnly(Set.of(") {
            let after = &rest[at + "allowOnly(Set.of(".len()..];
            let end = after.find("))").expect("closing of Set.of(");
            let mut pieces = after[..end].split('"');
            pieces.next(); // before the first quote
            while let (Some(key), Some(_after)) = (pieces.next(), pieces.next()) {
                keys.insert(key.to_owned());
            }
            rest = &after[end..];
        }
    }
    assert!(keys.len() > 30, "parsed only {keys:?}");
    keys
}

/// Every key, at every level, of a `Config` with every field set.
fn rust_config_keys() -> BTreeSet<String> {
    let mut c = Config::new("oj.p12");
    c.oj_keystore = OjKeystore {
        path: "oj.p12".into(),
        r#type: Some("PKCS12".into()),
        password: Some("p".into()),
    };
    c.oj_url = Some("https://oj".into());
    c.lotl_url = Some("https://lotl".into());
    c.countries = vec!["IT".into()];
    c.tl_versions = Some(vec![6]);
    c.pivot_support = Some(true);
    c.use_sunset_date = Some(true);
    c.tl_sync = Some(TlSync {
        accept_invalid_signature: Some(false),
        accept_expired: Some(true),
        accept_structure_errors: Some(true),
    });
    c.tl_threads = Some(4);
    c.online_cache_expiration_ms = Some(0);
    c.http = Some(Http {
        connect_timeout_ms: Some(1),
        response_timeout_ms: Some(1),
        tl_verify_tls: Some(false),
        trust_store: Some(TrustStore {
            path: "ts.p12".into(),
            r#type: Some("PKCS12".into()),
            password: Some("p".into()),
        }),
        allowed_schemes: Some(vec!["https".into()]),
        block_private_addresses: Some(true),
        max_response_bytes: Some(1),
        request_deadline_ms: Some(1),
        follow_redirects: Some(true),
        proxy: Some(Proxy {
            host: "proxy".into(),
            port: 3128,
            scheme: Some("http".into()),
            username: Some("u".into()),
            password: Some("p".into()),
            no_proxy: vec!["localhost".into()],
        }),
        use_system_proxy: Some(false),
        cache_ms: Some(1),
    });
    c.revocation = Some(Revocation::Online);
    c.aia = Some(true);
    c.reports = vec![Report::Detailed];
    c.require_trusted_lists = Some(true);
    c.extra_trusted_certificates = vec!["root.pem".into()];
    c.tsa = Some(Tsa {
        url: "https://tsa".into(),
        username: Some("u".into()),
        password: Some("p".into()),
        require_trusted: Some(true),
        max_clock_skew_ms: Some(1),
    });
    c.log_level = Some("warn".into());
    c.tl_snapshot = Some("lists.tlsnap".into());
    c.limits = Some(Limits {
        max_pdf_pages: Some(1),
        max_pdf_signatures: Some(1),
        max_pdf_annotations_per_page: Some(1),
        max_cms_certificates: Some(1),
    });
    let json = serde_json::to_value(&c).unwrap();
    let mut keys = BTreeSet::new();
    collect_keys(&json, &mut keys);
    keys
}

fn collect_keys(value: &serde_json::Value, keys: &mut BTreeSet<String>) {
    if let serde_json::Value::Object(map) = value {
        for (k, v) in map {
            keys.insert(k.clone());
            collect_keys(v, keys);
        }
    }
}

#[test]
fn config_keys_match_the_java_allow_lists() {
    let java = java_allowed_keys();
    let rust = rust_config_keys();
    let missing_in_rust: Vec<_> = java.difference(&rust).collect();
    let unknown_to_java: Vec<_> = rust.difference(&java).collect();
    assert!(
        missing_in_rust.is_empty() && unknown_to_java.is_empty(),
        "config_json keys the Java side allows but dss::Config lacks: {missing_in_rust:?}; \
         dss::Config fields the Java side rejects: {unknown_to_java:?}"
    );
}
