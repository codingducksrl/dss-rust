// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Shared helpers for the integration tests. They run against the library in build/native/<os>-<arch>/.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use dss::{Config, Engine, EngineBuilder, Revocation};

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

pub fn fixture(rel: &str) -> PathBuf {
    repo_root().join("testdata/fixtures").join(rel)
}

pub fn read_fixture(rel: &str) -> Vec<u8> {
    std::fs::read(fixture(rel)).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
}

/// A fresh directory under cargo's per-target temp dir.
pub fn temp_dir(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// No trusted lists, the synthetic test root trusted directly, embedded revocation only: works offline with
/// the committed fixtures. LT/LTA signatures are TOTAL_PASSED; B/T ones lack revocation data.
pub fn offline_config() -> Config {
    let mut c = Config::new(repo_root().join("trust/oj-keystore.p12"));
    c.require_trusted_lists = Some(false);
    c.extra_trusted_certificates = vec![fixture("pki/root-ca.pem")];
    c.revocation = Some(Revocation::Offline);
    c.log_level = Some("error".into());
    c
}

pub fn offline_engine(workers: usize) -> Engine {
    EngineBuilder::new(temp_dir("cache"), &offline_config())
        .workers(workers)
        .build()
        .expect("engine")
}
