// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! The CLI itself, against the library in build/native/<os>-<arch>/. Offline: no trusted lists, the synthetic
//! test root trusted directly, embedded revocation only.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// `dss-cli` with an offline engine, for the test to add a subcommand to.
fn dss_cli() -> Command {
    let root = repo_root();
    let cache = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-cache-{}", std::process::id()));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dss-cli"));
    cmd.arg("--oj-keystore")
        .arg(root.join("trust/oj-keystore.p12"))
        .arg("--cache-dir")
        .arg(&cache)
        .arg("--trust")
        .arg(root.join("testdata/fixtures/pki/root-ca.pem"))
        .args(["--allow-without-trusted-lists", "--offline-revocation"])
        .env_remove("DSS_TSA_URL");
    cmd
}

/// `dss-cli validate <fixture>` with stdout closed before it writes, as in `dss-cli validate doc.pdf | head`.
fn validate_into_closed_pipe(fixture: &str) -> (Option<i32>, String) {
    let mut child = dss_cli()
        .arg("validate")
        .arg(repo_root().join("testdata/fixtures").join(fixture))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dss-cli");
    drop(child.stdout.take());
    let out = child.wait_with_output().expect("wait for dss-cli");
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn closed_stdout_keeps_the_exit_status() {
    let (code, stderr) = validate_into_closed_pipe("pades/b-lta.pdf");
    assert_eq!(code, Some(0), "passed document; stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");

    let (code, stderr) = validate_into_closed_pipe("tampered/pades/b-lta.pdf");
    assert_eq!(code, Some(1), "tampered document; stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

fn extend(input: &Path, level: &str, out: &Path) -> Output {
    dss_cli()
        .arg("extend")
        .arg(input)
        .args(["--level", level, "-o"])
        .arg(out)
        .output()
        .expect("run dss-cli")
}

#[test]
fn extend_writes_the_pdf_or_exits_1() {
    let input = repo_root().join("testdata/fixtures/pades/b-lt.pdf");
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-extended-{}.pdf", std::process::id()));
    let _ = std::fs::remove_file(&out);
    let run = extend(&input, "lt", &out);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(0), "stdout: {stdout}; stderr: {stderr}");
    assert!(stdout.contains("PAdES-BASELINE-LT"), "{stdout}");
    let original = std::fs::read(&input).unwrap();
    let extended = std::fs::read(&out).unwrap();
    assert!(extended.len() > original.len() && extended.starts_with(&original));

    // LTA needs a TSA, and none is configured: DSS refuses, nothing is written.
    let _ = std::fs::remove_file(&out);
    let run = extend(&input, "lta", &out);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("no TSA is configured"), "{stderr}");
    assert!(!out.exists());
}

fn sign(args: &[&std::ffi::OsStr]) -> Output {
    dss_cli().arg("sign").args(args).output().expect("run dss-cli")
}

/// `sign prepare` writes the request, `sign complete` the signed PDF; the recorded CMS from
/// testdata/fixtures/signing/ stands in for the external signer.
#[test]
fn sign_prepare_then_complete() {
    let fixtures = repo_root().join("testdata/fixtures");
    let pdf = fixtures.join("content/document.pdf");
    let recorded: String = std::fs::read_to_string(fixtures.join("signing/pades-cms.json")).unwrap();
    let time = recorded
        .split("\"signing_time\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let request = tmp.join(format!("cli-request-{}.json", std::process::id()));
    let out = tmp.join(format!("cli-signed-{}.pdf", std::process::id()));
    let _ = std::fs::remove_file(&out);

    let run = sign(&[
        "prepare".as_ref(),
        pdf.as_os_str(),
        "--mode".as_ref(),
        "cms".as_ref(),
        "--level".as_ref(),
        "b".as_ref(),
        "--signing-time".as_ref(),
        time.as_ref(),
        "--request".as_ref(),
        request.as_os_str(),
    ]);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(0), "stdout: {stdout}; stderr: {stderr}");
    assert_eq!(stdout.trim().len(), 44, "the digest alone, base64: {stdout}");
    assert!(std::fs::read_to_string(&request).unwrap().contains(&time));

    let run = sign(&[
        "complete".as_ref(),
        pdf.as_os_str(),
        "--request".as_ref(),
        request.as_os_str(),
        "--signature".as_ref(),
        fixtures.join("signing/pades-cms.sig").as_os_str(),
        "-o".as_ref(),
        out.as_os_str(),
    ]);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(0), "stdout: {stdout}; stderr: {stderr}");
    assert!(stdout.contains("PAdES-BASELINE-T"), "{stdout}");
    assert!(std::fs::read(&out).unwrap().starts_with(&std::fs::read(&pdf).unwrap()));

    // A CMS for other content: refused with exit status 1, nothing written.
    let _ = std::fs::remove_file(&out);
    let run = sign(&[
        "complete".as_ref(),
        pdf.as_os_str(),
        "--request".as_ref(),
        request.as_os_str(),
        "--signature".as_ref(),
        fixtures.join("signing/cades-cms.sig").as_os_str(),
        "-o".as_ref(),
        out.as_os_str(),
    ]);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("not signed"), "{stderr}");
    assert!(!out.exists());
}

/// A visible signature from the --visible-* flags: completing it with the recorded CMS proves the flags build the
/// same options, and the same appearance, as testdata/fixtures/signing/pades-visible-cms.json.
#[test]
fn sign_visible() {
    use base64::Engine as _;
    let fixtures = repo_root().join("testdata/fixtures");
    let pdf = fixtures.join("content/document.pdf");
    let recorded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixtures.join("signing/pades-visible-cms.json")).unwrap()).unwrap();
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let id = std::process::id();
    let image = tmp.join(format!("cli-visible-{id}.png"));
    let image_bytes = base64::engine::general_purpose::STANDARD
        .decode(recorded["pades"]["visible"]["image"].as_str().unwrap())
        .unwrap();
    std::fs::write(&image, image_bytes).unwrap();
    let request = tmp.join(format!("cli-visible-request-{id}.json"));
    let out = tmp.join(format!("cli-visible-signed-{id}.pdf"));

    let run = sign(&[
        "prepare".as_ref(),
        pdf.as_os_str(),
        "--mode".as_ref(),
        "cms".as_ref(),
        "--level".as_ref(),
        "b".as_ref(),
        "--signing-time".as_ref(),
        recorded["signing_time"].as_str().unwrap().as_ref(),
        "--signer-name".as_ref(),
        "Mario Rossi".as_ref(),
        "--visible-page".as_ref(),
        "1".as_ref(),
        "--visible-rect".as_ref(),
        "300,650,240,80".as_ref(),
        "--visible-text".as_ref(),
        r"Firmato digitalmente da {signer_name}\n{signing_time}".as_ref(),
        "--visible-time-zone".as_ref(),
        "Europe/Rome".as_ref(),
        "--visible-image".as_ref(),
        image.as_os_str(),
        "--visible-background".as_ref(),
        "#F0F4FF".as_ref(),
        "--request".as_ref(),
        request.as_os_str(),
    ]);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(0), "{stderr}");

    let run = sign(&[
        "complete".as_ref(),
        pdf.as_os_str(),
        "--request".as_ref(),
        request.as_os_str(),
        "--signature".as_ref(),
        fixtures.join("signing/pades-visible-cms.sig").as_os_str(),
        "-o".as_ref(),
        out.as_os_str(),
    ]);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(0), "stdout: {stdout}; stderr: {stderr}");
    assert!(stdout.contains("PAdES-BASELINE-B"), "{stdout}");

    // Visible options without a placement are a usage error.
    let run = sign(&[
        "prepare".as_ref(),
        pdf.as_os_str(),
        "--mode".as_ref(),
        "cms".as_ref(),
        "--level".as_ref(),
        "b".as_ref(),
        "--visible-text".as_ref(),
        "x".as_ref(),
        "--request".as_ref(),
        request.as_os_str(),
    ]);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--visible-field"), "{stderr}");
}

#[test]
fn tl_snapshot_option_reaches_the_library() {
    let missing = Path::new(env!("CARGO_TARGET_TMPDIR")).join("no-such.tlsnap");
    let out = dss_cli()
        .arg("--tl-snapshot")
        .arg(&missing)
        .args(["tl", "status"])
        .output()
        .expect("run dss-cli");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("TlSnapshotRejected"), "{stderr}");
}

/// `tl snapshot` writes the synthetic lists; a config with `tl_snapshot` starts from them with an empty cache.
#[test]
#[ignore = "needs DSS_TEST_SYNTHETIC_DIR (scripts/test-rust.sh)"]
fn synthetic_tl_snapshot_written_and_loaded() {
    let dir = PathBuf::from(std::env::var("DSS_TEST_SYNTHETIC_DIR").expect("DSS_TEST_SYNTHETIC_DIR not set"));
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-snapshot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let file = tmp.join("lists.tlsnap");
    let out = Command::new(env!("CARGO_BIN_EXE_dss-cli"))
        .arg("--config")
        .arg(dir.join("config.json"))
        .arg("--cache-dir")
        .arg(dir.join("cache"))
        .args(["tl", "snapshot", "--json", "--out"])
        .arg(&file)
        .output()
        .expect("run dss-cli");
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let info: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(info["trusted_certificates"], 3);
    assert_eq!(info["size"].as_u64(), Some(std::fs::metadata(&file).unwrap().len()));

    let mut config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    config["tl_snapshot"] = file.to_string_lossy().into();
    let config_file = tmp.join("config.json");
    std::fs::write(&config_file, config.to_string()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_dss-cli"))
        .arg("--config")
        .arg(&config_file)
        .arg("--cache-dir")
        .arg(tmp.join("empty-cache"))
        .args(["tl", "status"])
        .output()
        .expect("run dss-cli");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("last refresh from snapshot"), "{stdout}");
    assert!(stdout.contains("lists.tlsnap"), "{stdout}");
}
