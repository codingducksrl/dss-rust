// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! The CLI itself, against the library in build/native/<os>-<arch>/. Offline: no trusted lists, the synthetic
//! test root trusted directly, embedded revocation only.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn fixture(rel: &str) -> PathBuf {
    repo_root().join("testdata/fixtures").join(rel)
}

/// A fresh directory under cargo's per-target temp dir, removed when dropped. Declare it before running the CLI
/// that uses it.
struct TempDir(PathBuf);

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<OsStr> for TempDir {
    fn as_ref(&self) -> &OsStr {
        self.0.as_os_str()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(name: &str) -> TempDir {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Canonical, so that paths the CLI prints compare equal on macOS (/var -> /private/var).
    TempDir(dir.canonicalize().unwrap())
}

/// `dss-cli` with no DSS_* variable from the caller's environment.
fn bare_cli(exe: &Path) -> Command {
    let mut cmd = Command::new(exe);
    for var in [
        "DSS_CACHE_DIR",
        "DSS_TL_SNAPSHOT",
        "DSS_OJ_KEYSTORE",
        "DSS_TSA_URL",
        "DSS_TSA_USER",
        "DSS_TSA_PASSWORD",
        "DSS_TSA_PASSWORD_FILE",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

/// `dss-cli` with an offline engine caching under `dir`, for the test to add a subcommand to.
fn dss_cli(dir: &Path) -> Command {
    let mut cmd = bare_cli(Path::new(env!("CARGO_BIN_EXE_dss-cli")));
    cmd.arg("--oj-keystore")
        .arg(repo_root().join("trust/oj-keystore.p12"))
        .arg("--cache-dir")
        .arg(dir.join("cache"))
        .arg("--trust")
        .arg(fixture("pki/root-ca.pem"))
        .args(["--allow-without-trusted-lists", "--offline-revocation"]);
    cmd
}

fn run(cmd: &mut Command) -> (Option<i32>, String, String) {
    let out = cmd.output().expect("run dss-cli");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `dss-cli validate <fixture>` with stdout closed before it writes, as in `dss-cli validate doc.pdf | head`.
fn validate_into_closed_pipe(fixture_name: &str) -> (Option<i32>, String) {
    let dir = temp_dir("cli-stdout");
    let mut child = dss_cli(&dir)
        .arg("validate")
        .arg(fixture(fixture_name))
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

/// The CLI's stderr closed before it writes, as in `dss-cli ... 2>&1 >/dev/null | true`: a panic would exit 101.
fn into_closed_stderr(cmd: &mut Command) -> Option<i32> {
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dss-cli");
    drop(child.stderr.take());
    child.wait().expect("wait for dss-cli").code()
}

#[test]
fn closed_stderr_keeps_the_exit_status_and_the_reports() {
    let dir = temp_dir("cli-stderr");
    let reports = dir.join("reports");
    let code = into_closed_stderr(
        dss_cli(&dir)
            .arg("validate")
            .arg(fixture("pades/b-lta.pdf"))
            .args(["--report", "detailed", "--out-dir"])
            .arg(&reports),
    );
    assert_eq!(code, Some(0));
    // "wrote ..." goes to stderr after each report: every report is still written.
    assert!(reports.join("b-lta.pdf.simple.xml").is_file());
    assert!(reports.join("b-lta.pdf.detailed.xml").is_file());

    let code = into_closed_stderr(dss_cli(&dir).arg("validate").arg(dir.join("missing.pdf")));
    assert_eq!(code, Some(2), "the error message goes nowhere, the status stays");
}

#[test]
fn help_documents_the_exit_status() {
    let (code, stdout, _) = run(bare_cli(Path::new(env!("CARGO_BIN_EXE_dss-cli"))).arg("--help"));
    assert_eq!(code, Some(0));
    assert!(stdout.contains("Exit status:"), "{stdout}");
    assert!(stdout.contains("TOTAL_PASSED"), "{stdout}");
}

#[test]
fn validate_json_and_reports() {
    let dir = temp_dir("cli-validate");
    let (code, stdout, stderr) = run(dss_cli(&dir)
        .arg("validate")
        .arg(fixture("pades/b-lta.pdf"))
        .arg("--json"));
    assert_eq!(code, Some(0), "{stderr}");
    let result: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(result["signatures"][0]["indication"], "TOTAL_PASSED", "{stdout}");
    assert!(
        !stdout.contains("_xml"),
        "the JSON leaves the XML reports out: {stdout}"
    );

    let reports = dir.join("reports");
    let (code, _, stderr) = run(dss_cli(&dir)
        .arg("validate")
        .arg(fixture("pades/b-lta.pdf"))
        .args(["--report", "detailed", "--report", "etsi", "--out-dir"])
        .arg(&reports));
    assert_eq!(code, Some(0), "{stderr}");
    for kind in ["simple", "detailed", "etsi"] {
        let xml = std::fs::read_to_string(reports.join(format!("b-lta.pdf.{kind}.xml"))).unwrap();
        assert!(xml.starts_with("<?xml"), "{kind}");
    }
    assert!(!reports.join("b-lta.pdf.diagnostic.xml").exists());

    // --report without --out-dir would compute reports and drop them: a usage error.
    let (code, _, stderr) = run(dss_cli(&dir)
        .arg("validate")
        .arg(fixture("pades/b-lta.pdf"))
        .args(["--report", "detailed"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("--out-dir"), "{stderr}");

    // The path of an unreadable document is in the error.
    let missing = dir.join("missing.pdf");
    let (code, _, stderr) = run(dss_cli(&dir).arg("validate").arg(&missing));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains(&*missing.to_string_lossy()), "{stderr}");
}

#[test]
fn validate_batch_lines_and_validation_time() {
    let dir = temp_dir("cli-batch");
    let passed = fixture("pades/b-lta.pdf");
    let tampered = fixture("tampered/pades/b-lta.pdf");
    let missing = dir.join("missing.pdf");
    let cases = dir.join("cases.txt");
    std::fs::write(
        &cases,
        format!(
            "# comment\n{}\n{}\n\n{}\n",
            passed.display(),
            tampered.display(),
            missing.display()
        ),
    )
    .unwrap();

    let batch = |time: &str| {
        run(dss_cli(&dir)
            .args(["validate-batch", "--parallel", "2", "--cases"])
            .arg(&cases)
            .args(["--validation-time", time]))
    };
    let (code, stdout, stderr) = batch("2026-11-01T00:00:00Z");
    assert_eq!(code, Some(0), "{stderr}");
    let lines: Vec<serde_json::Value> = stdout.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 3, "{stdout}");
    assert_eq!(lines[0]["file"], passed.to_string_lossy().as_ref());
    assert_eq!(lines[0]["ok"], true);
    assert_eq!(lines[0]["result"]["signatures"][0]["indication"], "TOTAL_PASSED");
    assert_eq!(lines[1]["result"]["signatures"][0]["indication"], "TOTAL_FAILED");
    assert_eq!(lines[2]["ok"], false);
    // The library's wire name, not the Rust variant's.
    assert_eq!(lines[2]["error"]["code"], "INVALID_ARGUMENT", "{stdout}");

    // An invalid instant is the batch's error, found once before any document: exit 2, no line.
    let (code, stdout, stderr) = batch("yesterday");
    assert_eq!(code, Some(2), "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("validation-time") && stderr.contains("validation_time"),
        "{stderr}"
    );
}

#[test]
fn extend_writes_the_pdf_or_exits_1() {
    let dir = temp_dir("cli-extend");
    let input = fixture("pades/b-lt.pdf");
    let out = dir.join("extended.pdf");
    let extend = |input: &Path, level: &str, out: &Path| {
        run(dss_cli(&dir)
            .arg("extend")
            .arg(input)
            .args(["--level", level, "-o"])
            .arg(out))
    };
    let (code, stdout, stderr) = extend(&input, "lt", &out);
    assert_eq!(code, Some(0), "stdout: {stdout}; stderr: {stderr}");
    assert!(stdout.contains("PAdES-BASELINE-LT"), "{stdout}");
    let original = std::fs::read(&input).unwrap();
    let extended = std::fs::read(&out).unwrap();
    assert!(extended.len() > original.len() && extended.starts_with(&original));

    // LTA needs a TSA, and none is configured: DSS refuses, nothing is written, no temporary file is left.
    let _ = std::fs::remove_file(&out);
    let (code, _, stderr) = extend(&input, "lta", &out);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("no TSA is configured"), "{stderr}");
    assert!(!out.exists());
    assert_eq!(leftovers(&dir), Vec::<String>::new());

    // In place: the input is replaced only by the complete result.
    let in_place = dir.join("in-place.pdf");
    std::fs::copy(&input, &in_place).unwrap();
    let (code, stdout, stderr) = run(dss_cli(&dir)
        .arg("extend")
        .arg(&in_place)
        .args(["--level", "lt", "--json", "-o"])
        .arg(&in_place));
    assert_eq!(code, Some(0), "{stderr}");
    let summary: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(summary["level"], "PAdES-BASELINE-LT", "{stdout}");
    let replaced = std::fs::read(&in_place).unwrap();
    assert_eq!(summary["size"].as_u64(), Some(replaced.len() as u64));
    assert!(replaced.len() > original.len() && replaced.starts_with(&original));
    assert_eq!(leftovers(&dir), Vec::<String>::new());

    // An output directory that does not exist is reported, with its path, before the engine runs.
    let unwritable = dir.join("no-such-dir/out.pdf");
    let (code, _, stderr) = extend(&input, "lt", &unwritable);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains(&*unwritable.to_string_lossy()), "{stderr}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // A write-protected output file is refused, as a plain write would be, not replaced by rename.
        let protected = dir.join("protected.pdf");
        std::fs::write(&protected, b"keep me").unwrap();
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o444)).unwrap();
        let (code, _, stderr) = extend(&input, "lt", &protected);
        assert_eq!(code, Some(2), "{stderr}");
        assert!(stderr.contains("protected.pdf"), "{stderr}");
        assert_eq!(std::fs::read(&protected).unwrap(), b"keep me");

        // A FIFO (as `-o >(cat > x.pdf)` gives) is written directly: there is no file to rename over.
        let fifo = dir.join("pipe.pdf");
        assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let reader = {
            let fifo = fifo.clone();
            std::thread::spawn(move || std::fs::read(fifo).unwrap())
        };
        let (code, _, stderr) = extend(&input, "lt", &fifo);
        assert_eq!(code, Some(0), "{stderr}");
        let piped = reader.join().unwrap();
        assert!(piped.len() > original.len() && piped.starts_with(&original));
        assert_eq!(leftovers(&dir), Vec::<String>::new());
    }
}

/// Temporary files the CLI left in `dir` (it names them `.<target>.<pid>.tmp`).
fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect()
}

/// `sign prepare` writes the request, `sign complete` the signed PDF; the recorded CMS from
/// testdata/fixtures/signing/ stands in for the external signer.
#[test]
fn sign_prepare_then_complete() {
    let dir = temp_dir("cli-sign");
    let pdf = fixture("content/document.pdf");
    let time = recorded("pades-cms")["signing_time"].as_str().unwrap().to_owned();
    let request = dir.join("request.json");
    let out = dir.join("signed.pdf");

    let (code, stdout, stderr) = run(dss_cli(&dir)
        .args(["sign", "prepare"])
        .arg(&pdf)
        .args(["--mode", "cms", "--level", "b", "--signing-time", &time, "--request"])
        .arg(&request));
    assert_eq!(code, Some(0), "stdout: {stdout}; stderr: {stderr}");
    assert_eq!(stdout.trim().len(), 44, "the digest alone, base64: {stdout}");
    assert!(std::fs::read_to_string(&request).unwrap().contains(&time));

    let (code, stdout, stderr) = run(dss_cli(&dir)
        .args(["sign", "complete"])
        .arg(&pdf)
        .arg("--request")
        .arg(&request)
        .arg("--signature")
        .arg(fixture("signing/pades-cms.sig"))
        .args(["--json", "-o"])
        .arg(&out));
    assert_eq!(code, Some(0), "stdout: {stdout}; stderr: {stderr}");
    let signed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(signed["level"], "PAdES-BASELINE-T", "{stdout}");
    assert!(std::fs::read(&out).unwrap().starts_with(&std::fs::read(&pdf).unwrap()));

    // A CMS for other content: refused with exit status 1, nothing written.
    let _ = std::fs::remove_file(&out);
    let (code, _, stderr) = run(dss_cli(&dir)
        .args(["sign", "complete"])
        .arg(&pdf)
        .arg("--request")
        .arg(&request)
        .arg("--signature")
        .arg(fixture("signing/cades-cms.sig"))
        .arg("-o")
        .arg(&out));
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("not signed"), "{stderr}");
    assert!(!out.exists());
    assert_eq!(leftovers(&dir), Vec::<String>::new());
}

fn recorded(case: &str) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(fixture(&format!("signing/{case}.json"))).unwrap()).unwrap()
}

/// The signer's certificate and its chain of a recorded signature-value case, written as DER files.
fn certificate_files(dir: &Path, case: &serde_json::Value) -> (PathBuf, PathBuf) {
    let der = |b64: &serde_json::Value| {
        base64::engine::general_purpose::STANDARD
            .decode(b64.as_str().unwrap())
            .unwrap()
    };
    let cert = dir.join("signer.der");
    let chain = dir.join("issuer.der");
    std::fs::write(&cert, der(&case["signing_certificate"])).unwrap();
    assert_eq!(case["certificate_chain"].as_array().unwrap().len(), 1);
    std::fs::write(&chain, der(&case["certificate_chain"][0])).unwrap();
    (cert, chain)
}

fn pem(der_file: &Path) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(std::fs::read(der_file).unwrap());
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

/// The recorded external signatures of the other modes and formats, through the CLI's flags: `--mode
/// signature-value` with `--cert`/`--chain` (DER and PEM bundles), CAdES detached and enveloping.
#[test]
fn sign_signature_value_and_cades() {
    let dir = temp_dir("cli-sign-modes");
    let complete = |document: &Path, request: &Path, signature: &str, out: &Path| {
        run(dss_cli(&dir)
            .args(["sign", "complete"])
            .arg(document)
            .arg("--request")
            .arg(request)
            .arg("--signature")
            .arg(fixture(&format!("signing/{signature}.sig")))
            .arg("-o")
            .arg(out))
    };

    // PAdES, signature value: DER certificate files.
    let case = recorded("pades-signature-value");
    let (cert, chain) = certificate_files(&dir, &case);
    let pdf = fixture("content/document.pdf");
    let request = dir.join("pades-request.json");
    let prepare = |cert_args: &[&OsStr], request: &Path| {
        run(dss_cli(&dir)
            .args(["sign", "prepare"])
            .arg(&pdf)
            .args(["--mode", "signature-value", "--level", "b", "--signing-time"])
            .arg(case["signing_time"].as_str().unwrap())
            .args(cert_args)
            .arg("--request")
            .arg(request))
    };
    let (code, digest, stderr) = prepare(
        &[
            "--cert".as_ref(),
            cert.as_os_str(),
            "--chain".as_ref(),
            chain.as_os_str(),
        ],
        &request,
    );
    assert_eq!(code, Some(0), "{stderr}");
    let (code, stdout, stderr) = complete(&pdf, &request, "pades-signature-value", &dir.join("signed.pdf"));
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stdout.contains("PAdES-BASELINE-B"), "{stdout}");

    // The same certificates as one PEM bundle given to --cert: the signer first, then its issuer. The library
    // takes one certificate per entry, so the CLI splits the bundle: same options, same digest.
    let bundle = dir.join("bundle.pem");
    std::fs::write(&bundle, format!("{}{}", pem(&cert), pem(&chain))).unwrap();
    let bundle_request = dir.join("bundle-request.json");
    let (code, bundle_digest, stderr) = prepare(&["--cert".as_ref(), bundle.as_os_str()], &bundle_request);
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(bundle_digest, digest);
    let written: serde_json::Value = serde_json::from_slice(&std::fs::read(&bundle_request).unwrap()).unwrap();
    assert_eq!(written["certificate_chain"].as_array().unwrap().len(), 1, "{written}");
    // A bundle given to --chain is split too.
    let (code, _, stderr) = prepare(
        &[
            "--cert".as_ref(),
            cert.as_os_str(),
            "--chain".as_ref(),
            bundle.as_os_str(),
        ],
        &bundle_request,
    );
    assert_eq!(code, Some(0), "{stderr}");
    let written: serde_json::Value = serde_json::from_slice(&std::fs::read(&bundle_request).unwrap()).unwrap();
    assert_eq!(written["certificate_chain"].as_array().unwrap().len(), 2, "{written}");

    // CAdES, CMS mode, detached (the default for content that is not a PDF).
    let txt = fixture("content/document.txt");
    let request = dir.join("cades-request.json");
    let (code, _, stderr) = run(dss_cli(&dir)
        .args(["sign", "prepare"])
        .arg(&txt)
        .args(["--mode", "cms", "--level", "b", "--signing-time"])
        .arg(recorded("cades-cms")["signing_time"].as_str().unwrap())
        .arg("--request")
        .arg(&request));
    assert_eq!(code, Some(0), "{stderr}");
    let (code, stdout, stderr) = complete(&txt, &request, "cades-cms", &dir.join("document.txt.p7s"));
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stdout.contains("CAdES-BASELINE-T (detached)"), "{stdout}");

    // CAdES, signature value, enveloping.
    let case = recorded("cades-signature-value");
    let (cert, chain) = certificate_files(&dir, &case);
    let request = dir.join("cades-sv-request.json");
    let (code, _, stderr) = run(dss_cli(&dir)
        .args(["sign", "prepare"])
        .arg(&txt)
        .args([
            "--mode",
            "signature-value",
            "--level",
            "b",
            "--format",
            "cades",
            "--packaging",
            "enveloping",
        ])
        .arg("--signing-time")
        .arg(case["signing_time"].as_str().unwrap())
        .arg("--cert")
        .arg(&cert)
        .arg("--chain")
        .arg(&chain)
        .arg("--request")
        .arg(&request));
    assert_eq!(code, Some(0), "{stderr}");
    // The flags give the recorded options, plus the file name the CLI always passes. DSS names the content in an
    // enveloping CMS after it and the fixture was prepared without one, so it goes before completing.
    let mut written: serde_json::Value = serde_json::from_slice(&std::fs::read(&request).unwrap()).unwrap();
    assert_eq!(written["filename"], "document.txt");
    written.as_object_mut().unwrap().remove("filename");
    written.as_object_mut().unwrap().remove("format");
    assert_eq!(written, case);
    std::fs::write(&request, written.to_string()).unwrap();
    let (code, stdout, stderr) = complete(&txt, &request, "cades-signature-value", &dir.join("document.txt.p7m"));
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stdout.contains("CAdES-BASELINE-B (enveloping)"), "{stdout}");
}

/// A visible signature from the --visible-* flags: completing it with the recorded CMS proves the flags build the
/// same options, and the same appearance, as testdata/fixtures/signing/pades-visible-cms.json.
#[test]
fn sign_visible() {
    let dir = temp_dir("cli-visible");
    let pdf = fixture("content/document.pdf");
    let recorded = recorded("pades-visible-cms");
    let image = dir.join("visible.png");
    let image_bytes = base64::engine::general_purpose::STANDARD
        .decode(recorded["pades"]["visible"]["image"].as_str().unwrap())
        .unwrap();
    std::fs::write(&image, image_bytes).unwrap();
    let request = dir.join("visible-request.json");
    let out = dir.join("visible-signed.pdf");
    let prepare = |visible: &[&OsStr]| {
        run(dss_cli(&dir)
            .args(["sign", "prepare"])
            .arg(&pdf)
            .args(["--mode", "cms", "--level", "b", "--signing-time"])
            .arg(recorded["signing_time"].as_str().unwrap())
            .args(visible)
            .arg("--request")
            .arg(&request))
    };

    let (code, _, stderr) = prepare(&[
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
    ]);
    assert_eq!(code, Some(0), "{stderr}");

    let (code, stdout, stderr) = run(dss_cli(&dir)
        .args(["sign", "complete"])
        .arg(&pdf)
        .arg("--request")
        .arg(&request)
        .arg("--signature")
        .arg(fixture("signing/pades-visible-cms.sig"))
        .arg("-o")
        .arg(&out));
    assert_eq!(code, Some(0), "stdout: {stdout}; stderr: {stderr}");
    assert!(stdout.contains("PAdES-BASELINE-B"), "{stdout}");

    // Visible options without a placement are a usage error.
    let (code, _, stderr) = prepare(&["--visible-text".as_ref(), "x".as_ref()]);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("--visible-field"), "{stderr}");

    // Non-finite numbers would reach the library as null ("not given"): refused by the CLI.
    for (flag, value) in [
        ("--visible-font-size", "nan"),
        ("--visible-font-size", "1e400"),
        ("--visible-rect", "nan,650,240,80"),
        ("--visible-rect", "300,650,inf,80"),
    ] {
        let placement: [&OsStr; 2] = if flag == "--visible-rect" {
            ["--visible-page".as_ref(), "1".as_ref()]
        } else {
            ["--visible-field".as_ref(), "Firma1".as_ref()]
        };
        let (code, _, stderr) = prepare(&[
            flag.as_ref(),
            value.as_ref(),
            "--visible-text".as_ref(),
            "x".as_ref(),
            placement[0],
            placement[1],
        ]);
        assert_eq!(code, Some(2), "{flag} {value}: {stderr}");
        assert!(stderr.contains("not a finite number"), "{flag} {value}: {stderr}");
    }
}

#[test]
fn tl_snapshot_option_reaches_the_library() {
    let dir = temp_dir("cli-tl");
    let missing = dir.join("no-such.tlsnap");
    let (code, _, stderr) = run(dss_cli(&dir).arg("--tl-snapshot").arg(&missing).args(["tl", "status"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("TL_SNAPSHOT_REJECTED"), "{stderr}");

    // Without lists, `tl status` exits 1 and names the root of trust in use.
    let (code, stdout, stderr) = run(dss_cli(&dir).args(["tl", "status"]));
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    let keystore = repo_root().join("trust/oj-keystore.p12");
    assert!(
        stdout.contains(&format!("OJ keystore: {}", keystore.display())),
        "{stdout}"
    );
    // The library reports the keystore it loaded, with its digest (the one snapshots record).
    let line = stdout.lines().find(|l| l.contains("OJ keystore: ")).unwrap();
    let sha = line
        .split_once("(sha256 ")
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("no digest: {line}"));
    assert!(sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()), "{line}");
    let (code, stdout, stderr) = run(dss_cli(&dir).args(["tl", "status", "--json"]));
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    let status: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(status["oj_keystore"]["sha256"], sha, "{stdout}");
}

/// `version` loads the library only: no engine and no cache directory created. (This development build always
/// finds the repository's keystore, so whether `version` works without any keystore is checked by
/// scripts/package.sh on the release layout; here, an --oj-keystore that does not exist is only reported.)
#[test]
fn version_needs_no_engine() {
    let dir = temp_dir("cli-version");
    let cache = dir.join("cache");
    let (code, stdout, stderr) = run(bare_cli(Path::new(env!("CARGO_BIN_EXE_dss-cli")))
        .arg("--cache-dir")
        .arg(&cache)
        .arg("version"));
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stdout.starts_with(&format!("dss-cli {}\n", env!("CARGO_PKG_VERSION"))),
        "{stdout}"
    );
    assert!(stdout.contains("\nEU DSS "), "{stdout}");
    // The rebuilt library reports its API version, and it is the one this build speaks. (The numbers are compared
    // with each other: naming dss::API_VERSION here would link this test binary against the library.)
    let api = stdout
        .lines()
        .find_map(|l| l.strip_prefix("API version "))
        .unwrap_or_else(|| panic!("{stdout}"));
    let (reported, expected) = api
        .strip_suffix(')')
        .and_then(|a| a.split_once(" (dss-cli expects "))
        .unwrap_or_else(|| panic!("{api}"));
    assert!(reported.parse::<u32>().is_ok(), "not reported: {api}");
    assert_eq!(reported, expected, "{api}");
    assert!(!cache.exists(), "version created the cache directory");

    let missing = dir.join("no-such-keystore.p12");
    let (code, stdout, stderr) = run(bare_cli(Path::new(env!("CARGO_BIN_EXE_dss-cli")))
        .arg("--oj-keystore")
        .arg(&missing)
        .arg("version"));
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stdout.contains("\nEU DSS "), "{stdout}");
}

/// The OJ keystore is the root of trust: it is looked up next to the executable and in the package layout, never
/// in the current directory (a directory supplying `trust/oj-keystore.p12` and a cache would otherwise choose the
/// trust anchors).
#[test]
fn oj_keystore_lookup() {
    let keystore = repo_root().join("trust/oj-keystore.p12");
    let reported = |exe: &Path, cwd: &Path| {
        let (code, stdout, stderr) = run(bare_cli(exe).current_dir(cwd).arg("version"));
        assert_eq!(code, Some(0), "{stderr}");
        stdout
            .lines()
            .find_map(|l| l.strip_prefix("OJ keystore: "))
            .unwrap_or_else(|| panic!("{stdout}"))
            .to_owned()
    };

    // A keystore planted in the current directory is not used (this development build falls back to the
    // repository's).
    let cwd = temp_dir("cli-cwd");
    std::fs::create_dir_all(cwd.join("trust")).unwrap();
    std::fs::write(cwd.join("trust/oj-keystore.p12"), b"planted").unwrap();
    let cli = Path::new(env!("CARGO_BIN_EXE_dss-cli"));
    assert_eq!(reported(cli, &cwd), keystore.display().to_string());

    // The package layout: bin/dss-cli and share/dss-native/oj-keystore.p12.
    let package = temp_dir("cli-package");
    std::fs::create_dir_all(package.join("bin")).unwrap();
    std::fs::create_dir_all(package.join("share/dss-native")).unwrap();
    std::fs::copy(cli, package.join("bin/dss-cli")).unwrap();
    std::fs::copy(&keystore, package.join("share/dss-native/oj-keystore.p12")).unwrap();
    assert_eq!(
        reported(&package.join("bin/dss-cli"), &cwd),
        package
            .join("bin/../share/dss-native/oj-keystore.p12")
            .display()
            .to_string()
    );

    // Next to the executable comes first.
    std::fs::copy(&keystore, package.join("bin/oj-keystore.p12")).unwrap();
    assert_eq!(
        reported(&package.join("bin/dss-cli"), &cwd),
        package.join("bin/oj-keystore.p12").display().to_string()
    );
}

#[test]
fn config_file_excludes_the_flags_it_replaces() {
    let dir = temp_dir("cli-config");
    let config = dir.join("config.json");
    let json = serde_json::json!({
        "oj_keystore": {"path": repo_root().join("trust/oj-keystore.p12")},
        "require_trusted_lists": false,
        "revocation": "offline",
        "extra_trusted_certificates": [fixture("pki/root-ca.pem")],
    });
    std::fs::write(&config, json.to_string()).unwrap();
    let cli = || {
        let mut cmd = bare_cli(Path::new(env!("CARGO_BIN_EXE_dss-cli")));
        cmd.arg("--config")
            .arg(&config)
            .arg("--cache-dir")
            .arg(dir.join("cache"));
        cmd
    };
    let (code, stdout, stderr) = run(cli().arg("validate").arg(fixture("pades/b-lta.pdf")));
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    // --log-level is not a trust input: it overrides the file's level (scripts/diff-vs-jvm.sh relies on it).
    let (code, stdout, stderr) = run(cli().args(["--log-level", "info", "tl", "status"]));
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert!(stderr.contains("INFO"), "the library logs at info: {stderr}");

    // A flag the config replaces, or its environment variable, is a usage error instead of being dropped.
    let (code, _, stderr) = run(cli().args(["--country", "IT", "tl", "status"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    let (code, _, stderr) = run(cli()
        .env("DSS_TL_SNAPSHOT", dir.join("x.tlsnap"))
        .args(["tl", "status"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("--tl-snapshot"), "{stderr}");

    // The same when the flag comes after the subcommand, where clap's own conflict check does not reach.
    let doc = fixture("pades/b-lta.pdf");
    let doc = doc.to_str().unwrap();
    for (args, flag) in [
        (&["validate", doc, "--country", "ZZZ"][..], "--country"),
        (
            &["tl", "status", "--tl-snapshot", "/nonexistent.tlsnap"],
            "--tl-snapshot",
        ),
        (&["tl", "status", "--offline-revocation"], "--offline-revocation"),
        (&["tl", "status", "--tsa-url", "http://tsa.invalid"], "--tsa-url"),
        (&["version", "--trust", doc], "--trust"),
    ] {
        let (code, stdout, stderr) = run(cli().args(args));
        assert_eq!(code, Some(2), "{args:?}: {stdout}{stderr}");
        assert!(
            stderr.contains("cannot be used with") && stderr.contains(flag),
            "{args:?}: {stderr}"
        );
        assert!(stdout.is_empty(), "{args:?}: {stdout}");
    }

    // An empty DSS_* variable is unset, not a given (and conflicting) empty value.
    let (code, stdout, stderr) = run(cli().env("DSS_TSA_URL", "").args(["tl", "status"]));
    assert_eq!(code, Some(1), "{stdout}{stderr}");
}

#[test]
fn engine_flags_are_checked() {
    let dir = temp_dir("cli-flags");
    // --tsa-user means nothing without a TSA.
    let (code, _, stderr) = run(dss_cli(&dir).args(["--tsa-user", "alice", "tl", "status"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("--tsa-url"), "{stderr}");
    let (code, _, stderr) = run(dss_cli(&dir).env("DSS_TSA_USER", "alice").args(["tl", "status"]));
    assert_eq!(code, Some(2), "{stderr}");
    let (code, _, stderr) = run(dss_cli(&dir).args(["tl", "status", "--tsa-user", "alice"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("--tsa-url"), "{stderr}");
    // The user from the environment and the URL as a flag (clap's own `requires` refused this mix).
    let (code, stdout, stderr) = run(dss_cli(&dir)
        .env("DSS_TSA_USER", "alice")
        .env("DSS_TSA_PASSWORD", "secret")
        .args(["--tsa-url", "https://tsa.invalid", "tl", "status"]));
    assert_eq!(code, Some(1), "no lists, but the engine starts: {stdout}{stderr}");

    // An unknown log level is refused instead of falling back to the library's INFO.
    let (code, _, stderr) = run(dss_cli(&dir).args(["--log-level", "bogus", "tl", "status"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("possible values"), "{stderr}");

    // A heap size without a unit would be bytes: refused before the isolate is created.
    let (code, _, stderr) = run(dss_cli(&dir).args(["--max-heap", "512", "tl", "status"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("max_heap"), "{stderr}");

    let (code, _, stderr) = run(dss_cli(&dir).args(["--tl-threads", "0", "tl", "status"]));
    assert_eq!(code, Some(2), "{stderr}");

    // The TSA password: --tsa-password-file (or DSS_TSA_PASSWORD_FILE) needs a user; a user needs a password.
    let tsa = ["--tsa-url", "https://tsa.invalid", "--tsa-user", "alice"];
    let password = dir.join("tsa-password");
    let (code, _, stderr) = run(dss_cli(&dir)
        .arg("--tsa-password-file")
        .arg(&password)
        .args(["tl", "status"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("--tsa-user"), "{stderr}");
    let (code, _, stderr) = run(dss_cli(&dir).args(tsa).args(["tl", "status"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("--tsa-password-file or the DSS_TSA_PASSWORD"),
        "{stderr}"
    );
    let (code, _, stderr) = run(dss_cli(&dir)
        .args(tsa)
        .env("DSS_TSA_PASSWORD_FILE", &password)
        .args(["tl", "status"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("TSA password file") && stderr.contains("tsa-password"),
        "{stderr}"
    );
    std::fs::write(&password, "secret\n").unwrap();
    let (code, stdout, stderr) = run(dss_cli(&dir)
        .args(tsa)
        .arg("--tsa-password-file")
        .arg(&password)
        .args(["tl", "status"]));
    assert_eq!(code, Some(1), "no lists, but the engine starts: {stdout}{stderr}");

    // An empty DSS_* variable is unset: DSS_TSA_USER= does not ask for a --tsa-url.
    let (code, stdout, stderr) = run(dss_cli(&dir).env("DSS_TSA_USER", "").args(["tl", "status"]));
    assert_eq!(code, Some(1), "{stdout}{stderr}");
}

/// `tl snapshot` writes the synthetic lists; a config with `tl_snapshot` starts from them with an empty cache.
#[test]
#[ignore = "needs DSS_TEST_SYNTHETIC_DIR (scripts/test-rust.sh)"]
fn synthetic_tl_snapshot_written_and_loaded() {
    let dir = PathBuf::from(std::env::var("DSS_TEST_SYNTHETIC_DIR").expect("DSS_TEST_SYNTHETIC_DIR not set"));
    let tmp = temp_dir("cli-snapshot");
    let file = tmp.join("lists.tlsnap");
    let cli = || bare_cli(Path::new(env!("CARGO_BIN_EXE_dss-cli")));
    let out: Output = cli()
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
    let out = cli()
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
