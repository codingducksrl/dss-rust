// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! dss-cli: a thin demo over the `dss` crate.
//!
//!   dss-cli validate <file> [--detached <file>]... [--report detailed|etsi|diagnostic]... [--out-dir <dir>] [--json]
//!   dss-cli extend <file.pdf> --level t|lt|lta --out <file.pdf> [--json]
//!   dss-cli sign prepare <file> --mode cms|signature-value --level b|t|lt|lta --request <request.json> [...]
//!                        [--visible-field <name> | --visible-page <n> --visible-rect x,y,w,h] [--visible-text ...]
//!   dss-cli sign complete <file> --request <request.json> --signature <file> --out <file> [--json]
//!   dss-cli tl refresh [--json]
//!   dss-cli tl status [--json]
//!   dss-cli tl snapshot --out <file> [--json]
//!   dss-cli --tl-snapshot <file> <command>   (any command: start from a snapshot instead of the cache)
//!   dss-cli version
//!
//! Exit status: 0 success (for `validate`: every signature TOTAL_PASSED), 1 validation not passed, extension
//! refused by DSS or external signature not usable, 2 error.
//! Output to a closed pipe (`| head`) is dropped; the exit status is the same.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use base64::Engine as _;
use clap::{Args, Parser, Subcommand, ValueEnum};

use dss::{
    Config, DetachedContent, DigestAlgorithm, Engine, EngineBuilder, ErrorCode, ExtendOptions, ImagePosition,
    Indication, Level, ListStatus, Options, Packaging, PadesOptions, Placement, Report, Reports, Revocation,
    SignOptions, SignatureFormat, Signed, SigningMode, TextAlign, TrustedListStatus, Tsa, VisibleSignature,
};

/// `println!` that returns write errors instead of panicking, and ignores a closed pipe.
macro_rules! out {
    ($($arg:tt)*) => {
        print_line(format_args!($($arg)*))?
    };
}

fn print_line(line: std::fmt::Arguments) -> io::Result<()> {
    match writeln!(io::stdout().lock(), "{line}") {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        r => r,
    }
}

#[derive(Parser)]
#[command(
    name = "dss-cli",
    version,
    about = "Validate CAdES/PAdES signatures with EU DSS, extend PAdES signatures, sign with an external signer; \
             manage EU trusted lists"
)]
struct Cli {
    #[command(flatten)]
    engine: EngineArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct EngineArgs {
    /// Trusted-list cache directory (created if missing).
    #[arg(long, env = "DSS_CACHE_DIR", default_value = "dss-cache", global = true)]
    cache_dir: PathBuf,
    /// Full config_json file; replaces every option below except --cache-dir and --max-heap.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Start from this trusted-list snapshot (`tl snapshot`) instead of the cache: no list is parsed or
    /// validated. It must have been written with the same trusted-list options (--country, --oj-keystore).
    #[arg(long, env = "DSS_TL_SNAPSHOT", global = true)]
    tl_snapshot: Option<PathBuf>,
    /// OJ keystore with the LOTL signing certificates [default: oj-keystore.p12 next to the executable,
    /// else trust/oj-keystore.p12].
    #[arg(long, env = "DSS_OJ_KEYSTORE", global = true)]
    oj_keystore: Option<PathBuf>,
    /// Load only these national trusted lists (repeatable, e.g. --country IT).
    #[arg(long = "country", global = true)]
    countries: Vec<String>,
    /// Use only revocation data embedded in the signatures (no CRL/OCSP/AIA requests).
    #[arg(long, global = true)]
    offline_revocation: bool,
    /// Extra trusted certificate, PEM or DER (repeatable).
    #[arg(long = "trust", global = true)]
    trusted_certificates: Vec<PathBuf>,
    /// Validate even if no trusted list is loaded.
    #[arg(long, global = true)]
    allow_without_trusted_lists: bool,
    /// RFC 3161 timestamping service, for `extend --level t|lta` and `sign` at T and LTA.
    #[arg(long, env = "DSS_TSA_URL", global = true)]
    tsa_url: Option<String>,
    /// HTTP Basic user for the TSA; the password comes from the DSS_TSA_PASSWORD environment variable.
    #[arg(long, env = "DSS_TSA_USER", global = true)]
    tsa_user: Option<String>,
    /// Maximum heap of the engine, e.g. 512m, 2g.
    #[arg(long, global = true)]
    max_heap: Option<String>,
    /// Extra isolate runtime option, for diagnostics (repeatable), e.g. -XX:+PrintGC.
    #[arg(long = "isolate-arg", allow_hyphen_values = true, global = true, hide = true)]
    isolate_args: Vec<String>,
    /// Library log level (stderr): error, warn, info, debug.
    #[arg(long, default_value = "error", global = true)]
    log_level: String,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a signed document (PDF, .p7m, .p7s; base64 and nested .p7m.p7m accepted).
    Validate(ValidateArgs),
    /// Validate many documents with one engine; one JSON line per document on stdout (used by
    /// scripts/diff-vs-jvm.sh).
    ValidateBatch(BatchArgs),
    /// Extend the signatures of a PDF to PAdES-BASELINE-T, -LT or -LTA and write the result.
    Extend(ExtendArgs),
    /// Sign with a key held elsewhere: `prepare` gives the digest to send to the signer, `complete` builds the
    /// signed document from what it returned.
    #[command(subcommand)]
    Sign(SignCommand),
    /// Trusted lists.
    #[command(subcommand)]
    Tl(TlCommand),
    /// Library and DSS versions.
    Version,
}

#[derive(Args)]
struct ValidateArgs {
    file: PathBuf,
    /// Signed content of a detached signature (repeatable).
    #[arg(long)]
    detached: Vec<PathBuf>,
    /// Extra report to produce (repeatable); written to --out-dir.
    #[arg(long = "report", value_enum)]
    reports: Vec<ReportArg>,
    /// Where to write the XML reports (<file>.simple.xml, ...).
    #[arg(long)]
    out_dir: Option<PathBuf>,
    /// Print the result as JSON (without the XML reports).
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct BatchArgs {
    /// File with one case per line: `<document>[<TAB><detached content>...]`. Paths as given are echoed back.
    #[arg(long)]
    cases: PathBuf,
    /// Validate as of this instant (ISO-8601 UTC) instead of now, e.g. to compare runs.
    #[arg(long)]
    validation_time: Option<String>,
    /// Documents validated in parallel [default: CPUs].
    #[arg(long)]
    parallel: Option<usize>,
}

#[derive(Args)]
struct ExtendArgs {
    /// Signed PDF.
    file: PathBuf,
    /// Target level: lt embeds the revocation data the signatures need; t and lta add a timestamp (--tsa-url).
    #[arg(long, value_enum)]
    level: LevelArg,
    /// Where to write the extended PDF.
    #[arg(long, short)]
    out: PathBuf,
    /// Print the result as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum LevelArg {
    T,
    Lt,
    Lta,
}

#[derive(Subcommand)]
enum SignCommand {
    /// Print the digest the external signer must sign (base64, on stdout) and write the request for `complete`.
    Prepare(Box<SignPrepareArgs>),
    /// Build the signed document from the request `prepare` wrote and what the external signer returned.
    Complete(SignCompleteArgs),
}

#[derive(Args)]
struct SignPrepareArgs {
    /// Document to sign: a PDF (PAdES by default) or any file (CAdES).
    file: PathBuf,
    /// cms: the signer returns a detached CMS for the content's digest. signature-value: it returns only the
    /// signature value for the digest of DSS's signed attributes (needs --cert).
    #[arg(long, value_enum)]
    mode: ModeArg,
    /// Level of the signed document: t and lta add a timestamp (--tsa-url) unless the signer's CMS has one,
    /// lt and lta embed the certificates and revocation data.
    #[arg(long, value_enum)]
    level: SignLevelArg,
    /// Signature format [default: pades for a PDF, cades otherwise].
    #[arg(long, value_enum)]
    format: Option<FormatArg>,
    /// CAdES: detached (.p7s) or enveloping (.p7m) [default: detached].
    #[arg(long, value_enum)]
    packaging: Option<PackagingArg>,
    #[arg(long, value_enum)]
    digest: Option<DigestArg>,
    /// Signer's certificate, PEM or DER (required with --mode signature-value).
    #[arg(long)]
    cert: Option<PathBuf>,
    /// Issuer certificate, PEM or DER (repeatable).
    #[arg(long)]
    chain: Vec<PathBuf>,
    /// Signing time, ISO-8601 UTC in whole seconds [default: now].
    #[arg(long)]
    signing_time: Option<String>,
    /// PAdES: /Reason of the signature dictionary.
    #[arg(long)]
    reason: Option<String>,
    /// PAdES: /Location.
    #[arg(long)]
    location: Option<String>,
    /// PAdES: /ContactInfo.
    #[arg(long)]
    contact_info: Option<String>,
    /// PAdES: /Name.
    #[arg(long)]
    signer_name: Option<String>,
    /// PAdES: bytes reserved for the CMS [default: 32768 for cms, 9472 for signature-value].
    #[arg(long)]
    content_size: Option<u32>,
    #[command(flatten)]
    visible: VisibleArgs,
    /// Where to write the request: the options, with the signing time, for `sign complete`.
    #[arg(long)]
    request: PathBuf,
    /// Print the whole prepare result as JSON instead of the digest alone.
    #[arg(long)]
    json: bool,
}

/// A visible PAdES signature: placed with --visible-field, or with --visible-page and --visible-rect.
#[derive(Args)]
struct VisibleArgs {
    /// Visible signature in this empty signature field of the PDF.
    #[arg(long, conflicts_with_all = ["visible_page", "visible_rect"])]
    visible_field: Option<String>,
    /// Visible signature in a new field on this page (from 1); needs --visible-rect.
    #[arg(long, requires = "visible_rect")]
    visible_page: Option<u32>,
    /// X,Y,WIDTH,HEIGHT of the new field, in points from the top-left corner of the page as displayed.
    #[arg(long, value_parser = parse_rect, requires = "visible_page", value_name = "X,Y,W,H")]
    visible_rect: Option<Rect>,
    /// Text of the visible signature (\n for a new line). Placeholders: {signer_name}, {signing_time}, {reason},
    /// {location}.
    #[arg(long)]
    visible_text: Option<String>,
    /// PNG or JPEG shown in the visible signature.
    #[arg(long)]
    visible_image: Option<PathBuf>,
    /// TrueType font for the text [default: PT Serif].
    #[arg(long)]
    visible_font: Option<PathBuf>,
    /// Largest font size in points; the text shrinks to fit [default: 10].
    #[arg(long)]
    visible_font_size: Option<f64>,
    /// Text colour, #RRGGBB [default: #000000].
    #[arg(long)]
    visible_text_color: Option<String>,
    /// Background colour, #RRGGBB [default: none].
    #[arg(long)]
    visible_background: Option<String>,
    #[arg(long, value_enum)]
    visible_text_align: Option<TextAlignArg>,
    /// Where the image goes relative to the text [default: left].
    #[arg(long, value_enum)]
    visible_image_position: Option<ImagePositionArg>,
    /// Time zone of {signing_time}, e.g. Europe/Rome [default: UTC].
    #[arg(long)]
    visible_time_zone: Option<String>,
    /// java.time pattern of {signing_time} [default: yyyy-MM-dd HH:mm:ss xxx].
    #[arg(long)]
    visible_date_format: Option<String>,
}

#[derive(Clone, Copy)]
struct Rect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

fn parse_rect(s: &str) -> Result<Rect, String> {
    let v: Vec<f64> = s
        .split(',')
        .map(|p| p.trim().parse::<f64>().map_err(|_| format!("'{p}' is not a number")))
        .collect::<Result<_, _>>()?;
    match v[..] {
        [x, y, width, height] => Ok(Rect { x, y, width, height }),
        _ => Err("expected X,Y,WIDTH,HEIGHT".into()),
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum TextAlignArg {
    Left,
    Center,
    Right,
}

#[derive(Clone, Copy, ValueEnum)]
enum ImagePositionArg {
    Left,
    Right,
    Top,
    Bottom,
    Behind,
}

#[derive(Args)]
struct SignCompleteArgs {
    /// The same document as for `sign prepare`.
    file: PathBuf,
    /// The request `sign prepare` wrote.
    #[arg(long)]
    request: PathBuf,
    /// What the external signer returned: a CMS (DER, BER, base64 or PEM) or a signature value (raw or base64).
    #[arg(long)]
    signature: PathBuf,
    /// Where to write the signed document.
    #[arg(long, short)]
    out: PathBuf,
    /// Print the result as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    Cms,
    SignatureValue,
}

#[derive(Clone, Copy, ValueEnum)]
enum SignLevelArg {
    B,
    T,
    Lt,
    Lta,
}

#[derive(Clone, Copy, ValueEnum)]
enum FormatArg {
    Pades,
    Cades,
}

#[derive(Clone, Copy, ValueEnum)]
enum PackagingArg {
    Detached,
    Enveloping,
}

#[derive(Clone, Copy, ValueEnum)]
enum DigestArg {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, ValueEnum)]
enum ReportArg {
    Detailed,
    Etsi,
    Diagnostic,
}

#[derive(Subcommand)]
enum TlCommand {
    /// Download and validate the LOTL and national trusted lists into the cache.
    Refresh {
        #[arg(long)]
        json: bool,
    },
    /// Show what is loaded (from the cache, without network).
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Write the loaded trusted lists to a snapshot file, for --tl-snapshot (config_json `tl_snapshot`). Load
    /// them first: from the cache, or with `tl refresh`.
    Snapshot {
        /// Where to write the snapshot.
        #[arg(long, short)]
        out: PathBuf,
        /// Print what describes the snapshot as JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let started = Instant::now();
    let workers = match &cli.command {
        Command::ValidateBatch(b) => b.parallel.unwrap_or_else(default_parallelism),
        _ => 1,
    };
    let engine = build_engine(&cli.engine, workers)?;
    let ready = started.elapsed();
    match cli.command {
        Command::Version => {
            let v = engine.version()?;
            out!(
                "dss-cli {}\nlibdssnative {}\nEU DSS {}\n{}",
                env!("CARGO_PKG_VERSION"),
                v.library,
                v.dss,
                v.runtime
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Tl(TlCommand::Status { json }) => {
            let status = engine.trusted_list_status()?;
            if json {
                out!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                print_status(&status)?;
                out!("(engine ready in {} ms)", ready.as_millis());
            }
            Ok(if status.loaded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Command::Tl(TlCommand::Snapshot { out, json }) => {
            let snapshot = engine.export_tl_snapshot()?;
            std::fs::write(&out, &snapshot.bytes)?;
            let info = &snapshot.info;
            if json {
                out!("{}", serde_json::to_string_pretty(info)?);
            } else {
                out!(
                    "Wrote {} ({} bytes): {} trusted certificates, lists loaded {} at {}",
                    out.display(),
                    info.size,
                    info.trusted_certificates,
                    info.lists_loaded.as_ref().map_or("?", |r| r.mode.as_str()),
                    info.lists_loaded.as_ref().map_or("?", |r| r.finished_at.as_str()),
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Tl(TlCommand::Refresh { json }) => {
            let record = engine.refresh_trusted_lists()?;
            let status = engine.trusted_list_status()?;
            if json {
                out!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                out!(
                    "Online refresh {} in {} ms",
                    if record.completed { "completed" } else { "FAILED" },
                    record.duration_ms
                );
                if let Some(e) = &record.error {
                    out!("  error: {e}");
                }
                print_status(&status)?;
            }
            Ok(if record.completed && status.loaded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Command::Validate(args) => validate(&engine, args),
        Command::ValidateBatch(args) => validate_batch(&engine, args, workers),
        Command::Extend(args) => extend(&engine, args),
        Command::Sign(SignCommand::Prepare(args)) => sign_prepare(&engine, *args),
        Command::Sign(SignCommand::Complete(args)) => sign_complete(&engine, args),
    }
}

fn default_parallelism() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// One output line per case, in input order. Exit status 2 only if the batch itself cannot run; per-document
/// failures are reported in their line.
fn validate_batch(engine: &Engine, args: BatchArgs, parallel: usize) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cases: Vec<Vec<String>> = std::fs::read_to_string(&args.cases)?
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| l.split('\t').map(str::to_owned).collect())
        .collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let lines: Vec<std::sync::Mutex<Option<String>>> = cases.iter().map(|_| std::sync::Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..parallel.max(1) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(case) = cases.get(i) else { break };
                    *lines[i].lock().unwrap() = Some(batch_line(engine, case, args.validation_time.as_deref()));
                }
            });
        }
    });
    for line in lines {
        out!("{}", line.into_inner().unwrap().unwrap_or_default());
    }
    Ok(ExitCode::SUCCESS)
}

fn batch_line(engine: &Engine, case: &[String], validation_time: Option<&str>) -> String {
    let file = &case[0];
    let options = Options {
        detached_contents: case[1..].iter().map(DetachedContent::file).collect(),
        validation_time: validation_time.map(str::to_owned),
        filename: Path::new(file).file_name().map(|n| n.to_string_lossy().into_owned()),
        ..Default::default()
    };
    let outcome = std::fs::read(file)
        .map_err(|e| dss::Error::Api {
            code: dss::ErrorCode::InvalidArgument,
            message: format!("{file}: {e}"),
        })
        .and_then(|doc| engine.validate_json(&doc, &serde_json::to_string(&options).expect("options serialize")));
    let line = match outcome {
        Ok(json) => {
            let mut result: serde_json::Value = serde_json::from_str(&json).unwrap_or(serde_json::Value::Null);
            strip_xml(&mut result);
            if let Some(obj) = result.as_object_mut() {
                obj.remove("ok");
            }
            serde_json::json!({"file": file, "ok": true, "result": result})
        }
        Err(e) => serde_json::json!({
            "file": file,
            "ok": false,
            "error": {"code": e.code().map(|c| format!("{c:?}")), "message": e.to_string()},
        }),
    };
    line.to_string()
}

fn build_engine(a: &EngineArgs, workers: usize) -> Result<Engine, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(&a.cache_dir)?;
    let mut builder = match &a.config {
        Some(path) => EngineBuilder::with_config_json(&a.cache_dir, std::fs::read_to_string(path)?),
        None => {
            let mut config = Config::new(oj_keystore(a)?);
            config.countries = a.countries.clone();
            config.extra_trusted_certificates = a.trusted_certificates.clone();
            if a.offline_revocation {
                config.revocation = Some(Revocation::Offline);
            }
            if a.allow_without_trusted_lists {
                config.require_trusted_lists = Some(false);
            }
            if let Some(url) = &a.tsa_url {
                let password = std::env::var("DSS_TSA_PASSWORD").ok();
                if a.tsa_user.is_some() && password.is_none() {
                    return Err("--tsa-user needs the DSS_TSA_PASSWORD environment variable".into());
                }
                config.tsa = Some(Tsa {
                    url: url.clone(),
                    username: a.tsa_user.clone(),
                    password: a.tsa_user.as_ref().and(password),
                });
            }
            config.log_level = Some(a.log_level.clone());
            config.tl_snapshot = a.tl_snapshot.clone();
            Engine::builder(&a.cache_dir, &config)
        }
    };
    builder = builder.workers(workers);
    if let Some(heap) = &a.max_heap {
        builder = builder.max_heap(heap);
    }
    for arg in &a.isolate_args {
        builder = builder.isolate_arg(arg);
    }
    Ok(builder.build()?)
}

fn oj_keystore(a: &EngineArgs) -> Result<PathBuf, String> {
    if let Some(p) = &a.oj_keystore {
        return Ok(p.clone());
    }
    let mut candidates = vec![];
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("oj-keystore.p12"));
        candidates.push(dir.join("../share/dss-native/oj-keystore.p12"));
    }
    candidates.push(PathBuf::from("trust/oj-keystore.p12"));
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| "OJ keystore not found: pass --oj-keystore or set DSS_OJ_KEYSTORE".to_string())
}

fn validate(engine: &Engine, args: ValidateArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let document = std::fs::read(&args.file)?;
    let mut reports: Vec<Report> = args
        .reports
        .iter()
        .map(|r| match r {
            ReportArg::Detailed => Report::Detailed,
            ReportArg::Etsi => Report::Etsi,
            ReportArg::Diagnostic => Report::Diagnostic,
        })
        .collect();
    reports.push(Report::Simple);
    let options = Options {
        reports: Some(reports),
        detached_contents: args.detached.iter().map(DetachedContent::file).collect(),
        filename: args.file.file_name().map(|n| n.to_string_lossy().into_owned()),
        ..Default::default()
    };
    let started = Instant::now();
    let result = engine.validate(&document, &options)?;
    let took = started.elapsed();

    if let Some(dir) = &args.out_dir {
        write_reports(dir, &args.file, &result, 0)?;
    }
    if args.json {
        let mut summary = serde_json::to_value(&result)?;
        strip_xml(&mut summary);
        out!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print_reports(&result, 0)?;
        out!("({} ms)", took.as_millis());
    }
    Ok(if result.all_passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn extend(engine: &Engine, args: ExtendArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let document = std::fs::read(&args.file)?;
    let options = ExtendOptions {
        level: match args.level {
            LevelArg::T => Level::T,
            LevelArg::Lt => Level::Lt,
            LevelArg::Lta => Level::Lta,
        },
        filename: args.file.file_name().map(|n| n.to_string_lossy().into_owned()),
    };
    let started = Instant::now();
    let extended = match engine.extend(&document, &options) {
        Ok(extended) => extended,
        Err(e) if e.code() == Some(ErrorCode::ExtensionFailed) => {
            eprintln!("not extended: {e}");
            return Ok(ExitCode::from(1));
        }
        Err(e) => return Err(e.into()),
    };
    let took = started.elapsed();
    std::fs::write(&args.out, &extended.document)?;
    if args.json {
        let mut summary = serde_json::to_value(&extended)?;
        summary["out"] = args.out.display().to_string().into();
        summary["size"] = extended.document.len().into();
        out!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        let decoded = if extended.transformations.is_empty() {
            String::new()
        } else {
            format!(", input decoded: {}", extended.transformations.join(", "))
        };
        out!(
            "Extended to {}: wrote {} ({} bytes{decoded}, {} ms)",
            extended.level,
            args.out.display(),
            extended.document.len(),
            took.as_millis()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn sign_prepare(engine: &Engine, args: SignPrepareArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let document = std::fs::read(&args.file)?;
    let mut options = SignOptions::new(
        match args.mode {
            ModeArg::Cms => SigningMode::Cms,
            ModeArg::SignatureValue => SigningMode::SignatureValue,
        },
        match args.level {
            SignLevelArg::B => Level::B,
            SignLevelArg::T => Level::T,
            SignLevelArg::Lt => Level::Lt,
            SignLevelArg::Lta => Level::Lta,
        },
    );
    options.format = args.format.map(|f| match f {
        FormatArg::Pades => SignatureFormat::Pades,
        FormatArg::Cades => SignatureFormat::Cades,
    });
    options.packaging = args.packaging.map(|p| match p {
        PackagingArg::Detached => Packaging::Detached,
        PackagingArg::Enveloping => Packaging::Enveloping,
    });
    options.digest_algorithm = args.digest.map(|d| match d {
        DigestArg::Sha256 => DigestAlgorithm::Sha256,
        DigestArg::Sha384 => DigestAlgorithm::Sha384,
        DigestArg::Sha512 => DigestAlgorithm::Sha512,
    });
    options.signing_certificate = args.cert.as_deref().map(certificate).transpose()?;
    options.certificate_chain = args.chain.iter().map(|p| certificate(p)).collect::<Result<_, _>>()?;
    options.signing_time = args.signing_time;
    options.filename = args.file.file_name().map(|n| n.to_string_lossy().into_owned());
    let visible = visible_signature(args.visible)?;
    if args.reason.is_some()
        || args.location.is_some()
        || args.contact_info.is_some()
        || args.signer_name.is_some()
        || args.content_size.is_some()
        || visible.is_some()
    {
        options.pades = Some(PadesOptions {
            reason: args.reason,
            location: args.location,
            contact_info: args.contact_info,
            signer_name: args.signer_name,
            content_size: args.content_size,
            visible,
        });
    }

    let prepared = match engine.prepare_signature(&document, &options) {
        Ok(prepared) => prepared,
        Err(e) if e.code() == Some(ErrorCode::SigningFailed) => {
            eprintln!("cannot sign: {e}");
            return Ok(ExitCode::from(1));
        }
        Err(e) => return Err(e.into()),
    };
    options.signing_time = Some(prepared.signing_time.clone());
    std::fs::write(&args.request, serde_json::to_string_pretty(&options)? + "\n")?;
    if args.json {
        out!("{}", serde_json::to_string_pretty(&prepared)?);
    } else {
        out!("{}", prepared.digest_base64());
        eprintln!(
            "{} digest to sign ({}, {}); request written to {}. Then: dss-cli sign complete {} --request {} \
             --signature <signer output> -o <signed file>",
            prepared.format,
            prepared.digest_algorithm,
            if matches!(args.mode, ModeArg::Cms) {
                "the signer returns a detached CMS"
            } else {
                "the signer returns the signature value"
            },
            args.request.display(),
            args.file.display(),
            args.request.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// The --visible-* options, or `None` when none is given.
fn visible_signature(a: VisibleArgs) -> Result<Option<VisibleSignature>, Box<dyn std::error::Error>> {
    let placement = match (a.visible_field, a.visible_page, a.visible_rect) {
        (Some(field), _, _) => Placement::Field { field },
        (None, Some(page), Some(r)) => Placement::Rect {
            page,
            x: r.x,
            y: r.y,
            width: r.width,
            height: r.height,
        },
        _ => {
            let any = a.visible_text.is_some()
                || a.visible_image.is_some()
                || a.visible_font.is_some()
                || a.visible_font_size.is_some()
                || a.visible_text_color.is_some()
                || a.visible_background.is_some()
                || a.visible_text_align.is_some()
                || a.visible_image_position.is_some()
                || a.visible_time_zone.is_some()
                || a.visible_date_format.is_some();
            if any {
                return Err("a visible signature needs --visible-field, or --visible-page and --visible-rect".into());
            }
            return Ok(None);
        }
    };
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let mut v = VisibleSignature::new(placement);
    v.text = a.visible_text.map(|t| t.replace("\\n", "\n"));
    v.image = a.visible_image.as_deref().map(read).transpose()?;
    v.font = a.visible_font.as_deref().map(read).transpose()?;
    v.font_size = a.visible_font_size;
    v.text_color = a.visible_text_color;
    v.background_color = a.visible_background;
    v.text_align = a.visible_text_align.map(|t| match t {
        TextAlignArg::Left => TextAlign::Left,
        TextAlignArg::Center => TextAlign::Center,
        TextAlignArg::Right => TextAlign::Right,
    });
    v.image_position = a.visible_image_position.map(|p| match p {
        ImagePositionArg::Left => ImagePosition::Left,
        ImagePositionArg::Right => ImagePosition::Right,
        ImagePositionArg::Top => ImagePosition::Top,
        ImagePositionArg::Bottom => ImagePosition::Bottom,
        ImagePositionArg::Behind => ImagePosition::Behind,
    });
    v.time_zone = a.visible_time_zone;
    v.date_format = a.visible_date_format;
    Ok(Some(v))
}

/// A certificate file as `SignOptions` takes it: PEM as is, DER as base64.
fn certificate(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(match std::str::from_utf8(&bytes) {
        Ok(text) if text.contains("-----BEGIN CERTIFICATE-----") => text.to_owned(),
        _ => base64::engine::general_purpose::STANDARD.encode(&bytes),
    })
}

fn sign_complete(engine: &Engine, args: SignCompleteArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let document = std::fs::read(&args.file)?;
    let request = std::fs::read_to_string(&args.request).map_err(|e| format!("{}: {e}", args.request.display()))?;
    let signature = std::fs::read(&args.signature).map_err(|e| format!("{}: {e}", args.signature.display()))?;
    let started = Instant::now();
    let (json, document) = match engine.complete_signature_json(&document, &request, &signature) {
        Ok(result) => result,
        Err(e) if e.code() == Some(ErrorCode::SigningFailed) => {
            eprintln!("not signed: {e}");
            return Ok(ExitCode::from(1));
        }
        Err(e) => return Err(e.into()),
    };
    let took = started.elapsed();
    let signed: Signed = serde_json::from_str(&json)?;
    std::fs::write(&args.out, &document)?;
    if args.json {
        let mut summary = serde_json::to_value(&signed)?;
        summary["out"] = args.out.display().to_string().into();
        summary["size"] = document.len().into();
        out!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        out!(
            "Signed {} ({}): wrote {} ({} bytes, {} ms)",
            signed.level,
            signed.packaging.to_lowercase(),
            args.out.display(),
            document.len(),
            took.as_millis()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn print_reports(r: &Reports, depth: usize) -> io::Result<()> {
    let pad = "  ".repeat(depth);
    let transformations = if r.transformations.is_empty() {
        String::new()
    } else {
        format!(" (decoded: {})", r.transformations.join(", "))
    };
    out!(
        "{pad}{} container, {} signature(s){transformations}",
        r.container,
        r.signatures.len()
    );
    for s in &r.signatures {
        let mark = if s.indication == Indication::TotalPassed {
            "✔"
        } else {
            "✘"
        };
        out!(
            "{pad}{mark} {:?}{}  {}  {}",
            s.indication,
            s.sub_indication
                .as_deref()
                .map(|x| format!(" / {x}"))
                .unwrap_or_default(),
            s.format.as_deref().unwrap_or("?"),
            s.qualification.as_deref().unwrap_or("?"),
        );
        out!("{pad}    signed by:    {}", s.signed_by.as_deref().unwrap_or("?"));
        out!("{pad}    signing time: {}", s.signing_time.as_deref().unwrap_or("?"));
        for e in &s.errors {
            out!("{pad}    error:   {e}");
        }
        if !s.warnings.is_empty() {
            out!("{pad}    {} warning(s)", s.warnings.len());
        }
    }
    for n in &r.nested {
        out!("{pad}  nested envelope:");
        print_reports(n, depth + 2)?;
    }
    Ok(())
}

fn write_reports(dir: &Path, file: &Path, r: &Reports, level: usize) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let base = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "document".into());
    let base = if level == 0 {
        base
    } else {
        format!("{base}.nested{level}")
    };
    let write = |kind: &str, xml: &Option<String>| -> std::io::Result<()> {
        if let Some(xml) = xml {
            let path = dir.join(format!("{base}.{kind}.xml"));
            std::fs::write(&path, xml)?;
            eprintln!("wrote {}", path.display());
        }
        Ok(())
    };
    write("simple", &Some(r.simple_report_xml.clone()))?;
    write("detailed", &r.detailed_report_xml)?;
    write("etsi", &r.etsi_report_xml)?;
    write("diagnostic", &r.diagnostic_data_xml)?;
    for n in &r.nested {
        write_reports(dir, file, n, level + 1)?;
    }
    Ok(())
}

fn strip_xml(v: &mut serde_json::Value) {
    if let Some(obj) = v.as_object_mut() {
        obj.retain(|k, _| !k.ends_with("_xml"));
        if let Some(serde_json::Value::Array(nested)) = obj.get_mut("nested") {
            nested.iter_mut().for_each(strip_xml);
        }
    }
}

fn print_status(s: &TrustedListStatus) -> io::Result<()> {
    out!(
        "Trusted lists {}: {} trusted certificates{}",
        if s.loaded { "loaded" } else { "NOT loaded" },
        s.trusted_certificates,
        if s.refresh_in_progress {
            " (online refresh running)"
        } else {
            ""
        }
    );
    for (label, r) in [
        ("from cache", &s.last_offline_refresh),
        ("online", &s.last_online_refresh),
    ] {
        if let Some(r) = r {
            let label = if r.mode == "snapshot" { "from snapshot" } else { label };
            out!(
                "  last refresh {label}: {} ({} ms, {} certificates)",
                r.finished_at,
                r.duration_ms,
                r.trusted_certificates
            );
        }
    }
    if let Some(t) = &s.tl_snapshot {
        out!(
            "  snapshot {} written {}, lists loaded {} at {}",
            t.path.as_deref().unwrap_or("?"),
            t.created_at,
            t.lists_loaded.as_ref().map_or("?", |r| r.mode.as_str()),
            t.lists_loaded.as_ref().map_or("?", |r| r.finished_at.as_str()),
        );
    }
    let row = |l: &ListStatus| -> io::Result<()> {
        let problem = [&l.download.error, &l.parsing.error, &l.validation.error]
            .into_iter()
            .flatten()
            .next()
            .map(|e| format!("  ! {}", e.chars().take(100).collect::<String>()))
            .unwrap_or_default();
        out!(
            "  {:<4} seq {:<4} next update {:<22} signature {:<14} {:<10}{}",
            l.territory.as_deref().unwrap_or("?"),
            l.sequence_number.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
            l.next_update.as_deref().unwrap_or("-"),
            l.validation.indication.as_deref().unwrap_or("-"),
            match l.used_for_trust {
                Some(true) => "trusted",
                Some(false) => "NOT USED",
                None => "",
            },
            problem
        );
        Ok(())
    };
    for l in &s.lotls {
        out!("  LOTL {}", l.url);
        row(l)?;
    }
    if !s.tls.is_empty() {
        out!("  {} national trusted lists:", s.tls.len());
        let mut tls: Vec<&ListStatus> = s.tls.iter().collect();
        tls.sort_by(|a, b| a.territory.cmp(&b.territory));
        tls.into_iter().try_for_each(row)?;
    }
    for a in &s.alerts {
        out!("  alert {} {}: {}", a.kind, a.url.as_deref().unwrap_or(""), a.message);
    }
    Ok(())
}
