// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! dss-cli: a thin demo over the `dss` crate.
//!
//! ```text
//! dss-cli validate <file> [--detached <file>]... [--report detailed|etsi|diagnostic --out-dir <dir>] [--json]
//! dss-cli validate-batch --cases <file> [--validation-time <instant>] [--parallel <n>]
//! dss-cli extend <file.pdf> --level t|lt|lta --out <file.pdf> [--json]
//! dss-cli sign prepare <file> --mode cms|signature-value --level b|t|lt|lta --request <request.json> [...]
//!                      [--visible-field <name> | --visible-page <n> --visible-rect x,y,w,h] [--visible-text ...]
//! dss-cli sign complete <file> --request <request.json> --signature <file> --out <file> [--json]
//! dss-cli tl refresh [--json]
//! dss-cli tl status [--json]
//! dss-cli tl snapshot --out <file> [--json]
//! dss-cli --tl-snapshot <file> <command>   (any command: start from a snapshot instead of the cache)
//! dss-cli version                          (no engine: loads the library only)
//! ```
//!
//! Exit status: 0 success (for `validate`: every signature TOTAL_PASSED), 1 validation not passed, trusted lists
//! not loaded, extension refused by DSS or external signature not usable, 2 error (`EXIT_STATUS`, printed by
//! `--help`). Output to a closed pipe (`| head`, stdout or stderr) is dropped; the exit status is the same.
//!
//! Files are written atomically (a temporary file next to the target, synced, then renamed over it), and the
//! temporary file is created before the engine runs, so an unwritable destination fails before any work or TSA
//! request is spent. A write-protected target is refused; a FIFO, `/dev/stdout` or a process substitution
//! (`-o >(...)`) is opened up front and written directly.

use std::ffi::OsString;
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

/// The exit-status contract, printed at the end of `--help`.
const EXIT_STATUS: &str = "\
Exit status:
  0  success: validate, every signature TOTAL_PASSED; tl status and tl refresh, trusted lists loaded
  1  validate: a signature is not TOTAL_PASSED (or there is none); tl status and tl refresh: no trusted list
     loaded; extend and sign: DSS refused (EXTENSION_FAILED, SIGNING_FAILED)
  2  error: bad arguments, unreadable or unwritable files, any other library error
validate-batch exits 0 once the batch ran, with per-document failures in their own line.
Output into a closed pipe (stdout or stderr) is dropped; the exit status is the same.";

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

/// `eprintln!` that never panics: diagnostics into a closed (or failing) stderr are dropped, so they cannot change
/// the exit status or interrupt the work, such as writing the remaining `--out-dir` reports.
macro_rules! err {
    ($($arg:tt)*) => {
        eprint_line(format_args!($($arg)*))
    };
}

fn eprint_line(line: std::fmt::Arguments) {
    let _ = writeln!(io::stderr().lock(), "{line}");
}

#[derive(Parser)]
#[command(
    name = "dss-cli",
    version,
    about = "Validate CAdES/PAdES signatures with EU DSS, extend PAdES signatures, sign with an external signer; \
             manage EU trusted lists",
    after_help = EXIT_STATUS
)]
struct Cli {
    #[command(flatten)]
    engine: EngineArgs,
    #[command(subcommand)]
    command: Command,
}

/// The engine options a full `--config` replaces: giving one of them (or its environment variable) together with
/// `--config` is a usage error instead of being silently dropped. (`--log-level` is not a trust input: with
/// `--config` it overrides the file's `log_level`.)
///
/// Clap enforces this only for flags placed before the subcommand; [`usage_problem`] checks the parsed values,
/// wherever the flag was given.
const CONFIG_REPLACES: [&str; 10] = [
    "tl_snapshot",
    "oj_keystore",
    "countries",
    "offline_revocation",
    "trusted_certificates",
    "allow_without_trusted_lists",
    "tsa_url",
    "tsa_user",
    "tsa_password_file",
    "tl_threads",
];

/// The first option given together with `--config` that the config file replaces, as `--flag` (with its
/// environment variable, if it has one). Clap's `conflicts_with_all` misses a global flag placed after the
/// subcommand (`--config c.json validate doc.pdf --country IT`), so the parsed values are checked here.
fn config_conflict(a: &EngineArgs) -> Option<&'static str> {
    a.config.as_ref()?;
    [
        (a.tl_snapshot.is_some(), "--tl-snapshot (or DSS_TL_SNAPSHOT)"),
        (a.oj_keystore.is_some(), "--oj-keystore (or DSS_OJ_KEYSTORE)"),
        (!a.countries.is_empty(), "--country"),
        (a.offline_revocation, "--offline-revocation"),
        (!a.trusted_certificates.is_empty(), "--trust"),
        (a.allow_without_trusted_lists, "--allow-without-trusted-lists"),
        (a.tsa_url.is_some(), "--tsa-url (or DSS_TSA_URL)"),
        (a.tsa_user.is_some(), "--tsa-user (or DSS_TSA_USER)"),
        (
            a.tsa_password_file.is_some(),
            "--tsa-password-file (or DSS_TSA_PASSWORD_FILE)",
        ),
        (a.tl_threads.is_some(), "--tl-threads"),
    ]
    .into_iter()
    .find_map(|(given, flag)| given.then_some(flag))
}

#[derive(Args)]
struct EngineArgs {
    /// Trusted-list cache directory (created if missing) [default: dss-native in the user cache directory:
    /// $XDG_CACHE_HOME or ~/.cache, ~/Library/Caches on macOS].
    #[arg(long, env = "DSS_CACHE_DIR", global = true)]
    cache_dir: Option<PathBuf>,
    /// Full config_json file. Excludes the trusted-list, trust and TSA options below (as flags or through their
    /// environment variables); --cache-dir, --max-heap and --isolate-arg still apply, --log-level overrides the
    /// file's log_level.
    #[arg(long, global = true, conflicts_with_all = CONFIG_REPLACES)]
    config: Option<PathBuf>,
    /// Start from this trusted-list snapshot (`tl snapshot`) instead of the cache: no list is parsed or
    /// validated. It must have been written with the same trusted-list options (--country, --oj-keystore).
    #[arg(long, env = "DSS_TL_SNAPSHOT", global = true)]
    tl_snapshot: Option<PathBuf>,
    /// OJ keystore with the LOTL signing certificates: the root of trust of the trusted lists [default:
    /// oj-keystore.p12 next to the executable or in ../share/dss-native/ relative to it; development builds
    /// also use the repository's trust/oj-keystore.p12]. Never looked up in the current directory.
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
    /// RFC 3161 timestamping service. Needed by `extend --level t|lta`, by `extend --level lt` for a signature
    /// without a timestamp (B level), and by `sign` at T, LT and LTA unless the signer's CMS has a timestamp.
    /// A TSA (or TL mirror, CRL or OCSP responder) on a loopback or private address is refused unless a --config
    /// file sets "http": {"block_private_addresses": false}.
    #[arg(long, env = "DSS_TSA_URL", global = true)]
    tsa_url: Option<String>,
    /// HTTP Basic user for the TSA (needs --tsa-url); the password comes from --tsa-password-file or the
    /// DSS_TSA_PASSWORD environment variable.
    #[arg(long, env = "DSS_TSA_USER", global = true)]
    tsa_user: Option<String>,
    /// File holding the TSA password (needs --tsa-user; trailing whitespace ignored): unlike DSS_TSA_PASSWORD it
    /// stays out of the environment of the process.
    #[arg(long, env = "DSS_TSA_PASSWORD_FILE", global = true)]
    tsa_password_file: Option<PathBuf>,
    /// Threads that download and validate the trusted lists, 1 to 64 [default: CPUs, at most 16].
    #[arg(long, global = true, value_parser = clap::value_parser!(u32).range(1..=64))]
    tl_threads: Option<u32>,
    /// Maximum heap of the engine, e.g. 512m, 2g (digits and a unit k, m, g or t).
    #[arg(long, global = true)]
    max_heap: Option<String>,
    /// Extra isolate runtime option, for diagnostics (repeatable), e.g. -XX:+PrintGC.
    #[arg(long = "isolate-arg", allow_hyphen_values = true, global = true, hide = true)]
    isolate_args: Vec<String>,
    /// Library log level (stderr) [default: error, or the --config file's]. At info, debug and trace, dss-cli
    /// also reports the OJ keystore and cache it uses.
    #[arg(long, value_enum, global = true)]
    log_level: Option<LogLevel>,
}

/// The library's log levels (slf4j-simple's names).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn name(self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
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
    /// Extra report to produce (repeatable); written to --out-dir, which it needs.
    #[arg(long = "report", value_enum, requires = "out_dir")]
    reports: Vec<ReportArg>,
    /// Where to write the XML reports (FILE.simple.xml, FILE.detailed.xml, ...).
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
    /// Validate as of this instant (ISO-8601 UTC) instead of now, e.g. to compare runs. Checked once, before the
    /// batch: an invalid instant exits with status 2.
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
    /// Target level: t adds a document timestamp, lt the certificates and revocation data the signatures need,
    /// lta both. Needs a TSA (--tsa-url) for t and lta, and for lt when a signature has no timestamp yet (B level).
    #[arg(long, value_enum)]
    level: LevelArg,
    /// Where to write the extended PDF (may be the input: it is replaced only once the result is complete).
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
    /// Level of the signed document: t, lt and lta need a signature timestamp, the signer's CMS's or one from
    /// --tsa-url; lt and lta also embed the certificates and revocation data.
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
    /// Signer's certificate, PEM or DER (required with --mode signature-value). A PEM bundle may follow it with
    /// its issuers, which go to the chain.
    #[arg(long)]
    cert: Option<PathBuf>,
    /// Issuer certificates, PEM (one or more) or DER (repeatable).
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
    /// PAdES: bytes reserved for the CMS [default: 32768 for cms, 9472 for signature-value]. Less than the
    /// estimated CMS needs is refused as INVALID_ARGUMENT (exit 2), by `prepare` and `complete` alike.
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
    #[arg(long, value_parser = parse_finite)]
    visible_font_size: Option<f64>,
    /// Text colour, #RRGGBB [default: black].
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
    let v: Vec<f64> = s.split(',').map(parse_finite).collect::<Result<_, _>>()?;
    match v[..] {
        [x, y, width, height] => Ok(Rect { x, y, width, height }),
        _ => Err("expected X,Y,WIDTH,HEIGHT".into()),
    }
}

/// A finite number: `nan`, `inf` and overflowing values (`1e400`) are refused here, where the JSON would
/// otherwise carry them as `null` (read by the library as "not given").
fn parse_finite(s: &str) -> Result<f64, String> {
    match s.trim().parse::<f64>() {
        Ok(v) if v.is_finite() => Ok(v),
        Ok(_) => Err(format!("'{}' is not a finite number", s.trim())),
        Err(_) => Err(format!("'{}' is not a number", s.trim())),
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
    /// Where to write the signed document (replaced only once the result is complete).
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
    drop_empty_dss_variables();
    let cli = Cli::parse();
    if let Some((kind, message)) = usage_problem(&cli.engine) {
        use clap::CommandFactory;
        // Clap's own usage error: same layout and exit status 2 as one it detects itself.
        Cli::command().error(kind, message).exit();
    }
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            err!("error: {e}");
            ExitCode::from(2)
        }
    }
}

/// An empty `DSS_*` variable (a blank `.env` line, `DSS_TSA_URL= dss-cli ...`) means unset, as in dss-server:
/// clap would otherwise take it as a given, empty option, with an error about a flag nobody typed.
fn drop_empty_dss_variables() {
    let empty: Vec<OsString> = std::env::vars_os()
        .filter(|(name, value)| name.to_str().is_some_and(|n| n.starts_with("DSS_")) && value.is_empty())
        .map(|(name, _)| name)
        .collect();
    for name in empty {
        // SAFETY: called first thing in main, before any other thread of this process exists.
        unsafe { std::env::remove_var(name) };
    }
}

/// The usage errors among the global engine options that clap cannot check itself: its `conflicts_with` misses a
/// global flag placed after the subcommand, and its `requires` wrongly fails on a global option given through its
/// environment variable while the required one is a flag before the subcommand
/// (`DSS_TSA_USER=alice dss-cli --tsa-url https://... extend ...`). So the parsed values are checked here.
fn usage_problem(a: &EngineArgs) -> Option<(clap::error::ErrorKind, String)> {
    use clap::error::ErrorKind;
    if let Some(flag) = config_conflict(a) {
        return Some((
            ErrorKind::ArgumentConflict,
            format!("the argument '--config <CONFIG>' cannot be used with {flag}: the config file replaces it"),
        ));
    }
    if a.tsa_user.is_some() && a.tsa_url.is_none() {
        return Some((
            ErrorKind::MissingRequiredArgument,
            "--tsa-user (or DSS_TSA_USER) needs --tsa-url (or DSS_TSA_URL)".to_owned(),
        ));
    }
    if a.tsa_password_file.is_some() && a.tsa_user.is_none() {
        return Some((
            ErrorKind::MissingRequiredArgument,
            "--tsa-password-file (or DSS_TSA_PASSWORD_FILE) needs --tsa-user (or DSS_TSA_USER)".to_owned(),
        ));
    }
    None
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if let Command::Version = cli.command {
        return version(&cli.engine);
    }
    let started = Instant::now();
    let workers = match &cli.command {
        Command::ValidateBatch(b) => b.parallel.unwrap_or_else(default_parallelism),
        _ => 1,
    };
    let engine = build_engine(&cli.engine, workers)?;
    let ready = started.elapsed();
    match cli.command {
        Command::Version => unreachable!("answered without an engine"),
        Command::Tl(TlCommand::Status { json }) => {
            let status = engine.trusted_list_status()?;
            if json {
                out!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                print_status(&status, || describe_keystore(&cli.engine))?;
                out!("(engine ready in {} ms)", ready.as_millis());
            }
            Ok(if status.loaded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Command::Tl(TlCommand::Snapshot { out, json }) => {
            let file = OutFile::create(&out)?;
            let snapshot = engine.export_tl_snapshot()?;
            file.commit(&snapshot.bytes)?;
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
                print_status(&status, || describe_keystore(&cli.engine))?;
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

/// `version` needs no engine: no cache directory, no trusted lists, no `dss_init`. It loads the library in an
/// isolate of its own, asks `dss_version` (which works before `dss_init`) and tears the isolate down.
fn version(a: &EngineArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let v = dss::library_version()?;
    out!(
        "dss-cli {}\nlibdssnative {}\nEU DSS {}\n{}",
        env!("CARGO_PKG_VERSION"),
        v.library,
        v.dss,
        v.runtime
    );
    out!("{}", api_version_line(v.api_version));
    out!("OJ keystore: {}", describe_keystore(a));
    Ok(ExitCode::SUCCESS)
}

/// The C/JSON contract the library speaks next to the one this build expects (an engine refuses a mismatch).
fn api_version_line(reported: Option<u32>) -> String {
    match reported {
        Some(n) => format!("API version {n} (dss-cli expects {})", dss::API_VERSION),
        None => format!("API version not reported (dss-cli expects {})", dss::API_VERSION),
    }
}

fn default_parallelism() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// One output line per case, in input order. Exit status 2 only if the batch itself cannot run (unreadable cases
/// file, invalid --validation-time); per-document failures are reported in their line.
fn validate_batch(engine: &Engine, args: BatchArgs, parallel: usize) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cases: Vec<Vec<String>> = read_text(&args.cases)?
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| l.split('\t').map(str::to_owned).collect())
        .collect();
    if let Some(time) = &args.validation_time {
        check_validation_time(engine, time)?;
    }
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

/// Lets the library judge `--validation-time` once, with its own parser, before any document: options are read
/// before the document, so a one-byte non-document fails with INVALID_ARGUMENT only when the options are wrong
/// (otherwise with UNSUPPORTED_DOCUMENT, or TRUSTED_LISTS_NOT_LOADED).
fn check_validation_time(engine: &Engine, time: &str) -> Result<(), String> {
    let options = serde_json::json!({ "validation_time": time }).to_string();
    match engine.validate_json(b"-", &options) {
        Err(e) if e.code() == Some(ErrorCode::InvalidArgument) => Err(format!("--validation-time {time:?}: {e}")),
        _ => Ok(()),
    }
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
            // The library's wire name (INVALID_ARGUMENT), null for errors that are not the library's.
            "error": {"code": e.code().map(|c| c.to_string()), "message": e.to_string()},
        }),
    };
    line.to_string()
}

fn build_engine(a: &EngineArgs, workers: usize) -> Result<Engine, Box<dyn std::error::Error>> {
    let cache_dir = cache_dir(a)?;
    std::fs::create_dir_all(&cache_dir).map_err(|e| format!("cache directory {}: {e}", cache_dir.display()))?;
    let mut builder = match &a.config {
        Some(path) => EngineBuilder::with_config_json(&cache_dir, config_file(path, a.log_level)?),
        None => {
            let keystore = oj_keystore(a)?;
            if a.log_level >= Some(LogLevel::Info) {
                err!(
                    "dss-cli: OJ keystore {}, cache directory {}",
                    absolute(&keystore).display(),
                    absolute(&cache_dir).display()
                );
            }
            let mut config = Config::new(keystore);
            config.countries = a.countries.clone();
            config.extra_trusted_certificates = a.trusted_certificates.clone();
            if a.offline_revocation {
                config.revocation = Some(Revocation::Offline);
            }
            if a.allow_without_trusted_lists {
                config.require_trusted_lists = Some(false);
            }
            if let Some(url) = &a.tsa_url {
                let mut tsa = Tsa::new(url.clone());
                tsa.username = a.tsa_user.clone();
                tsa.password = tsa_password(a)?;
                config.tsa = Some(tsa);
            }
            config.tl_threads = a.tl_threads;
            config.log_level = Some(a.log_level.unwrap_or(LogLevel::Error).name().into());
            config.tl_snapshot = a.tl_snapshot.clone();
            Engine::builder(&cache_dir, &config)
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

/// The TSA password for `--tsa-user`: the `--tsa-password-file` (`DSS_TSA_PASSWORD_FILE`) contents without
/// trailing whitespace, else the `DSS_TSA_PASSWORD` environment variable. `None` without a user.
fn tsa_password(a: &EngineArgs) -> Result<Option<String>, String> {
    match (&a.tsa_user, &a.tsa_password_file) {
        (None, _) => Ok(None),
        (Some(_), Some(path)) => Ok(Some(
            std::fs::read_to_string(path)
                .map_err(|e| format!("TSA password file {}: {e}", path.display()))?
                .trim_end()
                .to_owned(),
        )),
        (Some(_), None) => std::env::var("DSS_TSA_PASSWORD").map(Some).map_err(|_| {
            "--tsa-user needs the password: --tsa-password-file or the DSS_TSA_PASSWORD environment variable".to_owned()
        }),
    }
}

/// The `--config` file as is, or with `log_level` set to `--log-level` when that is given.
fn config_file(path: &Path, log_level: Option<LogLevel>) -> Result<String, String> {
    let text = read_text(path)?;
    let Some(level) = log_level else { return Ok(text) };
    let mut config: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let object = config
        .as_object_mut()
        .ok_or_else(|| format!("{}: not a JSON object", path.display()))?;
    object.insert("log_level".into(), level.name().into());
    Ok(config.to_string())
}

/// `--cache-dir` / `DSS_CACHE_DIR`, else `dss-native` in the user's cache directory. Never the current
/// directory: a directory someone else prepared must not decide which trusted lists are loaded.
fn cache_dir(a: &EngineArgs) -> Result<PathBuf, String> {
    match &a.cache_dir {
        Some(dir) => Ok(dir.clone()),
        None => default_cache_dir()
            .ok_or_else(|| "no cache directory: HOME is not set, pass --cache-dir or set DSS_CACHE_DIR".to_string()),
    }
}

fn default_cache_dir() -> Option<PathBuf> {
    let home = || std::env::var_os("HOME").map(PathBuf::from).filter(|h| h.is_absolute());
    let base = if cfg!(target_os = "macos") {
        home()?.join("Library/Caches")
    } else {
        // XDG Base Directory: a relative XDG_CACHE_HOME is invalid and ignored.
        match std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from) {
            Some(dir) if dir.is_absolute() => dir,
            _ => home()?.join(".cache"),
        }
    };
    Some(base.join("dss-native"))
}

/// The OJ keystore is the root of trust of the trusted lists, so it is looked up only where the installation put
/// it: never in the current directory.
fn oj_keystore(a: &EngineArgs) -> Result<PathBuf, String> {
    if let Some(p) = &a.oj_keystore {
        return Ok(p.clone());
    }
    keystore_candidates().into_iter().find(|p| p.is_file()).ok_or_else(|| {
        "OJ keystore not found next to the executable or in ../share/dss-native/ relative to it: pass \
         --oj-keystore or set DSS_OJ_KEYSTORE"
            .to_string()
    })
}

/// Where the keystore is looked up when no path is given: next to the executable, the package layout
/// (`bin/../share/dss-native/`), and for a development build (built without DSS_RELEASE_RPATH_ONLY=1) the
/// repository's `trust/oj-keystore.p12`, by the absolute path build.rs found.
fn keystore_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![];
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("oj-keystore.p12"));
        candidates.push(dir.join("../share/dss-native/oj-keystore.p12"));
    }
    if let Some(dev) = option_env!("DSS_CLI_DEV_OJ_KEYSTORE") {
        candidates.push(PathBuf::from(dev));
    }
    candidates
}

/// Which OJ keystore the engine uses (or would use), for `version` and `tl status`.
fn describe_keystore(a: &EngineArgs) -> String {
    if let Some(config) = &a.config {
        let path = read_text(config)
            .ok()
            .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
            .and_then(|v| v["oj_keystore"]["path"].as_str().map(str::to_owned));
        return match path {
            Some(p) => format!("{} (from {})", absolute(Path::new(&p)).display(), config.display()),
            None => format!("as {} says", config.display()),
        };
    }
    match oj_keystore(a) {
        Ok(p) => absolute(&p).display().to_string(),
        Err(e) => e,
    }
}

fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// `std::fs::read` with the path in the error.
fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// `std::fs::read_to_string` with the path in the error.
fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// An output file. [`create`](Self::create) opens it, or a temporary file next to it, before the engine runs, so
/// an unwritable destination is reported before any work or TSA request is spent; [`commit`](Self::commit)
/// writes the result.
///
/// A regular file (or a new one) is written atomically: the temporary file is written, synced and renamed over
/// the target, so the target, even when it is the input, is never left truncated or half-written, and an
/// uncommitted temporary file is removed on drop. An existing target must be writable, as for a plain write: a
/// write-protected file is refused, not replaced. Anything else (a FIFO, `/dev/stdout`, a process substitution
/// such as `-o >(gzip > x.gz)`, any path under `/dev` or `/proc`) is opened and written directly, since no
/// temporary file can be renamed over it.
#[derive(Debug)]
struct OutFile {
    target: PathBuf,
    /// The temporary file renamed over `target` on commit; `None` when writing `target` directly.
    tmp: Option<PathBuf>,
    file: Option<std::fs::File>,
}

impl OutFile {
    fn create(target: &Path) -> Result<OutFile, String> {
        let fail = |e: &dyn std::fmt::Display| format!("{}: {e}", target.display());
        // Following symlinks, as a plain write would.
        let existing = std::fs::metadata(target).ok();
        if existing.as_ref().is_some_and(|m| m.is_dir()) {
            return Err(fail(&"is a directory"));
        }
        let device_path = |p: &Path| p.starts_with("/dev") || p.starts_with("/proc");
        if existing.as_ref().is_some_and(|m| !m.is_file()) || device_path(target) {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(target)
                .map_err(|e| fail(&e))?;
            return Ok(OutFile {
                target: target.to_path_buf(),
                tmp: None,
                file: Some(file),
            });
        }
        // Through a symlink to the file it names, as a plain write would, instead of replacing the link.
        let target = match std::fs::symlink_metadata(target) {
            Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(target).map_err(|e| fail(&e))?,
            _ => target.to_path_buf(),
        };
        if existing.is_some() {
            // Replacing by rename needs only the directory's permission: check the file's own, without changing
            // it, so that a write-protected file stays protected.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&target)
                .map_err(|e| fail(&e))?;
        }
        let name = target.file_name().ok_or_else(|| fail(&"not a file name"))?;
        let dir = match target.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let mut tmp_name = OsString::from(".");
        tmp_name.push(name);
        tmp_name.push(format!(".{}.tmp", std::process::id()));
        let tmp = dir.join(tmp_name);
        // A leftover of a killed run with the same process id; create_new then refuses anything put back.
        let _ = std::fs::remove_file(&tmp);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| fail(&e))?;
        Ok(OutFile {
            target,
            tmp: Some(tmp),
            file: Some(file),
        })
    }

    fn commit(mut self, bytes: &[u8]) -> Result<(), String> {
        let mut file = self.file.take().expect("an OutFile is committed once");
        let fail = |e: io::Error| format!("{}: {e}", self.target.display());
        let Some(tmp) = self.tmp.take() else {
            // Written directly: a pipe or device has nothing to sync or rename.
            return file.write_all(bytes).and_then(|()| file.flush()).map_err(fail);
        };
        let written = file.write_all(bytes).and_then(|()| {
            // Replacing a file keeps its permissions.
            if let Ok(existing) = std::fs::metadata(&self.target) {
                file.set_permissions(existing.permissions())?;
            }
            file.sync_all()
        });
        drop(file);
        if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, &self.target)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(fail(e));
        }
        // Makes the rename itself durable; best effort (not every file system allows syncing a directory).
        if let Some(dir) = self.target.parent().filter(|d| !d.as_os_str().is_empty()) {
            let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
        }
        Ok(())
    }
}

impl Drop for OutFile {
    fn drop(&mut self) {
        if let Some(tmp) = self.tmp.take() {
            self.file.take();
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

fn validate(engine: &Engine, args: ValidateArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let document = read(&args.file)?;
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
    if let Some(dir) = &args.out_dir {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
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
    let document = read(&args.file)?;
    let mut options = ExtendOptions::new(match args.level {
        LevelArg::T => Level::T,
        LevelArg::Lt => Level::Lt,
        LevelArg::Lta => Level::Lta,
    });
    options.filename = args.file.file_name().map(|n| n.to_string_lossy().into_owned());
    let file = OutFile::create(&args.out)?;
    let started = Instant::now();
    let extended = match engine.extend(&document, &options) {
        Ok(extended) => extended,
        Err(e) if e.code() == Some(ErrorCode::ExtensionFailed) => {
            err!("not extended: {e}");
            return Ok(ExitCode::from(1));
        }
        Err(e) => return Err(e.into()),
    };
    let took = started.elapsed();
    file.commit(&extended.document)?;
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
    let document = read(&args.file)?;
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
    // The library takes one certificate per entry: PEM bundles are split here. A bundle given as --cert is the
    // signer's certificate followed by its issuers.
    let mut chain = vec![];
    if let Some(cert) = &args.cert {
        let mut certs = certificates(cert)?.into_iter();
        options.signing_certificate = certs.next();
        chain.extend(certs);
    }
    for p in &args.chain {
        chain.extend(certificates(p)?);
    }
    options.certificate_chain = chain;
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

    let request = OutFile::create(&args.request)?;
    let prepared = match engine.prepare_signature(&document, &options) {
        Ok(prepared) => prepared,
        Err(e) if e.code() == Some(ErrorCode::SigningFailed) => {
            err!("cannot sign: {e}");
            return Ok(ExitCode::from(1));
        }
        Err(e) => return Err(e.into()),
    };
    options.signing_time = Some(prepared.signing_time.clone());
    request.commit((serde_json::to_string_pretty(&options)? + "\n").as_bytes())?;
    if args.json {
        out!("{}", serde_json::to_string_pretty(&prepared)?);
    } else {
        out!("{}", prepared.digest_base64());
        err!(
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

/// The certificates of a file as `SignOptions` takes them, one per entry: each PEM block of a bundle on its own,
/// a DER file as base64.
fn certificates(path: &Path) -> Result<Vec<String>, String> {
    let bytes = read(path)?;
    match std::str::from_utf8(&bytes) {
        Ok(text) if text.contains(PEM_BEGIN) => pem_certificates(text).map_err(|e| format!("{}: {e}", path.display())),
        _ => Ok(vec![base64::engine::general_purpose::STANDARD.encode(&bytes)]),
    }
}

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// Each `CERTIFICATE` block of a PEM text, from BEGIN to END line; text around the blocks is dropped.
fn pem_certificates(text: &str) -> Result<Vec<String>, String> {
    let mut blocks = vec![];
    let mut rest = text;
    while let Some(start) = rest.find(PEM_BEGIN) {
        let block = &rest[start..];
        let end = block
            .find(PEM_END)
            .ok_or_else(|| format!("PEM certificate {} has no END line", blocks.len() + 1))?;
        blocks.push(format!("{}\n", &block[..end + PEM_END.len()]));
        rest = &block[end + PEM_END.len()..];
    }
    Ok(blocks)
}

fn sign_complete(engine: &Engine, args: SignCompleteArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let document = read(&args.file)?;
    let request = read_text(&args.request)?;
    let signature = read(&args.signature)?;
    let file = OutFile::create(&args.out)?;
    let started = Instant::now();
    let (json, document) = match engine.complete_signature_json(&document, &request, &signature) {
        Ok(result) => result,
        Err(e) if e.code() == Some(ErrorCode::SigningFailed) => {
            err!("not signed: {e}");
            return Ok(ExitCode::from(1));
        }
        Err(e) => return Err(e.into()),
    };
    let took = started.elapsed();
    let signed: Signed = serde_json::from_str(&json)?;
    file.commit(&document)?;
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

fn write_reports(dir: &Path, file: &Path, r: &Reports, level: usize) -> Result<(), String> {
    let base = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "document".into());
    let base = if level == 0 {
        base
    } else {
        format!("{base}.nested{level}")
    };
    let write = |kind: &str, xml: &Option<String>| -> Result<(), String> {
        if let Some(xml) = xml {
            let path = dir.join(format!("{base}.{kind}.xml"));
            OutFile::create(&path)?.commit(xml.as_bytes())?;
            err!("wrote {}", path.display());
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

/// The text of `tl status` and `tl refresh`. `keystore` describes the OJ keystore when the library does not
/// report the one it uses.
fn print_status(s: &TrustedListStatus, keystore: impl FnOnce() -> String) -> io::Result<()> {
    for line in status_lines(s, keystore) {
        out!("{line}");
    }
    Ok(())
}

fn status_lines(s: &TrustedListStatus, keystore: impl FnOnce() -> String) -> Vec<String> {
    let mut lines = vec![format!(
        "Trusted lists {}: {} trusted certificates{}",
        if s.loaded { "loaded" } else { "NOT loaded" },
        s.trusted_certificates,
        if s.refresh_in_progress {
            " (online refresh running)"
        } else {
            ""
        }
    )];
    for (label, r) in [
        ("from cache", &s.last_offline_refresh),
        ("online", &s.last_online_refresh),
    ] {
        if let Some(r) = r {
            let label = if r.mode == "snapshot" { "from snapshot" } else { label };
            lines.push(format!(
                "  last refresh {label}: {} ({} ms, {} certificates)",
                r.finished_at, r.duration_ms, r.trusted_certificates
            ));
        }
    }
    if let Some(t) = &s.tl_snapshot {
        lines.push(format!(
            "  snapshot {} written {}, lists loaded {} at {}",
            t.path.as_deref().unwrap_or("?"),
            t.created_at,
            t.lists_loaded.as_ref().map_or("?", |r| r.mode.as_str()),
            t.lists_loaded.as_ref().map_or("?", |r| r.finished_at.as_str()),
        ));
    }
    let number = |n: Option<u64>| n.map_or_else(|| "-".to_owned(), |n| n.to_string());
    // `published`: the sequence number the rollback protection holds this URL to (the last one published).
    let row = |l: &ListStatus| {
        let problem = [&l.download.error, &l.parsing.error, &l.validation.error]
            .into_iter()
            .flatten()
            .next()
            .map(|e| format!("  ! {}", e.chars().take(100).collect::<String>()))
            .unwrap_or_default();
        format!(
            "  {:<4} seq {:<4} published {:<4} next update {:<22} signature {:<14} {:<10}{}",
            l.territory.as_deref().unwrap_or("?"),
            number(l.sequence_number),
            number(l.last_published_sequence_number),
            l.next_update.as_deref().unwrap_or("-"),
            l.validation.indication.as_deref().unwrap_or("-"),
            match l.used_for_trust {
                Some(true) => "trusted",
                Some(false) => "NOT USED",
                None => "",
            },
            problem
        )
    };
    for l in &s.lotls {
        lines.push(format!("  LOTL {}", l.url));
        lines.push(row(l));
        for p in &l.pivots {
            lines.push(format!("    pivot {}", p.url));
            lines.push(format!("  {}", row(p)));
        }
    }
    if !s.tls.is_empty() {
        lines.push(format!("  {} national trusted lists:", s.tls.len()));
        let mut tls: Vec<&ListStatus> = s.tls.iter().collect();
        tls.sort_by(|a, b| a.territory.cmp(&b.territory));
        lines.extend(tls.into_iter().map(row));
    }
    for a in &s.alerts {
        let mut line = format!("  alert {} {}: {}", a.kind, a.url.as_deref().unwrap_or(""), a.message);
        // tl_rollback: which list was refused, and the one published from the URL that it is behind.
        if a.sequence_number.is_some() || a.previous_sequence_number.is_some() {
            line.push_str(&format!(
                " (refused sequence number {}, issued {}; published {}, issued {})",
                number(a.sequence_number),
                a.issue_date.as_deref().unwrap_or("?"),
                number(a.previous_sequence_number),
                a.previous_issue_date.as_deref().unwrap_or("?"),
            ));
        }
        if let Some(n) = a.count.filter(|&n| n > 1) {
            line.push_str(&format!(
                " [{n} times since {}]",
                a.first_seen.as_deref().unwrap_or("?")
            ));
        }
        lines.push(line);
    }
    lines.push(match &s.oj_keystore {
        Some(k) => format!(
            "  OJ keystore: {} (sha256 {})",
            absolute(Path::new(&k.path)).display(),
            k.sha256
        ),
        None => format!("  OJ keystore: {}", keystore()),
    });
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Also checks that every id in `CONFIG_REPLACES` and every `requires` names an argument.
    #[test]
    fn clap_definition_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn api_version_line_names_both_versions() {
        assert_eq!(
            api_version_line(Some(1)),
            format!("API version 1 (dss-cli expects {})", dss::API_VERSION)
        );
        assert!(api_version_line(None).starts_with("API version not reported"));
    }

    #[test]
    fn numbers_must_be_finite() {
        assert_eq!(parse_finite(" 12.5 "), Ok(12.5));
        for bad in ["nan", "NaN", "inf", "-inf", "infinity", "1e400"] {
            assert!(parse_finite(bad).unwrap_err().contains("not a finite number"), "{bad}");
        }
        assert!(parse_finite("ten").unwrap_err().contains("not a number"));
        let r = parse_rect("300, 650,240,80").unwrap();
        assert_eq!((r.x, r.y, r.width, r.height), (300.0, 650.0, 240.0, 80.0));
        assert!(parse_rect("nan,650,240,80").is_err());
        assert!(parse_rect("1,2,3").is_err());
    }

    #[test]
    fn pem_bundles_are_split_one_certificate_per_entry() {
        let one = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
        let two = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----";
        let bundle = format!("subject=CN=x\n{one}\n\nissuer=CN=y\r\n{two}\n");
        assert_eq!(
            pem_certificates(&bundle).unwrap(),
            vec![format!("{one}\n"), format!("{two}\n")]
        );
        assert_eq!(pem_certificates(one).unwrap().len(), 1);
        assert!(
            pem_certificates(&format!("{one}\n-----BEGIN CERTIFICATE-----\nCCCC\n"))
                .unwrap_err()
                .contains("no END line")
        );
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dss-cli-unit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn out_file_replaces_the_target_only_on_commit() {
        let dir = scratch("outfile");
        let target = dir.join("doc.pdf");
        std::fs::write(&target, b"original").unwrap();

        // Until commit, the target is untouched; dropping an uncommitted file leaves nothing behind.
        let file = OutFile::create(&target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
        assert_eq!(entries(&dir).len(), 2, "the temporary file sits next to the target");
        drop(file);
        assert_eq!(entries(&dir), vec!["doc.pdf"]);
        assert_eq!(std::fs::read(&target).unwrap(), b"original");

        OutFile::create(&target).unwrap().commit(b"extended").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"extended");
        assert_eq!(entries(&dir), vec!["doc.pdf"]);

        // Unwritable destinations fail at create, with the path.
        let missing = dir.join("no-such-dir/out.pdf");
        assert!(OutFile::create(&missing).unwrap_err().contains("no-such-dir/out.pdf"));
        assert!(OutFile::create(&dir).unwrap_err().contains("is a directory"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn out_file_keeps_permissions_and_writes_through_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("outfile-unix");
        let target = dir.join("doc.pdf");
        std::fs::write(&target, b"original").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let link = dir.join("link.pdf");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        OutFile::create(&link).unwrap().commit(b"new").unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o640);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_cache_dir_is_never_relative() {
        if let Some(dir) = default_cache_dir() {
            assert!(dir.is_absolute(), "{}", dir.display());
            assert!(dir.ends_with("dss-native"), "{}", dir.display());
        }
    }

    #[test]
    fn keystore_is_never_looked_up_in_the_current_directory() {
        for candidate in keystore_candidates() {
            assert!(candidate.is_absolute(), "{}", candidate.display());
        }
    }

    /// Clap's `conflicts_with_all` misses a global flag placed after the subcommand; `config_conflict` does not.
    #[test]
    fn config_conflicts_wherever_the_flag_is() {
        let parse = |args: &[&str]| Cli::try_parse_from(args.iter().copied());
        for args in [
            &[
                "dss-cli",
                "--config",
                "c.json",
                "validate",
                "doc.pdf",
                "--country",
                "IT",
            ][..],
            &[
                "dss-cli",
                "--config",
                "c.json",
                "tl",
                "status",
                "--tl-snapshot",
                "x.tlsnap",
            ],
            &[
                "dss-cli",
                "--config",
                "c.json",
                "extend",
                "d.pdf",
                "--level",
                "t",
                "-o",
                "o.pdf",
                "--tsa-url",
                "u",
            ],
            &["dss-cli", "--config", "c.json", "version", "--offline-revocation"],
            &["dss-cli", "--country", "IT", "--config", "c.json", "version"],
        ] {
            match parse(args) {
                Ok(cli) => assert!(config_conflict(&cli.engine).is_some(), "{args:?}"),
                Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ArgumentConflict, "{args:?}"),
            }
        }
        let cli = parse(&[
            "dss-cli",
            "--config",
            "c.json",
            "validate",
            "d.pdf",
            "--log-level",
            "info",
        ])
        .unwrap();
        assert_eq!(config_conflict(&cli.engine), None);
        let cli = parse(&["dss-cli", "validate", "d.pdf", "--country", "IT"]).unwrap();
        assert_eq!(config_conflict(&cli.engine), None);

        // `requires` between global options, wherever they are given.
        let problem = |args: &[&str]| usage_problem(&parse(args).unwrap().engine).map(|(kind, _)| kind);
        let missing = Some(clap::error::ErrorKind::MissingRequiredArgument);
        assert_eq!(problem(&["dss-cli", "version", "--tsa-user", "a"]), missing);
        assert_eq!(problem(&["dss-cli", "--tsa-password-file", "p", "version"]), missing);
        assert_eq!(
            problem(&["dss-cli", "--tsa-url", "u", "version", "--tsa-user", "a"]),
            None
        );
        assert_eq!(
            problem(&[
                "dss-cli",
                "--tsa-url",
                "u",
                "--tsa-user",
                "a",
                "version",
                "--tsa-password-file",
                "p"
            ]),
            None
        );
    }

    /// Replacing by rename needs only the directory's permission: a write-protected file is refused instead.
    #[cfg(unix)]
    #[test]
    fn out_file_refuses_a_write_protected_target() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("outfile-ro");
        let target = dir.join("protected.pdf");
        std::fs::write(&target, b"original").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o444)).unwrap();
        let refused = OutFile::create(&target).unwrap_err();
        assert!(refused.contains("protected.pdf"), "{refused}");
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
        assert_eq!(entries(&dir), vec!["protected.pdf"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Devices, FIFOs and process substitutions cannot be replaced by rename: they are written directly.
    #[cfg(unix)]
    #[test]
    fn out_file_writes_devices_and_fifos_directly() {
        let null = OutFile::create(Path::new("/dev/null")).unwrap();
        assert!(null.tmp.is_none());
        null.commit(b"discarded").unwrap();

        let dir = scratch("outfile-fifo");
        let fifo = dir.join("pipe");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(made.success());
        let reader = {
            let fifo = fifo.clone();
            std::thread::spawn(move || std::fs::read(fifo).unwrap())
        };
        let file = OutFile::create(&fifo).unwrap();
        assert!(file.tmp.is_none());
        file.commit(b"through the pipe").unwrap();
        assert_eq!(reader.join().unwrap(), b"through the pipe");
        assert_eq!(entries(&dir), vec!["pipe"], "no temporary file next to a FIFO");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_lines_show_the_rollback_protection() {
        let list = |url: &str, seq: u64, published: Option<u64>| {
            serde_json::json!({
                "url": url, "territory": "IT", "sequence_number": seq,
                "last_published_sequence_number": published, "version": 5, "issue_date": null,
                "next_update": null, "expired": null, "tsp_count": null, "service_count": null,
                "certificate_count": null, "used_for_trust": true,
                "download": {"status": "ERROR", "error": "rollback refused: the downloaded list is sequence number 41"}
            })
        };
        let status: TrustedListStatus = serde_json::from_value(serde_json::json!({
            "loaded": true, "oj_keystore": null, "trusted_certificates": 3, "extra_trusted_certificates": null,
            "snapshot_published_at": null, "tl_snapshot": null, "refresh_in_progress": false,
            "refresh_started_at": null, "last_offline_refresh": null, "last_online_refresh": null,
            "lotls": [], "tls": [list("https://tl.example/it.xml", 41, Some(42))],
            "alerts": [{
                "type": "tl_rollback", "url": "https://tl.example/it.xml", "message": "older list refused",
                "at": "2026-11-01T00:00:00Z", "first_seen": "2026-10-30T00:00:00Z",
                "last_seen": "2026-11-01T00:00:00Z", "count": 3,
                "previous_sequence_number": 42, "previous_issue_date": "2026-09-01T00:00:00Z",
                "sequence_number": 41, "issue_date": null
            }]
        }))
        .unwrap();
        let lines = status_lines(&status, || "/k.p12".into());
        let text = lines.join("\n");
        assert!(text.contains("IT   seq 41   published 42"), "{text}");
        assert!(text.contains("! rollback refused:"), "{text}");
        assert!(
            text.contains(
                "alert tl_rollback https://tl.example/it.xml: older list refused (refused sequence number 41, \
                 issued ?; published 42, issued 2026-09-01T00:00:00Z) [3 times since 2026-10-30T00:00:00Z]"
            ),
            "{text}"
        );
        assert_eq!(lines.last().unwrap(), "  OJ keystore: /k.p12");
    }

    #[test]
    fn tsa_password_file_is_read_without_trailing_whitespace() {
        let dir = scratch("tsa-password");
        let file = dir.join("password");
        std::fs::write(&file, "s3cret \r\n").unwrap();
        let file = file.to_str().unwrap();
        let cli = Cli::try_parse_from([
            "dss-cli",
            "--tsa-url",
            "u",
            "--tsa-user",
            "a",
            "--tsa-password-file",
            file,
            "version",
        ])
        .unwrap();
        assert_eq!(tsa_password(&cli.engine).unwrap().as_deref(), Some("s3cret"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
