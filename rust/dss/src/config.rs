// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! `config_json` and `options_json` as Rust types. The structs mirror the library's JSON key for key: a `None`
//! field is left out of the JSON and takes the library's default (stated on each field; README.md, "API", has
//! the same list). Passwords are redacted from the `Debug` output.

use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

/// Engine configuration. Only the OJ keystore is required; `None` fields take the library's defaults.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Config {
    /// The keystore holding the certificates that may sign the LOTL (from the OJ publication). Required.
    pub oj_keystore: OjKeystore,
    /// The Official Journal publication announcing the LOTL signers. Default: the library's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oj_url: Option<String>,
    /// Where the EU list of trusted lists is downloaded from. Default: the EU's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lotl_url: Option<String>,
    /// ISO 3166 codes of the national lists to load (`"EL"` for Greece, as in the LOTL); empty means all. Signatures
    /// from other member states are then not trusted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub countries: Vec<String>,
    /// Trusted-list (TSL) versions accepted, e.g. `[6]`. Default: DSS's, `[5, 6]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tl_versions: Option<Vec<u32>>,
    /// Follow LOTL pivots (default true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pivot_support: Option<bool>,
    /// Apply the sunset date of trust services (default true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_sunset_date: Option<bool>,
    /// Which downloaded lists become trust sources.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tl_sync: Option<TlSync>,
    /// Threads that download and validate the lists during a refresh, 1 to 64. Default: the number of CPUs, at
    /// most 16. The main cold-start tuning knob.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tl_threads: Option<u32>,
    /// How long a downloaded list is reused by an online refresh, in milliseconds. Default 0: re-download on every
    /// online refresh.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online_cache_expiration_ms: Option<u64>,
    /// Outbound HTTP: timeouts, TLS, proxy, and the policy every outbound request goes through.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<Http>,
    /// Where revocation data comes from (default [`Revocation::Online`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<Revocation>,
    /// Fetch missing intermediate certificates through AIA (default: when `revocation` is online).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aia: Option<bool>,
    /// Reports returned by default, in addition to the simple report.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reports: Vec<Report>,
    /// Refuse to validate while no trusted list is loaded (default true). `false` for a private PKI that trusts
    /// [`extra_trusted_certificates`](Self::extra_trusted_certificates) only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_trusted_lists: Option<bool>,
    /// PEM/DER certificate files trusted in addition to the trusted lists.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_trusted_certificates: Vec<PathBuf>,
    /// Timestamping service for [`Engine::extend`](crate::Engine::extend) to [`Level::T`] and [`Level::Lta`]
    /// (and for signing above the level the external signer delivers). Default: none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsa: Option<Tsa>,
    /// slf4j-simple level of the library's logs (on stderr): `off`, `error`, `warn` (default), `info`, `debug`,
    /// `trace`. The first engine of a process fixes it; [`InitInfo::log_level`](crate::InitInfo::log_level) says
    /// which one is in effect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    /// Trusted-list snapshot to start from instead of `<cache_dir>/tl`, written by
    /// [`Engine::export_tl_snapshot`](crate::Engine::export_tl_snapshot): no list is parsed or validated. The
    /// library checks that it is intact and matches this configuration; whether it can be trusted is for the
    /// application that hands it over to decide.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tl_snapshot: Option<PathBuf>,
    /// Structural limits a document must stay within before DSS runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
}

impl Config {
    /// A configuration with the library's defaults and this OJ keystore (a PKCS#12 file with the library's default
    /// password; see [`OjKeystore`] for another type or password).
    pub fn new(oj_keystore: impl Into<PathBuf>) -> Self {
        Config {
            oj_keystore: OjKeystore {
                path: oj_keystore.into(),
                r#type: None,
                password: None,
            },
            ..Default::default()
        }
    }
}

/// The keystore holding the certificates that may sign the LOTL.
#[derive(Clone, Default, Serialize)]
pub struct OjKeystore {
    /// The keystore file.
    pub path: PathBuf,
    /// Keystore type (default `PKCS12`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Keystore password (default: the library's).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl fmt::Debug for OjKeystore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OjKeystore")
            .field("path", &self.path)
            .field("type", &self.r#type)
            .field("password", &self.password.as_ref().map(|_| Redacted))
            .finish()
    }
}

/// Stands in for a password in `Debug` output.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"<redacted>\"")
    }
}

/// Which downloaded trusted lists become trust sources (`used_for_trust` in the status).
#[derive(Debug, Clone, Default, Serialize)]
pub struct TlSync {
    /// Trust lists whose XML signature does not validate (default false).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_invalid_signature: Option<bool>,
    /// Keep using lists past their `NextUpdate` (default true; qualification flags it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_expired: Option<bool>,
    /// Trust lists for which DSS records structure validation messages, such as a TSL version outside
    /// [`Config::tl_versions`] (default true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_structure_errors: Option<bool>,
}

/// Outbound HTTP settings: trusted-list downloads, CRL/OCSP/AIA fetches and the TSA.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Http {
    /// Connection timeout in milliseconds, 1 to 2147483647 (default 30000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    /// Response timeout in milliseconds, 1 to 2147483647 (default 60000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_timeout_ms: Option<u64>,
    /// Check the TLS server certificate of LOTL/TL downloads (default false: their XML signature is verified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tl_verify_tls: Option<bool>,
    /// Replaces the CA bundle built into the library for TLS connections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_store: Option<TrustStore>,
    /// URL schemes an outbound request may use, lower-case (default `["http", "https"]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_schemes: Option<Vec<String>>,
    /// Refuse requests to loopback, private, link-local and similar addresses, literal or resolved (default true).
    /// Hosts whose TL mirror, CRL or TSA sits on a private address set it to false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_private_addresses: Option<bool>,
    /// Largest response accepted, in bytes (default 67108864).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
    /// Wall-clock deadline of one request in milliseconds (default 120000; 0 disables).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_deadline_ms: Option<u64>,
    /// Follow HTTP redirects (default true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follow_redirects: Option<bool>,
    /// An explicit proxy. Excludes [`use_system_proxy`](Self::use_system_proxy).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Proxy>,
    /// Use the system (JVM property) proxy settings (default false).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_system_proxy: Option<bool>,
    /// How long CRL/AIA GET responses are reused across calls, in milliseconds (default 3600000; 0 disables).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_ms: Option<u64>,
}

/// An HTTP proxy for outbound requests.
#[derive(Clone, Default, Serialize)]
pub struct Proxy {
    /// Proxy host. Required.
    pub host: String,
    /// Proxy port, 1 to 65535. Required.
    pub port: u16,
    /// `"http"` (default) or `"https"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Proxy credentials: both or neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Proxy credentials: both or neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Hosts reached directly, without the proxy.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub no_proxy: Vec<String>,
}

impl Proxy {
    /// A proxy at `host:port` with the defaults.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Proxy {
            host: host.into(),
            port,
            ..Default::default()
        }
    }
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("scheme", &self.scheme)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| Redacted))
            .field("no_proxy", &self.no_proxy)
            .finish()
    }
}

/// A trust store of CA certificates for TLS connections.
#[derive(Clone, Default, Serialize)]
pub struct TrustStore {
    /// The keystore file.
    pub path: PathBuf,
    /// Keystore type (default `PKCS12`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Keystore password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl fmt::Debug for TrustStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustStore")
            .field("path", &self.path)
            .field("type", &self.r#type)
            .field("password", &self.password.as_ref().map(|_| Redacted))
            .finish()
    }
}

/// An RFC 3161 timestamping service. Over HTTPS it is trusted like CRL/OCSP servers (see `http.trust_store`).
#[derive(Clone, Default, Serialize)]
pub struct Tsa {
    /// The TSA endpoint. Credentials require `https`, and the URL must not carry userinfo.
    pub url: String,
    /// HTTP Basic credentials, when the TSA needs them: both or neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// HTTP Basic credentials, when the TSA needs them: both or neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// The TSA certificate must chain to the trusted lists or to
    /// [`Config::extra_trusted_certificates`] when the engine has any trust anchor (default true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_trusted: Option<bool>,
    /// How far from the host clock a timestamp token may be dated, in milliseconds (default 300000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_clock_skew_ms: Option<u64>,
}

impl Tsa {
    /// A TSA at `url` with the defaults and no credentials.
    pub fn new(url: impl Into<String>) -> Self {
        Tsa {
            url: url.into(),
            ..Default::default()
        }
    }
}

impl fmt::Debug for Tsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tsa")
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| Redacted))
            .field("require_trusted", &self.require_trusted)
            .field("max_clock_skew_ms", &self.max_clock_skew_ms)
            .finish()
    }
}

/// Structural limits a document must stay within before DSS runs; a document over one is refused with the
/// operation's error code. Every limit is at least 1.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Limits {
    /// Pages of a PDF (default 5000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_pdf_pages: Option<u32>,
    /// Signature revisions of a PDF (default 100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_pdf_signatures: Option<u32>,
    /// Annotations on one PDF page (default 5000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_pdf_annotations_per_page: Option<u32>,
    /// Certificates in a CMS (default 500).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cms_certificates: Option<u32>,
}

/// Where revocation data comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Revocation {
    /// Fetch CRLs/OCSP responses (default).
    Online,
    /// Use only revocation data embedded in the signature.
    Offline,
}

/// XML reports. The simple report is always returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Report {
    /// The simple report (always returned).
    Simple,
    /// The detailed report.
    Detailed,
    /// The ETSI validation report.
    Etsi,
    /// The diagnostic data.
    Diagnostic,
}

/// Per-validation options.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Options {
    /// Overrides the engine's default report set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reports: Option<Vec<Report>>,
    /// Signed content of a detached signature.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub detached_contents: Vec<DetachedContent>,
    /// Validate as of this instant (ISO-8601 UTC) instead of now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_time: Option<String>,
    /// Name of the document in the reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Validate CAdES envelopes nested in the signed content (default true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unwrap_nested: Option<bool>,
}

impl Options {
    /// The options as the library takes them: the JSON part, and the [`DetachedContent::Bytes`] entries, which
    /// travel as binary buffers through `dss_validate_with_contents` instead of as base64 in the JSON. The
    /// library adds the buffers to `detached_contents` before the entries the JSON carries.
    pub(crate) fn split(&self) -> (OptionsJson<'_>, Vec<DetachedBytes<'_>>) {
        let mut files = Vec::new();
        let mut bytes = Vec::new();
        for content in &self.detached_contents {
            match content {
                DetachedContent::File { .. } => files.push(content),
                DetachedContent::Bytes { name, content } => bytes.push(DetachedBytes {
                    name: name.as_deref(),
                    content,
                }),
            }
        }
        let json = OptionsJson {
            reports: &self.reports,
            detached_contents: files,
            validation_time: &self.validation_time,
            filename: &self.filename,
            unwrap_nested: &self.unwrap_nested,
        };
        (json, bytes)
    }
}

/// [`Options`] without its [`DetachedContent::Bytes`] entries, serialised exactly as `Options` is (the test
/// `options_split_keeps_the_json_shape` checks that; a field added to `Options` must be added here too).
#[derive(Serialize)]
pub(crate) struct OptionsJson<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    reports: &'a Option<Vec<Report>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    detached_contents: Vec<&'a DetachedContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_time: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unwrap_nested: &'a Option<bool>,
}

/// The signed content of a detached signature as bytes the caller holds, for
/// [`Engine::validate_with_contents`](crate::Engine::validate_with_contents): nothing is base64-encoded, the
/// buffer is read once, during the call. An empty content is refused by the library
/// ([`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument)), as is a call with more than 1024 of them.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct DetachedBytes<'a> {
    /// Name of the content in the reports (`None`: unnamed).
    pub name: Option<&'a str>,
    /// The content.
    pub content: &'a [u8],
}

impl<'a> DetachedBytes<'a> {
    /// A content with the name the reports show for it.
    pub fn named(name: &'a str, content: &'a [u8]) -> Self {
        DetachedBytes {
            name: Some(name),
            content,
        }
    }

    /// A content without a name.
    pub fn unnamed(content: &'a [u8]) -> Self {
        DetachedBytes { name: None, content }
    }
}

impl fmt::Debug for DetachedBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetachedBytes")
            .field("name", &self.name)
            .field("content", &format_args!("<{} bytes>", self.content.len()))
            .finish()
    }
}

/// The signed content of a detached signature: a file the library reads, or bytes sent along. Exactly one of the
/// two, by construction. Through [`Engine::validate`](crate::Engine::validate) the bytes travel as binary buffers
/// (see [`DetachedBytes`]) and are added to the contents before the files; in a serialised `Options` (the
/// `*_json` calls) they travel as base64.
#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum DetachedContent {
    /// A file the library reads.
    File {
        /// Name of the content in the reports (default: the file name).
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// The file.
        path: PathBuf,
    },
    /// The content itself.
    Bytes {
        /// Name of the content in the reports.
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// The content; travels as base64.
        #[serde(rename = "base64", with = "crate::types::base64_bytes")]
        content: Vec<u8>,
    },
}

impl DetachedContent {
    /// Content in a file, named after the file.
    pub fn file(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        DetachedContent::File { name, path }
    }

    /// Content held in memory, with the name the reports show for it.
    pub fn bytes(name: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        DetachedContent::Bytes {
            name: Some(name.into()),
            content: content.into(),
        }
    }

    /// The name of the content, when set.
    pub fn name(&self) -> Option<&str> {
        match self {
            DetachedContent::File { name, .. } | DetachedContent::Bytes { name, .. } => name.as_deref(),
        }
    }
}

impl fmt::Debug for DetachedContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetachedContent::File { name, path } => f
                .debug_struct("DetachedContent::File")
                .field("name", name)
                .field("path", path)
                .finish(),
            DetachedContent::Bytes { name, content } => f
                .debug_struct("DetachedContent::Bytes")
                .field("name", name)
                .field("content", &format_args!("<{} bytes>", content.len()))
                .finish(),
        }
    }
}

/// Baseline level: the target of [`Engine::extend`](crate::Engine::extend) (T, LT or LTA; the format follows the
/// document, PAdES for a PDF) and of a signature ([`SignOptions::level`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Level {
    /// BASELINE-B: the signature alone. Signing only: `extend` refuses it with
    /// [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument).
    B,
    /// PAdES-BASELINE-T: a document timestamp for signatures that have none (needs [`Config::tsa`]).
    T,
    /// PAdES-BASELINE-LT: the certificates and revocation data the signatures and timestamps need. Extending a
    /// B-level signature to LT needs a timestamp first, so it needs [`Config::tsa`] too.
    Lt,
    /// PAdES-BASELINE-LTA: LT, then a document timestamp over all of it (needs [`Config::tsa`]).
    Lta,
}

/// Per-extension options.
#[derive(Debug, Clone, Serialize)]
pub struct ExtendOptions {
    /// The target level: [`Level::T`], [`Level::Lt`] or [`Level::Lta`].
    pub level: Level,
    /// Name of the document in the library's messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

impl ExtendOptions {
    /// Options for extending to `level`.
    pub fn new(level: Level) -> Self {
        ExtendOptions { level, filename: None }
    }
}

/// The format of a new signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum SignatureFormat {
    /// Inside the PDF (PDF documents only).
    #[serde(rename = "PAdES")]
    Pades,
    /// A CMS: `.p7s` beside the content, or `.p7m` around it (see [`Packaging`]).
    #[serde(rename = "CAdES")]
    Cades,
}

/// What the external signer receives and returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningMode {
    /// It receives the digest of the content (for PAdES, of the PDF's signed byte ranges) and returns a detached
    /// CMS SignedData, possibly with a signature timestamp of its own.
    Cms,
    /// It receives the digest of the signed attributes DSS builds and returns only the signature value (RSA
    /// PKCS#1 v1.5, or ECDSA as DER or `r||s`). Needs [`SignOptions::signing_certificate`].
    SignatureValue,
}

/// CAdES only: whether the content stays apart from the signature or goes inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Packaging {
    /// `.p7s`: the CMS without the content (default).
    Detached,
    /// `.p7m`: the content inside the CMS.
    Enveloping,
}

/// The digest algorithm of a new signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DigestAlgorithm {
    /// SHA-256 (default).
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// Entries of the PDF signature dictionary, and the space reserved for the CMS.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PadesOptions {
    /// `/Reason`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `/Location`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// `/ContactInfo`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_info: Option<String>,
    /// `/Name`, and `{signer_name}` in a visible signature's text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_name: Option<String>,
    /// Bytes reserved for the CMS. Default: 9,472 in [`SigningMode::SignatureValue`] (DSS's), 32,768 in
    /// [`SigningMode::Cms`], where the external CMS may carry a whole certificate chain and a timestamp. In
    /// [`SigningMode::SignatureValue`] a size the CMS cannot fit is refused at `prepare`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_size: Option<u32>,
    /// A visible appearance; `None` signs invisibly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visible: Option<VisibleSignature>,
}

/// A visible signature: where it goes, and the text and/or image it shows. `None` fields take the library's
/// defaults (README.md, "Visible signatures").
#[derive(Debug, Clone, Serialize)]
pub struct VisibleSignature {
    /// An existing field or a new rectangle.
    #[serde(flatten)]
    pub placement: Placement,
    /// Lines separated by `\n`, with placeholders `{signer_name}`, `{signing_time}`, `{reason}`, `{location}`
    /// (`{{` and `}}` for literal braces). At most 10,000 characters, and not blank once filled in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// A TrueType font (TTF, or OTF with TrueType outlines; at most 32 MB, subsetting allowed by its licence).
    /// Default: PT Serif. Embedded as a subset.
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::types::base64_opt_bytes")]
    pub font: Option<Vec<u8>>,
    /// The largest size in points (default 10): the text shrinks and wraps at spaces to fit the box.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_size: Option<f64>,
    /// `#RRGGBB` (default black).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    /// Horizontal alignment of the text (default [`TextAlign::Left`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_align: Option<TextAlign>,
    /// `#RRGGBB` (default none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    /// A PNG or a JPEG (at most 25 megapixels and 16384 pixels on each side, Exif orientation 1).
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::types::base64_opt_bytes")]
    pub image: Option<Vec<u8>>,
    /// Where the image goes relative to the text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_position: Option<ImagePosition>,
    /// IANA time zone for `{signing_time}`, e.g. `"Europe/Rome"` (default UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
    /// `java.time` pattern for `{signing_time}` (default `"yyyy-MM-dd HH:mm:ss xxx"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_format: Option<String>,
}

impl VisibleSignature {
    /// An appearance at `placement`, with the defaults; set at least [`text`](Self::text) or
    /// [`image`](Self::image).
    pub fn new(placement: Placement) -> Self {
        VisibleSignature {
            placement,
            text: None,
            font: None,
            font_size: None,
            text_color: None,
            text_align: None,
            background_color: None,
            image: None,
            image_position: None,
            time_zone: None,
            date_format: None,
        }
    }
}

/// Where a visible signature goes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Placement {
    /// An empty signature field of the PDF, by its fully qualified name (not a Hidden or NoView widget).
    Field {
        /// The field's fully qualified name.
        field: String,
    },
    /// A new field on `page` (from 1), in points from the top-left corner of the page as displayed. `x` and `y`
    /// are 0 to 14400, `width` and `height` more than 0 and at most 14400.
    Rect {
        /// Page number, from 1.
        page: u32,
        /// Left edge, in points from the left of the page.
        x: f64,
        /// Top edge, in points from the top of the page.
        y: f64,
        /// Width in points.
        width: f64,
        /// Height in points.
        height: f64,
    },
}

/// Horizontal alignment of a visible signature's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TextAlign {
    /// Left-aligned (default).
    Left,
    /// Centred.
    Center,
    /// Right-aligned.
    Right,
}

/// Where the image goes relative to the text (default [`ImagePosition::Left`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImagePosition {
    /// Left of the text (default).
    Left,
    /// Right of the text.
    Right,
    /// Above the text.
    Top,
    /// Below the text.
    Bottom,
    /// Under the text, filling the box.
    Behind,
}

/// Options of [`Engine::prepare_signature`](crate::Engine::prepare_signature) and
/// [`Engine::complete_signature`](crate::Engine::complete_signature). Give both the same options; `complete`
/// also needs [`signing_time`](Self::signing_time) set to the one `prepare` returned.
#[derive(Debug, Clone, Serialize)]
pub struct SignOptions {
    /// What the external signer receives and returns.
    pub mode: SigningMode,
    /// Level of the signed document. Above what the external signer delivers, DSS adds it: T a timestamp from
    /// [`Config::tsa`], LT the certificates and revocation data, LTA both. With [`SigningMode::Cms`], a CMS that
    /// already has a verified signature timestamp is T even at [`Level::B`].
    pub level: Level,
    /// Default: PAdES for a PDF, CAdES for anything else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<SignatureFormat>,
    /// Default SHA-256.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_algorithm: Option<DigestAlgorithm>,
    /// ISO-8601 UTC in whole seconds. `prepare` picks the current time when it is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_time: Option<String>,
    /// The signer's certificate: base64 of its DER encoding, or PEM. Required in [`SigningMode::SignatureValue`];
    /// in [`SigningMode::Cms`] the CMS must then be signed with it. When given, `prepare` refuses a certificate
    /// that is expired or not yet valid at the signing time, or not meant for signing documents, before any
    /// external signature is spent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_certificate: Option<String>,
    /// Issuer certificates, as base64 DER or PEM: put into the CMS DSS builds, and used to build the chain for LT
    /// and LTA.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificate_chain: Vec<String>,
    /// CAdES only. Default [`Packaging::Detached`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packaging: Option<Packaging>,
    /// Name of the document. For PAdES it shapes the prepared PDF: keep it the same in both calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// PAdES only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pades: Option<PadesOptions>,
}

impl SignOptions {
    /// Options for a signature of `level` with an external signer working in `mode`.
    pub fn new(mode: SigningMode, level: Level) -> Self {
        SignOptions {
            mode,
            level,
            format: None,
            digest_algorithm: None,
            signing_time: None,
            signing_certificate: None,
            certificate_chain: vec![],
            packaging: None,
            filename: None,
            pades: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_passwords() {
        let mut config = Config::new("/trust/oj.p12");
        config.oj_keystore.password = Some("OJ_SECRET".into());
        config.tsa = Some(Tsa {
            username: Some("u".into()),
            password: Some("TSA_SECRET".into()),
            ..Tsa::new("https://tsa")
        });
        config.http = Some(Http {
            trust_store: Some(TrustStore {
                path: "/ts.p12".into(),
                r#type: None,
                password: Some("TS_SECRET".into()),
            }),
            proxy: Some(Proxy {
                username: Some("pu".into()),
                password: Some("PROXY_SECRET".into()),
                ..Proxy::new("proxy", 3128)
            }),
            ..Default::default()
        });
        let debug = format!("{config:?}");
        for secret in ["OJ_SECRET", "TSA_SECRET", "TS_SECRET", "PROXY_SECRET"] {
            assert!(!debug.contains(secret), "{debug}");
        }
        assert!(debug.contains("password: Some(\"<redacted>\")"), "{debug}");
        assert!(debug.contains("username: Some(\"u\")"), "{debug}");
        // The JSON sent to the library still carries them.
        let json = serde_json::to_string(&config).unwrap();
        assert!(
            json.contains("\"password\":\"OJ_SECRET\"") && json.contains("TSA_SECRET"),
            "{json}"
        );
    }

    #[test]
    fn detached_content_serializes_exactly_one_source() {
        let file = serde_json::to_value(DetachedContent::file("/data/document.txt")).unwrap();
        assert_eq!(
            file,
            serde_json::json!({"name": "document.txt", "path": "/data/document.txt"})
        );
        let bytes = serde_json::to_value(DetachedContent::bytes("doc.txt", b"hello".to_vec())).unwrap();
        assert_eq!(bytes, serde_json::json!({"name": "doc.txt", "base64": "aGVsbG8="}));
        assert_eq!(DetachedContent::file("/x/y.bin").name(), Some("y.bin"));
        let debug = format!("{:?}", DetachedContent::bytes("d", vec![0u8; 1000]));
        assert!(debug.contains("<1000 bytes>"), "{debug}");
    }

    /// `Options::split` serialises the same JSON as `Options`, minus the `Bytes` entries it hands over as buffers.
    #[test]
    fn options_split_keeps_the_json_shape() {
        // A full struct literal: a field added to Options fails to compile here until OptionsJson carries it.
        let options = Options {
            reports: Some(vec![Report::Detailed, Report::Etsi]),
            detached_contents: vec![
                DetachedContent::bytes("first.txt", b"one".to_vec()),
                DetachedContent::file("/data/document.txt"),
                DetachedContent::Bytes {
                    name: None,
                    content: b"two".to_vec(),
                },
            ],
            validation_time: Some("2026-01-01T00:00:00Z".into()),
            filename: Some("contract.pdf.p7s".into()),
            unwrap_nested: Some(false),
        };
        let (json, bytes) = options.split();
        let mut expected = serde_json::to_value(&options).unwrap();
        expected["detached_contents"] = serde_json::json!([{"name": "document.txt", "path": "/data/document.txt"}]);
        assert_eq!(serde_json::to_value(&json).unwrap(), expected);
        assert_eq!(bytes.len(), 2);
        assert_eq!((bytes[0].name, bytes[0].content), (Some("first.txt"), &b"one"[..]));
        assert_eq!((bytes[1].name, bytes[1].content), (None, &b"two"[..]));
        assert!(format!("{:?}", bytes[0]).contains("<3 bytes>"));

        let all_files = Options {
            detached_contents: vec![DetachedContent::file("/a"), DetachedContent::file("/b")],
            ..Default::default()
        };
        let (json, bytes) = all_files.split();
        assert!(bytes.is_empty());
        assert_eq!(
            serde_json::to_value(&json).unwrap(),
            serde_json::to_value(&all_files).unwrap()
        );
        let defaults = Options::default();
        let (json, bytes) = defaults.split();
        assert!(bytes.is_empty());
        assert_eq!(serde_json::to_value(&json).unwrap(), serde_json::json!({}));
        assert_eq!(DetachedBytes::named("n", b"x").name, Some("n"));
        assert_eq!(DetachedBytes::unnamed(b"x").name, None);
    }

    #[test]
    fn none_fields_stay_out_of_the_json() {
        let json = serde_json::to_value(Config::new("oj.p12")).unwrap();
        assert_eq!(json, serde_json::json!({"oj_keystore": {"path": "oj.p12"}}));
        let json = serde_json::to_value(Options::default()).unwrap();
        assert_eq!(json, serde_json::json!({}));
        let mut config = Config::new("oj.p12");
        config.tl_threads = Some(8);
        config.limits = Some(Limits {
            max_pdf_pages: Some(10),
            ..Default::default()
        });
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["tl_threads"], 8);
        assert_eq!(json["limits"], serde_json::json!({"max_pdf_pages": 10}));
    }
}
