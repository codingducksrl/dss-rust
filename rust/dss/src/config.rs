// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! `config_json` and `options_json` as Rust types. Field meanings and defaults: README.md, "API".

use std::path::PathBuf;

use serde::Serialize;

/// Engine configuration. Only the OJ keystore is required; `None` fields take the library's defaults.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Config {
    pub oj_keystore: OjKeystore,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oj_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lotl_url: Option<String>,
    /// ISO 3166 codes of the national lists to load; empty means all.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub countries: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tl_versions: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pivot_support: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_sunset_date: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tl_sync: Option<TlSync>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online_cache_expiration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<Http>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<Revocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aia: Option<bool>,
    /// Reports returned by default, in addition to the simple report.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reports: Vec<Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_trusted_lists: Option<bool>,
    /// PEM/DER certificate files trusted in addition to the trusted lists.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_trusted_certificates: Vec<PathBuf>,
    /// Timestamping service for [`Engine::extend`](crate::Engine::extend) to [`Level::T`] and [`Level::Lta`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsa: Option<Tsa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    /// Trusted-list snapshot to start from instead of `<cache_dir>/tl`, written by
    /// [`Engine::export_tl_snapshot`](crate::Engine::export_tl_snapshot): no list is parsed or validated. The
    /// library checks that it is intact and matches this configuration; whether it can be trusted is for the
    /// application that hands it over to decide.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tl_snapshot: Option<PathBuf>,
}

impl Config {
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

#[derive(Debug, Clone, Default, Serialize)]
pub struct OjKeystore {
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TlSync {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_invalid_signature: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_expired: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Http {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tl_verify_tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_store: Option<TrustStore>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TrustStore {
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// An RFC 3161 timestamping service. Over HTTPS it is trusted like CRL/OCSP servers (see `http.trust_store`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Tsa {
    pub url: String,
    /// HTTP Basic credentials, when the TSA needs them: both or neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl Tsa {
    pub fn new(url: impl Into<String>) -> Self {
        Tsa {
            url: url.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
    Simple,
    Detailed,
    Etsi,
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

#[derive(Debug, Clone, Serialize)]
pub struct DetachedContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Base64 of the content, for content that is not in a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

impl DetachedContent {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        DetachedContent {
            name,
            path: Some(path),
            base64: None,
        }
    }
}

/// Baseline level: the target of [`Engine::extend`](crate::Engine::extend) (T, LT or LTA; the format follows the
/// document, PAdES for a PDF) and of a signature ([`SignOptions::level`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Level {
    /// BASELINE-B: the signature alone. Signing only: `extend` refuses it.
    B,
    /// PAdES-BASELINE-T: a document timestamp for signatures that have none (needs [`Config::tsa`]).
    T,
    /// PAdES-BASELINE-LT: the certificates and revocation data the signatures and timestamps need.
    Lt,
    /// PAdES-BASELINE-LTA: LT, then a document timestamp over all of it (needs [`Config::tsa`]).
    Lta,
}

/// Per-extension options.
#[derive(Debug, Clone, Serialize)]
pub struct ExtendOptions {
    pub level: Level,
    /// Name of the document in the library's messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

impl ExtendOptions {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Entries of the PDF signature dictionary, and the space reserved for the CMS.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PadesOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_name: Option<String>,
    /// Bytes reserved for the CMS. Default: 9,472 in [`SigningMode::SignatureValue`] (DSS's), 32,768 in
    /// [`SigningMode::Cms`], where the external CMS may carry a whole certificate chain and a timestamp.
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
    #[serde(flatten)]
    pub placement: Placement,
    /// Lines separated by `\n`, with placeholders `{signer_name}`, `{signing_time}`, `{reason}`, `{location}`
    /// (`{{` and `}}` for literal braces).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// A TrueType font (TTF, or OTF with TrueType outlines). Default: PT Serif. Embedded as a subset.
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::types::base64_opt_bytes")]
    pub font: Option<Vec<u8>>,
    /// The largest size in points (default 10): the text shrinks and wraps at spaces to fit the box.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_size: Option<f64>,
    /// `#RRGGBB` (default black).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_align: Option<TextAlign>,
    /// `#RRGGBB` (default none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    /// A PNG or a JPEG.
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::types::base64_opt_bytes")]
    pub image: Option<Vec<u8>>,
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
    /// An empty signature field of the PDF, by its fully qualified name.
    Field { field: String },
    /// A new field on `page` (from 1), in points from the top-left corner of the page as displayed.
    Rect {
        page: u32,
        x: f64,
        y: f64,
        width: f64,
        height: f64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TextAlign {
    Left,
    Center,
    Right,
}

/// Where the image goes relative to the text (default [`ImagePosition::Left`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImagePosition {
    Left,
    Right,
    Top,
    Bottom,
    /// Under the text, filling the box.
    Behind,
}

/// Options of [`Engine::prepare_signature`](crate::Engine::prepare_signature) and
/// [`Engine::complete_signature`](crate::Engine::complete_signature). Give both the same options; `complete`
/// also needs [`signing_time`](Self::signing_time) set to the one `prepare` returned.
#[derive(Debug, Clone, Serialize)]
pub struct SignOptions {
    pub mode: SigningMode,
    /// Level of the signed document. Above what the external signer delivers, DSS adds it: T a timestamp from
    /// [`Config::tsa`], LT the certificates and revocation data, LTA both. With [`SigningMode::Cms`], a CMS that
    /// already has a signature timestamp is T even at [`Level::B`].
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
    /// in [`SigningMode::Cms`] the CMS must then be signed with it.
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
