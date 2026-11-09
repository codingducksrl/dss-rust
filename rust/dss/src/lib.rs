// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Safe Rust API to the EU Digital Signature Service (DSS) validation engine, compiled with GraalVM Native Image
//! into `libdssnative`. No JVM is needed at run time.
//!
//! ```no_run
//! use dss::{Config, Engine, Options, Revocation};
//!
//! let mut config = Config::new("trust/oj-keystore.p12");
//! config.countries = vec!["IT".into()];
//! let engine = Engine::builder("/var/lib/app/dss-cache", &config).workers(4).max_heap("1g").build()?;
//!
//! if !engine.init_info().trusted_lists_loaded {
//!     engine.refresh_trusted_lists()?; // first run: nothing cached yet
//! }
//! let reports = engine.validate(&std::fs::read("contract.pdf.p7m")?, &Options::default())?;
//! for s in reports.all_signatures() {
//!     println!("{:?} {:?} {:?}", s.indication, s.format, s.signed_by);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`Engine::extend`] raises PAdES signatures to T, LT or LTA, e.g. a PAdES-T to PAdES-LT by embedding the
//! revocation data its certificates need.
//!
//! [`Engine::prepare_signature`] and [`Engine::complete_signature`] sign with a key held elsewhere (a remote
//! signing service, an HSM): DSS builds the CAdES or PAdES document, the external signer only ever sees a digest.
//!
//! ```no_run
//! # fn external_signer(digest_base64: &str) -> Vec<u8> { unimplemented!() }
//! # let engine: dss::Engine = unimplemented!();
//! use dss::{Level, SignOptions, SigningMode};
//!
//! let pdf = std::fs::read("contract.pdf")?;
//! let mut options = SignOptions::new(SigningMode::Cms, Level::Lt);
//! let prepared = engine.prepare_signature(&pdf, &options)?;
//! let cms = external_signer(&prepared.digest_base64()); // returns a detached CMS for that digest
//! options.signing_time = Some(prepared.signing_time);
//! let signed = engine.complete_signature(&pdf, &options, &cms)?;
//! std::fs::write("contract-signed.pdf", &signed.document)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The library owns the EU trusted lists: [`Engine::refresh_trusted_lists`] refreshes them online (the
//! application decides when, or uses the `RefreshScheduler` of the `schedule` module with the `tokio` feature),
//! and [`Engine::trusted_list_status`] reports their state.
#![cfg_attr(feature = "tokio", doc = "\nThe scheduler: [`schedule::RefreshScheduler`].")]
#![warn(missing_docs)]

mod config;
mod engine;
mod error;
mod types;

#[cfg(feature = "tokio")]
pub mod schedule;

pub use config::{
    Config, DetachedBytes, DetachedContent, DigestAlgorithm, ExtendOptions, Http, ImagePosition, Level, Limits,
    OjKeystore, Options, Packaging, PadesOptions, Placement, Proxy, Report, Revocation, SignOptions, SignatureFormat,
    SigningMode, TextAlign, TlSync, TrustStore, Tsa, VisibleSignature,
};
pub use engine::{API_VERSION, CancelToken, Cancellable, Engine, EngineBuilder, library_version};
pub use error::{Error, ErrorCode, Result};
pub use types::{
    Alert, Changes, Extended, Indication, InitInfo, ListStatus, OjKeystoreInfo, Policy, PreparedSignature,
    RefreshRecord, Reports, SignatureSummary, Signed, Stage, TimestampSummary, TlSnapshot, TlSnapshotInfo,
    TrustedListStatus, Version,
};
