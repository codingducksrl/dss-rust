// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Results returned by the library, decoded from its JSON. The structs mirror the result shapes key for key
//! (README.md, "API"): fields a newer library adds are ignored, enum values this crate does not know decode to
//! `Unknown`, so the structs are `#[non_exhaustive]` and gain fields over time. Instants are ISO-8601 UTC
//! strings as the library writes them (e.g. `2026-03-01T10:15:30Z`).

use serde::{Deserialize, Deserializer, Serialize};

/// DSS's top-level validation outcome for one signature (ETSI EN 319 102-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum Indication {
    /// The signature is valid and its certificate chain reaches a trust anchor.
    TotalPassed,
    /// The signature is cryptographically valid (a lower level of the detailed report).
    Passed,
    /// The validation could not conclude: see `sub_indication` (missing revocation data, no trust anchor, ...).
    Indeterminate,
    /// The signature is invalid (a lower level of the detailed report).
    Failed,
    /// The signature is invalid: see `sub_indication` (`HASH_FAILURE`, `SIG_CRYPTO_FAILURE`, ...).
    TotalFailed,
    /// The document carries no signature.
    NoSignatureFound,
    /// A value this version of the crate does not know.
    #[serde(other)]
    Unknown,
}

/// Result of [`Engine::validate`](crate::Engine::validate).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Reports {
    /// `"PDF"` or `"CMS"`.
    pub container: String,
    /// Encodings removed before validation, e.g. `["base64"]`.
    #[serde(default)]
    pub transformations: Vec<String>,
    /// The signatures of this document (not those of [`nested`](Self::nested) envelopes).
    pub signatures: Vec<SignatureSummary>,
    /// Standalone document timestamps (PAdES document timestamps not tied to a signature).
    #[serde(default)]
    pub timestamps: Vec<TimestampSummary>,
    /// DSS's simple report.
    pub simple_report_xml: String,
    /// DSS's detailed report, when asked for ([`Report::Detailed`](crate::Report::Detailed)).
    pub detailed_report_xml: Option<String>,
    /// The ETSI validation report, when asked for ([`Report::Etsi`](crate::Report::Etsi)).
    pub etsi_report_xml: Option<String>,
    /// DSS's diagnostic data, when asked for ([`Report::Diagnostic`](crate::Report::Diagnostic)).
    pub diagnostic_data_xml: Option<String>,
    /// Validation of what a CAdES envelope wraps when that is signed too: another CAdES envelope (`.p7m.p7m`) or
    /// a signed PDF (`.pdf.p7m`).
    #[serde(default)]
    pub nested: Vec<Reports>,
}

impl Reports {
    /// Every signature at every nesting level, outermost first.
    pub fn all_signatures(&self) -> Vec<&SignatureSummary> {
        let mut out: Vec<&SignatureSummary> = self.signatures.iter().collect();
        for n in &self.nested {
            out.extend(n.all_signatures());
        }
        out
    }

    /// True when there is at least one signature and every signature at every level is TOTAL_PASSED (the same
    /// rule as the library's `all_passed`). Warnings and changes after signing do not count.
    pub fn all_passed(&self) -> bool {
        let all = self.all_signatures();
        !all.is_empty() && all.iter().all(|s| s.indication == Indication::TotalPassed)
    }
}

/// One signature of a validated document, taken from DSS's simple report.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct SignatureSummary {
    /// DSS's identifier of the signature (also in the XML reports).
    pub id: String,
    /// The outcome.
    pub indication: Indication,
    /// Why the outcome is not TOTAL_PASSED, e.g. `"HASH_FAILURE"`, `"TRY_LATER"`, `"NO_CERTIFICATE_CHAIN_FOUND"`
    /// (ETSI EN 319 102-1 names).
    pub sub_indication: Option<String>,
    /// e.g. `"PAdES-BASELINE-LTA"`.
    pub format: Option<String>,
    /// e.g. `"QESIG"`, `"ADESIG"`, `"NA"` (DSS's SignatureQualification names).
    pub qualification: Option<String>,
    /// The signing time the signature claims.
    pub signing_time: Option<String>,
    /// The earliest time the signature is proven to exist (a timestamp's, or the validation time).
    pub best_signature_time: Option<String>,
    /// The signer's name, from the signing certificate.
    pub signed_by: Option<String>,
    /// Subject DN of the signing certificate (RFC 2253), when DSS identified it.
    pub signer_dn: Option<String>,
    /// What the chain reaches: `"trusted_list"`, `"extra_trusted_certificates"` or `"none"`.
    pub trust_anchor: Option<String>,
    /// AdES validation errors (qualification messages are in
    /// [`qualification_errors`](Self::qualification_errors)).
    #[serde(default)]
    pub errors: Vec<String>,
    /// AdES validation warnings.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Qualification errors (e.g. no chain up to a trusted list).
    #[serde(default)]
    pub qualification_errors: Vec<String>,
    /// Qualification warnings.
    #[serde(default)]
    pub qualification_warnings: Vec<String>,
    /// Informational messages.
    #[serde(default)]
    pub info: Vec<String>,
    /// The signature policy the signature claims, when it claims one.
    pub policy: Option<Policy>,
    /// PAdES only: whether the PDF was changed after this signature (incremental updates).
    pub modified_after_signing: Option<bool>,
    /// PAdES only: what the changes after signing are.
    pub changes_after_signing: Option<Changes>,
    /// The signature's own timestamps (signature, archive and document timestamps covering it).
    #[serde(default)]
    pub timestamps: Vec<TimestampSummary>,
}

/// The signature policy a signature claims.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Policy {
    /// The policy identifier (OID or URI).
    pub id: Option<String>,
    /// Where the policy document is.
    pub url: Option<String>,
    /// Whether DSS identified (and could fetch) the policy.
    pub identified: Option<bool>,
    /// Whether the policy document's digest matches; `None` when the policy was not identified.
    pub digest_valid: Option<bool>,
}

/// Changes made to a PDF after a signature (counts of incremental-update objects by kind).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Changes {
    /// Objects of later signature extensions (DSS, timestamps).
    #[serde(default)]
    pub extension: u32,
    /// Later signatures or form fills.
    #[serde(default)]
    pub signature_or_form_fill: u32,
    /// Annotations added later.
    #[serde(default)]
    pub annotation: u32,
    /// Changes DSS could not classify.
    #[serde(default)]
    pub undefined: u32,
    /// Pages (from 1) added or removed after the signed revision.
    #[serde(default)]
    pub pages_differ: Vec<u64>,
    /// Pages (from 1) where later annotations overlap signed content.
    #[serde(default)]
    pub annotations_overlap: Vec<u64>,
    /// Object paths of active content (JavaScript, launch actions) in the document.
    #[serde(default)]
    pub active_content: Vec<String>,
}

/// A timestamp: a signature's own, or a standalone document timestamp.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct TimestampSummary {
    /// DSS's identifier of the timestamp.
    pub id: String,
    /// DSS's timestamp type, e.g. `"SIGNATURE_TIMESTAMP"`, `"ARCHIVE_TIMESTAMP"`, `"DOCUMENT_TIMESTAMP"`.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// The outcome of its validation.
    pub indication: Option<Indication>,
    /// Why the outcome is not TOTAL_PASSED.
    pub sub_indication: Option<String>,
    /// When the TSA says it was produced.
    pub production_time: Option<String>,
    /// The TSA's name, from its certificate.
    pub produced_by: Option<String>,
    /// e.g. `"QTSA"`, `"TSA"`, `"NA"` (DSS's TimestampQualification names).
    pub qualification: Option<String>,
    /// Validation errors.
    #[serde(default)]
    pub errors: Vec<String>,
    /// Validation warnings.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Result of [`Engine::extend`](crate::Engine::extend).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Extended {
    /// The extended PDF: the input (decoded, if it was base64 or PEM) followed by an incremental update.
    #[serde(skip)]
    pub document: Vec<u8>,
    /// `"PDF"`.
    pub container: String,
    /// Encodings removed from the input, e.g. `["base64"]`.
    #[serde(default)]
    pub transformations: Vec<String>,
    /// The level the signatures were extended to, e.g. `"PAdES-BASELINE-LT"`. Signatures already above it are
    /// left as they are.
    pub level: String,
}

/// Result of [`Engine::prepare_signature`](crate::Engine::prepare_signature): what to send to the external signer.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct PreparedSignature {
    /// `"PAdES"` or `"CAdES"`.
    pub format: String,
    /// e.g. `"SHA256"`.
    pub digest_algorithm: String,
    /// The digest the external signer signs. [`SigningMode::Cms`](crate::SigningMode::Cms): the content's (for
    /// PAdES, the PDF's signed byte ranges'). [`SigningMode::SignatureValue`](crate::SigningMode::SignatureValue):
    /// that of [`data_to_sign`](Self::data_to_sign); an RSA signer wraps it in a DigestInfo.
    #[serde(with = "base64_bytes")]
    pub digest: Vec<u8>,
    /// [`SigningMode::SignatureValue`](crate::SigningMode::SignatureValue) only: the DER signed attributes, for
    /// signers that hash the data themselves.
    #[serde(default, with = "base64_opt_bytes")]
    pub data_to_sign: Option<Vec<u8>>,
    /// The signing time the signature claims: set [`SignOptions::signing_time`](crate::SignOptions::signing_time)
    /// to it for `complete`. For CAdES in mode `cms` the signature claims the time of the CMS's own signing-time
    /// attribute instead; `complete` does not need it there.
    pub signing_time: String,
}

impl PreparedSignature {
    /// [`digest`](Self::digest) as standard base64, the way signing services usually take it.
    pub fn digest_base64(&self) -> String {
        base64_bytes::encode(&self.digest)
    }
}

/// Result of [`Engine::complete_signature`](crate::Engine::complete_signature).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Signed {
    /// PAdES: the PDF followed by the signature revision (and, from T up, what extension added). CAdES: the CMS.
    #[serde(skip)]
    pub document: Vec<u8>,
    /// `"PAdES"` or `"CAdES"`.
    pub format: String,
    /// The level reached, e.g. `"PAdES-BASELINE-LT"`.
    pub level: String,
    /// `"ENVELOPED"` (PAdES), `"DETACHED"` or `"ENVELOPING"` (CAdES).
    pub packaging: String,
}

pub(crate) mod base64_bytes {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn encode(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

pub(crate) mod base64_opt_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => super::base64_bytes::serialize(b, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapped(#[serde(with = "super::base64_bytes")] Vec<u8>);
        Ok(Option::<Wrapped>::deserialize(d)?.map(|w| w.0))
    }
}

/// A duration as the library reports it. Current libraries measure it on a monotonic clock, so it is never
/// negative; one built before that computed it from two wall-clock reads, which a clock step during the run made
/// negative: that is read as 0 rather than failing the whole result.
fn clamped_ms<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let ms = i64::deserialize(d)?;
    Ok(u64::try_from(ms).unwrap_or(0))
}

/// One trusted-list refresh (offline from cache, from a snapshot, or online).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct RefreshRecord {
    /// `"offline"` (from `<cache_dir>/tl`), `"snapshot"` (from [`Config::tl_snapshot`](crate::Config::tl_snapshot))
    /// or `"online"`.
    pub mode: String,
    /// When it started (wall clock).
    pub started_at: String,
    /// When it finished (wall clock). A clock step during the run can put it before
    /// [`started_at`](Self::started_at).
    pub finished_at: String,
    /// How long it took, in milliseconds, measured on a monotonic clock: never negative, even when the host clock
    /// stepped backwards during the run (a library built before it measured this way reported a negative value
    /// then; that is read as 0).
    #[serde(deserialize_with = "clamped_ms")]
    pub duration_ms: u64,
    /// False when the run produced nothing publishable (DSS could not run, or the pool it built was unusable:
    /// LOTL not downloadable after a snapshot start, LOTL badly signed, every list undownloadable); the previous
    /// lists are then kept and [`error`](Self::error) says why. Per-list problems are in the status.
    /// [`Engine::refresh_trusted_lists`](crate::Engine::refresh_trusted_lists) reports such a run as
    /// [`ErrorCode::TlRefreshFailed`](crate::ErrorCode::TlRefreshFailed) instead of returning it.
    pub completed: bool,
    /// Why nothing was published, when [`completed`](Self::completed) is false.
    pub error: Option<String>,
    /// Trust anchors loaded after the refresh (the kept pool's, when nothing was published).
    pub trusted_certificates: u64,
}

/// What `dss_init` reported, from [`Engine::init_info`](crate::Engine::init_info).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct InitInfo {
    /// Whether trusted lists were loaded from the cache or the snapshot.
    pub trusted_lists_loaded: bool,
    /// The OJ keystore in use, the root of trust of the trusted lists (the same as
    /// [`TrustedListStatus::oj_keystore`]; `None` for libraries that do not report it).
    pub oj_keystore: Option<OjKeystoreInfo>,
    /// The log level in effect (the first engine of the process fixes it; `None` for libraries that do not
    /// report it).
    pub log_level: Option<String>,
    /// The initial load.
    pub initial_load: RefreshRecord,
}

/// Library, DSS and runtime versions, from [`Engine::version`](crate::Engine::version) or, without an engine,
/// [`library_version`](crate::library_version).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Version {
    /// The library's version (its release tag).
    pub library: String,
    /// The DSS version compiled into it, e.g. `"6.5.1"`.
    pub dss: String,
    /// The GraalVM runtime, e.g. `"Substrate VM 25.0"`.
    pub runtime: String,
    /// The version of the C/JSON contract the library speaks (see [`API_VERSION`](crate::API_VERSION)); `None`
    /// for libraries that do not report it.
    pub api_version: Option<u32>,
}

/// The root of trust of the trusted lists: the OJ keystore in use, from [`TrustedListStatus::oj_keystore`] and
/// [`InitInfo::oj_keystore`]. The library also logs it at INFO when the engine starts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct OjKeystoreInfo {
    /// The keystore's path, as configured ([`OjKeystore::path`](crate::OjKeystore::path)).
    pub path: String,
    /// SHA-256 over the sorted SHA-256 digests of the keystore's certificates, 64 lowercase hex digits: the value
    /// a trusted-list snapshot records as `oj_keystore_sha256` ([`TlSnapshotInfo::settings`]), so a snapshot's
    /// provenance can be checked against a running engine, and two keystores holding the same certificates
    /// compare equal.
    pub sha256: String,
}

/// Result of [`Engine::trusted_list_status`](crate::Engine::trusted_list_status).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct TrustedListStatus {
    /// Whether trusted lists are loaded (from the cache, a snapshot or online).
    pub loaded: bool,
    /// The OJ keystore in use (`None` for libraries that do not report it).
    pub oj_keystore: Option<OjKeystoreInfo>,
    /// Trust anchors from the trusted lists.
    pub trusted_certificates: u64,
    /// Trust anchors loaded from [`Config::extra_trusted_certificates`](crate::Config::extra_trusted_certificates)
    /// (`None` for libraries that do not report it).
    pub extra_trusted_certificates: Option<u64>,
    /// When the current lists were published to the validators.
    pub snapshot_published_at: Option<String>,
    /// When the lists came from a trusted-list snapshot ([`Config::tl_snapshot`](crate::Config::tl_snapshot)).
    pub tl_snapshot: Option<TlSnapshotInfo>,
    /// Whether an online refresh is running now.
    pub refresh_in_progress: bool,
    /// When the running refresh started.
    pub refresh_started_at: Option<String>,
    /// The last load from the cache or snapshot.
    pub last_offline_refresh: Option<RefreshRecord>,
    /// The last online refresh.
    pub last_online_refresh: Option<RefreshRecord>,
    /// Configured [`Config::countries`](crate::Config::countries) that match no list in the LOTL.
    #[serde(default)]
    pub countries_unmatched: Vec<String>,
    /// The list(s) of trusted lists.
    #[serde(default)]
    pub lotls: Vec<ListStatus>,
    /// The national trusted lists.
    #[serde(default)]
    pub tls: Vec<ListStatus>,
    /// Noteworthy events, one entry per kind and URL (the last 100 kinds).
    #[serde(default)]
    pub alerts: Vec<Alert>,
}

/// State of one list of trusted lists (LOTL) or national trusted list.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ListStatus {
    /// Where the list is downloaded from.
    pub url: String,
    /// The territory (ISO 3166 code) of a national list, once parsed.
    pub territory: Option<String>,
    /// The list's sequence number.
    pub sequence_number: Option<u64>,
    /// The floor the rollback protection enforces for this URL: the sequence number of the last list published
    /// from it (kept in `<cache_dir>/tl-sequence-numbers.json`, never lowered). A downloaded or cached list behind
    /// it is refused: `download.status` is `ERROR` with an error starting `rollback refused:`, and a `tl_rollback`
    /// [`Alert`] is raised. `None` when nothing was published from this URL yet (or the library does not report
    /// it).
    pub last_published_sequence_number: Option<u64>,
    /// The TSL version.
    pub version: Option<u32>,
    /// When the list was issued.
    pub issue_date: Option<String>,
    /// When the next issue is due.
    pub next_update: Option<String>,
    /// Whether `next_update` has passed.
    pub expired: Option<bool>,
    /// Trust service providers in the list.
    pub tsp_count: Option<u64>,
    /// Trust services in the list.
    pub service_count: Option<u64>,
    /// Certificates in the list.
    pub certificate_count: Option<u64>,
    /// Whether its certificates are trust anchors (signature valid, see `tl_sync`).
    pub used_for_trust: Option<bool>,
    /// DSS's structure validation messages (a TSL version outside `tl_versions`, schema deviations); usually empty.
    #[serde(default)]
    pub structure_messages: Vec<String>,
    /// The download stage.
    #[serde(default)]
    pub download: Stage,
    /// The parsing stage.
    #[serde(default)]
    pub parsing: Stage,
    /// The signature-validation stage.
    #[serde(default)]
    pub validation: Stage,
    /// LOTL only: the pivots followed.
    #[serde(default)]
    pub pivots: Vec<ListStatus>,
}

/// Download, parsing or signature-validation state of a list.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Stage {
    /// DSS's cache state name, e.g. `"SYNCHRONIZED"`, `"ERROR"`, `"REFRESH_NEEDED"`.
    pub status: Option<String>,
    /// When the state last changed.
    pub last_state_transition: Option<String>,
    /// When the stage last succeeded.
    pub last_success_synchronization: Option<String>,
    /// The error of a failed stage.
    pub error: Option<String>,
    /// When the error was first seen.
    pub error_first_seen: Option<String>,
    /// When the error was last seen.
    pub error_last_seen: Option<String>,
    /// Validation stage only: signature indication of the list.
    pub indication: Option<String>,
    /// Validation stage only: sub-indication of the list's signature.
    pub sub_indication: Option<String>,
    /// Validation stage only: when the list was signed.
    pub signing_time: Option<String>,
    /// Validation stage only: who signed the list.
    pub signed_by: Option<String>,
}

/// A noteworthy trusted-list event.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Alert {
    /// `oj_url_changed`, `lotl_location_changed`, `tl_signature_error`, `tl_expired`, `refresh_not_published`,
    /// `cache_write_error` (one per list, `url` = the list), `countries_unmatched`, `lotl_signature_error`,
    /// `lotl_expired`, `lotl_structure_error`, `tl_structure_error`, `tl_rollback` (a list older than the one
    /// published from `url` was refused; the `*sequence_number` and `*issue_date` fields say which).
    #[serde(rename = "type")]
    pub kind: String,
    /// The list concerned, when there is one.
    pub url: Option<String>,
    /// What happened.
    pub message: String,
    /// When it was last seen (same as [`last_seen`](Self::last_seen)).
    pub at: String,
    /// When it was first seen.
    pub first_seen: Option<String>,
    /// When it was last seen.
    pub last_seen: Option<String>,
    /// How many times it was seen.
    pub count: Option<u64>,
    /// `tl_rollback` only: the sequence number of the list published from the URL (the floor).
    pub previous_sequence_number: Option<u64>,
    /// `tl_rollback` only: when the published list was issued.
    pub previous_issue_date: Option<String>,
    /// `tl_rollback` only: the sequence number of the refused list.
    pub sequence_number: Option<u64>,
    /// `tl_rollback` only: when the refused list was issued (`None` when it says nothing).
    pub issue_date: Option<String>,
}

/// A trusted-list snapshot file, from [`Engine::export_tl_snapshot`](crate::Engine::export_tl_snapshot).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TlSnapshot {
    /// Its header.
    pub info: TlSnapshotInfo,
    /// The file. Store it anywhere and name it in [`Config::tl_snapshot`](crate::Config::tl_snapshot).
    pub bytes: Vec<u8>,
}

/// What describes a trusted-list snapshot: its header and size, and where it was loaded from.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct TlSnapshotInfo {
    /// The file it was loaded from ([`TrustedListStatus::tl_snapshot`] only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Size of the file in bytes.
    pub size: u64,
    /// The snapshot format version.
    pub format: u32,
    /// The library version that wrote it.
    pub library: Option<String>,
    /// The DSS version that wrote it; an engine loading it must have the same.
    pub dss: Option<String>,
    /// When it was written.
    pub created_at: String,
    /// The load that validated the lists, from the cache or online. Exporting again keeps it.
    pub lists_loaded: Option<RefreshRecord>,
    /// Trust anchors in the snapshot.
    pub trusted_certificates: u64,
    /// The trusted-list settings it was written with; an engine loading it must have the same.
    #[serde(default)]
    pub settings: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(duration_ms: i64) -> serde_json::Value {
        serde_json::json!({
            "mode": "online", "started_at": "2026-03-01T10:15:30Z", "finished_at": "2026-03-01T10:15:25Z",
            "duration_ms": duration_ms, "completed": true, "error": null, "trusted_certificates": 7
        })
    }

    #[test]
    fn unknown_indications_decode_to_unknown() {
        let s: SignatureSummary = serde_json::from_value(serde_json::json!({
            "id": "S-1", "indication": "SOMETHING_NEW", "brand_new_field": 1
        }))
        .unwrap();
        assert_eq!(s.indication, Indication::Unknown);
        assert!(s.errors.is_empty() && s.timestamps.is_empty() && s.policy.is_none());
        let known: Indication = serde_json::from_str("\"TOTAL_PASSED\"").unwrap();
        assert_eq!(known, Indication::TotalPassed);
    }

    #[test]
    fn negative_durations_clamp_to_zero_instead_of_failing() {
        let r: RefreshRecord = serde_json::from_value(record(-5000)).unwrap();
        assert_eq!(r.duration_ms, 0);
        let r: RefreshRecord = serde_json::from_value(record(1234)).unwrap();
        assert_eq!(r.duration_ms, 1234);
        let status: TrustedListStatus = serde_json::from_value(serde_json::json!({
            "loaded": true, "trusted_certificates": 7, "snapshot_published_at": null, "tl_snapshot": null,
            "refresh_in_progress": false, "refresh_started_at": null,
            "last_offline_refresh": null, "last_online_refresh": record(-1),
            "lotls": [], "tls": [], "alerts": [{"type": "tl_expired", "url": null, "message": "m", "at": "t"}]
        }))
        .unwrap();
        assert_eq!(status.last_online_refresh.unwrap().duration_ms, 0);
        assert_eq!(status.alerts[0].count, None);
        assert!(status.countries_unmatched.is_empty());
        let init: InitInfo = serde_json::from_value(serde_json::json!({
            "trusted_lists_loaded": false, "initial_load": record(-1)
        }))
        .unwrap();
        assert_eq!(init.initial_load.duration_ms, 0);
        assert_eq!(init.log_level, None);
    }

    /// `dss_init` reports the root of trust like the status does; an older library's result (no `oj_keystore`)
    /// still decodes.
    #[test]
    fn init_info_carries_the_oj_keystore() {
        let sha = "a".repeat(64);
        let init: InitInfo = serde_json::from_value(serde_json::json!({
            "ok": true, "trusted_lists_loaded": true,
            "oj_keystore": {"path": "/etc/dss/oj-keystore.p12", "sha256": sha},
            "log_level": "info", "initial_load": record(42)
        }))
        .unwrap();
        let keystore = init.oj_keystore.expect("oj_keystore");
        assert_eq!(keystore.path, "/etc/dss/oj-keystore.p12");
        assert_eq!(keystore.sha256, sha);
        assert_eq!(init.log_level.as_deref(), Some("info"));
        assert_eq!(init.initial_load.duration_ms, 42);
        let older: InitInfo = serde_json::from_value(serde_json::json!({
            "ok": true, "trusted_lists_loaded": false, "initial_load": record(1)
        }))
        .unwrap();
        assert!(older.oj_keystore.is_none());
    }

    #[test]
    fn new_validation_fields_decode() {
        let r: Reports = serde_json::from_value(serde_json::json!({
            "container": "PDF", "all_passed": true, "simple_report_xml": "<x/>",
            "detailed_report_xml": null, "etsi_report_xml": null, "diagnostic_data_xml": null,
            "timestamps": [{"id": "T-1", "type": "DOCUMENT_TIMESTAMP", "indication": "PASSED",
                "sub_indication": null, "production_time": "2026-01-01T00:00:00Z", "produced_by": "TSA",
                "qualification": "QTSA", "errors": [], "warnings": []}],
            "signatures": [{"id": "S-1", "indication": "TOTAL_PASSED", "sub_indication": null,
                "format": "PAdES-BASELINE-LT", "qualification": "QESIG", "signing_time": null,
                "best_signature_time": null, "signed_by": "Mario", "signer_dn": null,
                "trust_anchor": "trusted_list", "errors": [], "warnings": ["w"],
                "qualification_errors": ["q"], "qualification_warnings": [], "info": ["i"],
                "policy": {"id": "1.2.3", "url": null, "identified": true, "digest_valid": true},
                "modified_after_signing": true,
                "changes_after_signing": {"extension": 1, "signature_or_form_fill": 0, "annotation": 0,
                    "undefined": 0, "pages_differ": [3], "annotations_overlap": [2], "active_content": []},
                "timestamps": [{"id": "T-2", "type": "SIGNATURE_TIMESTAMP", "indication": "WEIRD",
                    "sub_indication": null, "production_time": null, "produced_by": null,
                    "qualification": null, "errors": [], "warnings": []}]}]
        }))
        .unwrap();
        assert!(r.all_passed());
        assert_eq!(r.timestamps[0].kind.as_deref(), Some("DOCUMENT_TIMESTAMP"));
        assert_eq!(r.timestamps[0].indication, Some(Indication::Passed));
        let s = &r.signatures[0];
        assert_eq!(s.trust_anchor.as_deref(), Some("trusted_list"));
        assert_eq!(s.qualification_errors, vec!["q"]);
        assert_eq!(s.policy.as_ref().unwrap().id.as_deref(), Some("1.2.3"));
        assert_eq!(s.modified_after_signing, Some(true));
        let changes = s.changes_after_signing.as_ref().unwrap();
        assert_eq!(changes.extension, 1);
        assert_eq!(
            (&changes.pages_differ, &changes.annotations_overlap),
            (&vec![3], &vec![2])
        );
        assert_eq!(s.timestamps[0].indication, Some(Indication::Unknown));
    }

    /// The rollback-protection fields of the status: `last_published_sequence_number` on every list, the
    /// `tl_rollback` alert's details, and `oj_keystore`; a status without them (an older library) still decodes.
    #[test]
    fn rollback_protection_and_keystore_fields_decode() {
        let list = |floor: Option<u64>| {
            serde_json::json!({
                "url": "https://tl.example/IT.xml", "territory": "IT", "sequence_number": 41,
                "last_published_sequence_number": floor, "version": 6, "issue_date": "2026-01-01T00:00:00Z",
                "next_update": null, "expired": false, "tsp_count": 1, "service_count": 2, "certificate_count": 3,
                "used_for_trust": true, "structure_messages": [],
                "download": {"status": "ERROR", "error": "rollback refused: the downloaded list is sequence number 41 (issued 2026-01-01T00:00:00Z), behind the published 42 (issued 2026-02-01T00:00:00Z): a replayed older list is not used"},
                "parsing": {}, "validation": {}, "pivots": [{"url": "https://lotl.example/pivot-1.xml"}]
            })
        };
        let status: TrustedListStatus = serde_json::from_value(serde_json::json!({
            "loaded": true, "oj_keystore": {"path": "trust/oj-keystore.p12", "sha256": "ab12"},
            "trusted_certificates": 7, "snapshot_published_at": null, "tl_snapshot": null,
            "refresh_in_progress": false, "refresh_started_at": null,
            "last_offline_refresh": null, "last_online_refresh": null,
            "lotls": [list(None)], "tls": [list(Some(42))],
            "alerts": [{"type": "tl_rollback", "url": "https://tl.example/IT.xml", "message": "m",
                "at": "t", "first_seen": "t", "last_seen": "t", "count": 2,
                "previous_sequence_number": 42, "previous_issue_date": "2026-02-01T00:00:00Z",
                "sequence_number": 41, "issue_date": null},
                {"type": "cache_write_error", "url": "https://tl.example/IT.xml", "message": "m", "at": "t"}]
        }))
        .unwrap();
        let keystore = status.oj_keystore.as_ref().expect("oj_keystore");
        assert_eq!(
            (keystore.path.as_str(), keystore.sha256.as_str()),
            ("trust/oj-keystore.p12", "ab12")
        );
        assert_eq!(status.lotls[0].last_published_sequence_number, None);
        assert_eq!(status.lotls[0].pivots[0].last_published_sequence_number, None);
        assert_eq!(status.tls[0].last_published_sequence_number, Some(42));
        assert_eq!(status.tls[0].sequence_number, Some(41));
        assert!(
            status.tls[0]
                .download
                .error
                .as_deref()
                .unwrap()
                .starts_with("rollback refused:"),
            "{:?}",
            status.tls[0].download.error
        );
        let rollback = &status.alerts[0];
        assert_eq!(rollback.kind, "tl_rollback");
        assert_eq!(rollback.previous_sequence_number, Some(42));
        assert_eq!(rollback.previous_issue_date.as_deref(), Some("2026-02-01T00:00:00Z"));
        assert_eq!(rollback.sequence_number, Some(41));
        assert_eq!(rollback.issue_date, None);
        assert_eq!(rollback.count, Some(2));
        let plain = &status.alerts[1];
        assert_eq!(plain.previous_sequence_number, None);
        assert_eq!(plain.sequence_number, None);

        // An older library: no oj_keystore, no floors.
        let status: TrustedListStatus = serde_json::from_value(serde_json::json!({
            "loaded": false, "trusted_certificates": 0, "snapshot_published_at": null, "tl_snapshot": null,
            "refresh_in_progress": false, "refresh_started_at": null,
            "last_offline_refresh": null, "last_online_refresh": null,
            "lotls": [{"url": "u"}], "tls": [], "alerts": []
        }))
        .unwrap();
        assert!(status.oj_keystore.is_none());
        assert_eq!(status.lotls[0].last_published_sequence_number, None);
    }

    #[test]
    fn version_without_api_version_decodes() {
        let v: Version =
            serde_json::from_value(serde_json::json!({"library": "1", "dss": "6.5.1", "runtime": "r"})).unwrap();
        assert_eq!(v.api_version, None);
    }
}
