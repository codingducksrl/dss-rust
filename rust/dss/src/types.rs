// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Results returned by the library, decoded from its JSON. Field meanings: README.md, "API".

use serde::{Deserialize, Serialize};

/// DSS's top-level validation outcome for one signature (ETSI EN 319 102-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum Indication {
    TotalPassed,
    Passed,
    Indeterminate,
    Failed,
    TotalFailed,
    NoSignatureFound,
    #[serde(other)]
    Unknown,
}

/// Result of [`Engine::validate`](crate::Engine::validate).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Reports {
    /// `"PDF"` or `"CMS"`.
    pub container: String,
    /// Encodings removed before validation, e.g. `["base64"]`.
    #[serde(default)]
    pub transformations: Vec<String>,
    pub signatures: Vec<SignatureSummary>,
    pub simple_report_xml: String,
    pub detailed_report_xml: Option<String>,
    pub etsi_report_xml: Option<String>,
    pub diagnostic_data_xml: Option<String>,
    /// Validation of a CAdES envelope inside the signed content (`.p7m.p7m`).
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

    /// True when there is at least one signature and every signature at every level is TOTAL_PASSED.
    pub fn all_passed(&self) -> bool {
        let all = self.all_signatures();
        !all.is_empty() && all.iter().all(|s| s.indication == Indication::TotalPassed)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignatureSummary {
    pub id: String,
    pub indication: Indication,
    pub sub_indication: Option<String>,
    /// e.g. `"PAdES-BASELINE-LTA"`.
    pub format: Option<String>,
    /// e.g. `"QESIG"`, `"ADESIG"`, `"NA"`.
    pub qualification: Option<String>,
    pub signing_time: Option<String>,
    pub best_signature_time: Option<String>,
    pub signed_by: Option<String>,
    /// Subject DN of the signing certificate (RFC 2253), when DSS identified it.
    pub signer_dn: Option<String>,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Result of [`Engine::extend`](crate::Engine::extend).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Extended {
    /// The extended PDF: the input (decoded, if it was base64 or PEM) followed by an incremental update.
    #[serde(skip)]
    pub document: Vec<u8>,
    /// `"PDF"`.
    pub container: String,
    /// Encodings removed from the input, e.g. `["base64"]`.
    #[serde(default)]
    pub transformations: Vec<String>,
    /// The level the signatures were extended to, e.g. `"PAdES-BASELINE-LT"`.
    pub level: String,
}

/// Result of [`Engine::prepare_signature`](crate::Engine::prepare_signature): what to send to the external signer.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// to it for `complete`.
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

/// One trusted-list refresh (offline from cache, or online).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RefreshRecord {
    pub mode: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    /// False only if the refresh could not run at all; per-list problems are in the status.
    pub completed: bool,
    pub error: Option<String>,
    pub trusted_certificates: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InitInfo {
    pub trusted_lists_loaded: bool,
    pub initial_load: RefreshRecord,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Version {
    pub library: String,
    pub dss: String,
    pub runtime: String,
}

/// Result of [`Engine::trusted_list_status`](crate::Engine::trusted_list_status).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrustedListStatus {
    pub loaded: bool,
    pub trusted_certificates: u64,
    pub snapshot_published_at: Option<String>,
    /// When the lists came from a trusted-list snapshot ([`Config::tl_snapshot`](crate::Config::tl_snapshot)).
    pub tl_snapshot: Option<TlSnapshotInfo>,
    pub refresh_in_progress: bool,
    pub refresh_started_at: Option<String>,
    pub last_offline_refresh: Option<RefreshRecord>,
    pub last_online_refresh: Option<RefreshRecord>,
    #[serde(default)]
    pub lotls: Vec<ListStatus>,
    #[serde(default)]
    pub tls: Vec<ListStatus>,
    #[serde(default)]
    pub alerts: Vec<Alert>,
}

/// State of one list of trusted lists (LOTL) or national trusted list.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListStatus {
    pub url: String,
    pub territory: Option<String>,
    pub sequence_number: Option<u64>,
    pub version: Option<u32>,
    pub issue_date: Option<String>,
    pub next_update: Option<String>,
    pub expired: Option<bool>,
    pub tsp_count: Option<u64>,
    pub service_count: Option<u64>,
    pub certificate_count: Option<u64>,
    /// Whether its certificates are trust anchors (signature valid, see `tl_sync`).
    pub used_for_trust: Option<bool>,
    #[serde(default)]
    pub download: Stage,
    #[serde(default)]
    pub parsing: Stage,
    #[serde(default)]
    pub validation: Stage,
    #[serde(default)]
    pub pivots: Vec<ListStatus>,
}

/// Download, parsing or signature-validation state of a list.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Stage {
    pub status: Option<String>,
    pub last_state_transition: Option<String>,
    pub last_success_synchronization: Option<String>,
    pub error: Option<String>,
    pub error_first_seen: Option<String>,
    pub error_last_seen: Option<String>,
    /// Validation stage only: signature indication of the list.
    pub indication: Option<String>,
    pub sub_indication: Option<String>,
    pub signing_time: Option<String>,
    pub signed_by: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Alert {
    /// `oj_url_changed`, `lotl_location_changed`, `tl_signature_error`, `tl_expired`.
    #[serde(rename = "type")]
    pub kind: String,
    pub url: Option<String>,
    pub message: String,
    pub at: String,
}

/// A trusted-list snapshot file, from [`Engine::export_tl_snapshot`](crate::Engine::export_tl_snapshot).
#[derive(Debug, Clone)]
pub struct TlSnapshot {
    pub info: TlSnapshotInfo,
    /// The file. Store it anywhere and name it in [`Config::tl_snapshot`](crate::Config::tl_snapshot).
    pub bytes: Vec<u8>,
}

/// What describes a trusted-list snapshot: its header and size, and where it was loaded from.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlSnapshotInfo {
    /// The file it was loaded from ([`TrustedListStatus::tl_snapshot`] only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub size: u64,
    pub format: u32,
    pub library: Option<String>,
    pub dss: Option<String>,
    pub created_at: String,
    /// The load that validated the lists, from the cache or online. Exporting again keeps it.
    pub lists_loaded: Option<RefreshRecord>,
    pub trusted_certificates: u64,
    /// The trusted-list settings it was written with; an engine loading it must have the same.
    #[serde(default)]
    pub settings: serde_json::Value,
}
