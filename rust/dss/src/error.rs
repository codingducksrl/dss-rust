// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Errors of the safe API: the library's own error codes, and what can go wrong around them.

use std::fmt;
use std::sync::Mutex;

use serde::de::{Deserialize, Deserializer, Error as _};
use serde::ser::{Serialize, Serializer};

/// Error codes reported by the library (`error.code` in its JSON). Stable; new codes may be added: a code this
/// version of the crate does not know is [`ErrorCode::Unknown`], with its wire name kept.
///
/// [`Display`](fmt::Display) prints the wire name (`INVALID_ARGUMENT`), the same spelling serde reads and writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// A malformed argument: bad options JSON, unknown option, missing detached file, a detail of the request the
    /// library cannot act on (a visible-signature field that does not exist, a `pades.content_size` too small for
    /// the CMS, a user-password-encrypted PDF is [`UnsupportedDocument`](Self::UnsupportedDocument) instead).
    InvalidArgument,
    /// The configuration is invalid or references a file that cannot be loaded.
    InvalidConfig,
    /// The engine is not (or no longer) initialised.
    NotInitialized,
    /// No trusted list is loaded yet: empty cache and no successful online refresh.
    TrustedListsNotLoaded,
    /// Another online refresh is already running.
    RefreshInProgress,
    /// The online refresh published no trusted lists: DSS could not run, or what it built was unusable (the LOTL
    /// not downloadable after a snapshot start, the LOTL badly signed, every list undownloadable). The lists loaded
    /// before, if any, are kept; the message says why. Per-list problems of a published refresh are in the status.
    TlRefreshFailed,
    /// Neither a PDF nor a CMS/CAdES document (after base64/PEM unwrapping), or a PDF encrypted with a user
    /// password.
    UnsupportedDocument,
    /// DSS could not process the document, or the document is over one of the structural
    /// [`Limits`](crate::Limits).
    ValidationFailed,
    /// DSS refused to extend the signatures, or could not: a signature that does not validate, a revoked or
    /// expired certificate, missing revocation data (with [`Revocation::Offline`](crate::Revocation::Offline) it is
    /// never fetched), every signature already above the target level, a timestamp needed without a TSA
    /// configured, or a PDF over one of the structural [`Limits`](crate::Limits). A failing TSA is
    /// [`TsaFailed`](Self::TsaFailed).
    ExtensionFailed,
    /// A signature could not be prepared or completed: the external signature does not match the document and
    /// options (wrong digest, signer or key, or not a usable CMS), the signing certificate is expired or not yet
    /// valid at the signing time or is not a document-signing certificate (a CA certificate, a key usage without
    /// digitalSignature or nonRepudiation, an extended key usage limited to timestamping, TLS or OCSP), the PDF's
    /// existing signatures cannot be extended to the requested level together with the new one, the external CMS
    /// carries an invalid timestamp or disallowed unsigned attributes, the CMS does not fit the space reserved in
    /// the PDF, the PDF is over one of the structural [`Limits`](crate::Limits), or the requested level could not
    /// be added (no TSA configured, revocation data missing). A failing TSA is [`TsaFailed`](Self::TsaFailed).
    SigningFailed,
    /// Anything unexpected inside the library, including running out of heap.
    InternalError,
    /// The configured TSA failed while a timestamp was needed: it could not be reached or answered an HTTP error
    /// (retry later), or it returned a token the engine refuses (not from a timestamping certificate chaining to
    /// the trust anchors, dated further than [`Tsa::max_clock_skew_ms`](crate::Tsa::max_clock_skew_ms) from the
    /// host clock, signed with a weak algorithm, not over the digest sent, or with a wrong nonce).
    TsaFailed,
    /// The trusted-list snapshot named by [`Config::tl_snapshot`](crate::Config::tl_snapshot) cannot be used:
    /// unreadable, not a snapshot, damaged, written by another DSS version or with other trusted-list settings,
    /// trusting a list that `tl_sync` no longer allows, or whose trust anchors reference lists its summary does not
    /// hold.
    TlSnapshotRejected,
    /// A code this version of the crate does not know, with its wire name. New library codes reach the
    /// application unchanged this way (and [`Error::Api`] prints and serialises them as the library sent them).
    /// See [`from_wire`](Self::from_wire) for the bound on distinct names.
    Unknown(&'static str),
}

/// The name an unknown code gets once [`MAX_INTERNED`] distinct unknown names were seen.
const UNKNOWN: &str = "UNKNOWN";

/// How many distinct unknown names are kept: far more than the library will ever add in one version, and a bound
/// on what a stream of made-up codes can make the process keep.
const MAX_INTERNED: usize = 256;

/// The wire names, in the order of the variants. Only ever add to this list (the Java side does the same).
const KNOWN: &[(ErrorCode, &str)] = &[
    (ErrorCode::InvalidArgument, "INVALID_ARGUMENT"),
    (ErrorCode::InvalidConfig, "INVALID_CONFIG"),
    (ErrorCode::NotInitialized, "NOT_INITIALIZED"),
    (ErrorCode::TrustedListsNotLoaded, "TRUSTED_LISTS_NOT_LOADED"),
    (ErrorCode::RefreshInProgress, "REFRESH_IN_PROGRESS"),
    (ErrorCode::TlRefreshFailed, "TL_REFRESH_FAILED"),
    (ErrorCode::UnsupportedDocument, "UNSUPPORTED_DOCUMENT"),
    (ErrorCode::ValidationFailed, "VALIDATION_FAILED"),
    (ErrorCode::ExtensionFailed, "EXTENSION_FAILED"),
    (ErrorCode::SigningFailed, "SIGNING_FAILED"),
    (ErrorCode::InternalError, "INTERNAL_ERROR"),
    (ErrorCode::TsaFailed, "TSA_FAILED"),
    (ErrorCode::TlSnapshotRejected, "TL_SNAPSHOT_REJECTED"),
];

impl ErrorCode {
    /// The code for a wire name: a known variant, or [`Unknown`](Self::Unknown) holding the name.
    ///
    /// Unknown names are interned (kept for the life of the process) so that the code stays `Copy`. The library
    /// emits a fixed, small set of codes; a process that has seen 256 distinct unknown names (which only a source
    /// other than the library can produce, e.g. error JSON of another origin fed to this type's `Deserialize`)
    /// keeps no more: every further unknown name is `Unknown("UNKNOWN")`. The [`Error::Api`] built from a
    /// library result keeps the real name at the start of its message in that case.
    pub fn from_wire(name: &str) -> ErrorCode {
        if let Some((code, _)) = KNOWN.iter().find(|(_, n)| *n == name) {
            return *code;
        }
        static INTERNED: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
        let mut interned = INTERNED.lock().unwrap_or_else(|e| e.into_inner());
        ErrorCode::Unknown(intern(&mut interned, name))
    }

    /// The wire name: `INVALID_ARGUMENT`, ..., or the name an [`Unknown`](Self::Unknown) code was received with.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::Unknown(name) => name,
            known => KNOWN
                .iter()
                .find(|(c, _)| c == known)
                .map(|(_, n)| *n)
                .unwrap_or("UNKNOWN"),
        }
    }
}

/// `name` from `interned`, added (leaked once) when new and the set is under [`MAX_INTERNED`]; else [`UNKNOWN`].
fn intern(interned: &mut Vec<&'static str>, name: &str) -> &'static str {
    if name == UNKNOWN {
        return UNKNOWN;
    }
    if let Some(s) = interned.iter().find(|s| **s == name) {
        return s;
    }
    if interned.len() >= MAX_INTERNED {
        return UNKNOWN;
    }
    let s: &'static str = Box::leak(name.to_owned().into_boxed_str());
    interned.push(s);
    s
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let name = String::deserialize(d)?;
        if name.is_empty() {
            return Err(D::Error::custom("empty error code"));
        }
        Ok(ErrorCode::from_wire(&name))
    }
}

/// What a call to the engine can fail with.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The library returned `{"ok":false,"error":{...}}`. Prints as `CODE: message`, with the code's wire name.
    #[error("{code}: {message}")]
    Api {
        /// The library's error code.
        code: ErrorCode,
        /// The library's message, meant for logs and error responses.
        message: String,
    },
    /// libdssnative returned no result: not even an error result could be allocated (native memory exhausted). A
    /// Java-heap `OutOfMemoryError` is a normal [`Api`](Self::Api) error with [`ErrorCode::InternalError`].
    #[error("libdssnative returned no result (not even an error result could be allocated: native memory exhausted)")]
    NoResult,
    /// The library's JSON could not be decoded into the expected type, or the library and this crate speak
    /// different API versions (see [`API_VERSION`](crate::API_VERSION)).
    #[error("unexpected JSON from libdssnative: {0}")]
    Protocol(String),
    /// Creating the GraalVM isolate (or attaching a thread to it) failed with this status code.
    #[error("GraalVM isolate error {0}")]
    Isolate(i32),
    /// The engine's threads are gone (it is shutting down, or a worker panicked).
    #[error("engine is shut down")]
    Closed,
    /// A string passed to the library contained a NUL byte.
    #[error("argument contains a NUL byte")]
    Nul,
    /// An argument cannot be handed to the library as it is: a path that is not valid UTF-8, a heap size without a
    /// unit, an isolate option that is not one. Nothing was sent to the library.
    #[error("invalid argument: {0}")]
    Argument(String),
    /// One of the engine's threads could not be spawned (the process hit a thread or memory limit).
    #[error("cannot spawn engine thread: {0}")]
    Thread(String),
    /// The call's [`CancelToken`](crate::CancelToken) was cancelled before a worker took it: it was skipped
    /// (see [`Engine::cancellable`](crate::Engine::cancellable)).
    #[error("call cancelled before it ran")]
    Cancelled,
}

impl Error {
    /// The library's error code, if this is an [`Error::Api`].
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Error::Api { code, .. } => Some(*code),
            _ => None,
        }
    }
}

/// `std::result::Result` with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_round_trip_through_their_wire_names() {
        for (code, name) in KNOWN {
            assert_eq!(ErrorCode::from_wire(name), *code);
            assert_eq!(code.as_str(), *name);
            assert_eq!(code.to_string(), *name);
            assert_eq!(serde_json::to_string(code).unwrap(), format!("\"{name}\""));
            let back: ErrorCode = serde_json::from_str(&format!("\"{name}\"")).unwrap();
            assert_eq!(back, *code);
        }
        assert_eq!(ErrorCode::from_wire("TSA_FAILED"), ErrorCode::TsaFailed);
    }

    #[test]
    fn unknown_codes_keep_their_wire_name() {
        let code: ErrorCode = serde_json::from_str("\"BRAND_NEW_CODE\"").unwrap();
        assert_eq!(code, ErrorCode::Unknown("BRAND_NEW_CODE"));
        assert_eq!(code.as_str(), "BRAND_NEW_CODE");
        assert_eq!(serde_json::to_string(&code).unwrap(), "\"BRAND_NEW_CODE\"");
        // Interned once: the same code twice is the same pointer, and equal.
        let again = ErrorCode::from_wire("BRAND_NEW_CODE");
        assert_eq!(again, code);
        assert!(std::ptr::eq(again.as_str(), code.as_str()));
        assert_ne!(ErrorCode::from_wire("OTHER"), code);
        assert!(serde_json::from_str::<ErrorCode>("\"\"").is_err());
        assert!(serde_json::from_str::<ErrorCode>("7").is_err());
    }

    #[test]
    fn api_errors_print_the_wire_code() {
        let e = Error::Api {
            code: ErrorCode::InvalidArgument,
            message: "bad option".into(),
        };
        assert_eq!(e.to_string(), "INVALID_ARGUMENT: bad option");
        assert_eq!(e.code(), Some(ErrorCode::InvalidArgument));
        let e = Error::Api {
            code: ErrorCode::from_wire("BRAND_NEW_CODE"),
            message: "something new".into(),
        };
        assert_eq!(e.to_string(), "BRAND_NEW_CODE: something new");
        assert_eq!(Error::Nul.code(), None);
        let e = Error::Thread("dss-control: EAGAIN".into());
        assert_eq!(e.to_string(), "cannot spawn engine thread: dss-control: EAGAIN");
        assert_eq!(e.code(), None);
        assert_eq!(Error::Cancelled.to_string(), "call cancelled before it ran");
        assert_eq!(Error::Cancelled.code(), None);
    }

    /// The set of unknown names a process keeps is bounded: past the cap, names decode to UNKNOWN instead of
    /// being kept. (A private set, so that the process-wide one stays as the other tests expect it.)
    #[test]
    fn unknown_names_are_interned_up_to_a_bound() {
        let mut set = Vec::new();
        for i in 0..MAX_INTERNED {
            let name = format!("MADE_UP_{i}");
            assert_eq!(intern(&mut set, &name), name);
        }
        assert_eq!(set.len(), MAX_INTERNED);
        assert_eq!(intern(&mut set, "ONE_TOO_MANY"), UNKNOWN);
        assert_eq!(intern(&mut set, "ANOTHER"), UNKNOWN);
        assert_eq!(set.len(), MAX_INTERNED, "nothing more is kept");
        // Names seen before the cap are still found, and UNKNOWN itself is never kept.
        assert_eq!(intern(&mut set, "MADE_UP_7"), "MADE_UP_7");
        assert_eq!(intern(&mut set, UNKNOWN), UNKNOWN);
        assert_eq!(ErrorCode::from_wire(UNKNOWN), ErrorCode::Unknown(UNKNOWN));
        assert_eq!(ErrorCode::Unknown(UNKNOWN).as_str(), "UNKNOWN");
    }
}
