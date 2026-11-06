// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

use serde::Deserialize;

/// Error codes reported by the library (`error.code` in its JSON). Stable; new codes may be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ErrorCode {
    /// A malformed argument: bad options JSON, unknown option, missing detached file.
    InvalidArgument,
    /// The configuration is invalid or references a file that cannot be loaded.
    InvalidConfig,
    /// The engine is not (or no longer) initialised.
    NotInitialized,
    /// No trusted list is loaded yet: empty cache and no successful online refresh.
    TrustedListsNotLoaded,
    /// Another online refresh is already running.
    RefreshInProgress,
    /// The online refresh could not run at all (per-list errors are in the status instead).
    TlRefreshFailed,
    /// Neither a PDF nor a CMS/CAdES document (after base64/PEM unwrapping).
    UnsupportedDocument,
    /// DSS could not process the document.
    ValidationFailed,
    /// DSS refused to extend the signatures, or could not: a signature that does not validate, a revoked or
    /// expired certificate, missing revocation data, a signature already at a higher level, a timestamp needed
    /// without a TSA configured, or a TSA that failed.
    ExtensionFailed,
    /// A signature could not be prepared or completed: the external signature does not match the document and
    /// options (wrong digest, signer or key, or not a usable CMS), the signing certificate is expired or not yet
    /// valid at the signing time, the CMS does not fit the space reserved in the PDF, or the requested level could
    /// not be added (no TSA configured, the TSA failed, revocation data missing).
    SigningFailed,
    /// Anything unexpected inside the library, including running out of heap.
    InternalError,
    /// The trusted-list snapshot named by [`Config::tl_snapshot`](crate::Config::tl_snapshot) cannot be used:
    /// unreadable, not a snapshot, damaged, written by another DSS version or with other trusted-list settings, or
    /// trusting a list that `tl_sync` no longer allows.
    TlSnapshotRejected,
    /// A code this version of the crate does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The library returned `{"ok":false,"error":{...}}`.
    #[error("{code:?}: {message}")]
    Api { code: ErrorCode, message: String },
    /// The library returned NULL: it could not even build an error result (out of memory).
    #[error("libdssnative returned no result (out of memory)")]
    NoResult,
    /// The library's JSON could not be decoded into the expected type.
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

pub type Result<T, E = Error> = std::result::Result<T, E>;
