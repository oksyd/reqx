use std::collections::BTreeMap;
#[cfg(feature = "_async")]
use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

use crate::util::{duration_millis_ceil, exponential_backoff_with_jitter};

#[cfg(feature = "_async")]
mod asynchronous;
mod blocking;
mod session;
#[cfg(test)]
mod tests;

#[cfg(feature = "_async")]
pub use asynchronous::AsyncResumableUploader;
pub use blocking::BlockingResumableUploader;

/// Current resumable upload checkpoint schema version.
pub const RESUMABLE_UPLOAD_CHECKPOINT_VERSION: u32 = 2;
const LEGACY_RESUMABLE_UPLOAD_CHECKPOINT_VERSION: u32 = 1;
const MAX_RESUMABLE_UPLOAD_PART_NUMBER: u32 = u32::MAX;

fn legacy_checkpoint_version() -> u32 {
    LEGACY_RESUMABLE_UPLOAD_CHECKPOINT_VERSION
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
/// Checksum algorithm used for uploaded parts.
pub enum PartChecksumAlgorithm {
    /// MD5 checksum in lowercase hex form.
    Md5,
    /// SHA-256 checksum in lowercase hex form.
    Sha256,
}

impl PartChecksumAlgorithm {
    /// Returns the stable string identifier for this checksum algorithm.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha256 => "sha256",
        }
    }

    fn compute_hex(self, data: &[u8]) -> String {
        match self {
            Self::Md5 => format!("{:x}", md5::compute(data)),
            Self::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                encode_hex_lower(&hasher.finalize())
            }
        }
    }
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn normalize_token(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
/// Metadata recorded for one successfully uploaded part.
pub struct UploadedPart {
    /// One-based part number.
    pub part_number: u32,
    /// Remote ETag returned by the upload backend.
    pub etag: String,
    /// Number of bytes uploaded for this part.
    pub size: usize,
    #[serde(default)]
    /// Optional checksum recorded for this part.
    pub checksum: Option<String>,
}

impl UploadedPart {
    /// Creates metadata for an uploaded part without a checksum.
    pub fn new(part_number: u32, etag: impl Into<String>, size: usize) -> Self {
        Self {
            part_number,
            etag: etag.into(),
            size,
            checksum: None,
        }
    }

    /// Attaches a backend-provided checksum to this part.
    pub fn with_checksum(mut self, checksum: impl Into<String>) -> Self {
        self.checksum = Some(checksum.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
/// Serializable checkpoint used to resume multipart uploads.
pub struct ResumableUploadCheckpoint {
    #[serde(default = "legacy_checkpoint_version")]
    /// Checkpoint schema version.
    pub version: u32,
    /// Backend upload identifier.
    pub upload_id: String,
    /// Fixed part size used for this upload.
    pub part_size: usize,
    #[serde(default)]
    /// Optional checksum algorithm used for uploaded parts.
    pub checksum_algorithm: Option<PartChecksumAlgorithm>,
    /// Completed parts keyed by part number.
    pub completed_parts: BTreeMap<u32, UploadedPart>,
}

impl ResumableUploadCheckpoint {
    /// Creates an empty checkpoint for a new upload.
    pub fn new(upload_id: impl Into<String>, part_size: usize) -> Self {
        Self {
            version: RESUMABLE_UPLOAD_CHECKPOINT_VERSION,
            upload_id: upload_id.into(),
            part_size,
            checksum_algorithm: None,
            completed_parts: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Summary returned after a resumable upload completes.
pub struct ResumableUploadResult {
    /// Backend upload identifier.
    pub upload_id: String,
    /// Total number of uploaded bytes.
    pub total_bytes: u64,
    /// Total number of uploaded parts.
    pub total_parts: u32,
    /// Whether the upload resumed from an existing checkpoint.
    pub resumed: bool,
    /// Completed parts in order.
    pub completed_parts: Vec<UploadedPart>,
}

#[derive(Clone, Debug)]
/// Options controlling resumable upload chunking, retries, and verification.
pub struct ResumableUploadOptions {
    part_size: usize,
    max_attempts: usize,
    base_backoff: Duration,
    max_backoff: Duration,
    jitter_ratio: f64,
    abort_on_error: bool,
    part_checksum_algorithm: Option<PartChecksumAlgorithm>,
    verify_remote_etag: bool,
}

impl ResumableUploadOptions {
    /// Creates options with the default resumable upload settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the size of each uploaded part in bytes.
    pub fn with_part_size(mut self, part_size: usize) -> Self {
        self.part_size = part_size;
        self
    }

    /// Sets how many attempts are allowed for each part upload.
    pub fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Sets the base retry backoff used between part upload attempts.
    pub fn with_base_backoff(mut self, base_backoff: Duration) -> Self {
        self.base_backoff = base_backoff;
        self
    }

    /// Sets the maximum retry backoff used between part upload attempts.
    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    /// Sets the backoff jitter ratio applied to retry delays.
    pub fn with_jitter_ratio(mut self, jitter_ratio: f64) -> Self {
        self.jitter_ratio = jitter_ratio;
        self
    }

    /// Aborts the remote upload when a terminal error is encountered.
    pub fn with_abort_on_error(mut self, abort_on_error: bool) -> Self {
        self.abort_on_error = abort_on_error;
        self
    }

    /// Enables checksum verification for uploaded parts.
    pub fn with_part_checksum_algorithm(
        mut self,
        part_checksum_algorithm: PartChecksumAlgorithm,
    ) -> Self {
        self.part_checksum_algorithm = Some(part_checksum_algorithm);
        self
    }

    /// Disables checksum generation and verification for uploaded parts.
    pub fn without_part_checksum_algorithm(mut self) -> Self {
        self.part_checksum_algorithm = None;
        self
    }

    /// Verifies that the remote ETag matches the computed checksum.
    ///
    /// Enabling this requires a part checksum algorithm.
    pub fn with_verify_remote_etag(mut self, verify_remote_etag: bool) -> Self {
        self.verify_remote_etag = verify_remote_etag;
        self
    }

    /// Returns the configured part size in bytes.
    pub fn part_size(&self) -> usize {
        self.part_size
    }

    /// Returns the configured maximum attempts per part.
    pub fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    /// Returns the configured part checksum algorithm, if any.
    pub fn part_checksum_algorithm(&self) -> Option<PartChecksumAlgorithm> {
        self.part_checksum_algorithm
    }

    /// Returns whether remote ETags are checked against the expected checksum.
    pub fn verify_remote_etag(&self) -> bool {
        self.verify_remote_etag
    }

    fn backoff_for_retry(&self, retry_index: usize) -> Duration {
        exponential_backoff_with_jitter(
            retry_index,
            self.base_backoff,
            self.max_backoff,
            self.jitter_ratio,
        )
    }

    fn validate<E>(&self) -> Result<(), ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        if self.part_size == 0 {
            return Err(self.invalid_options("part_size must be greater than zero"));
        }
        if self.max_attempts == 0 {
            return Err(self.invalid_options("max_attempts must be greater than zero"));
        }
        if self.base_backoff.is_zero() {
            return Err(self.invalid_options("base_backoff must be greater than zero"));
        }
        if self.max_backoff.is_zero() {
            return Err(self.invalid_options("max_backoff must be greater than zero"));
        }
        if self.max_backoff < self.base_backoff {
            return Err(
                self.invalid_options("max_backoff must be greater than or equal to base_backoff")
            );
        }
        if !self.jitter_ratio.is_finite() || !(0.0..=1.0).contains(&self.jitter_ratio) {
            return Err(self.invalid_options("jitter_ratio must be finite and between 0.0 and 1.0"));
        }
        if self.verify_remote_etag && self.part_checksum_algorithm.is_none() {
            return Err(self.invalid_options("verify_remote_etag requires part_checksum_algorithm"));
        }
        Ok(())
    }

    fn invalid_options<E>(&self, message: &'static str) -> ResumableUploadError<E>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ResumableUploadError::InvalidOptions {
            part_size: self.part_size,
            max_attempts: self.max_attempts,
            base_backoff_ms: duration_millis_ceil(self.base_backoff),
            max_backoff_ms: duration_millis_ceil(self.max_backoff),
            jitter_ratio: self.jitter_ratio,
            message,
        }
    }

    fn expected_checksum(&self, chunk: &[u8]) -> Option<String> {
        self.part_checksum_algorithm
            .map(|algorithm| algorithm.compute_hex(chunk))
    }

    fn validate_uploaded_part<E>(
        &self,
        checkpoint: &ResumableUploadCheckpoint,
        part_number: u32,
        uploaded: &UploadedPart,
        expected_checksum: Option<&str>,
    ) -> Result<(), ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        let Some(expected_checksum) = expected_checksum else {
            return Ok(());
        };

        if let Some(actual_checksum) = uploaded.checksum.as_deref() {
            let normalized_expected = normalize_token(expected_checksum);
            let normalized_actual = normalize_token(actual_checksum);
            if normalized_actual != normalized_expected {
                return Err(ResumableUploadError::PartChecksumMismatch {
                    part_number,
                    expected_checksum: normalized_expected,
                    actual_checksum: normalized_actual,
                    checkpoint: checkpoint.clone(),
                });
            }
        }

        if self.verify_remote_etag {
            let normalized_expected = normalize_token(expected_checksum);
            let normalized_actual = normalize_token(&uploaded.etag);
            if normalized_actual != normalized_expected {
                return Err(ResumableUploadError::PartEtagMismatch {
                    part_number,
                    expected_etag: normalized_expected,
                    actual_etag: normalized_actual,
                    checkpoint: checkpoint.clone(),
                });
            }
        }

        Ok(())
    }
}

impl Default for ResumableUploadOptions {
    fn default() -> Self {
        Self {
            part_size: 8 * 1024 * 1024,
            max_attempts: 3,
            base_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(2),
            jitter_ratio: 0.2,
            abort_on_error: false,
            part_checksum_algorithm: None,
            verify_remote_etag: false,
        }
    }
}

#[derive(Error)]
#[non_exhaustive]
/// Error returned by a resumable upload operation.
pub enum ResumableUploadError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Resumable upload options were invalid.
    #[error(
        "invalid resumable upload options (part_size={part_size}, max_attempts={max_attempts}, base_backoff_ms={base_backoff_ms}, max_backoff_ms={max_backoff_ms}, jitter_ratio={jitter_ratio}): {message}"
    )]
    InvalidOptions {
        /// Configured part size.
        part_size: usize,
        /// Configured attempts per part.
        max_attempts: usize,
        /// Configured base backoff in milliseconds.
        base_backoff_ms: u128,
        /// Configured maximum backoff in milliseconds.
        max_backoff_ms: u128,
        /// Configured jitter ratio.
        jitter_ratio: f64,
        /// Validation failure explanation.
        message: &'static str,
    },
    /// Creating the remote upload session failed.
    #[error("failed to create resumable upload")]
    CreateFailed {
        #[source]
        /// Source error returned by the backend.
        source: E,
    },
    /// The checkpoint part size did not match the active options.
    #[error(
        "checkpoint part size mismatch: checkpoint={checkpoint_part_size} options={options_part_size}"
    )]
    CheckpointPartSizeMismatch {
        /// Part size stored in the checkpoint.
        checkpoint_part_size: usize,
        /// Part size configured in the active options.
        options_part_size: usize,
    },
    /// The checkpoint checksum algorithm did not match the active options.
    #[error(
        "checkpoint checksum algorithm mismatch: checkpoint={checkpoint_checksum_algorithm} options={options_checksum_algorithm}"
    )]
    CheckpointChecksumAlgorithmMismatch {
        /// Checksum algorithm stored in the checkpoint.
        checkpoint_checksum_algorithm: &'static str,
        /// Checksum algorithm configured in the active options.
        options_checksum_algorithm: &'static str,
    },
    /// The checkpoint version was newer than this crate understands.
    #[error(
        "unsupported checkpoint version {checkpoint_version}; max supported is {max_supported_version}"
    )]
    UnsupportedCheckpointVersion {
        /// Version stored in the checkpoint.
        checkpoint_version: u32,
        /// Highest checkpoint version supported by this crate.
        max_supported_version: u32,
    },
    /// The checkpoint upload id was empty.
    #[error("checkpoint upload id is empty")]
    EmptyUploadId,
    /// Reading the source stream failed.
    #[error("source read failed")]
    SourceRead {
        #[source]
        /// Source I/O error.
        source: std::io::Error,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// Uploading a part failed after exhausting retries.
    #[error("upload part {part_number} failed after {attempts} attempts")]
    PartUploadFailed {
        /// One-based part number.
        part_number: u32,
        /// Number of attempts that were made.
        attempts: usize,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
        #[source]
        /// Source error returned by the backend.
        source: E,
    },
    /// The backend returned metadata for a different part number.
    #[error("upload part {expected_part_number} returned metadata for part {actual_part_number}")]
    PartNumberMismatch {
        /// Expected one-based part number.
        expected_part_number: u32,
        /// Backend-reported one-based part number.
        actual_part_number: u32,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// The backend returned a byte size that did not match the uploaded chunk.
    #[error(
        "upload part {part_number} returned size {actual_size} but uploaded {expected_size} bytes"
    )]
    PartSizeMismatch {
        /// One-based part number.
        part_number: u32,
        /// Expected uploaded byte count.
        expected_size: usize,
        /// Backend-reported byte count.
        actual_size: usize,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// A backend-reported checksum did not match the expected checksum.
    #[error(
        "upload part {part_number} checksum mismatch: expected={expected_checksum} actual={actual_checksum}"
    )]
    PartChecksumMismatch {
        /// One-based part number.
        part_number: u32,
        /// Expected checksum in normalized lowercase form.
        expected_checksum: String,
        /// Actual checksum returned by the backend in normalized lowercase form.
        actual_checksum: String,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// A backend-reported ETag did not match the expected checksum.
    #[error(
        "upload part {part_number} etag mismatch: expected={expected_etag} actual={actual_etag}"
    )]
    PartEtagMismatch {
        /// One-based part number.
        part_number: u32,
        /// Expected ETag in normalized lowercase form.
        expected_etag: String,
        /// Actual ETag returned by the backend in normalized lowercase form.
        actual_etag: String,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// Completing the remote upload session failed.
    #[error("failed to complete resumable upload")]
    CompleteFailed {
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
        #[source]
        /// Source error returned by the backend.
        source: E,
    },
    /// Aborting the remote upload failed after another terminal upload error.
    #[error("failed to abort resumable upload after terminal error")]
    AbortFailed {
        /// Remote upload identifier whose cleanup failed.
        upload_id: String,
        /// Original terminal upload error that triggered cleanup.
        original: Box<ResumableUploadError<E>>,
        #[source]
        /// Source error returned by the backend abort operation.
        source: E,
    },
    /// The source stream produced no uploadable data.
    #[error("upload body produced no parts")]
    EmptyUploadBody,
    /// A required completed part was missing from the checkpoint.
    #[error("missing completed metadata for part {part_number}")]
    MissingCompletedPart {
        /// Missing one-based part number.
        part_number: u32,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// The source stream requires more parts than this checkpoint format can represent.
    #[error(
        "resumable upload requires part {attempted_part_number}, which exceeds max supported part number {max_part_number}"
    )]
    TooManyUploadParts {
        /// One-based part number that would have been needed.
        attempted_part_number: u64,
        /// Maximum one-based part number supported by the checkpoint format.
        max_part_number: u32,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
}

impl<E> std::fmt::Debug for ResumableUploadError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResumableUploadError")
            .field("message", &self.to_string())
            .finish()
    }
}

impl<E> ResumableUploadError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Returns the checkpoint carried by this error, when available.
    pub fn checkpoint(&self) -> Option<&ResumableUploadCheckpoint> {
        match self {
            Self::SourceRead { checkpoint, .. }
            | Self::PartUploadFailed { checkpoint, .. }
            | Self::PartNumberMismatch { checkpoint, .. }
            | Self::PartSizeMismatch { checkpoint, .. }
            | Self::PartChecksumMismatch { checkpoint, .. }
            | Self::PartEtagMismatch { checkpoint, .. }
            | Self::CompleteFailed { checkpoint, .. }
            | Self::MissingCompletedPart { checkpoint, .. }
            | Self::TooManyUploadParts { checkpoint, .. } => Some(checkpoint),
            Self::AbortFailed { original, .. } => original.checkpoint(),
            _ => None,
        }
    }

    /// Consumes the error and returns the checkpoint carried by it, when available.
    pub fn into_checkpoint(self) -> Option<ResumableUploadCheckpoint> {
        match self {
            Self::SourceRead { checkpoint, .. }
            | Self::PartUploadFailed { checkpoint, .. }
            | Self::PartNumberMismatch { checkpoint, .. }
            | Self::PartSizeMismatch { checkpoint, .. }
            | Self::PartChecksumMismatch { checkpoint, .. }
            | Self::PartEtagMismatch { checkpoint, .. }
            | Self::CompleteFailed { checkpoint, .. }
            | Self::MissingCompletedPart { checkpoint, .. }
            | Self::TooManyUploadParts { checkpoint, .. } => Some(checkpoint),
            Self::AbortFailed { original, .. } => original.into_checkpoint(),
            _ => None,
        }
    }
}

/// Backend contract for blocking resumable uploads.
pub trait BlockingResumableUploadBackend {
    /// Backend-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Starts a new remote upload session and returns its upload id.
    fn create_upload(&self) -> Result<String, Self::Error>;

    /// Uploads one part and returns metadata for the completed part.
    ///
    /// The returned `part_number` and `size` must match the requested part.
    fn upload_part(
        &self,
        upload_id: &str,
        part_number: u32,
        chunk: &[u8],
    ) -> Result<UploadedPart, Self::Error>;

    /// Finalizes the remote upload using the ordered completed parts.
    fn complete_upload(&self, upload_id: &str, parts: &[UploadedPart]) -> Result<(), Self::Error>;

    /// Aborts a remote upload session after a terminal error.
    fn abort_upload(&self, _upload_id: &str) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Backend contract for async resumable uploads.
#[cfg(feature = "_async")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-native"
    )))
)]
pub trait AsyncResumableUploadBackend {
    /// Backend-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Starts a new remote upload session and returns its upload id.
    fn create_upload(&self) -> impl Future<Output = Result<String, Self::Error>> + Send;

    /// Uploads one part and returns metadata for the completed part.
    ///
    /// The returned `part_number` and `size` must match the requested part.
    fn upload_part(
        &self,
        upload_id: &str,
        part_number: u32,
        chunk: &[u8],
    ) -> impl Future<Output = Result<UploadedPart, Self::Error>> + Send;

    /// Finalizes the remote upload using the ordered completed parts.
    fn complete_upload(
        &self,
        upload_id: &str,
        parts: &[UploadedPart],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Aborts a remote upload session after a terminal error.
    fn abort_upload(
        &self,
        _upload_id: &str,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }
}
