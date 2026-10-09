use std::collections::BTreeMap;
#[cfg(feature = "resumable-upload-async")]
use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

use crate::core::util::{duration_millis_ceil, exponential_backoff_with_jitter};

#[cfg(feature = "resumable-upload-async")]
mod asynchronous;
mod blocking;
mod session;
#[cfg(test)]
mod tests;

/// Drives resumable uploads with shared chunking, retry, and verification settings.
///
/// Use `upload_blocking`/`resume_blocking` for synchronous backends and
/// `upload_async`/`resume_async` for asynchronous backends. The base
/// `resumable-upload` feature is independent of HTTP/TLS; async methods require
/// `resumable-upload-async` explicitly and use Tokio I/O/time.
///
/// # Backend and source contract
///
/// Implements sequential multipart orchestration over your storage backend:
/// create a session, read bounded chunks, retry each part, then finalize ordered
/// part metadata. It supplies no service-specific HTTP/storage implementation.
/// Parts are one-based; the final part can be shorter. Empty input is rejected.
/// The backend must support retrying the same upload id/part number/content.
/// Upload retries are independent of any HTTP retries inside that backend.
/// Options are validated at the start of an operation, before backend/source I/O.
///
/// # Persistence and resume
///
/// Save [`ResumableUploadError::checkpoint`] when an error carries one. The
/// checkpoint is serializable; persistence and reloading belong to the caller.
/// Resume from byte zero of the complete unchanged source, using the same part
/// size and checksum algorithm. The uploader rereads chunks, checks completed
/// metadata, and skips matching parts. It does not seek the source, list remote
/// parts, or persist progress automatically. Without checksums, equal size alone
/// cannot detect changed source contents.
///
/// Checkpoints are returned on recoverable operation errors, not continuously
/// during an upload. Abrupt process termination or async cancellation does not
/// return a checkpoint or automatically abort the remote session. Backends can
/// provide additional durable state when the application needs crash recovery.
/// `abort_on_error` defaults to false; enabling it can invalidate a checkpoint's
/// remote session. Only the explicit current checkpoint schema is accepted.
///
/// ```no_run
/// # #[cfg(feature = "resumable-upload")]
/// fn transfer<B: reqx::advanced::BlockingResumableUploadBackend>(
///     backend: &B,
///     source_from_start: &mut impl std::io::Read,
///     saved: Option<reqx::advanced::ResumableUploadCheckpoint>,
/// ) -> Result<reqx::advanced::ResumableUploadResult,
///             reqx::advanced::ResumableUploadError<B::Error>> {
///     let uploader = reqx::advanced::ResumableUploader::default();
///     match saved {
///         Some(checkpoint) => uploader.resume_blocking(backend, source_from_start, checkpoint),
///         None => uploader.upload_blocking(backend, source_from_start),
///     }
/// }
/// # fn main() {}
/// ```
#[derive(Debug, Default)]
pub struct ResumableUploader {
    options: ResumableUploadOptions,
}

impl ResumableUploader {
    /// Creates an uploader with the provided options.
    ///
    /// Construction is infallible; upload/resume validates the options before I/O.
    /// `Default` uses [`ResumableUploadOptions::default`].
    pub fn new(options: ResumableUploadOptions) -> Self {
        Self { options }
    }

    /// Returns this uploader's immutable configuration.
    pub fn options(&self) -> &ResumableUploadOptions {
        &self.options
    }
}

/// Current resumable upload checkpoint schema version.
pub const RESUMABLE_UPLOAD_CHECKPOINT_VERSION: u32 = 2;
const MAX_RESUMABLE_UPLOAD_PART_NUMBER: u32 = u32::MAX;

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
///
/// Records an opaque backend session id, current schema version, part size,
/// checksum algorithm, and confirmed completed parts. Keys are one-based and
/// must equal each entry's `part_number`. A checkpoint describes the last known
/// successful progress; it does not prove that the remote session still exists.
///
/// Save/load with your chosen Serde format, then pass it to an uploader configured
/// with exactly the same part size and checksum algorithm. Resume rereads the
/// complete source from byte zero. Missing/older schema versions are rejected;
/// create new checkpoints through [`Self::new`] to set the current version.
/// The JSON example requires `serde_json` as an application dependency.
///
/// ```
/// # #[cfg(feature = "resumable-upload")]
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let checkpoint = reqx::advanced::ResumableUploadCheckpoint::new("session-id", 8 * 1024 * 1024);
/// let saved = serde_json::to_string(&checkpoint)?;
/// let restored: reqx::advanced::ResumableUploadCheckpoint = serde_json::from_str(&saved)?;
/// assert_eq!(restored.version, reqx::advanced::RESUMABLE_UPLOAD_CHECKPOINT_VERSION);
/// # Ok(())
/// # }
/// ```
pub struct ResumableUploadCheckpoint {
    /// Explicit schema version; resuming accepts only the current version.
    pub version: u32,
    /// Backend upload identifier.
    pub upload_id: String,
    /// Fixed part size used for this upload.
    pub part_size: usize,
    #[serde(default)]
    /// Optional checksum algorithm used for uploaded parts.
    pub checksum_algorithm: Option<PartChecksumAlgorithm>,
    /// Completed parts keyed by their matching, nonzero part number.
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
///
/// Defaults: 8 MiB parts, 3 attempts per part (including its first call), 200 ms
/// base backoff, 2 s ceiling, 0.2 jitter ratio, no automatic abort, no checksums,
/// and no remote ETag verification. These are separate from HTTP client settings.
/// There is no whole-upload timeout; the backend/caller owns time limits.
///
/// Invalid values are rejected by upload/resume before I/O: part size and attempt
/// count must be positive, backoffs must be positive with ceiling >= base, and
/// jitter must be finite in `0.0..=1.0`. Remote ETag verification requires a
/// configured checksum algorithm. Source/backend limits such as minimum part
/// sizes, object limits, or storage-service maximum part counts belong to the
/// backend; this checkpoint format supports part numbers up to `u32::MAX`.
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
    ///
    /// Defaults to false so an error checkpoint can remain resumable. When true,
    /// the backend's `abort_upload` is called after operation errors; a failed
    /// abort returns `AbortFailed` with the original error. Dropping/canceling an
    /// async operation does not run this asynchronous cleanup.
    pub fn with_abort_on_error(mut self, abort_on_error: bool) -> Self {
        self.abort_on_error = abort_on_error;
        self
    }

    /// Sets checksum generation and verification for uploaded parts.
    ///
    /// `None` disables a previously configured algorithm.
    pub fn with_part_checksum_algorithm(
        mut self,
        part_checksum_algorithm: Option<PartChecksumAlgorithm>,
    ) -> Self {
        self.part_checksum_algorithm = part_checksum_algorithm;
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
        if self.part_size > isize::MAX as usize {
            return Err(self.invalid_options("part_size must not exceed isize::MAX"));
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
    /// The checkpoint version did not match the current schema.
    #[error(
        "unsupported checkpoint version {checkpoint_version}; supported version is {supported_version}"
    )]
    UnsupportedCheckpointVersion {
        /// Version stored in the checkpoint.
        checkpoint_version: u32,
        /// Checkpoint version supported by this crate.
        supported_version: u32,
    },
    /// A completed part had a zero number or disagreed with its checkpoint key.
    #[error(
        "invalid checkpoint part number {part_number} at key {checkpoint_key}; both must be equal and greater than zero"
    )]
    InvalidCheckpointPartNumber {
        /// Key identifying the part in the checkpoint.
        checkpoint_key: u32,
        /// Part number recorded in the part metadata.
        part_number: u32,
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
    EmptyUploadBody {
        /// Created upload session, available for retry or explicit cleanup.
        checkpoint: ResumableUploadCheckpoint,
    },
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
    ///
    /// Operation failures after a session exists can carry the last confirmed
    /// parts. Configuration, create-session, and invalid-checkpoint failures may
    /// have no checkpoint. Persist this value before retrying from a fresh source.
    /// If automatic abort was enabled, verify remote session availability first.
    pub fn checkpoint(&self) -> Option<&ResumableUploadCheckpoint> {
        match self {
            Self::SourceRead { checkpoint, .. }
            | Self::PartUploadFailed { checkpoint, .. }
            | Self::PartNumberMismatch { checkpoint, .. }
            | Self::PartSizeMismatch { checkpoint, .. }
            | Self::PartChecksumMismatch { checkpoint, .. }
            | Self::PartEtagMismatch { checkpoint, .. }
            | Self::CompleteFailed { checkpoint, .. }
            | Self::EmptyUploadBody { checkpoint }
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
            | Self::EmptyUploadBody { checkpoint }
            | Self::MissingCompletedPart { checkpoint, .. }
            | Self::TooManyUploadParts { checkpoint, .. } => Some(checkpoint),
            Self::AbortFailed { original, .. } => original.into_checkpoint(),
            _ => None,
        }
    }
}

/// Backend contract for blocking resumable uploads.
///
/// Provides storage-protocol operations; it is not coupled to a reqx HTTP client.
/// Calls are sequential. `create_upload` and `complete_upload` are each called
/// once; only `upload_part` calls are automatically retried, up to the configured
/// attempt limit, on any backend error. Retrying a part must replace/reuse the
/// same session/part number with identical bytes safely.
///
/// Return [`UploadedPart`] with matching one-based number and byte length. ETags
/// are opaque by default. With a configured checksum, a backend-provided checksum
/// is validated; otherwise the uploader records its local checksum in the
/// checkpoint. Remote ETag verification additionally requires the ETag to encode
/// that checksum, which is an opt-in service-specific guarantee.
///
/// Finalization receives parts sorted by part number, including reused parts.
/// The default `abort_upload` is a no-op; implement remote cleanup when enabling
/// automatic abort. Backend timeout/retry settings are independent of uploader
/// retries. Resume trusts checkpoints and never automatically lists remote state.
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
///
/// Has the same sequential, idempotent part, metadata, retry, and abort contract
/// as [`BlockingResumableUploadBackend`]. Returned futures must be `Send`;
/// implementations may use `async fn` directly, with no `async_trait` dependency.
/// The trait uses generic static dispatch and is not a `dyn` backend interface.
/// Runtime and storage transport are owned by the application/backend.
///
/// ```no_run
/// # #[cfg(feature = "resumable-upload-async")]
/// async fn upload_bytes<B: reqx::advanced::AsyncResumableUploadBackend>(
///     backend: &B,
///     data: &[u8],
/// ) -> Result<reqx::advanced::ResumableUploadResult,
///             reqx::advanced::ResumableUploadError<B::Error>> {
///     let mut source = data;
///     reqx::advanced::ResumableUploader::default()
///         .upload_async(backend, &mut source).await
/// }
/// # fn main() {}
/// ```
#[cfg(feature = "resumable-upload-async")]
#[cfg_attr(docsrs, doc(cfg(feature = "resumable-upload-async")))]
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
