use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
#[cfg(feature = "_async")]
use std::pin::Pin;
#[cfg(feature = "_async")]
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(feature = "_async")]
use std::task::{Context, Poll};

#[cfg(feature = "_async")]
use super::session::read_chunk_async;
use super::session::{ResumableUploadSession, UploadChunkAction, read_chunk};
use super::*;

#[derive(Debug, Error)]
#[error("{message}")]
struct MockError {
    message: String,
}

impl MockError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[test]
fn uploaded_part_constructor_supports_optional_checksum() {
    let part = UploadedPart::new(7, "etag-7", 4096).with_checksum("checksum-7");

    assert_eq!(part.part_number, 7);
    assert_eq!(part.etag, "etag-7");
    assert_eq!(part.size, 4096);
    assert_eq!(part.checksum.as_deref(), Some("checksum-7"));
}

#[test]
fn backend_error_display_and_debug_omit_source_messages() {
    let secret_url = "https://uploads.example.test/object?token=secret";
    let checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
    let errors = [
        ResumableUploadError::CreateFailed {
            source: MockError::new(format!("create failed at {secret_url}")),
        },
        ResumableUploadError::PartUploadFailed {
            part_number: 1,
            attempts: 2,
            checkpoint: checkpoint.clone(),
            source: MockError::new(format!("part failed at {secret_url}")),
        },
        ResumableUploadError::CompleteFailed {
            checkpoint: checkpoint.clone(),
            source: MockError::new(format!("complete failed at {secret_url}")),
        },
        ResumableUploadError::AbortFailed {
            upload_id: "upload-1".to_owned(),
            original: Box::new(ResumableUploadError::CompleteFailed {
                checkpoint,
                source: MockError::new("complete upload failed"),
            }),
            source: MockError::new(format!("abort failed at {secret_url}")),
        },
    ];

    for error in errors {
        let display = error.to_string();
        let debug = format!("{error:?}");

        assert!(
            !display.contains("token=secret"),
            "display should omit backend source details: {display}"
        );
        assert!(
            !debug.contains("token=secret"),
            "debug should omit backend source details: {debug}"
        );

        let source = std::error::Error::source(&error).expect("source should be retained");
        assert!(
            source.to_string().contains("token=secret"),
            "source chain should preserve backend error details"
        );
    }
}

#[derive(Default)]
struct BlockingMockBackend {
    uploaded_parts: Mutex<BTreeMap<u32, Vec<u8>>>,
    attempts: Mutex<BTreeMap<u32, usize>>,
    fail_once_parts: Mutex<BTreeSet<u32>>,
    etag_overrides: Mutex<BTreeMap<u32, String>>,
    checksum_overrides: Mutex<BTreeMap<u32, Option<String>>>,
    fail_complete: AtomicBool,
    fail_abort: AtomicBool,
    aborts: AtomicUsize,
    create_calls: AtomicUsize,
    completed: AtomicUsize,
    completed_payloads: Mutex<Vec<Vec<UploadedPart>>>,
}

impl BlockingMockBackend {
    fn fail_once_for_part(&self, part_number: u32) {
        let mut fail_once = self.fail_once_parts.lock().expect("lock fail_once_parts");
        fail_once.insert(part_number);
    }

    fn set_etag_for_part(&self, part_number: u32, etag: impl Into<String>) {
        let mut etag_overrides = self.etag_overrides.lock().expect("lock etag_overrides");
        etag_overrides.insert(part_number, etag.into());
    }

    fn set_checksum_for_part(&self, part_number: u32, checksum: Option<String>) {
        let mut checksum_overrides = self
            .checksum_overrides
            .lock()
            .expect("lock checksum_overrides");
        checksum_overrides.insert(part_number, checksum);
    }

    fn fail_complete(&self) {
        self.fail_complete.store(true, Ordering::SeqCst);
    }

    fn fail_abort(&self) {
        self.fail_abort.store(true, Ordering::SeqCst);
    }
}

impl BlockingResumableUploadBackend for BlockingMockBackend {
    type Error = MockError;

    fn create_upload(&self) -> Result<String, Self::Error> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        Ok("upload-1".to_owned())
    }

    fn upload_part(
        &self,
        _upload_id: &str,
        part_number: u32,
        chunk: &[u8],
    ) -> Result<UploadedPart, Self::Error> {
        let mut attempts = self.attempts.lock().expect("lock attempts");
        let attempt = attempts
            .entry(part_number)
            .and_modify(|value| *value = value.saturating_add(1))
            .or_insert(1_usize);
        let mut fail_once = self.fail_once_parts.lock().expect("lock fail_once_parts");
        if fail_once.remove(&part_number) {
            return Err(MockError::new(format!(
                "part {part_number} failed on attempt {attempt}"
            )));
        }

        let mut uploaded = self.uploaded_parts.lock().expect("lock uploaded_parts");
        uploaded.insert(part_number, chunk.to_vec());

        let etag = self
            .etag_overrides
            .lock()
            .expect("lock etag_overrides")
            .get(&part_number)
            .cloned()
            .unwrap_or_else(|| PartChecksumAlgorithm::Md5.compute_hex(chunk));
        let checksum = self
            .checksum_overrides
            .lock()
            .expect("lock checksum_overrides")
            .get(&part_number)
            .cloned()
            .unwrap_or(None);

        Ok(UploadedPart {
            part_number,
            etag,
            size: chunk.len(),
            checksum,
        })
    }

    fn complete_upload(&self, _upload_id: &str, parts: &[UploadedPart]) -> Result<(), Self::Error> {
        if self.fail_complete.load(Ordering::SeqCst) {
            return Err(MockError::new("complete upload failed"));
        }
        self.completed_payloads
            .lock()
            .expect("lock completed_payloads")
            .push(parts.to_vec());
        self.completed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn abort_upload(&self, _upload_id: &str) -> Result<(), Self::Error> {
        self.aborts.fetch_add(1, Ordering::SeqCst);
        if self.fail_abort.load(Ordering::SeqCst) {
            return Err(MockError::new("abort upload failed"));
        }
        Ok(())
    }
}

struct FailingReader {
    chunk: Vec<u8>,
    served_chunk: bool,
}

impl FailingReader {
    fn new(chunk: &[u8]) -> Self {
        Self {
            chunk: chunk.to_vec(),
            served_chunk: false,
        }
    }
}

impl Read for FailingReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if !self.served_chunk {
            self.served_chunk = true;
            let len = self.chunk.len().min(buffer.len());
            buffer[..len].copy_from_slice(&self.chunk[..len]);
            return Ok(len);
        }

        Err(std::io::Error::other("source reader failed"))
    }
}

struct InterruptedOnceReader {
    data: Vec<u8>,
    offset: usize,
    interrupted: bool,
}

impl InterruptedOnceReader {
    fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            offset: 0,
            interrupted: false,
        }
    }
}

impl Read for InterruptedOnceReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        if self.offset >= self.data.len() {
            return Ok(0);
        }

        let read = buffer.len().min(self.data.len() - self.offset);
        buffer[..read].copy_from_slice(&self.data[self.offset..self.offset + read]);
        self.offset += read;
        Ok(read)
    }
}

#[cfg(feature = "_async")]
struct AsyncInterruptedOnceReader {
    data: Vec<u8>,
    offset: usize,
    interrupted: bool,
}

#[cfg(feature = "_async")]
impl AsyncInterruptedOnceReader {
    fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            offset: 0,
            interrupted: false,
        }
    }
}

#[cfg(feature = "_async")]
impl tokio::io::AsyncRead for AsyncInterruptedOnceReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let reader = self.get_mut();
        if !reader.interrupted {
            reader.interrupted = true;
            return Poll::Ready(Err(std::io::ErrorKind::Interrupted.into()));
        }
        if reader.offset >= reader.data.len() {
            return Poll::Ready(Ok(()));
        }

        let read = buffer.remaining().min(reader.data.len() - reader.offset);
        buffer.put_slice(&reader.data[reader.offset..reader.offset + read]);
        reader.offset += read;
        Poll::Ready(Ok(()))
    }
}

#[test]
fn read_chunk_retries_interrupted_reads() {
    let mut reader = InterruptedOnceReader::new(b"abcdef");

    let first = read_chunk(&mut reader, 4).expect("interrupted read should be retried");
    let second = read_chunk(&mut reader, 4).expect("remaining bytes should be readable");

    assert_eq!(first, b"abcd");
    assert_eq!(second, b"ef");
}

#[cfg(feature = "_async")]
#[tokio::test]
async fn read_chunk_async_retries_interrupted_reads() {
    let mut reader = AsyncInterruptedOnceReader::new(b"abcdef");

    let first = read_chunk_async(&mut reader, 4)
        .await
        .expect("interrupted read should be retried");
    let second = read_chunk_async(&mut reader, 4)
        .await
        .expect("remaining bytes should be readable");

    assert_eq!(first, b"abcd");
    assert_eq!(second, b"ef");
}

#[test]
fn checkpoint_deserializes_legacy_payload_without_version() {
    let payload = r#"{
            "upload_id":"upload-legacy",
            "part_size":4,
            "completed_parts":{
                "1":{"part_number":1,"etag":"etag-1","size":4}
            }
        }"#;

    let checkpoint: ResumableUploadCheckpoint =
        serde_json::from_str(payload).expect("legacy checkpoint should deserialize");

    assert_eq!(
        checkpoint.version,
        LEGACY_RESUMABLE_UPLOAD_CHECKPOINT_VERSION
    );
    assert_eq!(checkpoint.checksum_algorithm, None);
    assert_eq!(
        checkpoint
            .completed_parts
            .get(&1)
            .and_then(|item| item.checksum.as_deref()),
        None
    );
}

#[test]
fn upload_session_allows_maximum_part_number_as_final_chunk() {
    let options = ResumableUploadOptions::new()
        .with_part_size(1)
        .with_max_attempts(1)
        .with_jitter_ratio(0.0);
    let checkpoint = ResumableUploadCheckpoint::new("upload-1", 1);
    let mut session = ResumableUploadSession::new::<MockError>(&options, checkpoint, false)
        .expect("session should be built");
    session.part_number = u64::from(MAX_RESUMABLE_UPLOAD_PART_NUMBER);

    let plan = match session
        .next_chunk::<MockError>(b"x".to_vec())
        .expect("max part number should be accepted")
    {
        UploadChunkAction::Upload(plan) => plan,
        _ => panic!("max part number should produce an upload plan"),
    };
    assert_eq!(plan.part_number, MAX_RESUMABLE_UPLOAD_PART_NUMBER);

    session
        .accept_uploaded_part::<MockError>(
            &plan,
            UploadedPart {
                part_number: plan.part_number,
                etag: "etag-max".to_owned(),
                size: 1,
                checksum: None,
            },
        )
        .expect("max part number should be accepted as the final part");

    assert_eq!(session.total_parts(), MAX_RESUMABLE_UPLOAD_PART_NUMBER);
    assert!(matches!(
        session
            .next_chunk::<MockError>(Vec::new())
            .expect("empty chunk after max part should finish"),
        UploadChunkAction::Finish
    ));
}

#[test]
fn upload_session_rejects_part_numbers_past_checkpoint_range() {
    let options = ResumableUploadOptions::new()
        .with_part_size(1)
        .with_max_attempts(1)
        .with_jitter_ratio(0.0);
    let checkpoint = ResumableUploadCheckpoint::new("upload-1", 1);
    let mut session = ResumableUploadSession::new::<MockError>(&options, checkpoint, false)
        .expect("session should be built");
    session.part_number = u64::from(MAX_RESUMABLE_UPLOAD_PART_NUMBER) + 1;

    let error = match session.next_chunk::<MockError>(b"x".to_vec()) {
        Ok(_) => panic!("part number overflow should be rejected"),
        Err(error) => error,
    };

    match error {
        ResumableUploadError::TooManyUploadParts {
            attempted_part_number,
            max_part_number,
            checkpoint,
        } => {
            assert_eq!(
                attempted_part_number,
                u64::from(MAX_RESUMABLE_UPLOAD_PART_NUMBER) + 1
            );
            assert_eq!(max_part_number, MAX_RESUMABLE_UPLOAD_PART_NUMBER);
            assert!(checkpoint.completed_parts.is_empty());
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn upload_session_rejects_backend_part_number_mismatch() {
    let options = ResumableUploadOptions::new()
        .with_part_size(4)
        .with_max_attempts(1)
        .with_jitter_ratio(0.0);
    let checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
    let mut session = ResumableUploadSession::new::<MockError>(&options, checkpoint, false)
        .expect("session should be built");

    let plan = match session
        .next_chunk::<MockError>(b"abcd".to_vec())
        .expect("chunk should produce an upload plan")
    {
        UploadChunkAction::Upload(plan) => plan,
        _ => panic!("chunk should produce an upload plan"),
    };
    let error = session
        .accept_uploaded_part::<MockError>(
            &plan,
            UploadedPart {
                part_number: 99,
                etag: "etag-1".to_owned(),
                size: 4,
                checksum: None,
            },
        )
        .expect_err("backend part number mismatch should be rejected");

    match error {
        ResumableUploadError::PartNumberMismatch {
            expected_part_number,
            actual_part_number,
            checkpoint,
        } => {
            assert_eq!(expected_part_number, 1);
            assert_eq!(actual_part_number, 99);
            assert!(checkpoint.completed_parts.is_empty());
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn upload_session_rejects_backend_part_size_mismatch() {
    let options = ResumableUploadOptions::new()
        .with_part_size(4)
        .with_max_attempts(1)
        .with_jitter_ratio(0.0);
    let checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
    let mut session = ResumableUploadSession::new::<MockError>(&options, checkpoint, false)
        .expect("session should be built");

    let plan = match session
        .next_chunk::<MockError>(b"abcd".to_vec())
        .expect("chunk should produce an upload plan")
    {
        UploadChunkAction::Upload(plan) => plan,
        _ => panic!("chunk should produce an upload plan"),
    };
    let error = session
        .accept_uploaded_part::<MockError>(
            &plan,
            UploadedPart {
                part_number: 1,
                etag: "etag-1".to_owned(),
                size: 3,
                checksum: None,
            },
        )
        .expect_err("backend part size mismatch should be rejected");

    match error {
        ResumableUploadError::PartSizeMismatch {
            part_number,
            expected_size,
            actual_size,
            checkpoint,
        } => {
            assert_eq!(part_number, 1);
            assert_eq!(expected_size, 4);
            assert_eq!(actual_size, 3);
            assert!(checkpoint.completed_parts.is_empty());
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn blocking_resume_skips_already_completed_parts() {
    let backend = BlockingMockBackend::default();
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
    checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
    checkpoint.completed_parts.insert(
        1,
        UploadedPart {
            part_number: 1,
            etag: "etag-1".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
        },
    );

    let mut reader = std::io::Cursor::new(b"abcdefgh".to_vec());
    let result = uploader
        .resume(&backend, &mut reader, checkpoint)
        .expect("resume should succeed");

    assert!(result.resumed);
    assert_eq!(result.total_parts, 2);
    assert_eq!(backend.create_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        backend
            .attempts
            .lock()
            .expect("lock attempts")
            .get(&1)
            .copied(),
        None
    );
    assert_eq!(
        backend
            .attempts
            .lock()
            .expect("lock attempts")
            .get(&2)
            .copied(),
        Some(1)
    );
}

#[test]
fn blocking_resume_reuploads_checkpoint_part_when_verified_etag_mismatches() {
    let backend = BlockingMockBackend::default();
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_verify_remote_etag(true)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
    checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
    checkpoint.completed_parts.insert(
        1,
        UploadedPart {
            part_number: 1,
            etag: "stale-etag".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
        },
    );

    let mut reader = std::io::Cursor::new(b"abcdefgh".to_vec());
    let result = uploader
        .resume(&backend, &mut reader, checkpoint)
        .expect("resume should repair stale checkpoint etag");

    assert!(result.resumed);
    assert_eq!(result.total_parts, 2);
    let attempts = backend.attempts.lock().expect("lock attempts");
    assert_eq!(attempts.get(&1).copied(), Some(1));
    assert_eq!(attempts.get(&2).copied(), Some(1));
}

#[test]
fn blocking_failed_reupload_drops_stale_checkpoint_part() {
    let backend = BlockingMockBackend::default();
    backend.fail_once_for_part(1);
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_verify_remote_etag(true)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
    checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
    checkpoint.completed_parts.insert(
        1,
        UploadedPart {
            part_number: 1,
            etag: "stale-etag".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
        },
    );

    let mut reader = std::io::Cursor::new(b"abcdefgh".to_vec());
    let error = uploader
        .resume(&backend, &mut reader, checkpoint)
        .expect_err("failed reupload should return repairable checkpoint");

    match error {
        ResumableUploadError::PartUploadFailed {
            part_number,
            attempts,
            checkpoint,
            ..
        } => {
            assert_eq!(part_number, 1);
            assert_eq!(attempts, 1);
            assert!(
                !checkpoint.completed_parts.contains_key(&1),
                "stale checkpoint part must not be returned after failed reupload"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn blocking_resume_normalizes_checkpoint_part_numbers_before_completion() {
    let backend = BlockingMockBackend::default();
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
    checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
    checkpoint.completed_parts.insert(
        0,
        UploadedPart {
            part_number: 0,
            etag: "unused".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"zero")),
        },
    );
    checkpoint.completed_parts.insert(
        1,
        UploadedPart {
            part_number: 99,
            etag: "etag-1".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
        },
    );

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let result = uploader
        .resume(&backend, &mut reader, checkpoint)
        .expect("resume should normalize checkpoint part metadata");

    assert_eq!(result.total_parts, 1);
    assert_eq!(result.completed_parts[0].part_number, 1);
    assert_eq!(
        backend
            .attempts
            .lock()
            .expect("lock attempts")
            .get(&1)
            .copied(),
        None
    );

    let completed_payloads = backend
        .completed_payloads
        .lock()
        .expect("lock completed_payloads");
    assert_eq!(completed_payloads.len(), 1);
    assert_eq!(completed_payloads[0].len(), 1);
    assert_eq!(completed_payloads[0][0].part_number, 1);
}

#[test]
fn blocking_resume_rejects_checkpoint_that_is_ahead_of_source() {
    let backend = BlockingMockBackend::default();
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
    checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
    checkpoint.completed_parts.insert(
        1,
        UploadedPart {
            part_number: 1,
            etag: "etag-1".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
        },
    );
    checkpoint.completed_parts.insert(
        2,
        UploadedPart {
            part_number: 2,
            etag: "etag-2".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"efgh")),
        },
    );

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .resume(&backend, &mut reader, checkpoint)
        .expect_err("resume should reject checkpoints that run past the source");

    match error {
        ResumableUploadError::SourceRead { source, checkpoint } => {
            assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
            assert_eq!(checkpoint.completed_parts.len(), 2);
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn blocking_retry_failure_returns_checkpoint_for_resume() {
    let backend = BlockingMockBackend::default();
    backend.fail_once_for_part(2);
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_max_attempts(1)
            .with_base_backoff(Duration::from_millis(1))
            .with_max_backoff(Duration::from_millis(1))
            .with_jitter_ratio(0.0),
    );

    let mut reader = std::io::Cursor::new(b"abcdefgh".to_vec());
    let error = uploader
        .upload(&backend, &mut reader)
        .expect_err("upload should fail when retries exhausted");

    match error {
        ResumableUploadError::PartUploadFailed {
            part_number,
            attempts,
            checkpoint,
            ..
        } => {
            assert_eq!(part_number, 2);
            assert_eq!(attempts, 1);
            let part_1 = checkpoint
                .completed_parts
                .get(&1)
                .expect("part 1 should be in checkpoint");
            assert_eq!(
                part_1.checksum.as_deref(),
                Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd").as_str())
            );
            assert!(!checkpoint.completed_parts.contains_key(&2));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn blocking_upload_rejects_invalid_options_before_create_upload() {
    let backend = BlockingMockBackend::default();
    let uploader = BlockingResumableUploader::new(ResumableUploadOptions::new().with_part_size(0));

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .upload(&backend, &mut reader)
        .expect_err("invalid options should fail before creating an upload");

    match error {
        ResumableUploadError::InvalidOptions {
            part_size, message, ..
        } => {
            assert_eq!(part_size, 0);
            assert_eq!(message, "part_size must be greater than zero");
        }
        other => panic!("unexpected error variant: {other}"),
    }
    assert_eq!(backend.create_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.aborts.load(Ordering::SeqCst), 0);
}

#[test]
fn resumable_upload_options_reject_incoherent_backoff_window() {
    let options = ResumableUploadOptions::new()
        .with_base_backoff(Duration::from_millis(80))
        .with_max_backoff(Duration::from_millis(50));

    let error = options
        .validate::<MockError>()
        .expect_err("max backoff below base backoff should be invalid");

    match error {
        ResumableUploadError::InvalidOptions {
            base_backoff_ms,
            max_backoff_ms,
            message,
            ..
        } => {
            assert_eq!(base_backoff_ms, 80);
            assert_eq!(max_backoff_ms, 50);
            assert_eq!(
                message,
                "max_backoff must be greater than or equal to base_backoff"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn blocking_abort_on_error_aborts_after_source_read_failure() {
    let backend = BlockingMockBackend::default();
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_abort_on_error(true)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut reader = FailingReader::new(b"abcd");
    let error = uploader
        .upload(&backend, &mut reader)
        .expect_err("upload should fail when the source reader errors");

    match error {
        ResumableUploadError::SourceRead { checkpoint, .. } => {
            assert_eq!(checkpoint.completed_parts.len(), 1);
        }
        other => panic!("unexpected error variant: {other}"),
    }

    assert_eq!(backend.aborts.load(Ordering::SeqCst), 1);
}

#[test]
fn blocking_abort_on_error_aborts_after_complete_failure() {
    let backend = BlockingMockBackend::default();
    backend.fail_complete();
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_abort_on_error(true)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .upload(&backend, &mut reader)
        .expect_err("upload should fail when completion fails");

    match error {
        ResumableUploadError::CompleteFailed { checkpoint, .. } => {
            assert_eq!(checkpoint.completed_parts.len(), 1);
        }
        other => panic!("unexpected error variant: {other}"),
    }

    assert_eq!(backend.aborts.load(Ordering::SeqCst), 1);
}

#[test]
fn blocking_abort_failure_preserves_original_error_and_checkpoint() {
    let backend = BlockingMockBackend::default();
    backend.fail_complete();
    backend.fail_abort();
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_abort_on_error(true)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .upload(&backend, &mut reader)
        .expect_err("abort failure should be reported");

    assert_eq!(
        error
            .checkpoint()
            .map(|checkpoint| checkpoint.completed_parts.len()),
        Some(1)
    );
    match error {
        ResumableUploadError::AbortFailed {
            upload_id,
            original,
            source,
        } => {
            assert_eq!(upload_id, "upload-1");
            assert_eq!(source.to_string(), "abort upload failed");
            assert!(matches!(
                *original,
                ResumableUploadError::CompleteFailed { .. }
            ));
        }
        other => panic!("unexpected error variant: {other}"),
    }
    assert_eq!(backend.aborts.load(Ordering::SeqCst), 1);
}

#[test]
fn blocking_abort_on_error_aborts_empty_upload_body() {
    let backend = BlockingMockBackend::default();
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_abort_on_error(true)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut reader = std::io::Cursor::new(Vec::<u8>::new());
    let error = uploader
        .upload(&backend, &mut reader)
        .expect_err("empty uploads should fail");

    match error {
        ResumableUploadError::EmptyUploadBody => {}
        other => panic!("unexpected error variant: {other}"),
    }

    assert_eq!(backend.aborts.load(Ordering::SeqCst), 1);
}

#[test]
fn blocking_etag_mismatch_returns_integrity_error() {
    let backend = BlockingMockBackend::default();
    backend.set_etag_for_part(1, "not-md5");
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_verify_remote_etag(true)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .upload(&backend, &mut reader)
        .expect_err("upload should fail on etag mismatch");

    match error {
        ResumableUploadError::PartEtagMismatch {
            part_number,
            checkpoint,
            ..
        } => {
            assert_eq!(part_number, 1);
            assert!(checkpoint.completed_parts.is_empty());
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn blocking_checkpoint_checksum_algorithm_mismatch_is_rejected() {
    let backend = BlockingMockBackend::default();
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Sha256)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
    checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .resume(&backend, &mut reader, checkpoint)
        .expect_err("resume should reject checksum algorithm mismatch");

    match error {
        ResumableUploadError::CheckpointChecksumAlgorithmMismatch { .. } => {}
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn blocking_checkpoint_checksum_algorithm_downgrade_is_rejected() {
    let backend = BlockingMockBackend::default();
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
    checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .resume(&backend, &mut reader, checkpoint)
        .expect_err("resume should reject checksum algorithm downgrade");

    match error {
        ResumableUploadError::CheckpointChecksumAlgorithmMismatch {
            checkpoint_checksum_algorithm,
            options_checksum_algorithm,
        } => {
            assert_eq!(checkpoint_checksum_algorithm, "md5");
            assert_eq!(options_checksum_algorithm, "none");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn blocking_part_checksum_mismatch_returns_integrity_error() {
    let backend = BlockingMockBackend::default();
    backend.set_checksum_for_part(1, Some("bad-checksum".to_owned()));
    let uploader = BlockingResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .upload(&backend, &mut reader)
        .expect_err("upload should fail on checksum mismatch");

    match error {
        ResumableUploadError::PartChecksumMismatch {
            part_number,
            checkpoint,
            ..
        } => {
            assert_eq!(part_number, 1);
            assert!(checkpoint.completed_parts.is_empty());
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn resumable_upload_jittered_backoff_never_exceeds_max_backoff() {
    let options = ResumableUploadOptions::new()
        .with_base_backoff(Duration::from_millis(50))
        .with_max_backoff(Duration::from_millis(80))
        .with_jitter_ratio(1.0);

    for _ in 0..256 {
        let backoff = options.backoff_for_retry(4);
        assert!(backoff <= Duration::from_millis(80));
    }
}

#[test]
fn resumable_upload_backoff_preserves_sub_millisecond_durations() {
    let options = ResumableUploadOptions::new()
        .with_base_backoff(Duration::from_micros(500))
        .with_max_backoff(Duration::from_micros(900))
        .with_jitter_ratio(0.0);

    assert_eq!(options.backoff_for_retry(1), Duration::from_micros(500));
    assert_eq!(options.backoff_for_retry(2), Duration::from_micros(900));
}

#[test]
fn resumable_upload_options_reject_nan_jitter_ratio() {
    let options = ResumableUploadOptions::new()
        .with_base_backoff(Duration::from_millis(50))
        .with_max_backoff(Duration::from_millis(80))
        .with_jitter_ratio(f64::NAN);

    let error = options
        .validate::<MockError>()
        .expect_err("nan jitter ratio should be invalid");

    match error {
        ResumableUploadError::InvalidOptions {
            jitter_ratio,
            message,
            ..
        } => {
            assert!(jitter_ratio.is_nan());
            assert_eq!(
                message,
                "jitter_ratio must be finite and between 0.0 and 1.0"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn resumable_upload_options_reject_etag_verification_without_checksum() {
    let options = ResumableUploadOptions::new().with_verify_remote_etag(true);

    let error = options
        .validate::<MockError>()
        .expect_err("etag verification without checksums should be invalid");

    match error {
        ResumableUploadError::InvalidOptions { message, .. } => {
            assert_eq!(
                message,
                "verify_remote_etag requires part_checksum_algorithm"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[cfg(feature = "_async")]
#[derive(Default)]
struct AsyncMockBackend {
    uploaded_parts: Arc<Mutex<BTreeMap<u32, Vec<u8>>>>,
    attempts: Arc<Mutex<BTreeMap<u32, usize>>>,
    fail_once_parts: Arc<Mutex<BTreeSet<u32>>>,
    fail_complete: Arc<AtomicBool>,
    fail_abort: Arc<AtomicBool>,
    aborts: Arc<AtomicUsize>,
    create_calls: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
    completed_payloads: Arc<Mutex<Vec<Vec<UploadedPart>>>>,
}

#[cfg(feature = "_async")]
impl AsyncMockBackend {
    fn fail_once_for_part(&self, part_number: u32) {
        let mut fail_once = self.fail_once_parts.lock().expect("lock fail_once_parts");
        fail_once.insert(part_number);
    }

    fn fail_complete(&self) {
        self.fail_complete.store(true, Ordering::SeqCst);
    }

    fn fail_abort(&self) {
        self.fail_abort.store(true, Ordering::SeqCst);
    }
}

#[cfg(feature = "_async")]
impl AsyncResumableUploadBackend for AsyncMockBackend {
    type Error = MockError;

    async fn create_upload(&self) -> Result<String, Self::Error> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        Ok("upload-async-1".to_owned())
    }

    async fn upload_part(
        &self,
        _upload_id: &str,
        part_number: u32,
        chunk: &[u8],
    ) -> Result<UploadedPart, Self::Error> {
        let mut attempts = self.attempts.lock().expect("lock attempts");
        let attempt = attempts
            .entry(part_number)
            .and_modify(|value| *value = value.saturating_add(1))
            .or_insert(1_usize);
        let mut fail_once = self.fail_once_parts.lock().expect("lock fail_once_parts");
        if fail_once.remove(&part_number) {
            return Err(MockError::new(format!(
                "part {part_number} failed on attempt {attempt}"
            )));
        }

        let mut uploaded = self.uploaded_parts.lock().expect("lock uploaded_parts");
        uploaded.insert(part_number, chunk.to_vec());
        Ok(UploadedPart {
            part_number,
            etag: PartChecksumAlgorithm::Md5.compute_hex(chunk),
            size: chunk.len(),
            checksum: None,
        })
    }

    async fn complete_upload(
        &self,
        _upload_id: &str,
        parts: &[UploadedPart],
    ) -> Result<(), Self::Error> {
        if self.fail_complete.load(Ordering::SeqCst) {
            return Err(MockError::new("complete upload failed"));
        }
        self.completed_payloads
            .lock()
            .expect("lock completed_payloads")
            .push(parts.to_vec());
        self.completed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn abort_upload(&self, _upload_id: &str) -> Result<(), Self::Error> {
        self.aborts.fetch_add(1, Ordering::SeqCst);
        if self.fail_abort.load(Ordering::SeqCst) {
            return Err(MockError::new("abort upload failed"));
        }
        Ok(())
    }
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_resume_reuses_checkpoint_and_completes() {
    let backend = AsyncMockBackend::default();
    backend.fail_once_for_part(2);
    let uploader = AsyncResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_max_attempts(1)
            .with_base_backoff(Duration::from_millis(1))
            .with_max_backoff(Duration::from_millis(1))
            .with_jitter_ratio(0.0),
    );

    let mut first_reader = std::io::Cursor::new(b"abcdefgh".to_vec());
    let first_error = uploader
        .upload(&backend, &mut first_reader)
        .await
        .expect_err("first upload should fail");
    let checkpoint = first_error
        .into_checkpoint()
        .expect("checkpoint should be attached");
    let part_1 = checkpoint
        .completed_parts
        .get(&1)
        .expect("part 1 should be uploaded before failure");
    assert!(part_1.checksum.is_some());

    let mut second_reader = std::io::Cursor::new(b"abcdefgh".to_vec());
    let resumed = AsyncResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_max_attempts(2)
            .with_base_backoff(Duration::from_millis(1))
            .with_max_backoff(Duration::from_millis(1))
            .with_jitter_ratio(0.0),
    )
    .resume(&backend, &mut second_reader, checkpoint)
    .await
    .expect("resume should succeed");

    assert!(resumed.resumed);
    assert_eq!(resumed.total_parts, 2);
    assert_eq!(backend.completed.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_upload_rejects_invalid_options_before_create_upload() {
    let backend = AsyncMockBackend::default();
    let uploader = AsyncResumableUploader::new(ResumableUploadOptions::new().with_max_attempts(0));

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .upload(&backend, &mut reader)
        .await
        .expect_err("invalid options should fail before creating an upload");

    match error {
        ResumableUploadError::InvalidOptions {
            max_attempts,
            message,
            ..
        } => {
            assert_eq!(max_attempts, 0);
            assert_eq!(message, "max_attempts must be greater than zero");
        }
        other => panic!("unexpected error variant: {other}"),
    }
    assert_eq!(backend.create_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.aborts.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_resume_reuploads_checkpoint_part_when_verified_etag_mismatches() {
    let backend = AsyncMockBackend::default();
    let uploader = AsyncResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_verify_remote_etag(true)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut checkpoint = ResumableUploadCheckpoint::new("upload-async-1", 4);
    checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
    checkpoint.completed_parts.insert(
        1,
        UploadedPart {
            part_number: 1,
            etag: "stale-etag".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
        },
    );

    let mut reader = std::io::Cursor::new(b"abcdefgh".to_vec());
    let result = uploader
        .resume(&backend, &mut reader, checkpoint)
        .await
        .expect("resume should repair stale checkpoint etag");

    assert!(result.resumed);
    assert_eq!(result.total_parts, 2);
    let attempts = backend.attempts.lock().expect("lock attempts");
    assert_eq!(attempts.get(&1).copied(), Some(1));
    assert_eq!(attempts.get(&2).copied(), Some(1));
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_resume_normalizes_checkpoint_part_numbers_before_completion() {
    let backend = AsyncMockBackend::default();
    let uploader = AsyncResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut checkpoint = ResumableUploadCheckpoint::new("upload-async-1", 4);
    checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
    checkpoint.completed_parts.insert(
        0,
        UploadedPart {
            part_number: 0,
            etag: "unused".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"zero")),
        },
    );
    checkpoint.completed_parts.insert(
        1,
        UploadedPart {
            part_number: 99,
            etag: "etag-1".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
        },
    );

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let result = uploader
        .resume(&backend, &mut reader, checkpoint)
        .await
        .expect("resume should normalize checkpoint part metadata");

    assert_eq!(result.total_parts, 1);
    assert_eq!(result.completed_parts[0].part_number, 1);
    assert_eq!(
        backend
            .attempts
            .lock()
            .expect("lock attempts")
            .get(&1)
            .copied(),
        None
    );

    let completed_payloads = backend
        .completed_payloads
        .lock()
        .expect("lock completed_payloads");
    assert_eq!(completed_payloads.len(), 1);
    assert_eq!(completed_payloads[0].len(), 1);
    assert_eq!(completed_payloads[0][0].part_number, 1);
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_resume_rejects_checkpoint_that_is_ahead_of_source() {
    let backend = AsyncMockBackend::default();
    let uploader = AsyncResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut checkpoint = ResumableUploadCheckpoint::new("upload-async-1", 4);
    checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
    checkpoint.completed_parts.insert(
        1,
        UploadedPart {
            part_number: 1,
            etag: "etag-1".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
        },
    );
    checkpoint.completed_parts.insert(
        2,
        UploadedPart {
            part_number: 2,
            etag: "etag-2".to_owned(),
            size: 4,
            checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"efgh")),
        },
    );

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .resume(&backend, &mut reader, checkpoint)
        .await
        .expect_err("resume should reject checkpoints that run past the source");

    match error {
        ResumableUploadError::SourceRead { source, checkpoint } => {
            assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
            assert_eq!(checkpoint.completed_parts.len(), 2);
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_abort_on_error_aborts_after_complete_failure() {
    let backend = AsyncMockBackend::default();
    backend.fail_complete();
    let uploader = AsyncResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_abort_on_error(true)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .upload(&backend, &mut reader)
        .await
        .expect_err("upload should fail when completion fails");

    match error {
        ResumableUploadError::CompleteFailed { checkpoint, .. } => {
            assert_eq!(checkpoint.completed_parts.len(), 1);
        }
        other => panic!("unexpected error variant: {other}"),
    }

    assert_eq!(backend.aborts.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_abort_failure_preserves_original_error_and_checkpoint() {
    let backend = AsyncMockBackend::default();
    backend.fail_complete();
    backend.fail_abort();
    let uploader = AsyncResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_abort_on_error(true)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );

    let mut reader = std::io::Cursor::new(b"abcd".to_vec());
    let error = uploader
        .upload(&backend, &mut reader)
        .await
        .expect_err("abort failure should be reported");

    assert_eq!(
        error
            .checkpoint()
            .map(|checkpoint| checkpoint.completed_parts.len()),
        Some(1)
    );
    match error {
        ResumableUploadError::AbortFailed {
            upload_id,
            original,
            source,
        } => {
            assert_eq!(upload_id, "upload-async-1");
            assert_eq!(source.to_string(), "abort upload failed");
            assert!(matches!(
                *original,
                ResumableUploadError::CompleteFailed { .. }
            ));
        }
        other => panic!("unexpected error variant: {other}"),
    }
    assert_eq!(backend.aborts.load(Ordering::SeqCst), 1);
}
