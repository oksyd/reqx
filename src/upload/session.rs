use std::io::{self, Read};
use std::time::Duration;

#[cfg(feature = "_async")]
use crate::util::read_async_retry_interrupted;
use crate::util::read_retry_interrupted;

use super::{
    LEGACY_RESUMABLE_UPLOAD_CHECKPOINT_VERSION, MAX_RESUMABLE_UPLOAD_PART_NUMBER,
    RESUMABLE_UPLOAD_CHECKPOINT_VERSION, ResumableUploadCheckpoint, ResumableUploadError,
    ResumableUploadOptions, ResumableUploadResult, UploadedPart, normalize_token,
};

fn checkpoint_supports_version(version: u32) -> bool {
    (LEGACY_RESUMABLE_UPLOAD_CHECKPOINT_VERSION..=RESUMABLE_UPLOAD_CHECKPOINT_VERSION)
        .contains(&version)
}

fn validate_and_upgrade_checkpoint<E>(
    options: &ResumableUploadOptions,
    checkpoint: &mut ResumableUploadCheckpoint,
) -> Result<(), ResumableUploadError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    if !checkpoint_supports_version(checkpoint.version) {
        return Err(ResumableUploadError::UnsupportedCheckpointVersion {
            checkpoint_version: checkpoint.version,
            max_supported_version: RESUMABLE_UPLOAD_CHECKPOINT_VERSION,
        });
    }

    if checkpoint.part_size != options.part_size {
        return Err(ResumableUploadError::CheckpointPartSizeMismatch {
            checkpoint_part_size: checkpoint.part_size,
            options_part_size: options.part_size,
        });
    }

    if checkpoint.upload_id.trim().is_empty() {
        return Err(ResumableUploadError::EmptyUploadId);
    }

    match (
        checkpoint.checksum_algorithm,
        options.part_checksum_algorithm(),
    ) {
        (Some(checkpoint_algorithm), Some(options_algorithm))
            if checkpoint_algorithm != options_algorithm =>
        {
            return Err(ResumableUploadError::CheckpointChecksumAlgorithmMismatch {
                checkpoint_checksum_algorithm: checkpoint_algorithm.as_str(),
                options_checksum_algorithm: options_algorithm.as_str(),
            });
        }
        (Some(checkpoint_algorithm), None) => {
            return Err(ResumableUploadError::CheckpointChecksumAlgorithmMismatch {
                checkpoint_checksum_algorithm: checkpoint_algorithm.as_str(),
                options_checksum_algorithm: "none",
            });
        }
        (None, Some(options_algorithm)) => {
            checkpoint.checksum_algorithm = Some(options_algorithm);
        }
        _ => {}
    }

    if checkpoint.version < RESUMABLE_UPLOAD_CHECKPOINT_VERSION {
        checkpoint.version = RESUMABLE_UPLOAD_CHECKPOINT_VERSION;
    }

    normalize_checkpoint_part_numbers(checkpoint);

    Ok(())
}

fn normalize_checkpoint_part_numbers(checkpoint: &mut ResumableUploadCheckpoint) {
    checkpoint.completed_parts.retain(|part_number, part| {
        if *part_number == 0 {
            return false;
        }
        part.part_number = *part_number;
        true
    });
}

fn checkpoint_part_matches(
    existing: &UploadedPart,
    expected_size: usize,
    expected_checksum: Option<&str>,
    verify_remote_etag: bool,
) -> bool {
    if existing.size != expected_size {
        return false;
    }

    let Some(expected_checksum) = expected_checksum else {
        return true;
    };

    let Some(existing_checksum) = existing.checksum.as_deref() else {
        return false;
    };

    let normalized_expected = normalize_token(expected_checksum);
    if normalize_token(existing_checksum) != normalized_expected {
        return false;
    }

    !verify_remote_etag || normalize_token(&existing.etag) == normalized_expected
}

fn checkpoint_has_remaining_parts(
    checkpoint: &ResumableUploadCheckpoint,
    next_part_number: u64,
) -> Option<u32> {
    let next_part_number = u32::try_from(next_part_number).ok()?;
    checkpoint
        .completed_parts
        .range(next_part_number..)
        .next()
        .map(|(&part_number, _)| part_number)
}

pub(super) fn read_chunk<R>(reader: &mut R, part_size: usize) -> io::Result<Vec<u8>>
where
    R: Read,
{
    let mut buffer = vec![0_u8; part_size];
    let mut read_len = 0_usize;

    while read_len < part_size {
        let read = read_retry_interrupted(reader, &mut buffer[read_len..])?;
        if read == 0 {
            break;
        }
        read_len = read_len.saturating_add(read);
    }

    buffer.truncate(read_len);
    Ok(buffer)
}

#[cfg(feature = "_async")]
pub(super) async fn read_chunk_async<R>(reader: &mut R, part_size: usize) -> io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; part_size];
    let mut read_len = 0_usize;

    while read_len < part_size {
        let read = read_async_retry_interrupted(reader, &mut buffer[read_len..]).await?;
        if read == 0 {
            break;
        }
        read_len = read_len.saturating_add(read);
    }

    buffer.truncate(read_len);
    Ok(buffer)
}

pub(super) struct UploadPartPlan {
    pub(super) part_number: u32,
    pub(super) chunk: Vec<u8>,
    expected_checksum: Option<String>,
}

pub(super) enum UploadChunkAction {
    Finish,
    Skip,
    Upload(UploadPartPlan),
}

pub(super) struct UploadPartRetry<'a> {
    options: &'a ResumableUploadOptions,
    attempt: usize,
}

impl<'a> UploadPartRetry<'a> {
    pub(super) const fn new(options: &'a ResumableUploadOptions) -> Self {
        Self {
            options,
            attempt: 1,
        }
    }

    pub(super) fn record_failure<E>(
        &mut self,
        session: &ResumableUploadSession<'_>,
        plan: &UploadPartPlan,
        source: E,
    ) -> Result<Duration, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        if self.attempt >= self.options.max_attempts {
            return Err(session.part_upload_failed(plan, self.attempt, source));
        }

        let delay = self.options.backoff_for_retry(self.attempt);
        self.attempt += 1;
        Ok(delay)
    }
}

pub(super) struct ResumableUploadSession<'a> {
    options: &'a ResumableUploadOptions,
    checkpoint: ResumableUploadCheckpoint,
    resumed: bool,
    total_bytes: u64,
    pub(super) part_number: u64,
}

impl<'a> ResumableUploadSession<'a> {
    pub(super) fn new<E>(
        options: &'a ResumableUploadOptions,
        mut checkpoint: ResumableUploadCheckpoint,
        resumed: bool,
    ) -> Result<Self, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        options.validate::<E>()?;
        validate_and_upgrade_checkpoint::<E>(options, &mut checkpoint)?;
        Ok(Self {
            options,
            checkpoint,
            resumed,
            total_bytes: 0,
            part_number: 1,
        })
    }

    pub(super) fn upload_id(&self) -> &str {
        &self.checkpoint.upload_id
    }

    pub(super) fn next_chunk<E>(
        &mut self,
        chunk: Vec<u8>,
    ) -> Result<UploadChunkAction, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        if chunk.is_empty() {
            if let Some(expected_part_number) =
                checkpoint_has_remaining_parts(&self.checkpoint, self.part_number)
            {
                return Err(ResumableUploadError::SourceRead {
                    source: io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("source ended before checkpointed part {expected_part_number}"),
                    ),
                    checkpoint: self.checkpoint.clone(),
                });
            }
            return Ok(UploadChunkAction::Finish);
        }

        let part_number = self.current_part_number::<E>()?;
        self.total_bytes = self.total_bytes.saturating_add(chunk.len() as u64);
        let expected_checksum = self.options.expected_checksum(&chunk);
        if let Some(existing) = self.checkpoint.completed_parts.get(&part_number) {
            if checkpoint_part_matches(
                existing,
                chunk.len(),
                expected_checksum.as_deref(),
                self.options.verify_remote_etag(),
            ) {
                self.advance_part_number();
                return Ok(UploadChunkAction::Skip);
            }
            self.checkpoint.completed_parts.remove(&part_number);
        }

        Ok(UploadChunkAction::Upload(UploadPartPlan {
            part_number,
            chunk,
            expected_checksum,
        }))
    }

    pub(super) fn accept_uploaded_part<E>(
        &mut self,
        plan: &UploadPartPlan,
        uploaded: UploadedPart,
    ) -> Result<(), ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        if uploaded.part_number != plan.part_number {
            return Err(ResumableUploadError::PartNumberMismatch {
                expected_part_number: plan.part_number,
                actual_part_number: uploaded.part_number,
                checkpoint: self.checkpoint.clone(),
            });
        }
        if uploaded.size != plan.chunk.len() {
            return Err(ResumableUploadError::PartSizeMismatch {
                part_number: plan.part_number,
                expected_size: plan.chunk.len(),
                actual_size: uploaded.size,
                checkpoint: self.checkpoint.clone(),
            });
        }

        let mut uploaded = uploaded;
        self.options.validate_uploaded_part::<E>(
            &self.checkpoint,
            plan.part_number,
            &uploaded,
            plan.expected_checksum.as_deref(),
        )?;
        if uploaded.checksum.is_none() {
            uploaded.checksum = plan.expected_checksum.clone();
        }
        self.checkpoint
            .completed_parts
            .insert(plan.part_number, uploaded);
        self.advance_part_number();
        Ok(())
    }

    pub(super) fn source_read_error<E>(&self, source: io::Error) -> ResumableUploadError<E>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ResumableUploadError::SourceRead {
            source,
            checkpoint: self.checkpoint.clone(),
        }
    }

    fn part_upload_failed<E>(
        &self,
        plan: &UploadPartPlan,
        attempts: usize,
        source: E,
    ) -> ResumableUploadError<E>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ResumableUploadError::PartUploadFailed {
            part_number: plan.part_number,
            attempts,
            checkpoint: self.checkpoint.clone(),
            source,
        }
    }

    pub(super) fn complete_upload_failed<E>(&self, source: E) -> ResumableUploadError<E>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ResumableUploadError::CompleteFailed {
            checkpoint: self.checkpoint.clone(),
            source,
        }
    }

    fn ordered_parts<E>(&self) -> Result<Vec<UploadedPart>, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        let total_parts = self.total_parts();
        let mut ordered_parts = Vec::with_capacity(total_parts as usize);
        for current in 1..=total_parts {
            let Some(part) = self.checkpoint.completed_parts.get(&current) else {
                return Err(ResumableUploadError::MissingCompletedPart {
                    part_number: current,
                    checkpoint: self.checkpoint.clone(),
                });
            };
            ordered_parts.push(part.clone());
        }
        Ok(ordered_parts)
    }

    pub(super) fn ordered_completed_parts<E>(
        &self,
    ) -> Result<Vec<UploadedPart>, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        if self.total_parts() == 0 {
            return Err(ResumableUploadError::EmptyUploadBody);
        }
        self.ordered_parts()
    }

    pub(super) fn total_parts(&self) -> u32 {
        self.part_number
            .saturating_sub(1)
            .min(u64::from(MAX_RESUMABLE_UPLOAD_PART_NUMBER)) as u32
    }

    pub(super) fn finish(self, completed_parts: Vec<UploadedPart>) -> ResumableUploadResult {
        let total_parts = self.total_parts();
        ResumableUploadResult {
            upload_id: self.checkpoint.upload_id,
            total_bytes: self.total_bytes,
            total_parts,
            resumed: self.resumed,
            completed_parts,
        }
    }

    fn current_part_number<E>(&self) -> Result<u32, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        u32::try_from(self.part_number).map_err(|_| ResumableUploadError::TooManyUploadParts {
            attempted_part_number: self.part_number,
            max_part_number: MAX_RESUMABLE_UPLOAD_PART_NUMBER,
            checkpoint: self.checkpoint.clone(),
        })
    }

    fn advance_part_number(&mut self) {
        self.part_number += 1;
    }
}
