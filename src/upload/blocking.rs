use std::io::Read;
use std::thread::sleep;

use super::session::{
    ResumableUploadSession, UploadChunkAction, UploadPartPlan, UploadPartRetry, read_chunk,
};
use super::{
    BlockingResumableUploadBackend, ResumableUploadCheckpoint, ResumableUploadError,
    ResumableUploadOptions, ResumableUploadResult, UploadedPart,
};

/// Blocking helper that drives a multipart upload with checkpoints and retries.
pub struct BlockingResumableUploader {
    options: ResumableUploadOptions,
}

impl BlockingResumableUploader {
    /// Creates a new uploader with the provided options.
    pub fn new(options: ResumableUploadOptions) -> Self {
        Self { options }
    }

    /// Returns the options used by this uploader.
    pub fn options(&self) -> &ResumableUploadOptions {
        &self.options
    }

    /// Starts a new resumable upload.
    pub fn upload<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: BlockingResumableUploadBackend,
        R: Read,
    {
        self.options.validate::<B::Error>()?;
        let upload_id = backend
            .create_upload()
            .map_err(|source| ResumableUploadError::CreateFailed { source })?;
        let mut checkpoint = ResumableUploadCheckpoint::new(upload_id, self.options.part_size);
        checkpoint.checksum_algorithm = self.options.part_checksum_algorithm();
        self.upload_with_checkpoint(backend, reader, checkpoint, false)
    }

    /// Resumes an upload from an existing checkpoint.
    pub fn resume<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        checkpoint: ResumableUploadCheckpoint,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: BlockingResumableUploadBackend,
        R: Read,
    {
        self.upload_with_checkpoint(backend, reader, checkpoint, true)
    }

    fn abort_error_if_configured<B>(
        &self,
        backend: &B,
        upload_id: &str,
        error: ResumableUploadError<B::Error>,
    ) -> ResumableUploadError<B::Error>
    where
        B: BlockingResumableUploadBackend,
    {
        if self.options.abort_on_error
            && let Err(source) = backend.abort_upload(upload_id)
        {
            return ResumableUploadError::AbortFailed {
                upload_id: upload_id.to_owned(),
                original: Box::new(error),
                source,
            };
        }
        error
    }

    fn upload_with_checkpoint<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        checkpoint: ResumableUploadCheckpoint,
        resumed: bool,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: BlockingResumableUploadBackend,
        R: Read,
    {
        let mut session =
            ResumableUploadSession::new::<B::Error>(&self.options, checkpoint, resumed)?;

        loop {
            let chunk = match read_chunk(reader, self.options.part_size) {
                Ok(chunk) => chunk,
                Err(source) => {
                    let error = session.source_read_error(source);
                    return Err(self.abort_error_if_configured(
                        backend,
                        session.upload_id(),
                        error,
                    ));
                }
            };

            let action = match session.next_chunk::<B::Error>(chunk) {
                Ok(action) => action,
                Err(error) => {
                    return Err(self.abort_error_if_configured(
                        backend,
                        session.upload_id(),
                        error,
                    ));
                }
            };

            match action {
                UploadChunkAction::Finish => break,
                UploadChunkAction::Skip => continue,
                UploadChunkAction::Upload(plan) => {
                    let uploaded = self.upload_part_with_retries(backend, &session, &plan)?;
                    if let Err(error) = session.accept_uploaded_part::<B::Error>(&plan, uploaded) {
                        return Err(self.abort_error_if_configured(
                            backend,
                            session.upload_id(),
                            error,
                        ));
                    }
                }
            }
        }

        let ordered_parts = match session.ordered_completed_parts::<B::Error>() {
            Ok(parts) => parts,
            Err(error) => {
                return Err(self.abort_error_if_configured(backend, session.upload_id(), error));
            }
        };

        if let Err(source) = backend.complete_upload(session.upload_id(), &ordered_parts) {
            let error = session.complete_upload_failed(source);
            return Err(self.abort_error_if_configured(backend, session.upload_id(), error));
        }

        Ok(session.finish(ordered_parts))
    }

    fn upload_part_with_retries<B>(
        &self,
        backend: &B,
        session: &ResumableUploadSession<'_>,
        plan: &UploadPartPlan,
    ) -> Result<UploadedPart, ResumableUploadError<B::Error>>
    where
        B: BlockingResumableUploadBackend,
    {
        let mut retry = UploadPartRetry::new(&self.options);
        loop {
            match backend.upload_part(session.upload_id(), plan.part_number, &plan.chunk) {
                Ok(part) => return Ok(part),
                Err(source) => match retry.record_failure(session, plan, source) {
                    Ok(delay) => {
                        if !delay.is_zero() {
                            sleep(delay);
                        }
                    }
                    Err(error) => {
                        return Err(self.abort_error_if_configured(
                            backend,
                            session.upload_id(),
                            error,
                        ));
                    }
                },
            }
        }
    }
}

impl Default for BlockingResumableUploader {
    fn default() -> Self {
        Self::new(ResumableUploadOptions::default())
    }
}
