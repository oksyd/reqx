use std::io::Read;
use std::thread::sleep;

use super::session::{
    ResumableUploadSession, UploadChunkAction, UploadPartPlan, UploadPartRetry, read_chunk,
};
use super::{
    BlockingResumableUploadBackend, ResumableUploadCheckpoint, ResumableUploadError,
    ResumableUploadResult, ResumableUploader, UploadedPart,
};

impl ResumableUploader {
    /// Starts a new resumable upload using a synchronous backend.
    pub fn upload_blocking<B, R>(
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
        self.upload_with_checkpoint_blocking(backend, reader, checkpoint, false)
    }

    /// Resumes an upload using a synchronous backend.
    ///
    /// The checkpoint must use the current schema version and match the configured
    /// part size and checksum algorithm. Invalid part numbers are rejected.
    ///
    /// `reader` must provide the entire source from the beginning; reopen or
    /// rewind a reader consumed by a previous attempt. Completed parts are read
    /// again and skipped only when their size and configured checksums match.
    /// Without checksums, the caller must ensure the source contents are unchanged.
    pub fn resume_blocking<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        checkpoint: ResumableUploadCheckpoint,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: BlockingResumableUploadBackend,
        R: Read,
    {
        self.options.validate::<B::Error>()?;
        self.upload_with_checkpoint_blocking(backend, reader, checkpoint, true)
    }

    fn abort_error_if_configured_blocking<B>(
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

    fn upload_with_checkpoint_blocking<B, R>(
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

        let result = (|| {
            loop {
                let chunk = read_chunk(reader, self.options.part_size)
                    .map_err(|source| session.source_read_error(source))?;

                match session.next_chunk::<B::Error>(chunk)? {
                    UploadChunkAction::Finish => break,
                    UploadChunkAction::Skip => continue,
                    UploadChunkAction::Upload(plan) => {
                        let uploaded =
                            self.upload_part_with_retries_blocking(backend, &session, &plan)?;
                        session.accept_uploaded_part::<B::Error>(&plan, uploaded)?;
                    }
                }
            }

            let ordered_parts = session.ordered_completed_parts::<B::Error>()?;
            backend
                .complete_upload(session.upload_id(), &ordered_parts)
                .map_err(|source| session.complete_upload_failed(source))?;
            Ok(ordered_parts)
        })();

        let ordered_parts = match result {
            Ok(parts) => parts,
            Err(error) => {
                return Err(self.abort_error_if_configured_blocking(
                    backend,
                    session.upload_id(),
                    error,
                ));
            }
        };

        Ok(session.finish(ordered_parts))
    }

    fn upload_part_with_retries_blocking<B>(
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
                Err(source) => {
                    let delay = retry.record_failure(session, plan, source)?;
                    if !delay.is_zero() {
                        sleep(delay);
                    }
                }
            }
        }
    }
}
