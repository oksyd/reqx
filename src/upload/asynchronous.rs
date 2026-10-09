use super::session::{
    ResumableUploadSession, UploadChunkAction, UploadPartPlan, UploadPartRetry, read_chunk_async,
};
use super::{
    AsyncResumableUploadBackend, ResumableUploadCheckpoint, ResumableUploadError,
    ResumableUploadResult, ResumableUploader, UploadedPart,
};

impl ResumableUploader {
    /// Starts a new resumable upload using an asynchronous backend.
    ///
    /// Validates options, creates one remote session, uploads chunks sequentially,
    /// and completes with ordered parts. Only part uploads are retried; the reader
    /// is consumed from its current position. Empty input is an error. See
    /// [`AsyncResumableUploadBackend`] and [`ResumableUploader`] for persistence and cleanup.
    #[cfg_attr(docsrs, doc(cfg(feature = "resumable-upload-async")))]
    pub async fn upload_async<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: AsyncResumableUploadBackend,
        R: tokio::io::AsyncRead + Unpin,
    {
        self.options.validate::<B::Error>()?;
        let upload_id = backend
            .create_upload()
            .await
            .map_err(|source| ResumableUploadError::CreateFailed { source })?;
        let mut checkpoint = ResumableUploadCheckpoint::new(upload_id, self.options.part_size);
        checkpoint.checksum_algorithm = self.options.part_checksum_algorithm();
        self.upload_with_checkpoint_async(backend, reader, checkpoint, false)
            .await
    }

    /// Resumes an upload using an asynchronous backend.
    ///
    /// The checkpoint must use the current schema version and match the configured
    /// part size and checksum algorithm. Invalid part numbers are rejected.
    ///
    /// `reader` must provide the entire source from the beginning; reopen or
    /// rewind a reader consumed by a previous attempt. Completed parts are read
    /// again and skipped only when their size and configured checksums match.
    /// Without checksums, the caller must ensure the source contents are unchanged.
    /// Options/checkpoints are validated before source or backend I/O. Remote
    /// session existence and durable checkpoint persistence belong to the caller;
    /// the uploader does not list remote parts. See [`ResumableUploader`].
    #[cfg_attr(docsrs, doc(cfg(feature = "resumable-upload-async")))]
    pub async fn resume_async<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        checkpoint: ResumableUploadCheckpoint,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: AsyncResumableUploadBackend,
        R: tokio::io::AsyncRead + Unpin,
    {
        self.options.validate::<B::Error>()?;
        self.upload_with_checkpoint_async(backend, reader, checkpoint, true)
            .await
    }

    async fn abort_error_if_configured_async<B>(
        &self,
        backend: &B,
        upload_id: &str,
        error: ResumableUploadError<B::Error>,
    ) -> ResumableUploadError<B::Error>
    where
        B: AsyncResumableUploadBackend,
    {
        if self.options.abort_on_error
            && let Err(source) = backend.abort_upload(upload_id).await
        {
            return ResumableUploadError::AbortFailed {
                upload_id: upload_id.to_owned(),
                original: Box::new(error),
                source,
            };
        }
        error
    }

    async fn upload_with_checkpoint_async<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        checkpoint: ResumableUploadCheckpoint,
        resumed: bool,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: AsyncResumableUploadBackend,
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut session =
            ResumableUploadSession::new::<B::Error>(&self.options, checkpoint, resumed)?;

        let result = async {
            loop {
                let chunk = read_chunk_async(reader, self.options.part_size)
                    .await
                    .map_err(|source| session.source_read_error(source))?;

                match session.next_chunk::<B::Error>(chunk)? {
                    UploadChunkAction::Finish => break,
                    UploadChunkAction::Skip => continue,
                    UploadChunkAction::Upload(plan) => {
                        let uploaded = self
                            .upload_part_with_retries_async(backend, &session, &plan)
                            .await?;
                        session.accept_uploaded_part::<B::Error>(&plan, uploaded)?;
                    }
                }
            }

            let ordered_parts = session.ordered_completed_parts::<B::Error>()?;
            backend
                .complete_upload(session.upload_id(), &ordered_parts)
                .await
                .map_err(|source| session.complete_upload_failed(source))?;
            Ok(ordered_parts)
        }
        .await;

        let ordered_parts = match result {
            Ok(parts) => parts,
            Err(error) => {
                return Err(self
                    .abort_error_if_configured_async(backend, session.upload_id(), error)
                    .await);
            }
        };

        Ok(session.finish(ordered_parts))
    }

    async fn upload_part_with_retries_async<B>(
        &self,
        backend: &B,
        session: &ResumableUploadSession<'_>,
        plan: &UploadPartPlan,
    ) -> Result<UploadedPart, ResumableUploadError<B::Error>>
    where
        B: AsyncResumableUploadBackend,
    {
        let mut retry = UploadPartRetry::new(&self.options);
        loop {
            match backend
                .upload_part(session.upload_id(), plan.part_number, &plan.chunk)
                .await
            {
                Ok(part) => return Ok(part),
                Err(source) => {
                    let delay = retry.record_failure(session, plan, source)?;
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    }
}
