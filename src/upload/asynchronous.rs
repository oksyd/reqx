use super::session::{
    ResumableUploadSession, UploadChunkAction, UploadPartPlan, UploadPartRetry, read_chunk_async,
};
use super::{
    AsyncResumableUploadBackend, ResumableUploadCheckpoint, ResumableUploadError,
    ResumableUploadOptions, ResumableUploadResult, UploadedPart,
};

#[cfg(feature = "_async")]
/// Async helper that drives a multipart upload with checkpoints and retries.
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-native"
    )))
)]
pub struct AsyncResumableUploader {
    options: ResumableUploadOptions,
}

#[cfg(feature = "_async")]
impl AsyncResumableUploader {
    /// Creates a new uploader with the provided options.
    pub fn new(options: ResumableUploadOptions) -> Self {
        Self { options }
    }

    /// Returns the options used by this uploader.
    pub fn options(&self) -> &ResumableUploadOptions {
        &self.options
    }

    /// Starts a new resumable upload.
    pub async fn upload<B, R>(
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
        self.upload_with_checkpoint(backend, reader, checkpoint, false)
            .await
    }

    /// Resumes an upload from an existing checkpoint.
    ///
    /// `reader` must provide the entire source from the beginning; reopen or
    /// rewind a reader consumed by a previous attempt. Completed parts are read
    /// again and skipped only when their size and configured checksums match.
    /// Without checksums, the caller must ensure the source contents are unchanged.
    pub async fn resume<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        checkpoint: ResumableUploadCheckpoint,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: AsyncResumableUploadBackend,
        R: tokio::io::AsyncRead + Unpin,
    {
        self.upload_with_checkpoint(backend, reader, checkpoint, true)
            .await
    }

    async fn abort_error_if_configured<B>(
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

    async fn upload_with_checkpoint<B, R>(
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

        loop {
            let chunk = match read_chunk_async(reader, self.options.part_size).await {
                Ok(chunk) => chunk,
                Err(source) => {
                    let error = session.source_read_error(source);
                    return Err(self
                        .abort_error_if_configured(backend, session.upload_id(), error)
                        .await);
                }
            };

            let action = match session.next_chunk::<B::Error>(chunk) {
                Ok(action) => action,
                Err(error) => {
                    return Err(self
                        .abort_error_if_configured(backend, session.upload_id(), error)
                        .await);
                }
            };

            match action {
                UploadChunkAction::Finish => break,
                UploadChunkAction::Skip => continue,
                UploadChunkAction::Upload(plan) => {
                    let uploaded = self
                        .upload_part_with_retries(backend, &session, &plan)
                        .await?;
                    if let Err(error) = session.accept_uploaded_part::<B::Error>(&plan, uploaded) {
                        return Err(self
                            .abort_error_if_configured(backend, session.upload_id(), error)
                            .await);
                    }
                }
            }
        }

        let ordered_parts = match session.ordered_completed_parts::<B::Error>() {
            Ok(parts) => parts,
            Err(error) => {
                return Err(self
                    .abort_error_if_configured(backend, session.upload_id(), error)
                    .await);
            }
        };

        if let Err(source) = backend
            .complete_upload(session.upload_id(), &ordered_parts)
            .await
        {
            let error = session.complete_upload_failed(source);
            return Err(self
                .abort_error_if_configured(backend, session.upload_id(), error)
                .await);
        }

        Ok(session.finish(ordered_parts))
    }

    async fn upload_part_with_retries<B>(
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
                Err(source) => match retry.record_failure(session, plan, source) {
                    Ok(delay) => {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                    }
                    Err(error) => {
                        return Err(self
                            .abort_error_if_configured(backend, session.upload_id(), error)
                            .await);
                    }
                },
            }
        }
    }
}

#[cfg(feature = "_async")]
impl Default for AsyncResumableUploader {
    fn default() -> Self {
        Self::new(ResumableUploadOptions::default())
    }
}
