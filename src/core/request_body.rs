use bytes::Bytes;

pub(crate) enum RequestBody<Stream> {
    Buffered(Bytes),
    Streaming(Stream),
}

impl<Stream> Default for RequestBody<Stream> {
    fn default() -> Self {
        Self::Buffered(Bytes::new())
    }
}

impl<Stream> RequestBody<Stream> {
    pub(crate) fn is_replayable(&self) -> bool {
        matches!(self, Self::Buffered(_))
    }

    pub(crate) fn known_length(&self) -> Option<usize> {
        match self {
            Self::Buffered(body) => Some(body.len()),
            Self::Streaming(_) => None,
        }
    }

    // Buffered bytes can be shared between attempts. A stream is moved once;
    // execution state prevents replay until a redirect explicitly drops it.
    pub(crate) fn take_for_attempt(&mut self) -> Self {
        match self {
            Self::Buffered(body) => Self::Buffered(body.clone()),
            Self::Streaming(_) => std::mem::take(self),
        }
    }
}
