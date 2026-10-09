use std::convert::Infallible;
use std::error::Error as StdError;

use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};

type BoxBodyError = Box<dyn StdError + Send + Sync>;
pub(crate) type ReqBody = UnsyncBoxBody<Bytes, BoxBodyError>;

pub(crate) type RequestBody = crate::core::request_body::RequestBody<ReqBody>;

fn map_infallible_to_box_error(never: Infallible) -> BoxBodyError {
    match never {}
}

pub(crate) fn buffered_req_body(body: Bytes) -> ReqBody {
    Full::new(body)
        .map_err(map_infallible_to_box_error)
        .boxed_unsync()
}

pub(crate) fn stream_req_body<S, E>(stream: S) -> ReqBody
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: StdError + Send + Sync + 'static,
{
    BodyExt::boxed_unsync(StreamBody::new(stream.map(|item| {
        item.map(Frame::data)
            .map_err(|error| Box::new(error) as BoxBodyError)
    })))
}

pub(crate) enum ReadBodyError {
    Read(hyper::Error),
    TooLarge { actual_bytes: usize },
}

pub(crate) async fn read_all_body_limited(
    mut body: Incoming,
    max_bytes: usize,
) -> Result<Bytes, ReadBodyError> {
    let mut collected = Vec::new();
    let mut total_len = 0_usize;

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(ReadBodyError::Read)?;
        if let Some(data) = frame.data_ref() {
            total_len = total_len.saturating_add(data.len());
            if total_len > max_bytes {
                return Err(ReadBodyError::TooLarge {
                    actual_bytes: total_len,
                });
            }
            collected.extend_from_slice(data);
        }
    }

    Ok(Bytes::from(collected))
}
