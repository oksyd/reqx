use crate::async_client::Client;

#[test]
fn body_stream_accepts_send_non_sync_stream() {
    use std::cell::Cell;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures_core::Stream;

    struct NonSyncByteStream {
        emitted: Cell<bool>,
    }

    impl Stream for NonSyncByteStream {
        type Item = Result<bytes::Bytes, std::io::Error>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            if this.emitted.replace(true) {
                Poll::Ready(None)
            } else {
                Poll::Ready(Some(Ok(bytes::Bytes::from_static(b"x"))))
            }
        }
    }

    let client = Client::builder("https://api.example.com")
        .build()
        .expect("client should build");
    let _request = client.post("/v1/upload").body_stream(NonSyncByteStream {
        emitted: Cell::new(false),
    });
}
