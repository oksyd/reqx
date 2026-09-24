#![cfg(any(feature = "_async", feature = "_blocking"))]

mod support;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use reqx::prelude::RetryPolicy;

struct Server {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Server {
    fn new(truncated_first: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut served = 0;
            while served < 2 && !worker_stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .expect("read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .expect("write timeout");
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if stream.read(&mut byte).expect("request header") == 0 {
                        break;
                    }
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                let length = if served == 0 && truncated_first {
                    20
                } else {
                    2
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\nok"
                );
                stream.write_all(response.as_bytes()).expect("response");
                served += 1;
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("server worker");
        }
    }
}

#[cfg(feature = "_async")]
#[tokio::test]
async fn async_stream_terminal_reads_release_global_and_host_capacity() {
    support::install_crypto_provider();
    use tokio::io::AsyncReadExt;
    for per_host in [false, true] {
        for truncated in [false, true] {
            let server = Server::new(truncated);
            let builder = reqx::Client::builder(&server.url)
                .metrics_enabled(true)
                .retry_policy(RetryPolicy::disabled());
            let client = if per_host {
                builder.max_in_flight_per_host(1)
            } else {
                builder.max_in_flight(1)
            }
            .build()
            .expect("client");
            let mut stream = client
                .get("/")
                .send_stream()
                .await
                .expect("response headers");
            let mut bytes = Vec::new();
            let result = stream.read_to_end(&mut bytes).await;
            assert_eq!(result.is_err(), truncated);
            let next = client
                .get("/")
                .total_timeout(Duration::from_millis(200))
                .send()
                .await;
            assert!(next.is_ok(), "completed stream retained capacity: {next:?}");
            assert_eq!(stream.read(&mut [0; 1]).await.expect("fused stream"), 0);
            drop(stream);
            let metrics = client.metrics_snapshot();
            assert_eq!(metrics.requests.started, 2);
            assert_eq!(metrics.requests.in_flight, 0);
            assert_eq!(metrics.requests.canceled, 0);
            assert_eq!(metrics.requests.failed, u64::from(truncated));
            assert_eq!(metrics.requests.succeeded, 2 - u64::from(truncated));
        }
    }
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_stream_terminal_reads_release_global_and_host_capacity() {
    support::install_crypto_provider();
    for per_host in [false, true] {
        for truncated in [false, true] {
            let server = Server::new(truncated);
            let builder = reqx::blocking::Client::builder(&server.url)
                .metrics_enabled(true)
                .retry_policy(RetryPolicy::disabled());
            let client = if per_host {
                builder.max_in_flight_per_host(1)
            } else {
                builder.max_in_flight(1)
            }
            .build()
            .expect("client");
            let mut stream = client.get("/").send_stream().expect("response headers");
            let mut bytes = Vec::new();
            let result = stream.read_to_end(&mut bytes);
            assert_eq!(result.is_err(), truncated);
            let next = client
                .get("/")
                .total_timeout(Duration::from_millis(200))
                .send();
            assert!(next.is_ok(), "completed stream retained capacity: {next:?}");
            assert_eq!(stream.read(&mut [0; 1]).expect("fused stream"), 0);
            drop(stream);
            let metrics = client.metrics_snapshot();
            assert_eq!(metrics.requests.started, 2);
            assert_eq!(metrics.requests.in_flight, 0);
            assert_eq!(metrics.requests.canceled, 0);
            assert_eq!(metrics.requests.failed, u64::from(truncated));
            assert_eq!(metrics.requests.succeeded, 2 - u64::from(truncated));
        }
    }
}

#[cfg(feature = "_async")]
#[tokio::test]
async fn canceling_queued_requests_records_completion_once() {
    support::install_crypto_provider();
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    for streamed in [false, true] {
        let server = Server::new(false);
        let client = reqx::Client::builder(&server.url)
            .max_in_flight(1)
            .metrics_enabled(true)
            .retry_policy(RetryPolicy::disabled())
            .build()
            .expect("client");
        let stream = client
            .get("/")
            .send_stream()
            .await
            .expect("holding response");
        let mut queued = Box::pin(async {
            if streamed {
                client.get("/").send_stream().await.map(|_| ())
            } else {
                client.get("/").send().await.map(|_| ())
            }
        });
        poll_fn(|cx| {
            assert!(queued.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(queued);
        let metrics = client.metrics_snapshot();
        assert_eq!(metrics.requests.started, 2);
        assert_eq!(metrics.requests.in_flight, 1);
        assert_eq!(metrics.requests.canceled, 1);
        assert_eq!(metrics.latency.samples, 1);
        stream
            .into_bytes_limited(10)
            .await
            .expect("consume holding response");
        let metrics = client.metrics_snapshot();
        assert_eq!(metrics.requests.succeeded, 1);
        assert_eq!(metrics.requests.canceled, 1);
        assert_eq!(metrics.requests.in_flight, 0);
        assert_eq!(metrics.latency.samples, 2);
    }
}

#[cfg(feature = "_async")]
#[tokio::test]
async fn canceling_transport_and_buffered_body_records_completion_once() {
    support::install_crypto_provider();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct HeadersReceived(Arc<tokio::sync::Notify>);

    impl reqx::advanced::Interceptor for HeadersReceived {
        fn on_response(
            &self,
            _context: &reqx::advanced::RequestContext,
            _status: http::StatusCode,
            _headers: &http::HeaderMap,
        ) {
            self.0.notify_one();
        }
    }

    for (streamed, send_headers) in [(false, false), (true, false), (false, true)] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("connection");
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.expect("request header"));
            }
            if send_headers {
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                    .await
                    .expect("headers");
            }
            ready_tx.send(()).expect("signal request received");
            std::future::pending::<()>().await;
            drop(socket);
        });
        let headers_received = Arc::new(tokio::sync::Notify::new());
        let client = reqx::Client::builder(url)
            .interceptor(HeadersReceived(headers_received.clone()))
            .metrics_enabled(true)
            .retry_policy(RetryPolicy::disabled())
            .build()
            .expect("client");
        let request_client = client.clone();
        let request = tokio::spawn(async move {
            if streamed {
                request_client.get("/").send_stream().await.map(|_| ())
            } else {
                request_client.get("/").send().await.map(|_| ())
            }
        });
        tokio::time::timeout(Duration::from_secs(2), ready_rx)
            .await
            .expect("server ready")
            .expect("ready signal");
        if send_headers {
            tokio::time::timeout(Duration::from_secs(2), headers_received.notified())
                .await
                .expect("client entered the body read");
        }
        request.abort();
        assert!(request.await.expect_err("request canceled").is_cancelled());
        server.abort();
        let _ = server.await;
        let metrics = client.metrics_snapshot();
        assert_eq!(metrics.requests.started, 1);
        assert_eq!(metrics.requests.in_flight, 0);
        assert_eq!(metrics.requests.canceled, 1);
        assert_eq!(metrics.requests.failed, 0);
        assert_eq!(metrics.requests.succeeded, 0);
        assert_eq!(metrics.latency.samples, 1);
    }
}

#[cfg(feature = "_async")]
#[tokio::test]
async fn async_stream_copy_deadline_covers_stalled_writes_and_flushes() {
    support::install_crypto_provider();
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;

    struct StalledWriter {
        stall_flush: bool,
    }

    impl AsyncWrite for StalledWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.stall_flush {
                Poll::Ready(Ok(bytes.len()))
            } else {
                Poll::Pending
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    for limited in [false, true] {
        for stall_flush in [false, true] {
            let server = Server::new(false);
            let client = reqx::Client::builder(&server.url)
                .metrics_enabled(true)
                .max_in_flight(1)
                .retry_policy(RetryPolicy::disabled())
                .build()
                .expect("client");
            let stream = client
                .get("/")
                .total_timeout(Duration::from_millis(200))
                .send_stream()
                .await
                .expect("response headers");
            let mut writer = StalledWriter { stall_flush };
            let result = tokio::time::timeout(Duration::from_secs(1), async {
                if limited {
                    stream.copy_to_writer_limited(&mut writer, 2).await
                } else {
                    stream.copy_to_writer(&mut writer).await
                }
            })
            .await
            .expect("total timeout must wake a stalled writer");
            assert!(matches!(result, Err(reqx::Error::DeadlineExceeded { .. })));
            let metrics = client.metrics_snapshot();
            assert_eq!(metrics.requests.failed, 1);
            assert_eq!(metrics.requests.canceled, 0);
            assert_eq!(metrics.requests.in_flight, 0);
            assert_eq!(
                metrics
                    .errors
                    .by_code
                    .get(&reqx::ErrorCode::DeadlineExceeded),
                Some(&1)
            );
            client
                .get("/")
                .total_timeout(Duration::from_millis(200))
                .send()
                .await
                .expect("timed out copy must release capacity");
        }
    }
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_stream_copy_reports_deadline_after_slow_flush() {
    support::install_crypto_provider();
    struct SlowFlushWriter;

    impl Write for SlowFlushWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            std::thread::sleep(Duration::from_millis(300));
            Ok(())
        }
    }

    for limited in [false, true] {
        let server = Server::new(false);
        let client = reqx::blocking::Client::builder(&server.url)
            .metrics_enabled(true)
            .max_in_flight(1)
            .retry_policy(RetryPolicy::disabled())
            .build()
            .expect("client");
        let stream = client
            .get("/")
            .total_timeout(Duration::from_millis(200))
            .send_stream()
            .expect("response headers");
        let mut writer = SlowFlushWriter;
        let result = if limited {
            stream.copy_to_writer_limited(&mut writer, 2)
        } else {
            stream.copy_to_writer(&mut writer)
        };
        assert!(matches!(result, Err(reqx::Error::DeadlineExceeded { .. })));
        let metrics = client.metrics_snapshot();
        assert_eq!(metrics.requests.failed, 1);
        assert_eq!(metrics.requests.succeeded, 0);
        assert_eq!(metrics.requests.canceled, 0);
        assert_eq!(
            metrics
                .errors
                .by_code
                .get(&reqx::ErrorCode::DeadlineExceeded),
            Some(&1)
        );
        client
            .get("/")
            .total_timeout(Duration::from_millis(200))
            .send()
            .expect("timed out copy must release capacity");
    }
}
