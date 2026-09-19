#![cfg(any(feature = "_async", feature = "_blocking"))]
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqx::prelude::{RedirectPolicy, RetryPolicy};

struct Server {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn new(ip: &str, redirect: Option<String>) -> Self {
        Self::start(ip, redirect, false)
    }

    fn proxy() -> Self {
        Self::start("127.0.0.1", None, true)
    }

    fn start(ip: &str, redirect: Option<String>, proxy: bool) -> Self {
        let listener = TcpListener::bind((ip, 0)).expect("bind server");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let (mut socket, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(e) => panic!("accept: {e}"),
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("timeout");
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .expect("timeout");
                let header = read_header(&mut socket);
                captured.lock().expect("requests").push(header.clone());
                if proxy {
                    forward_request(socket, header);
                    continue;
                }
                let status = if redirect.is_some() {
                    "302 Found"
                } else {
                    "200 OK"
                };
                let location = redirect
                    .as_ref()
                    .map(|url| format!("Location: {url}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 {status}\r\n{location}Content-Length: 2\r\nConnection: close\r\n\r\nok"
                );
                socket.write_all(response.as_bytes()).expect("response");
            }
        });
        Self {
            address,
            requests,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("server");
        }
    }
}

// This fixture forwards bodyless HTTP requests, including CONNECT tunnels used
// by the async client. Origins close each response, so EOF delimits forwarding.
fn read_header(socket: &mut TcpStream) -> String {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).expect("request header");
        header.push(byte[0]);
        assert!(header.len() < 8192);
    }
    String::from_utf8(header).expect("ASCII request")
}

fn forward_request(mut client: TcpStream, header: String) {
    let first_line = header.lines().next().expect("request line");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().expect("method");
    let target = parts.next().expect("target");
    let (authority, request) = if method == "CONNECT" {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .expect("tunnel response");
        (target.to_owned(), read_header(&mut client))
    } else {
        let uri: http::Uri = target.parse().expect("absolute proxy URI");
        let authority = uri.authority().expect("authority").to_string();
        let path = uri.path_and_query().map_or("/", |path| path.as_str());
        let (_, headers) = header.split_once("\r\n").expect("headers");
        (authority, format!("{method} {path} HTTP/1.1\r\n{headers}"))
    };
    let mut upstream = TcpStream::connect(authority).expect("connect to origin");
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    upstream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("write timeout");
    upstream
        .write_all(request.as_bytes())
        .expect("forward request");
    std::io::copy(&mut upstream, &mut client).expect("forward response");
}

macro_rules! cidr_suite {
    ($client:path, $await:ident) => {{
        for rule in ["127.0.0.0/8", "192.168.88.0/24"] {
            let destination = Server::new("127.0.0.1", None);
            let proxy = Server::proxy();
            let client = <$client>::builder(format!("http://{}", destination.address))
                .http_proxy(
                    format!("http://{}", proxy.address)
                        .parse()
                        .expect("proxy URI"),
                )
                .no_proxy([rule, "*.example.com", "::1/128"])
                .request_timeout(Duration::from_secs(2))
                .retry_policy(RetryPolicy::disabled())
                .build()
                .expect("client");
            let response = $await!(client.get("/").send());
            let response = response.expect("request succeeds through the selected route");
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(response.body().as_ref(), b"ok");
            assert_eq!(destination.requests.lock().expect("requests").len(), 1);
            if rule == "127.0.0.0/8" {
                assert!(proxy.requests.lock().expect("requests").is_empty());
            } else {
                assert_eq!(proxy.requests.lock().expect("requests").len(), 1);
            }
        }
        // A redirect from a matching literal to localhost must use the proxy,
        // although localhost resolves into the excluded loopback network.
        let destination = Server::new("127.0.0.1", None);
        let source = Server::new(
            "127.0.0.1",
            Some(format!(
                "http://localhost:{}/next",
                destination.address.port()
            )),
        );
        let proxy = Server::proxy();
        let client = <$client>::builder(format!("http://{}", source.address))
            .http_proxy(
                format!("http://{}", proxy.address)
                    .parse()
                    .expect("proxy URI"),
            )
            .no_proxy(["127.0.0.0/8", "::/0"])
            .redirect_policy(RedirectPolicy::limited(2))
            .request_timeout(Duration::from_secs(2))
            .retry_policy(RetryPolicy::disabled())
            .build()
            .expect("client");
        let response = $await!(client.get("/").send()).expect("redirect through proxy");
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.body().as_ref(), b"ok");
        assert_eq!(source.requests.lock().expect("requests").len(), 1);
        assert_eq!(destination.requests.lock().expect("requests").len(), 1);
        assert_eq!(proxy.requests.lock().expect("requests").len(), 1);

        for invalid in ["192.168.0.0/33", "::/129", "example.com/24"] {
            assert!(matches!(
                <$client>::builder("http://example.com")
                    .no_proxy([invalid])
                    .build(),
                Err(reqx::Error::InvalidNoProxyRule { .. })
            ));
            assert!(matches!(
                <$client>::builder("http://example.com").try_no_proxy([invalid]),
                Err(reqx::Error::InvalidNoProxyRule { .. })
            ));
        }
    }};
}

#[cfg(feature = "_async")]
#[tokio::test]
async fn async_no_proxy_cidr_routing() {
    macro_rules! wait {
        ($e:expr) => {
            $e.await
        };
    }
    cidr_suite!(reqx::Client, wait);
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_no_proxy_cidr_routing() {
    macro_rules! wait {
        ($e:expr) => {
            $e
        };
    }
    cidr_suite!(reqx::blocking::Client, wait);
}
