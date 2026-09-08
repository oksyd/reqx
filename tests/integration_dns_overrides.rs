#![cfg(any(feature = "_async", feature = "_blocking"))]
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
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
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if socket.read(&mut byte).expect("header") == 0 {
                        break;
                    }
                    header.push(byte[0]);
                    assert!(header.len() < 8192);
                }
                let header = String::from_utf8(header).expect("ASCII request");
                captured.lock().expect("requests").push(header);
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

// The same behavior suite runs through each public client, including standalone
// blocking builds where an async runtime is not available.
macro_rules! dns_suite {
    ($client:path, $await:ident) => {{
        for ip in ["127.0.0.1", "::1"] {
            if ip == "::1" && TcpListener::bind((ip, 0)).is_err() {
                eprintln!("IPv6 loopback unavailable; skipping IPv6 connection case");
                continue;
            }
            let server = Server::new(ip, None);
            let dead = SocketAddr::from(([127, 0, 0, 2], server.address.port()));
            let url = format!("http://pinned.invalid:{}/resource", server.address.port());
            let client = <$client>::builder(&url)
                .resolve_to_addrs("PINNED.INVALID.", &[dead, server.address])
                .request_timeout(Duration::from_secs(2))
                .retry_policy(RetryPolicy::disabled())
                .build()
                .expect("client");
            for _ in 0..2 {
                let response =
                    $await!(client.get("").send()).expect("connect to validated address");
                assert_eq!(response.status(), http::StatusCode::OK);
            }
            for request in server.requests.lock().expect("requests").iter() {
                assert!(request.to_ascii_lowercase().contains(&format!(
                    "host: pinned.invalid:{}\r\n",
                    server.address.port()
                )));
                assert!(request.starts_with("GET /resource "));
            }
        }
        let server = Server::new("127.0.0.1", None);
        // With no explicit URL port, the address port is the connection port.
        let client = <$client>::builder("http://port.invalid")
            .resolve("port.invalid", server.address)
            .build()
            .expect("client");
        $await!(client.get("/").send()).expect("override port");
        assert!(
            server.requests.lock().expect("requests")[0]
                .to_ascii_lowercase()
                .contains("host: port.invalid\r\n")
        );
        // Explicit URL port takes precedence over the address port (including zero).
        for port in [0, 1] {
            let mut address = server.address;
            address.set_port(port);
            let client =
                <$client>::builder(format!("http://explicit.invalid:{}", server.address.port()))
                    .resolve("explicit.invalid", address)
                    .build()
                    .expect("client");
            $await!(client.get("/").send()).expect("explicit URL port");
        }
        let client = <$client>::builder(format!("http://localhost:{}", server.address.port()))
            .resolve(
                "localhost",
                SocketAddr::from(([127, 0, 0, 2], server.address.port())),
            )
            .request_timeout(Duration::from_millis(200))
            .retry_policy(RetryPolicy::standard().max_attempts(2))
            .build()
            .expect("client");
        let before = server.requests.lock().expect("requests").len();
        assert!(
            $await!(client.get("/").send()).is_err(),
            "must not fall back to localhost DNS"
        );
        assert_eq!(server.requests.lock().expect("requests").len(), before);
        let client = <$client>::builder(format!("http://localhost:{}", server.address.port()))
            .resolve("unrelated.invalid", server.address)
            .build()
            .expect("client");
        $await!(client.get("/").send()).expect("unconfigured host still uses system DNS");

        for target in ["target.invalid", "localhost"] {
            let destination = Server::new("127.0.0.1", None);
            let source = Server::new(
                "127.0.0.1",
                Some(format!(
                    "http://{target}:{}/next",
                    destination.address.port()
                )),
            );
            let client = <$client>::builder("http://source.invalid")
                .resolve("source.invalid", source.address)
                .resolve("target.invalid", destination.address)
                .redirect_policy(RedirectPolicy::limited(2))
                .build()
                .expect("client");
            $await!(client.get("/").send()).expect("redirect uses destination's own DNS policy");
            assert_eq!(destination.requests.lock().expect("requests").len(), 1);
        }
        for addresses in [vec![], vec![server.address; 17]] {
            let result = <$client>::builder("http://example.com")
                .resolve_to_addrs("example.com", &addresses)
                .build();
            assert!(matches!(
                result,
                Err(reqx::Error::InvalidDnsOverrideConfig { .. })
            ));
        }
        let result = <$client>::builder("http://example.com")
            .resolve("example.com", server.address)
            .http_proxy("http://proxy.invalid:8080".parse().expect("proxy URI"))
            .no_proxy(["*"])
            .build();
        assert!(matches!(
            result,
            Err(reqx::Error::InvalidDnsOverrideConfig { .. })
        ));
    }};
}

#[cfg(feature = "_async")]
#[tokio::test]
async fn async_dns_overrides() {
    macro_rules! wait {
        ($e:expr) => {
            $e.await
        };
    }
    dns_suite!(reqx::Client, wait);
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_dns_overrides() {
    macro_rules! wait {
        ($e:expr) => {
            $e
        };
    }
    dns_suite!(reqx::blocking::Client, wait);
}
