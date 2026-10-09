# reqx

[![crates.io](https://img.shields.io/crates/v/reqx.svg)](https://crates.io/crates/reqx)
[![docs.rs](https://docs.rs/reqx/badge.svg)](https://docs.rs/reqx)
[![CI](https://github.com/oksyd/reqx/actions/workflows/ci.yaml/badge.svg)](https://github.com/oksyd/reqx/actions/workflows/ci.yaml)
[![license](https://img.shields.io/crates/l/reqx.svg)](LICENSE)

HTTP transport for Rust API SDKs with async and blocking clients, retries,
timeouts, streaming, and pluggable TLS backends.

## Installation

Requires Rust 1.99.0 or newer.

```bash
cargo add reqx
```

The default build enables the async client, rustls with ring, and gzip decoding.

## Documentation

- [API reference and feature selection](https://docs.rs/reqx)
- [Examples](examples/README.md)
- [Changelog](CHANGELOG.md)
