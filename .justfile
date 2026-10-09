set shell := ["bash", "-euo", "pipefail", "-c"]

patch:
    cargo release patch --no-publish --execute

minor:
    cargo release minor --no-publish --execute

publish:
    cargo publish

ci:
    #!/usr/bin/env bash
    set -euo pipefail
    export CARGO_BUILD_WARNINGS=deny

    cargo fmt --all --check
    cargo check --all-targets
    cargo check --all-targets --no-default-features
    cargo clippy --all-targets --all-features -- -D warnings
    cargo rustdoc --lib --all-features -- -D warnings
    cargo test --doc
    cargo test --doc --all-features
    cargo nextest run
    cargo nextest run --all-features

# Check nightly-only docs.rs feature annotations.
docsrs:
    CARGO_BUILD_WARNINGS=deny cargo +nightly rustdoc --lib --all-features -- --cfg docsrs -D warnings

bench:
    cargo bench --bench transport
