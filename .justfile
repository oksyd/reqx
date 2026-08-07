set shell := ["bash", "-euo", "pipefail", "-c"]

patch:
    cargo release patch --no-publish --execute

minor:
    cargo release minor --no-publish --execute

publish:
    cargo publish

ci:
    cargo fmt --all --check
    cargo check --all-targets
    cargo check --lib --no-default-features
    cargo clippy --all-targets --all-features -- -D warnings
    cargo +nightly rustdoc --lib --all-features -- --cfg docsrs
    cargo test --doc
    cargo test --doc --all-features
    cargo nextest run
    cargo nextest run --all-features

bench:
    cargo bench --bench transport
