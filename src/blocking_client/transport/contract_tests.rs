use super::is_timeout_io_error;

#[cfg(feature = "_blocking")]
#[test]
fn blocking_timeout_io_error_helper_detects_plain_and_wrapped_timeouts() {
    let plain = std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out");
    assert!(is_timeout_io_error(&plain));

    let would_block = std::io::Error::new(std::io::ErrorKind::WouldBlock, "would block");
    assert!(is_timeout_io_error(&would_block));

    let wrapped = std::io::Error::other(ureq::Error::Timeout(ureq::Timeout::RecvBody));
    assert!(is_timeout_io_error(&wrapped));

    let reset = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
    assert!(!is_timeout_io_error(&reset));
}
