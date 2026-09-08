#[cfg(any(
    test,
    feature = "compression-gzip",
    feature = "compression-brotli",
    feature = "compression-zstd"
))]
use std::io::Read;

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_ENCODING;
use http::{Method, StatusCode};

#[cfg(any(
    test,
    feature = "compression-gzip",
    feature = "compression-brotli",
    feature = "compression-zstd"
))]
use crate::util::read_retry_interrupted;

#[derive(Debug)]
pub(crate) enum DecodeContentEncodingError {
    Decode { encoding: String, message: String },
    TooLarge { actual_bytes: usize },
}

#[cfg(any(
    test,
    feature = "compression-gzip",
    feature = "compression-brotli",
    feature = "compression-zstd"
))]
fn read_to_end_limited<R: Read>(
    reader: &mut R,
    encoding: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, DecodeContentEncodingError> {
    let mut decoded = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];

    loop {
        let read = read_retry_interrupted(reader, &mut chunk).map_err(|error| {
            DecodeContentEncodingError::Decode {
                encoding: encoding.to_owned(),
                message: error.to_string(),
            }
        })?;
        if read == 0 {
            break;
        }
        let next_size = decoded.len().saturating_add(read);
        if next_size > max_bytes {
            return Err(DecodeContentEncodingError::TooLarge {
                actual_bytes: next_size,
            });
        }
        decoded.extend_from_slice(&chunk[..read]);
    }

    Ok(decoded)
}

#[cfg(feature = "compression-gzip")]
fn decode_deflate_limited(
    body: &Bytes,
    encoding: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, DecodeContentEncodingError> {
    let mut zlib_decoder = flate2::read::ZlibDecoder::new(body.as_ref());
    match read_to_end_limited(&mut zlib_decoder, encoding, max_bytes) {
        Ok(decoded) => Ok(decoded),
        Err(DecodeContentEncodingError::Decode { .. }) => {
            let mut raw_decoder = flate2::read::DeflateDecoder::new(body.as_ref());
            read_to_end_limited(&mut raw_decoder, encoding, max_bytes)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn should_decode_content_encoded_body(
    method: &Method,
    status: StatusCode,
    body_len: usize,
) -> bool {
    if body_len == 0 {
        return false;
    }
    if *method == Method::HEAD {
        return false;
    }
    if status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
    {
        return false;
    }
    true
}

pub(crate) fn decode_content_encoded_body_limited(
    mut body: Bytes,
    headers: &HeaderMap,
    max_bytes: usize,
) -> Result<Bytes, DecodeContentEncodingError> {
    if body.len() > max_bytes {
        return Err(DecodeContentEncodingError::TooLarge {
            actual_bytes: body.len(),
        });
    }

    let mut encodings = Vec::new();
    for content_encoding in headers.get_all(CONTENT_ENCODING) {
        let content_encoding =
            content_encoding
                .to_str()
                .map_err(|error| DecodeContentEncodingError::Decode {
                    encoding: "content-encoding".to_owned(),
                    message: error.to_string(),
                })?;
        encodings.extend(
            content_encoding
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty()),
        );
    }
    if encodings.is_empty() {
        return Ok(body);
    }

    let mut encodings = encodings.into_iter().map(str::to_owned).collect::<Vec<_>>();

    while let Some(encoding) = encodings.pop() {
        let decoded = match encoding.to_ascii_lowercase().as_str() {
            "identity" => {
                if body.len() > max_bytes {
                    return Err(DecodeContentEncodingError::TooLarge {
                        actual_bytes: body.len(),
                    });
                }
                body.to_vec()
            }
            #[cfg(feature = "compression-gzip")]
            "gzip" => {
                let mut decoder = flate2::read::MultiGzDecoder::new(body.as_ref());
                read_to_end_limited(&mut decoder, &encoding, max_bytes)?
            }
            #[cfg(feature = "compression-gzip")]
            "deflate" => decode_deflate_limited(&body, &encoding, max_bytes)?,
            #[cfg(feature = "compression-brotli")]
            "br" => {
                let mut decoder = brotli::Decompressor::new(body.as_ref(), 4096);
                read_to_end_limited(&mut decoder, &encoding, max_bytes)?
            }
            #[cfg(feature = "compression-zstd")]
            "zstd" => {
                let mut decoder =
                    zstd::stream::read::Decoder::new(body.as_ref()).map_err(|error| {
                        DecodeContentEncodingError::Decode {
                            encoding: encoding.clone(),
                            message: error.to_string(),
                        }
                    })?;
                read_to_end_limited(&mut decoder, &encoding, max_bytes)?
            }
            other => {
                return Err(DecodeContentEncodingError::Decode {
                    encoding: other.to_owned(),
                    message: "unsupported content-encoding".to_owned(),
                });
            }
        };
        body = Bytes::from(decoded);
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "compression-gzip", feature = "compression-brotli"))]
    use std::io::Write;
    use std::io::{self, Read};

    use bytes::Bytes;
    use http::HeaderMap;
    use http::header::CONTENT_ENCODING;

    #[cfg(any(
        not(feature = "compression-gzip"),
        not(feature = "compression-brotli"),
        not(feature = "compression-zstd")
    ))]
    use super::DecodeContentEncodingError;
    use super::{decode_content_encoded_body_limited, read_to_end_limited};

    struct InterruptedOnceReader {
        data: Vec<u8>,
        offset: usize,
        interrupted: bool,
    }

    impl InterruptedOnceReader {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                offset: 0,
                interrupted: false,
            }
        }
    }

    impl Read for InterruptedOnceReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.offset >= self.data.len() {
                return Ok(0);
            }

            let read = buffer.len().min(self.data.len() - self.offset);
            buffer[..read].copy_from_slice(&self.data[self.offset..self.offset + read]);
            self.offset += read;
            Ok(read)
        }
    }

    #[test]
    fn read_to_end_limited_retries_interrupted_reads() {
        let mut reader = InterruptedOnceReader::new(b"decoded");
        let decoded = read_to_end_limited(&mut reader, "test", 16)
            .expect("interrupted read should be retried");

        assert_eq!(decoded, b"decoded");
    }

    #[cfg(any(
        not(feature = "compression-gzip"),
        not(feature = "compression-brotli"),
        not(feature = "compression-zstd")
    ))]
    fn assert_disabled_codec_is_rejected(encoding: &'static str) {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_ENCODING,
            encoding.parse().expect("encoding is valid"),
        );
        let error =
            decode_content_encoded_body_limited(Bytes::from_static(b"encoded"), &headers, 64)
                .expect_err("disabled codec must not be decoded");
        assert!(matches!(
            error,
            DecodeContentEncodingError::Decode { encoding: actual, .. } if actual == encoding
        ));
    }

    #[cfg(any(
        feature = "compression-gzip",
        feature = "compression-brotli",
        feature = "compression-zstd"
    ))]
    fn assert_codec_decodes(encoding: &'static str, encoded: Vec<u8>, expected: &[u8]) {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_ENCODING,
            encoding.parse().expect("encoding is valid"),
        );
        let decoded = decode_content_encoded_body_limited(Bytes::from(encoded), &headers, 1024)
            .expect("enabled codec should decode");
        assert_eq!(decoded.as_ref(), expected);
    }

    #[cfg(feature = "compression-gzip")]
    #[test]
    fn enabled_gzip_decodes() {
        let expected = b"gzip capability";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(expected).expect("gzip should encode");
        assert_codec_decodes(
            "gzip",
            encoder.finish().expect("gzip should finish"),
            expected,
        );
    }

    #[cfg(feature = "compression-brotli")]
    #[test]
    fn enabled_brotli_decodes() {
        let expected = b"brotli capability";
        let mut encoded = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut encoded, 4096, 5, 22);
            encoder.write_all(expected).expect("brotli should encode");
        }
        assert_codec_decodes("br", encoded, expected);
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn enabled_zstd_decodes() {
        let expected = b"zstd capability";
        let encoded = zstd::stream::encode_all(&expected[..], 0).expect("zstd should encode");
        assert_codec_decodes("zstd", encoded, expected);
    }

    #[cfg(not(feature = "compression-gzip"))]
    #[test]
    fn disabled_gzip_is_rejected() {
        assert_disabled_codec_is_rejected("gzip");
        assert_disabled_codec_is_rejected("deflate");
    }

    #[cfg(not(feature = "compression-brotli"))]
    #[test]
    fn disabled_brotli_is_rejected() {
        assert_disabled_codec_is_rejected("br");
    }

    #[cfg(not(feature = "compression-zstd"))]
    #[test]
    fn disabled_zstd_is_rejected() {
        assert_disabled_codec_is_rejected("zstd");
    }

    #[cfg(feature = "compression-gzip")]
    #[test]
    fn gzip_decodes_all_members_and_checks_the_combined_limit_and_tail() {
        fn member(data: &[u8]) -> Vec<u8> {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(data).expect("encode member");
            encoder.finish().expect("finish member")
        }
        let mut encoded = member(&[b'a'; 80]);
        encoded.extend(member(&[b'b'; 80]));
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, "gzip".parse().expect("header"));
        let decoded = decode_content_encoded_body_limited(encoded.clone().into(), &headers, 160)
            .expect("decode both members");
        assert_eq!(decoded.len(), 160);
        assert_eq!(&decoded[..80], &[b'a'; 80]);
        assert_eq!(&decoded[80..], &[b'b'; 80]);
        assert!(encoded.len() < 100, "limit must apply to decoded bytes");
        assert!(matches!(
            decode_content_encoded_body_limited(encoded.clone().into(), &headers, 100),
            Err(super::DecodeContentEncodingError::TooLarge { .. })
        ));
        encoded.pop();
        assert!(matches!(
            decode_content_encoded_body_limited(encoded.into(), &headers, 160),
            Err(super::DecodeContentEncodingError::Decode { .. })
        ));
    }
}
