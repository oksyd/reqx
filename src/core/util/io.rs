use std::sync::Mutex;

#[cfg(any(
    test,
    feature = "_blocking",
    feature = "compression-gzip",
    feature = "compression-brotli",
    feature = "compression-zstd"
))]
use std::io;

pub(crate) fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(any(
    test,
    feature = "_blocking",
    feature = "compression-gzip",
    feature = "compression-brotli",
    feature = "compression-zstd"
))]
pub(crate) fn read_retry_interrupted<R>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize>
where
    R: io::Read + ?Sized,
{
    loop {
        match reader.read(buffer) {
            Ok(read) => return Ok(read),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}
