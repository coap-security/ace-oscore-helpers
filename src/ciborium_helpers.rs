#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

#[derive(Debug, Copy, Clone)]
pub enum PullError {
    /// End of file reached mid-string
    MidStringTermination,
    /// Expected text string contains non-UTF8 bytes
    InvalidUtf8,
    /// Expected that a (text or byte, depending on context) string element would be present
    ExpectedStringElement,
}

use PullError::*;

impl From<PullError> for &'static str {
    fn from(e: PullError) -> Self {
        match e {
            MidStringTermination => "End of file reached mid-stream",
            InvalidUtf8 => "Text string contained invalid (non-UTF8) bytes",
            ExpectedStringElement => "String element expected",
        }
    }
}

#[cfg(feature = "alloc")]
pub(crate) fn pull_into_string<R: ciborium_io::Read>(
    decoder: &mut ciborium_ll::Decoder<R>,
) -> Result<String, PullError> {
    match decoder.pull() {
        // Not accepting indefinite-length here even though it'd be technically feasible
        Ok(ciborium_ll::Header::Text(Some(n))) => {
            let mut bytes = Vec::with_capacity(n);
            // Hoping the compiler will know to elide the zerioing when it sees into the reader
            bytes.resize(n, 0);
            use ciborium_io::Read;
            decoder
                .read_exact(&mut bytes)
                .map_err(|_| MidStringTermination)?;

            String::from_utf8(bytes).map_err(|_| InvalidUtf8)
        }
        _ => Err(ExpectedStringElement),
    }
}

pub(crate) fn pull_into_bytes<const N: usize, R: ciborium_io::Read>(
    decoder: &mut ciborium_ll::Decoder<R>,
) -> Result<heapless::Vec<u8, N>, PullError> {
    match decoder.pull() {
        // Not accepting indefinite-length here even though it'd be technically feasible
        Ok(ciborium_ll::Header::Bytes(Some(n))) if n <= N => {
            let mut ret = heapless::Vec::new();
            // This zeroes, but that write should be optimized away
            ret.resize_default(n).expect("n <= N was checked");
            use ciborium_io::Read;
            decoder
                .read_exact(&mut ret)
                .map_err(|_| MidStringTermination)?;
            Ok(ret)
        }
        _ => Err(ExpectedStringElement),
    }
}
