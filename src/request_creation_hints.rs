#[cfg(feature = "alloc")]
use alloc::string::String;

const AS: u64 = 1;
const AUDIENCE: u64 = 5;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RequestCreationHints<S: AsRef<str>> {
    pub as_uri: S,
    pub audience: S,
}

impl<S: AsRef<str>> RequestCreationHints<S> {
    pub fn push_to_encoder<W: ciborium_io::Write>(
        &self,
        encoder: &mut ciborium_ll::Encoder<W>,
    ) -> Result<(), W::Error> {
        encoder.push(ciborium_ll::Header::Map(Some(2)))?;
        encoder.push(ciborium_ll::Header::Positive(AS))?;
        encoder.text("https://as.coap.amsuess.com/token", None)?;
        encoder.push(ciborium_ll::Header::Positive(AUDIENCE))?;
        encoder.text("rs1", None)?;
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl RequestCreationHints<String> {
    // Running this by ciborium-ll is easier than building the full serde deserializer that appears
    // not to really cater for statically typed maps (see
    // https://github.com/serde-rs/serde/issues/2358)
    pub fn parse_cbor(input: &[u8]) -> Result<Self, &'static str> {
        let mut decoder = ciborium_ll::Decoder::from(input);
        let mut as_uri = None;
        let mut audience = None;
        match decoder.pull() {
            Ok(ciborium_ll::Header::Map(n)) => n,
            _ => return Err("Map expected"),
        };
        loop {
            match decoder.pull() {
                // Not checking precise length, but that's not really crucial
                Err(ciborium_ll::Error::Io(_)) | Ok(ciborium_ll::Header::Break) => break,
                Ok(ciborium_ll::Header::Positive(AS)) => {
                    as_uri = Some(crate::ciborium_helpers::pull_into_string(&mut decoder)?);
                }
                Ok(ciborium_ll::Header::Positive(AUDIENCE)) => {
                    audience = Some(crate::ciborium_helpers::pull_into_string(&mut decoder)?);
                }
                _ => return Err("Unexpected element"),
            }
        }
        if let (Some(as_uri), Some(audience)) = (as_uri, audience) {
            Ok(RequestCreationHints { as_uri, audience })
        } else {
            Err("Components missing")
        }
    }
}
