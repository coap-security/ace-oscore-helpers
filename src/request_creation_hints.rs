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
        encoder.text(self.as_uri.as_ref(), None)?;
        encoder.push(ciborium_ll::Header::Positive(AUDIENCE))?;
        encoder.text(self.audience.as_ref(), None)?;
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

#[cfg(test)]
mod test {
    use super::*;

    /// Example adjusted from RFC9200
    const ENCODED: &[u8] = &[
        0xa2, 0x01, 0x78, 0x1c, 0x63, 0x6f, 0x61, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x61, 0x73, 0x2e,
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x6f, 0x6b,
        0x65, 0x6e, 0x05, 0x76, 0x63, 0x6f, 0x61, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x72, 0x73, 0x2e,
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    ];

    #[test]
    fn parse() {
        let rch = RequestCreationHints::parse_cbor(ENCODED).unwrap();
        assert_eq!(&rch.as_uri, "coaps://as.example.com/token");
        assert_eq!(&rch.audience, "coaps://rs.example.com");
    }

    #[test]
    fn serialize() {
        let rch = RequestCreationHints {
            as_uri: "coaps://as.example.com/token",
            audience: "coaps://rs.example.com",
        };
        let mut buffer = alloc::vec::Vec::new();
        let mut encoder = ciborium_ll::Encoder::from(&mut buffer);
        rch.push_to_encoder(&mut encoder).unwrap();
        assert_eq!(buffer, ENCODED);
    }
}
