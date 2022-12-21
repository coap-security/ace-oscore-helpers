use core::ops::DerefMut;

use coset::OscoreInputMaterial;
use coap_message::{ReadableMessage, MutableWritableMessage, MessageOption};
use coap_handler_implementations::option_processing::CriticalOptionsRemain;

/// The CoaP Content-Format for application/ace+cbor (per RFC 9200)
const CONTENT_FORMAT_ACE_CBOR: u16 = 19;

// FIXME: Make ResourceServer generic on this
//
// When configuring an RS with more than 256 active tokens, beware that not only last_id2 needs a
// larger type, but also one needs to start considering the relevant algorithms' maximum ID
// lengths.
const MAX_TOKENS: usize = 4;

/// Maximum length of any ID stored.
///
/// To accomodate any choice of the peers, this should be the longest nonce length supported by any
/// algorithm minus 6. (Longer values do no harm, this implementation will not choose any long
/// IDs on its own).
const MAX_ID_LEN: usize = 7;

const MAX_NONCE_LEN: usize = 16;

const MAX_TOKEN_SIZE: usize = 256; // FIXME: guessed

pub type Id = heapless::Vec<u8, MAX_ID_LEN>;
pub type Nonce = heapless::Vec<u8, MAX_NONCE_LEN>;

/// Shared identifiers and secrets between an RS and an AS
// TBD: generalize over lifetimes (or make values AsRef<[u8]>) and cipher
#[derive(Debug)]
pub struct RsAsSharedData {
    // FIXME: Introduce proper constructor once types are decided
    pub issuer: Option<&'static str>,
    pub audience: Option<&'static str>,
    pub key: aead::Key<ccm::Ccm<aes::Aes256,  aead::generic_array::typenum::U16, aead::generic_array::typenum::U13>>,
}

/// ...
///
/// ## Possible improvements
///
/// If more than just the RS produces IDs, this could take a prefix from the environment (or any
/// other means of sharding) to also allow having OSCORE recipient IDs not from here.
#[derive(Debug)]
pub struct ResourceServer<APPCLAIMS: for<'a> TryFrom<&'a coset::cwt::ClaimsSet>> {
    last_id2: core::num::Wrapping<u8>,
    // Note that for the relevant MAX_TOKENS, there'd be no gains from an indexed data structure
    //
    // TBD: We could store whether the token was used for successful communication, and then ensure
    // that some previously-used tokens are not evicted before unverified ones.
    tokens: uluru::LRUCache<(liboscore::PrimitiveContext, APPCLAIMS), MAX_TOKENS>,
    // It might also make sense to have these iterable
    as_data: RsAsSharedData,
}

impl<APPCLAIMS: for<'a> TryFrom<&'a coset::cwt::ClaimsSet>> ResourceServer<APPCLAIMS> {
    pub fn new_with_association(as_data: RsAsSharedData) -> Self {
        Self {
            last_id2: Default::default(), // any is good
            tokens: Default::default(), // empty
            as_data,
        }
    }

    /// Produce an id2 value that is not in current use
    ///
    /// This is infallible, because the token pool is always smaller than the ID space
    fn take_id2(&mut self) -> Id {
        loop {
            self.last_id2 += 1;
            let id = Id::try_from([self.last_id2.0].as_ref()).unwrap();
            if self.tokens.iter().all(|(osc, _)| osc.recipient_id() != &id) {
                return id;
            }
        }
    }

    /// Insert a POSTed token.
    ///
    /// Returns id2 and nonce2; at that point, all derivations have been performed and the context
    /// is stored.
    ///
    /// ## Possible improvements
    ///
    /// If the material is recognized, its old version could be evicted (as suggested in RFC9203
    /// right above 4.2.1).
    fn derive_and_insert(&mut self, material: OscoreInputMaterial, app_claims: APPCLAIMS, id1: Id, nonce1: Nonce) -> Result<(Id, Nonce), crate::oscore_claims::DeriveError> {
        let nonce2 = Nonce::try_from([4].as_ref()).unwrap(); // FIXME DANGER (also won't work as
                                                             // the length is wrong)
        let id2 = self.take_id2();

        let context = crate::oscore_claims::derive(material, &id1, &id2, &nonce1, &nonce2)?;
        self.tokens.insert((context, app_claims));

        Ok((id2, nonce2))
    }
}

/// The /authz-info resource as accessed without OSCORE protection (to which tokens with nonce and
/// ID are posted).
///
/// The protected /authz-info endpoint (to which tokens are posted for updating) is currently not
/// implemented (but would be implemented in a different struct).
///
/// Given that the endpoint may live independently of the handler, we can't keep a mutable
/// reference to it. Instead, we store a closure that grants us exclusive access to it, typically
/// backed by a platform dependent mutex.
pub struct UnprotectedAuthzInfoEndpoint<APPCLAIMS: for<'b> TryFrom<&'b coset::cwt::ClaimsSet>, RS_ACCESS: for<'b> FnMut() -> Option<RS_DEREF>, RS_DEREF: DerefMut<Target=ResourceServer<APPCLAIMS>>> {
    rs: RS_ACCESS,
}

impl<APPCLAIMS: for<'b> TryFrom<&'b coset::cwt::ClaimsSet>, RS_ACCESS: for<'b> FnMut() -> Option<RS_DEREF>, RS_DEREF: DerefMut<Target=ResourceServer<APPCLAIMS>>> UnprotectedAuthzInfoEndpoint<APPCLAIMS, RS_ACCESS, RS_DEREF> {
    pub fn new(rs: RS_ACCESS) -> Self {
        Self { rs }
    }
}

impl<APPCLAIMS: for<'b> TryFrom<&'b coset::cwt::ClaimsSet>, RS_ACCESS: for<'b> FnMut() -> Option<RS_DEREF>, RS_DEREF: DerefMut<Target=ResourceServer<APPCLAIMS>>> coap_handler::Handler for UnprotectedAuthzInfoEndpoint<APPCLAIMS, RS_ACCESS, RS_DEREF> {
    type RequestData = Result<(Id, Nonce), AuthzInfoError>;

    fn extract_request_data(&mut self, message: &impl ReadableMessage) -> Self::RequestData {
        if message.code().into() != coap_numbers::code::POST {
            return Err(AuthzInfoError::BadMethod);
        }

        use coap_handler_implementations::option_processing::OptionsExt;
        message.options()
            .filter(|o| match (o.number(), o.value_uint()) {
                (coap_numbers::option::CONTENT_FORMAT, Some(CONTENT_FORMAT_ACE_CBOR)) => false,
                (coap_numbers::option::ACCEPT, Some(CONTENT_FORMAT_ACE_CBOR)) => false,
                _ => true
            })
            .ignore_elective_others()?;

        
        let UnprotectedAuthzInfoPost { access_token, nonce1, ace_client_recipientid } = UnprotectedAuthzInfoPost::parse(message.payload())?;

        let mut rs = (self.rs)()
            .ok_or(AuthzInfoError::RsCurrentlyUnavailable)?;
        let rs = rs.deref_mut();

        use coset::CborSerializable;
        let envelope = coset::CoseEncrypt0::from_slice(&access_token)?;
        let iv: &[u8] = &envelope.unprotected.iv;
        let mut cipher: crate::aesccm::RustCryptoCcmCoseCipher::<aes::Aes256,  aead::generic_array::typenum::U16, aead::generic_array::typenum::U13> = crate::aesccm::RustCryptoCcmCoseCipher::new(
            rs.as_data.key,
            *aead::generic_array::GenericArray::from_slice(&iv),
            );

        let claims = dcaf::decrypt_access_token(&access_token.to_vec(), &mut cipher, Some(&[]))?;

        // Check if the claims are compatible with us

        if claims.issuer.as_ref().map(|s| Some(s.as_ref()) == rs.as_data.issuer) == Some(false) {
            // There's no hard rule saying we have to reject, but it's good practice.
            return Err(AuthzInfoError::AuthzInfoError("Not from our AS"));
        }
        
        if claims.audience.as_ref().map(|s| Some(s.as_ref()) == rs.as_data.audience) == Some(false) {
            // We have to reject if it's not us based on RFC7519 Section 4.1.3.
            return Err(AuthzInfoError::AuthzInfoError("Not for us"));
        }

        let app_claims: APPCLAIMS = (&claims).try_into()
            .map_err(|_| AuthzInfoError::AuthzInfoError("No valid application claims"))?;

        let pop_key = crate::oscore_claims::extract_oscore(claims)?;


        // Reserve an ID, derive and off we go

        rs.derive_and_insert(pop_key, app_claims, ace_client_recipientid, nonce1)
            .map_err(AuthzInfoError::DeriveError)
    }
    fn estimate_length(&mut self, _: &Self::RequestData) -> usize {
        assert!(MAX_NONCE_LEN < 24);
        assert!(MAX_ID_LEN < 24);
        2 /* content-format */ + 1 /* payload marker */ + 7 /* CBOR structure */ + MAX_NONCE_LEN + MAX_ID_LEN
    }
    fn build_response(&mut self, message: &mut impl MutableWritableMessage, request: Self::RequestData) {
        match request {
            Ok((id, nonce)) => {
                message.set_code(coap_numbers::code::CHANGED.try_into().map_err(|_| ()).unwrap());
                message.add_option_uint(
                    coap_numbers::option::CONTENT_FORMAT.try_into().map_err(|_| ()).unwrap(),
                    CONTENT_FORMAT_ACE_CBOR
                    );

                // Using the WindowedInfinityWithETag really more as a writer that has ciborium IO
                // implemented. (It's non-idempotent POSTs, so we can't do blockwise easily anyway).
                let full_payload = message.payload_mut_with_len(7 + MAX_NONCE_LEN + MAX_ID_LEN);

                let original_len = full_payload.len();

                use ciborium_ll::{Encoder, Header};
                use ciborium_io::Write;
                let mut encoder = Encoder::from(full_payload);
                encoder.push(Header::Map(Some(2))).unwrap();
                encoder.push(Header::Positive(crate::NONCE2)).unwrap();
                encoder.bytes(&nonce, None).unwrap();
                encoder.push(Header::Positive(crate::ACE_SERVER_RECIPIENTID)).unwrap();
                encoder.bytes(&id, None).unwrap();
                encoder.flush().unwrap();

                // Not checking for overflow: It won't happen by construction
//                 drop(encoder);
//                 let new_len = original_len - full_payload.len();
                // Actually even guessing the encoded length due to
                // https://github.com/enarx/ciborium/issues/64
                let new_len = 7 + nonce.len() + id.len();
                message.truncate(new_len);
            }
            Err(e) => {
                let code = match e {
                    AuthzInfoError::AuthzInfoError(_) => coap_numbers::code::BAD_REQUEST,
                    AuthzInfoError::DeriveError(_) => coap_numbers::code::BAD_REQUEST,
                    AuthzInfoError::CriticalOptionsRemain(_) => coap_numbers::code::BAD_OPTION,
                    AuthzInfoError::BadMethod => coap_numbers::code::METHOD_NOT_ALLOWED,
                    AuthzInfoError::RsCurrentlyUnavailable => coap_numbers::code::SERVICE_UNAVAILABLE,
                };

                message.set_code(code.try_into().map_err(|_| ()).unwrap());
                message.set_payload(b"");
            }
        }
    }
}

// I'd love to just let serde derive this, but apparently it won't do the numeric map keys.
struct UnprotectedAuthzInfoPost {
    access_token: heapless::Vec<u8, MAX_TOKEN_SIZE>,
    nonce1: Nonce,
    ace_client_recipientid: Id,
}

impl UnprotectedAuthzInfoPost {
    // This should be a three-line derive from the relevant CDDL
    fn parse(input: &[u8]) -> Result<Self, AuthzInfoError> {
        let mut access_token = None;
        let mut nonce1 = None;
        let mut ace_client_recipientid = None;

        let mut decoder = ciborium_ll::Decoder::from(input);
        match decoder.pull() {
            Ok(ciborium_ll::Header::Map(Some(3) | None)) => (),
            _ => return Err(AuthzInfoError::AuthzInfoError("Wrong map length"))
        };

        fn pull_into_bytes<const N: usize, R: ciborium_io::Read>(decoder: &mut ciborium_ll::Decoder<R>) -> Result<heapless::Vec<u8, N>, AuthzInfoError> {
            match decoder.pull() {
                // Not accepting indefinite-length here even though it'd be technically feasible
                Ok(ciborium_ll::Header::Bytes(Some(n))) if n <= N => {
                    let mut ret = heapless::Vec::new();
                    // This zeroes, but that write should be optimized away 
                    ret.resize_default(n);
                    use ciborium_io::Read;
                    decoder.read_exact(&mut ret)
                        .map_err(|_| AuthzInfoError::AuthzInfoError("Mid-string termination"))?;
                    Ok(ret)
                },
                _ => Err(AuthzInfoError::AuthzInfoError("Wrong structure"))
            }
        }

        for _ in 0..3 {
            match decoder.pull() {
                Ok(ciborium_ll::Header::Positive(crate::ACCESS_TOKEN)) => {
                    access_token = Some(pull_into_bytes(&mut decoder)?);
                }
                Ok(ciborium_ll::Header::Positive(crate::NONCE1)) => {
                    nonce1 = Some(pull_into_bytes(&mut decoder)?);
                }
                Ok(ciborium_ll::Header::Positive(crate::ACE_CLIENT_RECIPIENTID)) => {
                    ace_client_recipientid = Some(pull_into_bytes(&mut decoder)?);
                }
                _ => return Err(AuthzInfoError::AuthzInfoError("Unknown key"))
            }
        }

        if decoder.pull().is_ok() {
            return Err(AuthzInfoError::AuthzInfoError("Extra data"));
        }

        if let (Some(access_token), Some(nonce1), Some(ace_client_recipientid)) =
            (access_token, nonce1, ace_client_recipientid) {
            Ok(Self { access_token, nonce1, ace_client_recipientid })
        } else {
            Err(AuthzInfoError::AuthzInfoError("Missing data"))
        }
    }
}

/// Error type for POSTs to /authz-info.
///
/// The string is mostly used for internal diagnostics, though it may optionally be sent in a
/// diagnostic payload.
#[derive(Debug)]
pub enum AuthzInfoError {
    BadMethod,
    DeriveError(crate::oscore_claims::DeriveError),
    CriticalOptionsRemain(CriticalOptionsRemain),
    RsCurrentlyUnavailable,
    AuthzInfoError(&'static str),
}

impl From<CriticalOptionsRemain> for AuthzInfoError {
    fn from(s: CriticalOptionsRemain) -> Self { AuthzInfoError::CriticalOptionsRemain(s) }
}

impl<T> From<ciborium_ll::Error<T>> for AuthzInfoError
{
    fn from(_: ciborium_ll::Error<T>) -> Self { AuthzInfoError::AuthzInfoError("Format error") }
}

impl From<coset::CoseError> for AuthzInfoError
{
    fn from(_: coset::CoseError) -> Self { AuthzInfoError::AuthzInfoError("COSE structure error") }
}

impl<T: core::fmt::Display> From<dcaf::error::AccessTokenError<T>> for AuthzInfoError
{
    fn from(_: dcaf::error::AccessTokenError<T>) -> Self { AuthzInfoError::AuthzInfoError("Decryption failed") }
}

impl From<crate::oscore_claims::NoOscoreCnf> for AuthzInfoError
{
    fn from(_: crate::oscore_claims::NoOscoreCnf) -> Self { AuthzInfoError::AuthzInfoError("No OSCORE cnf contained") }
}
