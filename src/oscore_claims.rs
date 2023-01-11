//! Extractor for [coset::OscoreInputMaterial] (proposed in
//! [PR58](https://github.com/google/coset/pull/58)) from a [coset::cwt::ClaimsSet].
//!
//! This is not yet ready for inclusion in `coset`, not only because it's depending on a PR, but
//! also because an intermediate structure is implemented in `dcaf`:
//! [dcaf::common::cbor_values::ProofOfPossessionKey].

/// Error type indicating that a token does not contain usable credentials to set up OSCORE through
/// the ACE OSCORE profile
#[derive(defmt::Format, Debug)]
pub struct NoOscoreCnf;

// This takes ownership of a ClaimsSet because the i128 keyed map version dcaf works with contains
// owned Value items.
pub fn extract_oscore(
    mut claims: coset::cwt::ClaimsSet,
) -> Result<coset::OscoreInputMaterial, NoOscoreCnf> {
    let mut cnfs = claims.rest.drain(..).filter(|(key, _)| {
        matches!(
            key,
            coset::RegisteredLabelWithPrivate::Assigned(coset::iana::CwtClaimName::Cnf)
        )
    });

    // That's all a mouthful given that the parsing CDDL would be a two-liner...

    let (_, cnf) = cnfs.next().ok_or(NoOscoreCnf)?;
    if cnfs.next().is_some() {
        // Duplicate key
        return Err(NoOscoreCnf);
    }

    let cnf = match cnf {
        // This is mainly impedance matching between how dcaf treats maps, and how coset uses Value
        ciborium::value::Value::Map(mut v) => v
            .drain(..)
            .map(|(k, v)| (k.as_integer().unwrap().into(), v))
            .collect(),
        _ => return Err(NoOscoreCnf),
    };

    use dcaf::ToCborMap;
    let encrypted_pop_key = dcaf::common::cbor_values::ProofOfPossessionKey::try_from_cbor_map(cnf)
        .map_err(|_| NoOscoreCnf)?;

    match encrypted_pop_key {
        dcaf::common::cbor_values::ProofOfPossessionKey::OscoreInputMaterial(x) => Ok(x),
        _ => Err(NoOscoreCnf),
    }
}

#[cfg(feature = "liboscore")]
mod for_liboscore {
    extern crate alloc;

    // Both are limited to lengths encodable in 1+1 in CBOR (any values > 255 would need adjustments in
    // MAX_SALT calculation).
    const NONCE_MAX: usize = 32;
    const INPUT_SALT_MAX: usize = 32;

    /// Intermediat results of the derivation process
    struct ConcreteOscoreInputs<'a> {
        hkdf: liboscore::HkdfAlg,
        master_secret: &'a [u8],
        combined_salt: alloc::vec::Vec<u8>,
        context_id: Option<&'a [u8]>,
        aead: liboscore::AeadAlg,
        sender_id: &'a [u8],
        recipient_id: &'a [u8],
    }

    #[derive(Debug, Copy, Clone, defmt::Format)]
    #[non_exhaustive]
    pub enum DeriveError {
        NonceTooLong,
        InputSaltTooLong,
        IdTooLong,
        AlgorithmUnknown,
        EqualIds,
        WrongOscoreVersion,
        MissingEssentials,
    }

    impl From<liboscore::AlgorithmNotSupported> for DeriveError {
        fn from(_: liboscore::AlgorithmNotSupported) -> Self {
            DeriveError::AlgorithmUnknown
        }
    }

    impl From<liboscore::DeriveError> for DeriveError {
        fn from(_: liboscore::DeriveError) -> Self {
            // Could be the sender/recipient ID or the ID context
            DeriveError::IdTooLong
        }
    }

    /// Helper for derive() that preprocesses all input but doesn't perform OSCORE's internal key
    /// derivation yet
    fn derive_generic<'a>(
        material: &'a coset::OscoreInputMaterial,
        nonce1: &'a [u8],
        nonce2: &'a [u8],
        sender_id: &'a [u8],
        recipient_id: &'a [u8],
    ) -> Result<ConcreteOscoreInputs<'a>, DeriveError> {
        use coset::iana::EnumI64;

        let version = material
            .version
            .as_ref()
            .map(|&v| v.try_into())
            .unwrap_or(Ok(1));
        let master_secret = material
            .ms
            .as_deref()
            .ok_or(DeriveError::MissingEssentials)?;
        fn alg_as_i32(alg: &coset::Algorithm) -> Option<i32> {
            i32::try_from(match alg {
                coset::RegisteredLabelWithPrivate::Assigned(a) => a.to_i64(),
                coset::RegisteredLabelWithPrivate::PrivateUse(i) => *i,
                coset::RegisteredLabelWithPrivate::Text(_) => return None,
            })
            .ok()
        }
        let hkdf = liboscore::HkdfAlg::from_number(
            material
                .hkdf
                .as_ref()
                .map(alg_as_i32)
                .unwrap_or(Some(5)) // FIXME: magic constant; OSCORE says it's SHA-256 but doesn't give it
                // by number
                .ok_or(DeriveError::AlgorithmUnknown)?,
        )?;
        let aead = liboscore::AeadAlg::from_number(
            material
                .alg
                .as_ref()
                .map(alg_as_i32)
                .unwrap_or(Some(10)) // FIXME: magic constant; OSCORE's default algorithm
                .ok_or(DeriveError::AlgorithmUnknown)?,
        )?;
        let input_salt = material.salt.as_deref().unwrap_or(b"");
        let context_id = material.context_id.as_deref();

        // Let's do consistent input validation -- then we can simply unwrap later, plus we get
        // deterministic errors and don't fail just because the other components happened to be so
        // short things fit.
        if nonce1.len() > NONCE_MAX || nonce2.len() > NONCE_MAX {
            return Err(DeriveError::NonceTooLong);
        }

        if version != Ok(1) {
            return Err(DeriveError::WrongOscoreVersion);
        }

        if input_salt.len() > INPUT_SALT_MAX {
            return Err(DeriveError::InputSaltTooLong);
        }

        if sender_id == recipient_id {
            return Err(DeriveError::EqualIds);
        }

        // Not trying to shave the few bytes off the stack usage that could be freed if values for
        // NONCE_MAX etc were < 24
        const MAX_COMBINED_SALT: usize = 2 + INPUT_SALT_MAX + 2 + NONCE_MAX + 2 + NONCE_MAX;
        // ciborium_ll::Write is not implemented for heapless::Vec -- and as long as we depend on
        // ciborium in its current form, alloc isn't going away anyway. Once it does, it's trivial to
        // do the switch (for then it'll also have an implementation or heapless Vec):
        //
        // Workaround for https://github.com/enarx/ciborium/issues/66
        //
        // let mut combined_salt = heapless::Vec::<u8, MAX_COMBINED_SALT>::new();
        let mut combined_salt = alloc::vec::Vec::with_capacity(MAX_COMBINED_SALT);
        {
            // Following RFC 9203 Sectioin 4.3
            let mut salt_encoder = ciborium_ll::Encoder::from(&mut combined_salt);
            salt_encoder.bytes(input_salt, None).unwrap();
            salt_encoder.bytes(nonce1, None).unwrap();
            salt_encoder.bytes(nonce2, None).unwrap();
        }

        Ok(ConcreteOscoreInputs {
            hkdf,
            master_secret,
            combined_salt,
            context_id,
            aead,
            sender_id,
            recipient_id,
        })
    }

    pub fn derive(
        material: &coset::OscoreInputMaterial,
        nonce1: &[u8],
        nonce2: &[u8],
        sender_id: &[u8],
        recipient_id: &[u8],
    ) -> Result<liboscore::PrimitiveContext, DeriveError> {
        let oscore_inputs = derive_generic(material, nonce1, nonce2, sender_id, recipient_id)?;

        let immutables = liboscore::PrimitiveImmutables::derive(
            oscore_inputs.hkdf,
            oscore_inputs.master_secret,
            &oscore_inputs.combined_salt,
            oscore_inputs.context_id,
            oscore_inputs.aead,
            oscore_inputs.sender_id,
            oscore_inputs.recipient_id,
        )?;

        Ok(liboscore::PrimitiveContext::new_from_fresh_material(
            immutables,
        ))
    }

    #[cfg(test)]
    mod test {
        #[test]
        fn test_derive() {
            // From RFC9203 fig. 4, without the removed access token
            let token_response: &[u8] = &[
                164, 1, 73, 131, 67, 161, 1, 10, 162, 4, 76, 83, 24, 38, 2, 2, 25, 14, 16, 8, 161,
                4, 162, 0, 65, 1, 2, 80, 249, 175, 131, 131, 104, 227, 83, 231, 136, 136, 225, 66,
                107, 217, 78, 111,
            ];

            use dcaf::ToCborMap;
            let token_response =
                dcaf::AccessTokenResponse::deserialize_from(token_response).unwrap();
            let dcaf::ProofOfPossessionKey::OscoreInputMaterial(material) = token_response.cnf.unwrap() else {
                panic!("Unexpected PoP key");
            };
            // Nonces from RFC fig. 13
            let derived = super::derive_generic(
                &material,
                &[1, 138, 39, 143, 127, 170, 181, 90],
                &[37, 168, 153, 28, 215, 0, 172, 1],
                &[],
                &[0x01],
            )
            .unwrap();

            // Note that the RFC does not show that particular value (it doesn't contain test
            // vectors); for the example of a combined salt which it does show, it uses what is the
            // master secret in fig. 4 as the master salt.
            #[rustfmt::skip]
            assert_eq!(
                derived.combined_salt,
                [64, 72, 1, 138, 39, 143, 127, 170, 181, 90, 72, 37, 168, 153, 28, 215, 0, 172, 1 ]
            );
            assert_eq!(
                derived.master_secret,
                [249, 175, 131, 131, 104, 227, 83, 231, 136, 136, 225, 66, 107, 217, 78, 111]
            );
        }
    }
}

#[cfg(feature = "liboscore")]
pub use for_liboscore::{derive, DeriveError};
