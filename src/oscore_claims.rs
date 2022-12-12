//! Extractor for [coset::OscoreInputMaterial] (proposed in
//! [PR58](https://github.com/google/coset/pull/58)) from a [coset::cwt::ClaimsSet].
//!
//! This is not yet ready for inclusion in `coset`, not only because it's depending on a PR, but
//! also because an intermediate structure is implemented in `dcaf`:
//! [dcaf::common::cbor_values::ProofOfPossessionKey].

/// Error type indicating that a token does not contain usable credentials to set up OSCORE through
/// the ACE OSCORE profile
#[derive(defmt::Format)]
pub struct NoOscoreCnf;

// This takes ownership of a ClaimsSet because the i128 keyed map version dcaf works with contains
// owned Value items.
pub fn extract_oscore(mut claims: coset::cwt::ClaimsSet) -> Result<coset::OscoreInputMaterial, NoOscoreCnf> {
    let mut cnfs = claims.rest.drain(..)
        .filter(|(key, _)| matches!(key, coset::RegisteredLabelWithPrivate::Assigned(coset::iana::CwtClaimName::Cnf)));

    // That's all a mouthful given that the parsing CDDL would be a two-liner...

    let (_, cnf) = cnfs.next()
        .ok_or(NoOscoreCnf)?;
    if cnfs.next().is_some() {
        // Duplicate key
        return Err(NoOscoreCnf);
    }

    let cnf = match cnf {
        // This is mainly impedance matching between how dcaf treats maps, and how coset uses Value
        ciborium::value::Value::Map(mut v) => v.drain(..).map(|(k, v)| (k.as_integer().unwrap().into(), v)).collect(),
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
