use coset::CborSerializable;

fn main() {
    let response_from_ace_java = hex_literal::hex!("
a2 01 58 65 d0 83 44 a1  01 18 1f a1 05 4d 67 d8
13 d2 cd bc 28 59 f0 c2  e9 f3 30 58 4c f3 0b 8f
55 a8 af 8d 1d d2 0d c0  db 44 68 50 e6 45 39 39
6b 0f ac fd 8b ea ef fd  9b 03 93 98 6e f9 d2 f8
e7 18 a3 72 ef 4c 4f b9  a6 7e f2 d2 40 26 02 34
5a 76 71 d4 23 08 5f f3  14 48 5a 8a f1 fd e4 1f
10 dc 17 20 d0 23 64 d5  0b 08 a1 04 a4 00 41 02
02 50 a4 ac 59 1b d4 1c  d6 21 ef a7 92 53 6a 4e
e5 e0 05 41 8c 06 41 02
");
    use dcaf::ToCborMap;
    let response = dcaf::AccessTokenResponse::deserialize_from(response_from_ace_java.as_slice())
        .unwrap();
    dbg!(&response);

    println!("Before we process that, let's try a token from the Python cose library...");

    // created with
    // msg_new = cose.messages.Enc0Message( {1: 31}, {5: bytes.fromhex('67D813D2CDBC2859F0C2E9F330')}, cbor2.dumps({"cnf":"cnf"}))
    // msg_new.key = cose.keys.SymmetricKey(bytes(list(b'abc') + list(range(4, 33))))
    // msg_new.encode().hex()
    //
    // with the leading tag already stripped
    let python_token = hex_literal::hex!("8344a101181fa1054d67d813d2cdbc2859f0c2e9f3305819f4698e7a9dcf8d01c7e2995b2a23e283dedb617bcf52299da4");
    let envelope = coset::CoseEncrypt0::from_slice(&python_token).unwrap();
    dbg!(&envelope);
    let iv = envelope.unprotected.iv;
    let mut cipher: ace_oscore_helpers::aesccm::RustCryptoCcmCoseCipher::<aes::Aes256,  aead::generic_array::typenum::U16, aead::generic_array::typenum::U13> = ace_oscore_helpers::aesccm::RustCryptoCcmCoseCipher::new(
        aead::generic_array::arr![u8; 'a' as u8, 'b' as u8, 'c' as u8, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
        *aead::generic_array::GenericArray::from_slice(&iv),
        );
    dbg!(
        dcaf::decrypt_access_token(&python_token.to_vec(), &mut cipher, Some(&[]))
        );

    println!("I'd now send the access_token on...");

    /* [1..].to_vec(): Workaround for https://github.com/google/coset/pull/59, and dcaf's weird API
     * choice of using Vec */
    let token = response.access_token[1..].to_vec();

    // Pre-parsing to find the cipher to set up, and also populate its nonce
    // (dcaf's decrypt_access_token is lacking there IMO)
    let envelope = coset::CoseEncrypt0::from_slice(&token).unwrap();
    dbg!(&envelope);
    let iv = envelope.unprotected.iv;

    let mut cipher: ace_oscore_helpers::aesccm::RustCryptoCcmCoseCipher::<aes::Aes256,  aead::generic_array::typenum::U16, aead::generic_array::typenum::U13> = ace_oscore_helpers::aesccm::RustCryptoCcmCoseCipher::new(
        aead::generic_array::arr![u8; 'a' as u8, 'b' as u8, 'c' as u8, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
        *aead::generic_array::GenericArray::from_slice(&iv),
        );
    let claims = dcaf::decrypt_access_token(&token, &mut cipher, Some(&[])).unwrap();
    dbg!(&claims);
    let mut rest = claims.rest;
    let (type_, value) = rest.drain(..1).next().unwrap();
    assert!(dbg!(type_) == coset::cwt::ClaimName::Assigned(coset::iana::CwtClaimName::Cnf));
    let value = match value {
        ciborium::value::Value::Map(mut v) => v.drain(..).map(|(k, v)| (k.as_integer().unwrap().into(), v)).collect(),
        _ => panic!(),
    };
    let encrypted_pop_key = dcaf::common::cbor_values::ProofOfPossessionKey::try_from_cbor_map(value).unwrap();
    dbg!(&encrypted_pop_key);

    assert!(Some(encrypted_pop_key) == response.cnf);
}
