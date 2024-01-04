// SPDX-FileCopyrightText: Copyright 2022 EDF (Électricité de France S.A.)
// SPDX-License-Identifier: BSD-3-Clause
// See README for all details on copyright, authorship and license.
//! A standalone RS that doesn't really offer any resources other than /authz-info
//!
//! This can be tested by running the following:
//!
//! ```sh
//! $ diag2cbor.rb > post-me.cbor
//! {1: h'8344A101181FA1054DA175FD2F60B3AFBDA3EBC31124583566E0A6CB3C45DB9D1D632CDA1314479B1D0EC2585384349F0B0B7DB58AD0D8C12E8D4AA549FEA0F46C7ED6CA14E04AA9EA368E3602', 40: h'34', 43: h'01'}
//! ^D
//! $ aiocoap-client coap://localhost/authz-info -m POST --payload @post-me.cbor
//! CBOR message shown in naïve Python decoding
//! {42: b'\x04', 44: b'\x02'}
//! ```

use embedded_nal::UdpClientStack;
use embedded_nal::UdpFullStack;

#[derive(Debug)]
struct AppClaims(String);

impl<'a> TryFrom<&'a coset::cwt::ClaimsSet> for AppClaims {
    type Error = core::convert::Infallible;
    fn try_from(claimsset: &'a coset::cwt::ClaimsSet) -> Result<Self, core::convert::Infallible> {
        Ok(Self(format!("{:?}", claimsset)))
    }
}

fn main() {
    let mut stack = std_embedded_nal::Stack::default();

    let mut sock = stack.socket().expect("Can't create a socket");

    // The data between the AS and the rs1 of the ACE-Java demo sever
    let association = ace_oscore_helpers::resourceserver::RsAsSharedData {
        issuer: Some("AS"),
        audience: "rs1",
        as_uri: "http://example.com/token",
        // When using different material, consider keeping src/resourcecerver.rs
        // test_token_processing in sync.
        key: aead::generic_array::arr![u8; 'a' as u8, 'b' as u8, 'c' as u8, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
    };

    let rs = ace_oscore_helpers::resourceserver::ResourceServer::<AppClaims, _>::new_with_association_and_randomness(
        association,
        rand::thread_rng(),
    );
    let rs = core::cell::RefCell::new(rs);

    stack.bind(&mut sock, 5683).expect("Can't bind to port");

    loop {
        let authz_info =
            ace_oscore_helpers::resourceserver::UnprotectedAuthzInfoEndpoint::new(|| {
                rs.try_borrow_mut().ok()
            });

        use coap_handler_implementations::HandlerBuilder;
        let mut handler =
            coap_handler_implementations::new_dispatcher().at(&["authz-info"], authz_info);

        match embedded_nal_minimal_coapserver::poll(&mut stack, &mut sock, &mut handler) {
            Err(embedded_nal::nb::Error::WouldBlock) => {
                // See <https://github.com/rust-embedded-community/embedded-nal/issues/47>
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            e => e.expect("UDP error during send/receive"),
        }
    }
}
