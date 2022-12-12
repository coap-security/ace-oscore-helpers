use embedded_nal::UdpFullStack;
use embedded_nal::UdpClientStack;

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
        audience: Some("rs1"),
        key: aead::generic_array::arr![u8; 'a' as u8, 'b' as u8, 'c' as u8, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
    };

    let mut rs = ace_oscore_helpers::resourceserver::ResourceServer::<AppClaims>::new_with_association(association);

    stack.bind(&mut sock, 5683).expect("Can't bind to port");

    loop {
//         dbg!(&rs);

        let authz_info = ace_oscore_helpers::resourceserver::UnprotectedAuthzInfoEndpoint::new(&mut rs);

        use coap_handler_implementations::HandlerBuilder;
        let mut handler = coap_handler_implementations::new_dispatcher()
            .at(&["authz-info"], authz_info);

        match embedded_nal_minimal_coapserver::poll(&mut stack, &mut sock, &mut handler) {
            Err(embedded_nal::nb::Error::WouldBlock) => {
                // See <https://github.com/rust-embedded-community/embedded-nal/issues/47>
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            e => e.expect("UDP error during send/receive"),
        }
    }
}