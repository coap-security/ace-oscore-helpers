//! Collection of tools useful for implementing the ACE OSCORE profile (RFC9203)
//!
//! It is expected that parts of this might be moved into standalone crates, or into the coset or
//! dcaf crates.
#![no_std]

pub mod aesccm;
#[cfg(feature = "liboscore")]
pub mod resourceserver;
pub mod oscore_claims;

// FIXME: Provide a means to set up COSE keys rather than constructing keys manually
pub use aead;
pub use aes;

// from RFC9203
// FIXME: I'd rather provide encoding and decoding structs for payloads around /authz-info, but the
// CBOR encoder situation doesn't support the general writers yet.
pub const ACCESS_TOKEN: u64 = 1;
pub const NONCE1: u64 = 40;
pub const NONCE2: u64 = 42;
pub const ACE_CLIENT_RECIPIENTID: u64 = 43;
pub const ACE_SERVER_RECIPIENTID: u64 = 44;
