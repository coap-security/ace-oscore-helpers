//! Collection of tools useful for implementing the ACE OSCORE profile (RFC9203)
//!
//! It is expected that parts of this might be moved into standalone crates, or into the coset or
//! dcaf crates.
#![no_std]

pub mod aesccm;
pub mod resourceserver;
pub mod oscore_claims;

// FIXME: Provide a means to set up COSE keys rather than constructing keys manually
pub use aead;
pub use aes;
