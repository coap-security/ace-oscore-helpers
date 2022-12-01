#![no_std]

pub mod aesccm;

// FIXME: Provide a means to set up COSE keys rather than constructing keys manually
pub use aead;
pub use aes;
