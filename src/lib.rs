// SPDX-FileCopyrightText: Copyright 2022 EDF (Électricité de France S.A.)
// SPDX-License-Identifier: BSD-3-Clause
// See README for all details on copyright, authorship and license.
//! Collection of tools useful for implementing the ACE OSCORE profile (RFC9203)
//!
//! It is expected that parts of this might be moved into standalone crates, or into the coset or
//! dcaf crates.
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod ciborium_helpers;

pub mod aesccm;
pub mod oscore_claims;
#[cfg(feature = "liboscore")]
pub mod resourceserver;

pub mod request_creation_hints;

// FIXME: Provide a means to set up COSE keys rather than constructing keys manually
pub use aead;
pub use aes;

// FIXME: I'd rather provide encoding and decoding structs for payloads around /authz-info, but the
// CBOR encoder situation doesn't support the general writers yet.
/// OAuth Parameters CBOR Mapping value for access_token (RFC9200 Section 8.10)
pub const ACCESS_TOKEN: u64 = 1;
/// OAuth Parameters CBOR Mapping value for nonce1 (RFC9203 Section 9.3)
pub const NONCE1: u64 = 40;
/// OAuth Parameters CBOR Mapping value for nonce2 (RFC9203 Section 9.3)
pub const NONCE2: u64 = 42;
/// OAuth Parameters CBOR Mapping value for ace_client_recipientid (RFC9203 Section 9.3)
pub const ACE_CLIENT_RECIPIENTID: u64 = 43;
/// OAuth Parameters CBOR Mapping value for ace_server_recipientid (RFC9203 Section 9.3)
pub const ACE_SERVER_RECIPIENTID: u64 = 44;
