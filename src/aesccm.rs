//! Constructor for AES-CCM keys with which AS-RS communication (in the form access tokens) is
//! secured
//!
//! Source: <https://gist.github.com/falko17/3639876b57744c6dd2a166b5bc9cc126>
//!
//! This is not thoroughly documented in detail as the key constructions are subject to [ongoing
//! refactoring](https://github.com/namib-project/dcaf-rs/pull/10), and key construction for dcaf
//! will be vastly simplified when that step has concluded.
extern crate alloc;
use alloc::vec::Vec;

// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2022 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use aead::generic_array::{ArrayLength, GenericArray};
use aead::{Aead, Key, KeyInit, Payload};
use aes::cipher::{Block, BlockCipher, BlockEncrypt};
use ccm::consts::U16;
use ccm::{Ccm, NonceSize, TagSize};
use coset::{Algorithm, Header};
use dcaf::error::CoseCipherError;
use dcaf::token::CoseCipherCommon;
use dcaf::CoseEncrypt0Cipher;

pub struct RustCryptoCcmCoseCipher<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit,
    C::BlockSize: ArrayLength<Block<C>>,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    key: Key<Ccm<C, M, N>>,
    nonce: GenericArray<u8, N>,
}

impl<C, M, N> RustCryptoCcmCoseCipher<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit,
    C::BlockSize: ArrayLength<Block<C>>,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    pub fn new(
        key: Key<Ccm<C, M, N>>,
        nonce: GenericArray<u8, N>,
    ) -> RustCryptoCcmCoseCipher<C, M, N> {
        RustCryptoCcmCoseCipher { key, nonce }
    }
}

impl<C, M, N> CoseCipherCommon for RustCryptoCcmCoseCipher<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    type Error = aead::Error;

    fn header(
        &self,
        unprotected_header: &mut Header,
        protected_header: &mut Header,
    ) -> Result<(), CoseCipherError<Self::Error>> {
        if !protected_header.iv.is_empty() || !unprotected_header.iv.is_empty() {
            return Err(CoseCipherError::existing_header("iv"));
        }
        if protected_header.alg.is_some() || unprotected_header.alg.is_some() {
            return Err(CoseCipherError::existing_header("alg"));
        }
        protected_header.alg = Some(Algorithm::Assigned(
            coset::iana::Algorithm::AES_CCM_16_64_128, // Same algorithm as used in libdcaf
        ));
        protected_header.iv = Vec::from(self.nonce.as_slice());
        Ok(())
    }
}

impl<C, M, N> CoseEncrypt0Cipher for RustCryptoCcmCoseCipher<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit,
    C::BlockSize: ArrayLength<Block<C>>,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let ccm_instance = Ccm::<C, M, N>::new(&self.key);
        ccm_instance
            .encrypt(
                &self.nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("error during encryption")
    }

    fn decrypt(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CoseCipherCommon>::Error>> {
        let ccm_instance = Ccm::<C, M, N>::new(&self.key);
        ccm_instance
            .decrypt(
                &self.nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_e| CoseCipherError::DecryptionFailure)
    }
}
