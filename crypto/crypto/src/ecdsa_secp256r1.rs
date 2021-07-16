// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module provides an API for the ECDSA signature scheme over the secp256r1 twisted curve as
//! as specified in [FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final) (Digital Signature Standard).
//!
//!
//! # Examples
#![allow(clippy::integer_arithmetic)]

use crate::{
    hash::{CryptoHash, CryptoHasher},
    traits::*,
};
use anyhow::{anyhow, Result};
use diem_crypto_derive::{DeserializeKey, SerializeKey, SilentDebug, SilentDisplay};
use mirai_annotations::*;
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use serde::Serialize;
use std::{
    convert::{TryFrom, TryInto},
    fmt,
};

/// An ECDSA secp256r1 private key
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct EcdsaPrivateKey(P256SigningKey);

#[cfg(feature = "assert-private-keys-not-cloneable")]
static_assertions::assert_not_impl_any!(EcdsaPrivateKey: Clone);

#[cfg(any(test, feature = "cloneable-private-keys"))]
impl Clone for EcdsaPrivateKey {
    fn clone(&self) -> Self {
        let private_bytes = self.0.to_bytes();
        let p256_signing_key = P256SigningKey::from_bytes(&private_bytes)
            .map_err(|_| CryptoMaterialError::DeserializationError)
            .expect("EcdsaPrivateKey cloning: from_bytes after to_bytes should not fail.");
        EcdsaPrivateKey(p256_signing_key)
    }
}

/// An ECDSA secp256r1 public key
#[derive(DeserializeKey, Clone, SerializeKey)]
pub struct EcdsaPublicKey(P256VerifyingKey);

#[cfg(mirai)]
use crate::tags::ValidatedPublicKeyTag;
#[cfg(not(mirai))]
struct ValidatedPublicKeyTag {}

/// An ECDSA secp256r1 signature
#[derive(DeserializeKey, Clone, SerializeKey)]
pub struct EcdsaSignature(P256Signature);

impl EcdsaPrivateKey {
    /// The length of the EcdsaPrivateKey.
    pub const LENGTH: usize = 32;

    /// Serialize an EcdsaPrivateKey.
    pub fn to_bytes(&self) -> [u8; EcdsaPrivateKey::LENGTH] {
        self.0
            .to_bytes()
            .try_into()
            .map_err(|_| CryptoMaterialError::SerializationError)
            .expect("EcdsaPrivateKey to_bytes should not fail.")
    }

    /// Deserialize an EcdsaPrivateKey without any validation checks apart from expected key size.
    fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<EcdsaPrivateKey, CryptoMaterialError> {
        if bytes.len() != EcdsaPrivateKey::LENGTH {
            Err(CryptoMaterialError::WrongLengthError)
        } else {
            let p256_signing_key = P256SigningKey::from_bytes(&bytes)
                .map_err(|_| CryptoMaterialError::DeserializationError)?;
            Ok(EcdsaPrivateKey(p256_signing_key))
        }
    }

    /// Private function aimed at minimizing code duplication between sign
    /// methods of the SigningKey implementation. This should remain private.
    fn sign_arbitrary_message(&self, message: &[u8]) -> EcdsaSignature {
        EcdsaSignature(self.0.sign(message))
    }
}

impl EcdsaPublicKey {
    /// The length of the EcdsaPublicKey
    pub const LENGTH: usize = 33;

    /// Serialize an EcdsaPublicKey.
    pub fn to_bytes(&self) -> [u8; EcdsaPublicKey::LENGTH] {
        self.0
            .to_encoded_point(true)
            .to_bytes()
            // Note that we expect 33 bytes; unfortunately, Rust supports slice -> array conversion
            // using try_into for up to 32 elements. A temp hack is via slice -> vec -> array.
            .to_vec()
            .try_into()
            .map_err(|_| CryptoMaterialError::SerializationError)
            .expect("Serialization of EcdsaPublicKey should not fail.")
    }

    /// Deserialize an EcdsaPublicKey without any validation checks apart from expected key size.
    pub(crate) fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<EcdsaPublicKey, CryptoMaterialError> {
        if bytes.len() != EcdsaPublicKey::LENGTH {
            return Err(CryptoMaterialError::WrongLengthError);
        }
        let encoded_point = p256::EncodedPoint::from_bytes(&bytes)
            .map_err(|_| CryptoMaterialError::DeserializationError)?;
        let p256_verifying_key = P256VerifyingKey::from_encoded_point(&encoded_point)
            .map_err(|_| CryptoMaterialError::DeserializationError)?;
        Ok(EcdsaPublicKey(p256_verifying_key))
    }
}

impl EcdsaSignature {
    /// The length of the EcdsaSignature
    pub const LENGTH: usize = 64;

    /// Serialize an EcdsaSignature.
    pub fn to_bytes(&self) -> [u8; EcdsaSignature::LENGTH] {
        self.to_compressed_signature_bytes()
    }

    /// Deserialize an EcdsaSignature without any validation checks
    /// apart from expected key size.
    pub(crate) fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<EcdsaSignature, CryptoMaterialError> {
        if bytes.len() != EcdsaSignature::LENGTH {
            return Err(CryptoMaterialError::WrongLengthError);
        }
        let p256_signature = P256Signature::try_from(bytes)
            .map_err(|_| CryptoMaterialError::DeserializationError)?;
        Ok(EcdsaSignature(p256_signature))
    }

    // Compressing signature to 64 bytes via concatenated r and s signature parts.
    fn to_compressed_signature_bytes(&self) -> [u8; EcdsaSignature::LENGTH] {
        let mut sig_bytes = [0u8; EcdsaSignature::LENGTH];
        sig_bytes[..32].copy_from_slice(&self.0.r().to_bytes());
        sig_bytes[32..].copy_from_slice(&self.0.s().to_bytes());
        sig_bytes
    }

    // TODO: uncomment when needed in tests.
    // /// return an all-zero signature (for test only)
    // #[cfg(any(test, feature = "fuzzing"))]
    // pub fn dummy_signature() -> Self {
    //     Self::from_bytes_unchecked(&[0u8; Self::LENGTH]).unwrap()
    // }
}

///////////////////////
// PrivateKey Traits //
///////////////////////

impl PrivateKey for EcdsaPrivateKey {
    type PublicKeyMaterial = EcdsaPublicKey;
}

impl SigningKey for EcdsaPrivateKey {
    type VerifyingKeyMaterial = EcdsaPublicKey;
    type SignatureMaterial = EcdsaSignature;

    fn sign<T: CryptoHash + Serialize>(&self, message: &T) -> EcdsaSignature {
        let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)
            .expect("Serialization of signable material should not fail.");
        EcdsaPrivateKey::sign_arbitrary_message(&self, bytes.as_ref())
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn sign_arbitrary_message(&self, message: &[u8]) -> EcdsaSignature {
        EcdsaPrivateKey::sign_arbitrary_message(self, message)
    }
}

impl Uniform for EcdsaPrivateKey {
    fn generate<R>(rng: &mut R) -> Self
    where
        R: ::rand::RngCore + ::rand::CryptoRng,
    {
        let signing_key = P256SigningKey::random(rng);
        EcdsaPrivateKey(signing_key)
    }
}

impl PartialEq<Self> for EcdsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for EcdsaPrivateKey {}

// We could have a distinct kind of validation for the PrivateKey, for
// ex. checking the derived PublicKey is valid?
impl TryFrom<&[u8]> for EcdsaPrivateKey {
    type Error = CryptoMaterialError;

    /// Deserialize an EcdsaPrivateKey. This method will also check for key validity.
    fn try_from(bytes: &[u8]) -> std::result::Result<EcdsaPrivateKey, CryptoMaterialError> {
        // TODO: ensure that P256 crate exhausts the required private key validation checks.
        EcdsaPrivateKey::from_bytes_unchecked(bytes)
    }
}

impl Length for EcdsaPrivateKey {
    fn length(&self) -> usize {
        Self::LENGTH
    }
}

impl ValidCryptoMaterial for EcdsaPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl Genesis for EcdsaPrivateKey {
    fn genesis() -> Self {
        let mut buf = [0u8; EcdsaPrivateKey::LENGTH];
        buf[EcdsaPrivateKey::LENGTH - 1] = 1;
        Self::try_from(buf.as_ref()).unwrap()
    }
}

//////////////////////
// PublicKey Traits //
//////////////////////

// Implementing From<&PrivateKey<...>> allows to derive a public key in a more elegant fashion
impl From<&EcdsaPrivateKey> for EcdsaPublicKey {
    fn from(private_key: &EcdsaPrivateKey) -> Self {
        EcdsaPublicKey(P256VerifyingKey::from(&private_key.0))
    }
}

// We deduce PublicKey from this
impl PublicKey for EcdsaPublicKey {
    type PrivateKeyMaterial = EcdsaPrivateKey;
}

impl std::hash::Hash for EcdsaPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = self.to_bytes();
        state.write(&encoded_pubkey);
    }
}

// Those are required by the implementation of hash above
impl PartialEq for EcdsaPublicKey {
    fn eq(&self, other: &EcdsaPublicKey) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for EcdsaPublicKey {}

// We deduce VerifyingKey from pointing to the signature material
// we get the ability to do `pubkey.validate(msg, signature)`
impl VerifyingKey for EcdsaPublicKey {
    type SigningKeyMaterial = EcdsaPrivateKey;
    type SignatureMaterial = EcdsaSignature;
}

impl fmt::Display for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0.to_encoded_point(true)))
    }
}

impl fmt::Debug for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcdsaPublicKey({})", self)
    }
}

impl TryFrom<&[u8]> for EcdsaPublicKey {
    type Error = CryptoMaterialError;

    /// Deserialize an EcdsaPublicKey. This method will also check for key validity, for instance
    /// it will only deserialize keys that are safe against small subgroup attacks.
    fn try_from(bytes: &[u8]) -> std::result::Result<EcdsaPublicKey, CryptoMaterialError> {
        let public_key = EcdsaPublicKey::from_bytes_unchecked(bytes)?;
        add_tag!(&public_key, ValidatedPublicKeyTag); // This key has gone through validity checks.
        Ok(public_key)
    }
}

impl Length for EcdsaPublicKey {
    fn length(&self) -> usize {
        EcdsaPublicKey::LENGTH
    }
}

impl ValidCryptoMaterial for EcdsaPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).to_bytes().to_vec()
    }
}

//////////////////////
// Signature Traits //
//////////////////////

impl Signature for EcdsaSignature {
    type VerifyingKeyMaterial = EcdsaPublicKey;
    type SigningKeyMaterial = EcdsaPrivateKey;

    /// Verifies that the provided signature is valid for the provided
    /// message, according to the RFC8032 algorithm. This strict verification performs the
    /// recommended check of 5.1.7 §3, on top of the required RFC8032 verifications.
    fn verify<T: CryptoHash + Serialize>(
        &self,
        message: &T,
        public_key: &EcdsaPublicKey,
    ) -> Result<()> {
        let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)?;
        Self::verify_arbitrary_msg(self, &bytes, public_key)
    }

    /// Checks that `self` is valid for an arbitrary &[u8] `message` using `public_key`.
    /// Outside of this crate, this particular function should only be used for native signature
    /// verification in move
    fn verify_arbitrary_msg(&self, message: &[u8], public_key: &EcdsaPublicKey) -> Result<()> {
        public_key
            .0
            .verify(message, &self.0)
            .map_err(|e| anyhow!("{}", e))
            .and(Ok(()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl Length for EcdsaSignature {
    fn length(&self) -> usize {
        EcdsaSignature::LENGTH
    }
}

impl ValidCryptoMaterial for EcdsaSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl std::hash::Hash for EcdsaSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_signature = self.to_bytes();
        state.write(&encoded_signature);
    }
}

impl TryFrom<&[u8]> for EcdsaSignature {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> std::result::Result<EcdsaSignature, CryptoMaterialError> {
        EcdsaSignature::from_bytes_unchecked(bytes)
    }
}

// Those are required by the implementation of hash above
impl PartialEq for EcdsaSignature {
    fn eq(&self, other: &EcdsaSignature) -> bool {
        self.to_bytes()[..] == other.to_bytes()[..]
    }
}

impl Eq for EcdsaSignature {}

impl fmt::Display for EcdsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl fmt::Debug for EcdsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcdsaSignature({})", self)
    }
}

// TODO: Add proptests
// #[cfg(any(test, feature = "fuzzing"))]
// use crate::test_utils::{self, KeyPair};

// /// Produces a uniformly random ecdsa keypair from a seed
// #[cfg(any(test, feature = "fuzzing"))]
// pub fn keypair_strategy() -> impl Strategy<Value = KeyPair<EcdsaPrivateKey, EcdsaPublicKey>> {
//     test_utils::uniform_keypair_strategy::<EcdsaPrivateKey, EcdsaPublicKey>()
// }

#[cfg(any(test, feature = "fuzzing"))]
use proptest::prelude::*;

#[cfg(any(test, feature = "fuzzing"))]
impl proptest::arbitrary::Arbitrary for EcdsaPublicKey {
    type Parameters = ();
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        crate::test_utils::uniform_keypair_strategy::<EcdsaPrivateKey, EcdsaPublicKey>()
            .prop_map(|v| v.public_key)
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[test]
fn sign_verify() {
    let message = b"Hello world";
    let message2 = b"Hello world2";
    let key_bytes = b"12345678901234567890123456789012";

    let private_key = EcdsaPrivateKey::from_bytes_unchecked(key_bytes).unwrap();
    let public_key = EcdsaPublicKey::from(&private_key);
    let signature = private_key.sign_arbitrary_message(&message.to_vec().as_slice());
    let signature2 = private_key.sign_arbitrary_message(&message2.to_vec().as_slice());

    assert!(signature
        .verify_arbitrary_msg(&message.to_vec().as_slice(), &public_key)
        .is_ok());
    assert!(signature2
        .verify_arbitrary_msg(&message.to_vec().as_slice(), &public_key)
        .is_err());
}

#[test]
fn serialization_full_cycle() {
    let message = b"Hello world";
    let key_bytes = b"12345678901234567890123456789012";

    let private_key = EcdsaPrivateKey::from_bytes_unchecked(key_bytes).unwrap();
    let private_key_2 = EcdsaPrivateKey::from_bytes_unchecked(&private_key.to_bytes()).unwrap();
    assert_eq!(private_key, private_key_2);

    let public_key = EcdsaPublicKey::from(&private_key);
    let public_key2 = EcdsaPublicKey::from_bytes_unchecked(&public_key.to_bytes()).unwrap();
    assert_eq!(public_key, public_key2);

    let signature = private_key.sign_arbitrary_message(&message.to_vec().as_slice());
    let signature2 = EcdsaSignature::from_bytes_unchecked(&signature.to_bytes()).unwrap();
    assert_eq!(signature, signature2);
}
