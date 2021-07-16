// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module provides an API for the PureEdDSA signature scheme over the ed25519 twisted
//! Edwards curve as defined in [RFC8032](https://tools.ietf.org/html/rfc8032).
//!
//! Signature verification also checks and rejects non-canonical signatures.
//!
//! # Examples
//!
//! ```
//! use diem_crypto_derive::{CryptoHasher, BCSCryptoHash};
//! use diem_crypto::{
//!     ed25519::*,
//!     traits::{Signature, SigningKey, Uniform},
//! };
//! use rand::{rngs::StdRng, SeedableRng};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
//! pub struct TestCryptoDocTest(String);
//! let message = TestCryptoDocTest("Test message".to_string());
//!
//! let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
//! let private_key = Ed25519PrivateKey::generate(&mut rng);
//! let public_key: Ed25519PublicKey = (&private_key).into();
//! let signature = private_key.sign(&message);
//! assert!(signature.verify(&message, &public_key).is_ok());
//! ```
//! **Note**: The above example generates a private key using a private function intended only for
//! testing purposes. Production code should find an alternate means for secure key generation.
#![allow(clippy::integer_arithmetic)]

use crate::{
    hash::{CryptoHash, CryptoHasher},
    traits::*,
};
use anyhow::{anyhow, Result};
use core::convert::TryFrom;
use diem_crypto_derive::{DeserializeKey, SerializeKey, SilentDebug, SilentDisplay};
use mirai_annotations::*;
use serde::Serialize;
use std::{cmp::Ordering, fmt};

pub use ed25519_dalek;

/// The length of the Ed25519PrivateKey
pub const ED25519_PRIVATE_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
/// The length of the Ed25519PublicKey
pub const ED25519_PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
/// The length of the Ed25519Signature
pub const ED25519_SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// The order of ed25519 as defined in [RFC8032](https://tools.ietf.org/html/rfc8032).
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// An Ed25519 private key
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct Ed25519PrivateKey(ed25519_dalek::SecretKey);

#[cfg(feature = "assert-private-keys-not-cloneable")]
static_assertions::assert_not_impl_any!(Ed25519PrivateKey: Clone);

#[cfg(any(test, feature = "cloneable-private-keys"))]
impl Clone for Ed25519PrivateKey {
    fn clone(&self) -> Self {
        let serialized: &[u8] = &(self.to_bytes());
        Ed25519PrivateKey::try_from(serialized).unwrap()
    }
}

/// An Ed25519 public key
#[derive(DeserializeKey, Clone, SerializeKey)]
pub struct Ed25519PublicKey(ed25519_dalek::PublicKey);

#[cfg(mirai)]
use crate::tags::ValidatedPublicKeyTag;
#[cfg(not(mirai))]
struct ValidatedPublicKeyTag {}

/// An Ed25519 signature
#[derive(DeserializeKey, Clone, SerializeKey)]
pub struct Ed25519Signature(ed25519_dalek::Signature);

impl Ed25519PrivateKey {
    /// The length of the Ed25519PrivateKey
    pub const LENGTH: usize = ED25519_PRIVATE_KEY_LENGTH;

    /// Serialize an Ed25519PrivateKey.
    pub fn to_bytes(&self) -> [u8; ED25519_PRIVATE_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// Deserialize an Ed25519PrivateKey without any validation checks apart from expected key size.
    fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<Ed25519PrivateKey, CryptoMaterialError> {
        match ed25519_dalek::SecretKey::from_bytes(bytes) {
            Ok(dalek_secret_key) => Ok(Ed25519PrivateKey(dalek_secret_key)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }

    /// Private function aimed at minimizing code duplication between sign
    /// methods of the SigningKey implementation. This should remain private.
    fn sign_arbitrary_message(&self, message: &[u8]) -> Ed25519Signature {
        let secret_key: &ed25519_dalek::SecretKey = &self.0;
        let public_key: Ed25519PublicKey = self.into();
        let expanded_secret_key: ed25519_dalek::ExpandedSecretKey =
            ed25519_dalek::ExpandedSecretKey::from(secret_key);
        let sig = expanded_secret_key.sign(message.as_ref(), &public_key.0);
        Ed25519Signature(sig)
    }
}

impl Ed25519PublicKey {
    /// Serialize an Ed25519PublicKey.
    pub fn to_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// Deserialize an Ed25519PublicKey without any validation checks apart from expected key size.
    pub(crate) fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<Ed25519PublicKey, CryptoMaterialError> {
        match ed25519_dalek::PublicKey::from_bytes(bytes) {
            Ok(dalek_public_key) => Ok(Ed25519PublicKey(dalek_public_key)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }

    /// Deserialize an Ed25519PublicKey from its representation as an x25519
    /// public key, along with an indication of sign. This is meant to
    /// compensate for the poor key storage capabilities of key management
    /// solutions, and NOT to promote double usage of keys under several
    /// schemes, which would lead to BAD vulnerabilities.
    ///
    /// Arguments:
    /// - `x25519_bytes`: bit representation of a public key in clamped
    ///            Montgomery form, a.k.a. the x25519 public key format.
    /// - `negative`: whether to interpret the given point as a negative point,
    ///               as the Montgomery form erases the sign byte. By XEdDSA
    ///               convention, if you expect to ever convert this back to an
    ///               x25519 public key, you should pass `false` for this
    ///               argument.
    #[cfg(test)]
    pub(crate) fn from_x25519_public_bytes(
        x25519_bytes: &[u8],
        negative: bool,
    ) -> Result<Self, CryptoMaterialError> {
        if x25519_bytes.len() != 32 {
            return Err(CryptoMaterialError::DeserializationError);
        }
        let key_bits = {
            let mut bits = [0u8; 32];
            bits.copy_from_slice(x25519_bytes);
            bits
        };
        let mtg_point = curve25519_dalek::montgomery::MontgomeryPoint(key_bits);
        let sign = if negative { 1u8 } else { 0u8 };
        let ed_point = mtg_point
            .to_edwards(sign)
            .ok_or(CryptoMaterialError::DeserializationError)?;
        Ed25519PublicKey::try_from(&ed_point.compress().as_bytes()[..])
    }
}

impl Ed25519Signature {
    /// The length of the Ed25519Signature
    pub const LENGTH: usize = ED25519_SIGNATURE_LENGTH;

    /// Serialize an Ed25519Signature.
    pub fn to_bytes(&self) -> [u8; ED25519_SIGNATURE_LENGTH] {
        self.0.to_bytes()
    }

    /// Deserialize an Ed25519Signature without any validation checks (malleability)
    /// apart from expected key size.
    pub(crate) fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<Ed25519Signature, CryptoMaterialError> {
        match ed25519_dalek::Signature::try_from(bytes) {
            Ok(dalek_signature) => Ok(Ed25519Signature(dalek_signature)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }

    /// return an all-zero signature (for test only)
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn dummy_signature() -> Self {
        Self::from_bytes_unchecked(&[0u8; Self::LENGTH]).unwrap()
    }

    /// Check for correct size and third-party based signature malleability issues.
    /// This method is required to ensure that given a valid signature for some message under some
    /// key, an attacker cannot produce another valid signature for the same message and key.
    ///
    /// According to [RFC8032](https://tools.ietf.org/html/rfc8032), signatures comprise elements
    /// {R, S} and we should enforce that S is of canonical form (smaller than L, where L is the
    /// order of edwards25519 curve group) to prevent signature malleability. Without this check,
    /// one could add a multiple of L into S and still pass signature verification, resulting in
    /// a distinct yet valid signature.
    ///
    /// This method does not check the R component of the signature, because R is hashed during
    /// signing and verification to compute h = H(ENC(R) || ENC(A) || M), which means that a
    /// third-party cannot modify R without being detected.
    ///
    /// Note: It's true that malicious signers can already produce varying signatures by
    /// choosing a different nonce, so this method protects against malleability attacks performed
    /// by a non-signer.
    pub fn check_malleability(bytes: &[u8]) -> std::result::Result<(), CryptoMaterialError> {
        if bytes.len() != ED25519_SIGNATURE_LENGTH {
            return Err(CryptoMaterialError::WrongLengthError);
        }
        if !check_s_lt_l(&bytes[32..]) {
            return Err(CryptoMaterialError::CanonicalRepresentationError);
        }
        Ok(())
    }
}

///////////////////////
// PrivateKey Traits //
///////////////////////

impl PrivateKey for Ed25519PrivateKey {
    type PublicKeyMaterial = Ed25519PublicKey;
}

impl SigningKey for Ed25519PrivateKey {
    type VerifyingKeyMaterial = Ed25519PublicKey;
    type SignatureMaterial = Ed25519Signature;

    fn sign<T: CryptoHash + Serialize>(&self, message: &T) -> Ed25519Signature {
        let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)
            .expect("Serialization of signable material should not fail.");
        Ed25519PrivateKey::sign_arbitrary_message(&self, bytes.as_ref())
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn sign_arbitrary_message(&self, message: &[u8]) -> Ed25519Signature {
        Ed25519PrivateKey::sign_arbitrary_message(self, message)
    }
}

impl Uniform for Ed25519PrivateKey {
    fn generate<R>(rng: &mut R) -> Self
    where
        R: ::rand::RngCore + ::rand::CryptoRng,
    {
        Ed25519PrivateKey(ed25519_dalek::SecretKey::generate(rng))
    }
}

impl PartialEq<Self> for Ed25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for Ed25519PrivateKey {}

// We could have a distinct kind of validation for the PrivateKey, for
// ex. checking the derived PublicKey is valid?
impl TryFrom<&[u8]> for Ed25519PrivateKey {
    type Error = CryptoMaterialError;

    /// Deserialize an Ed25519PrivateKey. This method will also check for key validity.
    fn try_from(bytes: &[u8]) -> std::result::Result<Ed25519PrivateKey, CryptoMaterialError> {
        // Note that the only requirement is that the size of the key is 32 bytes, something that
        // is already checked during deserialization of ed25519_dalek::SecretKey
        // Also, the underlying ed25519_dalek implementation ensures that the derived public key
        // is safe and it will not lie in a small-order group, thus no extra check for PublicKey
        // validation is required.
        Ed25519PrivateKey::from_bytes_unchecked(bytes)
    }
}

impl Length for Ed25519PrivateKey {
    fn length(&self) -> usize {
        Self::LENGTH
    }
}

impl ValidCryptoMaterial for Ed25519PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl Genesis for Ed25519PrivateKey {
    fn genesis() -> Self {
        let mut buf = [0u8; ED25519_PRIVATE_KEY_LENGTH];
        buf[ED25519_PRIVATE_KEY_LENGTH - 1] = 1;
        Self::try_from(buf.as_ref()).unwrap()
    }
}

//////////////////////
// PublicKey Traits //
//////////////////////

// Implementing From<&PrivateKey<...>> allows to derive a public key in a more elegant fashion
impl From<&Ed25519PrivateKey> for Ed25519PublicKey {
    fn from(private_key: &Ed25519PrivateKey) -> Self {
        let secret: &ed25519_dalek::SecretKey = &private_key.0;
        let public: ed25519_dalek::PublicKey = secret.into();
        Ed25519PublicKey(public)
    }
}

// We deduce PublicKey from this
impl PublicKey for Ed25519PublicKey {
    type PrivateKeyMaterial = Ed25519PrivateKey;
}

impl std::hash::Hash for Ed25519PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = self.to_bytes();
        state.write(&encoded_pubkey);
    }
}

// Those are required by the implementation of hash above
impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Ed25519PublicKey) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for Ed25519PublicKey {}

// We deduce VerifyingKey from pointing to the signature material
// we get the ability to do `pubkey.validate(msg, signature)`
impl VerifyingKey for Ed25519PublicKey {
    type SigningKeyMaterial = Ed25519PrivateKey;
    type SignatureMaterial = Ed25519Signature;
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0.as_bytes()))
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PublicKey({})", self)
    }
}

impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = CryptoMaterialError;

    /// Deserialize an Ed25519PublicKey. This method will also check for key validity, for instance
    ///  it will only deserialize keys that are safe against small subgroup attacks.
    fn try_from(bytes: &[u8]) -> std::result::Result<Ed25519PublicKey, CryptoMaterialError> {
        // We need to access the Edwards point which is not directly accessible from
        // ed25519_dalek::PublicKey, so we need to do some custom deserialization.
        if bytes.len() != ED25519_PUBLIC_KEY_LENGTH {
            return Err(CryptoMaterialError::WrongLengthError);
        }

        let mut bits = [0u8; ED25519_PUBLIC_KEY_LENGTH];
        bits.copy_from_slice(&bytes[..ED25519_PUBLIC_KEY_LENGTH]);

        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(bits);
        let point = compressed
            .decompress()
            .ok_or(CryptoMaterialError::DeserializationError)?;

        // Check if the point lies on a small subgroup. This is required
        // when using curves with a small cofactor (in ed25519, cofactor = 8).
        if point.is_small_order() {
            return Err(CryptoMaterialError::SmallSubgroupError);
        }

        // Unfortunately, tuple struct `PublicKey` is private so we cannot
        // Ok(Ed25519PublicKey(ed25519_dalek::PublicKey(compressed, point)))
        // and we have to again invoke deserialization.
        let public_key = Ed25519PublicKey::from_bytes_unchecked(bytes)?;
        add_tag!(&public_key, ValidatedPublicKeyTag); // This key has gone through validity checks.
        Ok(public_key)
    }
}

impl Length for Ed25519PublicKey {
    fn length(&self) -> usize {
        ED25519_PUBLIC_KEY_LENGTH
    }
}

impl ValidCryptoMaterial for Ed25519PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

//////////////////////
// Signature Traits //
//////////////////////

impl Signature for Ed25519Signature {
    type VerifyingKeyMaterial = Ed25519PublicKey;
    type SigningKeyMaterial = Ed25519PrivateKey;

    /// Verifies that the provided signature is valid for the provided
    /// message, according to the RFC8032 algorithm. This strict verification performs the
    /// recommended check of 5.1.7 §3, on top of the required RFC8032 verifications.
    fn verify<T: CryptoHash + Serialize>(
        &self,
        message: &T,
        public_key: &Ed25519PublicKey,
    ) -> Result<()> {
        // Public keys should be validated to be safe against small subgroup attacks, etc.
        precondition!(has_tag!(public_key, ValidatedPublicKeyTag));
        let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)?;
        Self::verify_arbitrary_msg(self, &bytes, public_key)
    }

    /// Checks that `self` is valid for an arbitrary &[u8] `message` using `public_key`.
    /// Outside of this crate, this particular function should only be used for native signature
    /// verification in move
    fn verify_arbitrary_msg(&self, message: &[u8], public_key: &Ed25519PublicKey) -> Result<()> {
        // Public keys should be validated to be safe against small subgroup attacks, etc.
        precondition!(has_tag!(public_key, ValidatedPublicKeyTag));
        Ed25519Signature::check_malleability(&self.to_bytes())?;

        public_key
            .0
            .verify_strict(message, &self.0)
            .map_err(|e| anyhow!("{}", e))
            .and(Ok(()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Batch signature verification as described in the original EdDSA article
    /// by Bernstein et al. "High-speed high-security signatures". Current implementation works for
    /// signatures on the same message and it checks for malleability.
    #[cfg(feature = "batch")]
    fn batch_verify<T: CryptoHash + Serialize>(
        message: &T,
        keys_and_signatures: Vec<(Self::VerifyingKeyMaterial, Self)>,
    ) -> Result<()> {
        for (_, sig) in keys_and_signatures.iter() {
            Ed25519Signature::check_malleability(&sig.to_bytes())?
        }
        let mut message_bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
        bcs::serialize_into(&mut message_bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)?;

        let batch_argument = keys_and_signatures
            .iter()
            .map(|(key, signature)| (key.0, signature.0));
        let (dalek_public_keys, dalek_signatures): (Vec<_>, Vec<_>) = batch_argument.unzip();
        let message_ref = &(&message_bytes)[..];
        // The original batching algorithm works for different messages and it expects as many
        // messages as the number of signatures. In our case, we just populate the same
        // message to meet dalek's api requirements.
        let messages = vec![message_ref; dalek_signatures.len()];
        ed25519_dalek::verify_batch(&messages[..], &dalek_signatures[..], &dalek_public_keys[..])
            .map_err(|e| anyhow!("{}", e))?;
        Ok(())
    }
}

impl Length for Ed25519Signature {
    fn length(&self) -> usize {
        ED25519_SIGNATURE_LENGTH
    }
}

impl ValidCryptoMaterial for Ed25519Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl std::hash::Hash for Ed25519Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_signature = self.to_bytes();
        state.write(&encoded_signature);
    }
}

impl TryFrom<&[u8]> for Ed25519Signature {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Ed25519Signature, CryptoMaterialError> {
        Ed25519Signature::check_malleability(bytes)?;
        Ed25519Signature::from_bytes_unchecked(bytes)
    }
}

// Those are required by the implementation of hash above
impl PartialEq for Ed25519Signature {
    fn eq(&self, other: &Ed25519Signature) -> bool {
        self.to_bytes()[..] == other.to_bytes()[..]
    }
}

impl Eq for Ed25519Signature {}

impl fmt::Display for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0.to_bytes()[..]))
    }
}

impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Signature({})", self)
    }
}

/// Check if S < L to capture invalid signatures.
fn check_s_lt_l(s: &[u8]) -> bool {
    for i in (0..32).rev() {
        match s[i].cmp(&L[i]) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            _ => {}
        }
    }
    // As this stage S == L which implies a non canonical S.
    false
}

#[cfg(any(test, feature = "fuzzing"))]
use crate::test_utils::{self, KeyPair};

/// Produces a uniformly random ed25519 keypair from a seed
#[cfg(any(test, feature = "fuzzing"))]
pub fn keypair_strategy() -> impl Strategy<Value = KeyPair<Ed25519PrivateKey, Ed25519PublicKey>> {
    test_utils::uniform_keypair_strategy::<Ed25519PrivateKey, Ed25519PublicKey>()
}

#[cfg(any(test, feature = "fuzzing"))]
use proptest::prelude::*;

#[cfg(any(test, feature = "fuzzing"))]
impl proptest::arbitrary::Arbitrary for Ed25519PublicKey {
    type Parameters = ();
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        crate::test_utils::uniform_keypair_strategy::<Ed25519PrivateKey, Ed25519PublicKey>()
            .prop_map(|v| v.public_key)
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}
