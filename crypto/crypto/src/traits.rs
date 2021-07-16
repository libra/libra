// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module provides a generic set of traits for dealing with cryptographic primitives.
//!
//! For examples on how to use these traits, see the implementations of the [`ed25519`] or
//! [`bls12381`] modules.

use crate::hash::CryptoHash;
use anyhow::Result;
use core::convert::{From, TryFrom};
use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, hash::Hash};
use thiserror::Error;

/// An error type for key and signature validation issues, see [`ValidCryptoMaterial`][ValidCryptoMaterial].
///
/// This enum reflects there are two interesting causes of validation
/// failure for the ingestion of key or signature material: deserialization errors
/// (often, due to mangled material or curve equation failure for ECC) and
/// validation errors (material recognizable but unacceptable for use,
/// e.g. unsafe).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{:?}", self)]
pub enum CryptoMaterialError {
    /// Struct to be signed does not serialize correctly.
    SerializationError,
    /// Key or signature material does not deserialize correctly.
    DeserializationError,
    /// Key or signature material deserializes, but is otherwise not valid.
    ValidationError,
    /// Key, threshold or signature material does not have the expected size.
    WrongLengthError,
    /// Part of the signature or key is not canonical resulting to malleability issues.
    CanonicalRepresentationError,
    /// A curve point (i.e., a public key) lies on a small group.
    SmallSubgroupError,
    /// A curve point (i.e., a public key) does not satisfy the curve equation.
    PointNotOnCurveError,
    /// BitVec errors in accountable multi-sig schemes.
    BitVecError(String),
}

/// The serialized length of the data that enables macro derived serialization and deserialization.
pub trait Length {
    /// The serialized length of the data
    fn length(&self) -> usize;
}

/// Key or more generally crypto material with a notion of byte validation.
///
/// A type family for material that knows how to serialize and
/// deserialize, as well as validate byte-encoded material. The
/// validation must be implemented as a [`TryFrom`][TryFrom] which
/// classifies its failures against the above
/// [`CryptoMaterialError`][CryptoMaterialError].
///
/// This provides an implementation for a validation that relies on a
/// round-trip to bytes and corresponding [`TryFrom`][TryFrom].
pub trait ValidCryptoMaterial:
    // The for<'a> exactly matches the assumption "deserializable from any lifetime".
    for<'a> TryFrom<&'a [u8], Error = CryptoMaterialError> + Serialize + DeserializeOwned
{
    /// Convert the valid crypto material to bytes.
    fn to_bytes(&self) -> Vec<u8>;
}

/// An extension to to/from Strings for [`ValidCryptoMaterial`][ValidCryptoMaterial].
///
/// Relies on [`hex`][::hex] for string encoding / decoding.
/// No required fields, provides a default implementation.
pub trait ValidCryptoMaterialStringExt: ValidCryptoMaterial {
    /// When trying to convert from bytes, we simply decode the string into
    /// bytes before checking if we can convert.
    fn from_encoded_string(encoded_str: &str) -> std::result::Result<Self, CryptoMaterialError> {
        let bytes_out = ::hex::decode(encoded_str);
        // We defer to `try_from` to make sure we only produce valid crypto materials.
        bytes_out
            // We reinterpret a failure to serialize: key is mangled someway.
            .or(Err(CryptoMaterialError::DeserializationError))
            .and_then(|ref bytes| Self::try_from(bytes))
    }
    /// A function to encode into hex-string after serializing.
    fn to_encoded_string(&self) -> Result<String> {
        Ok(::hex::encode(&self.to_bytes()))
    }
}

// There's nothing required in this extension, so let's just derive it
// for anybody that has a ValidCryptoMaterial.
impl<T: ValidCryptoMaterial> ValidCryptoMaterialStringExt for T {}

/// A type family for key material that should remain secret and has an
/// associated type of the [`PublicKey`][PublicKey] family.
pub trait PrivateKey: Sized {
    /// We require public / private types to be coupled, i.e. their
    /// associated type is each other.
    type PublicKeyMaterial: PublicKey<PrivateKeyMaterial = Self>;

    /// Returns the associated public key
    fn public_key(&self) -> Self::PublicKeyMaterial {
        self.into()
    }
}

/// A type family of valid keys that know how to sign.
///
/// This trait has a requirement on a `pub(crate)` marker trait meant to
/// specifically limit its implementations to the present crate.
///
/// A trait for a [`ValidCryptoMaterial`][ValidCryptoMaterial] which knows how to sign a
/// message, and return an associated `Signature` type.
pub trait SigningKey:
    PrivateKey<PublicKeyMaterial = <Self as SigningKey>::VerifyingKeyMaterial>
    + ValidCryptoMaterial
    + private::Sealed
{
    /// The associated verifying key type for this signing key.
    type VerifyingKeyMaterial: VerifyingKey<SigningKeyMaterial = Self>;
    /// The associated signature type for this signing key.
    type SignatureMaterial: Signature<SigningKeyMaterial = Self>;

    /// Signs an object that has an distinct domain-separation hasher and
    /// that we know how to serialize. There is no pre-hashing into a
    /// `HashValue` to be done by the caller.
    ///
    /// Note: this assumes serialization is unfaillible. See diem_common::bcs::ser
    /// for a discussion of this assumption.
    fn sign<T: CryptoHash + Serialize>(&self, message: &T) -> Self::SignatureMaterial;

    /// Signs a non-hash input message. For testing only.
    #[cfg(any(test, feature = "fuzzing"))]
    fn sign_arbitrary_message(&self, message: &[u8]) -> Self::SignatureMaterial;

    /// Returns the associated verifying key
    fn verifying_key(&self) -> Self::VerifyingKeyMaterial {
        self.public_key()
    }
}

/// A type for key material that can be publicly shared, and in asymmetric
/// fashion, can be obtained from a [`PrivateKey`][PrivateKey]
/// reference.
/// This convertibility requirement ensures the existence of a
/// deterministic, canonical public key construction from a private key.
pub trait PublicKey: Sized + Clone + Eq + Hash +
    // This unsightly turbofish type parameter is the precise constraint
    // needed to require that there exists an
    //
    // ```
    // impl From<&MyPrivateKeyMaterial> for MyPublicKeyMaterial
    // ```
    //
    // declaration, for any `MyPrivateKeyMaterial`, `MyPublicKeyMaterial`
    // on which we register (respectively) `PublicKey` and `PrivateKey`
    // implementations.
    for<'a> From<&'a <Self as PublicKey>::PrivateKeyMaterial> {
    /// We require public / private types to be coupled, i.e. their
    /// associated type is each other.
    type PrivateKeyMaterial: PrivateKey<PublicKeyMaterial = Self>;
}

/// A type family of public keys that are used for signing.
///
/// This trait has a requirement on a `pub(crate)` marker trait meant to
/// specifically limit its implementations to the present crate.
///
/// It is linked to a type of the Signature family, which carries the
/// verification implementation.
pub trait VerifyingKey:
    PublicKey<PrivateKeyMaterial = <Self as VerifyingKey>::SigningKeyMaterial>
    + ValidCryptoMaterial
    + private::Sealed
{
    /// The associated signing key type for this verifying key.
    type SigningKeyMaterial: SigningKey<VerifyingKeyMaterial = Self>;
    /// The associated signature type for this verifying key.
    type SignatureMaterial: Signature<VerifyingKeyMaterial = Self>;

    /// We provide the striaghtfoward implementation which dispatches to the signature.
    fn verify_struct_signature<T: CryptoHash + Serialize>(
        &self,
        message: &T,
        signature: &Self::SignatureMaterial,
    ) -> Result<()> {
        signature.verify(message, self)
    }

    /// We provide the implementation which dispatches to the signature.
    fn batch_verify<T: CryptoHash + Serialize>(
        message: &T,
        keys_and_signatures: Vec<(Self, Self::SignatureMaterial)>,
    ) -> Result<()> {
        Self::SignatureMaterial::batch_verify(message, keys_and_signatures)
    }
}

/// A type family for signature material that knows which public key type
/// is needed to verify it, and given such a public key, knows how to
/// verify.
///
/// This trait simply requires an association to some type of the
/// [`PublicKey`][PublicKey] family of which we are the `SignatureMaterial`.
///
/// This trait has a requirement on a `pub(crate)` marker trait meant to
/// specifically limit its implementations to the present crate.
///
/// It should be possible to write a generic signature function that
/// checks signature material passed as `&[u8]` and only returns Ok when
/// that material de-serializes to a signature of the expected concrete
/// scheme. This would be done as an extension trait of
/// [`Signature`][Signature].
pub trait Signature:
    for<'a> TryFrom<&'a [u8], Error = CryptoMaterialError>
    + Sized
    + Debug
    + Clone
    + Eq
    + Hash
    + private::Sealed
{
    /// The associated verifying key type for this signature.
    type VerifyingKeyMaterial: VerifyingKey<SignatureMaterial = Self>;
    /// The associated signing key type for this signature
    type SigningKeyMaterial: SigningKey<SignatureMaterial = Self>;

    /// Verification for a struct we unabmiguously know how to serialize and
    /// that we have a domain separation prefix for.
    fn verify<T: CryptoHash + Serialize>(
        &self,
        message: &T,
        public_key: &Self::VerifyingKeyMaterial,
    ) -> Result<()>;

    /// Native verification function.
    fn verify_arbitrary_msg(
        &self,
        message: &[u8],
        public_key: &Self::VerifyingKeyMaterial,
    ) -> Result<()>;

    /// Convert the signature into a byte representation.
    fn to_bytes(&self) -> Vec<u8>;

    /// The implementer can override a batch verification implementation
    /// that by default iterates over each signature. More efficient
    /// implementations exist and should be implemented for many schemes.
    fn batch_verify<T: CryptoHash + Serialize>(
        message: &T,
        keys_and_signatures: Vec<(Self::VerifyingKeyMaterial, Self)>,
    ) -> Result<()> {
        for (key, signature) in keys_and_signatures {
            signature.verify(message, &key)?
        }
        Ok(())
    }
}

/// A type family for schemes which know how to generate key material from
/// a cryptographically-secure [`CryptoRng`][::rand::CryptoRng].
pub trait Uniform {
    /// Generate key material from an RNG. This should generally not be used for production
    /// purposes even with a good source of randomness. When possible use hardware crypto to generate and
    /// store private keys.
    fn generate<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng;

    /// Generate a random key using the shared TEST_SEED
    fn generate_for_testing() -> Self
    where
        Self: Sized,
    {
        let mut rng: StdRng = SeedableRng::from_seed(crate::test_utils::TEST_SEED);
        Self::generate(&mut rng)
    }
}

/// A type family with a by-convention notion of genesis private key.
pub trait Genesis: PrivateKey {
    /// Produces the genesis private key.
    fn genesis() -> Self;
}

/// A pub(crate) mod hiding a Sealed trait and its implementations, allowing
/// us to make sure implementations are constrained to the crypto crate.
// See https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub(crate) mod private {
    pub trait Sealed {}

    // Implement for the ed25519, multi-ed25519 signatures
    impl Sealed for crate::ed25519::Ed25519PrivateKey {}
    impl Sealed for crate::ed25519::Ed25519PublicKey {}
    impl Sealed for crate::ed25519::Ed25519Signature {}

    impl Sealed for crate::multi_ed25519::MultiEd25519PrivateKey {}
    impl Sealed for crate::multi_ed25519::MultiEd25519PublicKey {}
    impl Sealed for crate::multi_ed25519::MultiEd25519Signature {}

    // #[cfg(feature = "crypto-experimental")]
    impl Sealed for crate::ecdsa_secp256r1::EcdsaPrivateKey {}
    // #[cfg(feature = "crypto-experimental")]
    impl Sealed for crate::ecdsa_secp256r1::EcdsaPublicKey {}
    // #[cfg(feature = "crypto-experimental")]
    impl Sealed for crate::ecdsa_secp256r1::EcdsaSignature {}
}
