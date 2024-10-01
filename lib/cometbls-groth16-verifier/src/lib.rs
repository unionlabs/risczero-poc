#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use crate::{bounded::{BoundedI32, BoundedI64}, constants::*};

use alloc::vec::Vec;
use core::{marker::PhantomData, ops::{Add, Rem}};

use ark_ff::vec;
use byteorder::{BigEndian, ByteOrder};
// use constants::*;
use hex_literal::hex;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use substrate_bn::G1;

type H256 = [u8; 32];
pub struct U256(pub primitive_types::U256);

pub const TIMESTAMP_SECONDS_MAX: i64 = 253_402_300_799;
pub const TIMESTAMP_SECONDS_MIN: i64 = -62_135_596_800;

pub const NANOS_PER_SECOND: i32 = 1_000_000_000;
const NANOS_MAX: i32 = NANOS_PER_SECOND - 1;

#[derive(Deserialize, Serialize)]
pub struct VerifyZkpRequest {
    pub chain_id: alloc::string::String,
    pub trusted_validators_hash: H256,

    // LightHeader
    pub height: i64,
    pub validators_hash: H256,
    pub next_validators_hash: H256,
    pub app_hash: H256,
    // LightHeader - Timestamp
    pub seconds: i64,
    pub nanos: i32,

    pub zkp: Vec<u8>,
}
pub fn handle_verify_zkp_request(request: VerifyZkpRequest) -> Result<(), crate::Error> {
    verify_zkp(
        request.chain_id.as_str(),
        request.trusted_validators_hash,
        &LightHeader {
            height: request.height.try_into().unwrap(),
            validators_hash: request.validators_hash.into(),
            next_validators_hash: request.next_validators_hash.into(),
            app_hash: request.app_hash.into(),
            time: Timestamp {
                seconds: request.seconds.try_into().unwrap(),
                nanos: request.nanos.try_into().unwrap(),
            }
        },
        request.zkp,
    )
}

pub struct Timestamp {
    /// As per the proto docs: "Must be from 0001-01-01T00:00:00Z to
    /// 9999-12-31T23:59:59Z inclusive."
    pub seconds: BoundedI64<TIMESTAMP_SECONDS_MIN, TIMESTAMP_SECONDS_MAX>,
    // As per the proto docs: "Must be from 0 to 999,999,999 inclusive."
    pub nanos: BoundedI32<0, NANOS_MAX>,
}

pub struct LightHeader {
    pub height: BoundedI64<0, { i64::MAX }>,
    pub time: Timestamp,
    pub validators_hash: H256,
    pub next_validators_hash: H256,
    pub app_hash: H256,
}



impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self(primitive_types::U256::from(value))
    }
}


impl U256 {
    #[must_use]
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(primitive_types::U256(limbs))
    }


    #[must_use]
    pub fn from_be_bytes(bz: [u8; 32]) -> Self {
        Self(primitive_types::U256::from_big_endian(&bz))
    }


    #[must_use]
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut buf = [0; 32];
        self.0.to_big_endian(&mut buf);
        buf
    }
}

impl Rem for U256 {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        Self(self.0 % rhs.0)
    }
}


impl Add for U256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}


pub trait ByteArrayExt<const N: usize> {
    fn array_slice<const OFFSET: usize, const LEN: usize>(&self) -> [u8; LEN];
}

impl<const N: usize> ByteArrayExt<N> for [u8; N] {
    fn array_slice<const OFFSET: usize, const LEN: usize>(&self) -> [u8; LEN] {
        const { assert!(OFFSET + LEN <= N) };

        // unsafe { *&raw const(self[OFFSET..(OFFSET + LEN)]).cast::<[u8; LEN]>() }
        self[OFFSET..OFFSET+LEN].try_into().unwrap()
    }
}

mod constants;
mod uint;
mod errors;
mod bounded;

pub const NB_PUBLIC_INPUTS: usize = 2;

pub const HMAC_O: &[u8] = &hex!("1F333139281E100F5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C");
pub const HMAC_I: &[u8] = &hex!("75595B5342747A653636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636");
pub const PRIME_R_MINUS_ONE: U256 = U256::from_limbs([
    4891460686036598784,
    2896914383306846353,
    13281191951274694749,
    3486998266802970665,
]);

const _: () = assert!(GAMMA_ABC_G1.len() == NB_PUBLIC_INPUTS + 1);

fn hmac_keccak(message: &[u8]) -> [u8; 32] {
    sha3::Keccak256::new()
        .chain_update(
            HMAC_O
                .iter()
                .copied()
                .chain(
                    sha3::Keccak256::new()
                        .chain_update(
                            HMAC_I
                                .iter()
                                .copied()
                                .chain(message.iter().copied())
                                .collect::<Vec<_>>(),
                        )
                        .finalize(),
                )
                .collect::<Vec<_>>(),
        )
        .finalize()
        .into()
}

// Union whitepaper: (1) H_{hmac_r}
fn hash_to_field(message: &[u8]) -> U256 {
    (U256::from_be_bytes(hmac_keccak(message)) % PRIME_R_MINUS_ONE) + U256::from(1)
}

// Gnark commitment hashing, we employ our custom hash_to_field in the prover itself
fn hash_commitment(proof_commitment: &substrate_bn::AffineG1) -> Result<U256, Error> {
    let mut buffer = [0u8; 64];
    proof_commitment
        .x()
        .to_big_endian(&mut buffer[0..32])
        .map_err(|_| Error::InvalidCommitment)?;
    proof_commitment
        .y()
        .to_big_endian(&mut buffer[32..64])
        .map_err(|_| Error::InvalidCommitment)?;
    Ok(hash_to_field(&buffer))
}

pub const FQ_SIZE: usize = 32;
pub const G1_SIZE: usize = 2 * FQ_SIZE;
pub const G2_SIZE: usize = 2 * G1_SIZE;

pub struct G1Affine<FromOrder: ByteOrder>(PhantomData<FromOrder>, substrate_bn::AffineG1);
pub type G1AffineBE = G1Affine<BigEndian>;

impl TryFrom<[u8; G1_SIZE]> for G1AffineBE {
    type Error = Error;
    fn try_from(value: [u8; G1_SIZE]) -> Result<Self, Self::Error> {
        Ok(G1Affine(
            PhantomData,
            substrate_bn::AffineG1::new(
                substrate_bn::Fq::from_slice(&value.array_slice::<0, FQ_SIZE>())
                    .map_err(|_| Error::InvalidPoint)?,
                substrate_bn::Fq::from_slice(&value.array_slice::<FQ_SIZE, FQ_SIZE>())
                    .map_err(|_| Error::InvalidPoint)?,
            )
            .map_err(|_| Error::InvalidPoint)?,
        ))
    }
}

pub struct G2Affine<FromOrder>(PhantomData<FromOrder>, substrate_bn::AffineG2);
pub type G2AffineBE = G2Affine<BigEndian>;

impl TryFrom<[u8; G2_SIZE]> for G2AffineBE {
    type Error = Error;
    fn try_from(value: [u8; G2_SIZE]) -> Result<Self, Self::Error> {
        Ok(G2Affine(
            PhantomData,
            substrate_bn::AffineG2::new(
                substrate_bn::Fq2::new(
                    substrate_bn::Fq::from_slice(&value.array_slice::<FQ_SIZE, FQ_SIZE>())
                        .map_err(|_| Error::InvalidPoint)?,
                    substrate_bn::Fq::from_slice(&value.array_slice::<0, FQ_SIZE>())
                        .map_err(|_| Error::InvalidPoint)?,
                ),
                substrate_bn::Fq2::new(
                    substrate_bn::Fq::from_slice(
                        &value.array_slice::<{ G1_SIZE + FQ_SIZE }, FQ_SIZE>(),
                    )
                    .map_err(|_| Error::InvalidPoint)?,
                    substrate_bn::Fq::from_slice(&value.array_slice::<G1_SIZE, FQ_SIZE>())
                        .map_err(|_| Error::InvalidPoint)?,
                ),
            )
            .map_err(|_| Error::InvalidPoint)?,
        ))
    }
}

/// A verification key in the Groth16 SNARK.
pub struct VerifyingKey {
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: substrate_bn::AffineG1,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: substrate_bn::AffineG2,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: substrate_bn::AffineG2,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: substrate_bn::AffineG2,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is the generator of `E::G1`.
    pub gamma_abc_g1: Vec<substrate_bn::AffineG1>,
}

pub struct Proof {
    /// The `A` element in `G1`.
    pub a: substrate_bn::AffineG1,
    /// The `B` element in `G2`.
    pub b: substrate_bn::AffineG2,
    /// The `C` element in `G1`.
    pub c: substrate_bn::AffineG1,
}

pub struct ZKP<FromOrder> {
    pub proof: Proof,
    pub proof_commitment: substrate_bn::AffineG1,
    pub proof_commitment_pok: substrate_bn::AffineG1,
    pub _marker: PhantomData<FromOrder>,
}

// G1 + G2 + G1 + G1 + G1
pub const EXPECTED_PROOF_SIZE: usize = G1_SIZE + G2_SIZE + G1_SIZE + G1_SIZE + G1_SIZE;

// [a ... b ... c ... proof_commitment ... commitment_pok]
pub type RawZKP = [u8; EXPECTED_PROOF_SIZE];

impl<FromOrder: ByteOrder> TryFrom<&[u8]> for ZKP<FromOrder>
where
    G1Affine<FromOrder>: TryFrom<[u8; G1_SIZE], Error = Error>,
    G2Affine<FromOrder>: TryFrom<[u8; G2_SIZE], Error = Error>,
{
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value = RawZKP::try_from(value).map_err(|_| Error::InvalidRawProof)?;
        let G1Affine(_, a) = G1Affine::<FromOrder>::try_from(value.array_slice::<0, G1_SIZE>())?;
        let G2Affine(_, b) =
            G2Affine::<FromOrder>::try_from(value.array_slice::<G1_SIZE, G2_SIZE>())?;
        let G1Affine(_, c) =
            G1Affine::<FromOrder>::try_from(value.array_slice::<{ G1_SIZE + G2_SIZE }, G1_SIZE>())?;
        let G1Affine(_, proof_commitment) = G1Affine::<FromOrder>::try_from(
            value.array_slice::<{ G1_SIZE + G2_SIZE + G1_SIZE }, G1_SIZE>(),
        )?;
        let G1Affine(_, proof_commitment_pok) = G1Affine::<FromOrder>::try_from(
            value.array_slice::<{ G1_SIZE + G2_SIZE + G1_SIZE + G1_SIZE }, G1_SIZE>(),
        )?;
        Ok(Self {
            proof: Proof { a, b, c },
            proof_commitment,
            proof_commitment_pok,
            _marker: PhantomData,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    InvalidPublicInput,
    InvalidPoint,
    InvalidProof,
    InvalidPok,
    InvalidVerifyingKey,
    InvalidCommitment,
    InvalidRawProof,
    InvalidChainId,
    InvalidHeight,
    InvalidTimestamp,
    InvalidSliceLength,
}

pub fn verify_zkp(
    chain_id: &str,
    trusted_validators_hash: H256,
    header: &LightHeader,
    zkp: impl Into<Vec<u8>>,
) -> Result<(), Error> {
    verify_generic_zkp_2(
        chain_id,
        trusted_validators_hash,
        header,
        PEDERSEN_G,
        PEDERSEN_G_ROOT_SIGMA_NEG,
        ZKP::try_from(zkp.into().as_ref())?,
    )
}

fn verify_generic_zkp_2(
    chain_id: &str,
    trusted_validators_hash: H256,
    header: &LightHeader,
    g: substrate_bn::AffineG2,
    g_root_sigma_neg: substrate_bn::AffineG2,
    zkp: ZKP<BigEndian>,
) -> Result<(), Error> {
    if chain_id.len() > 31 {
        return Err(Error::InvalidChainId);
    }
    // Constant + public inputs
    let decode_scalar = move |x: U256| -> Result<substrate_bn::Fr, Error> {
        substrate_bn::Fr::new(x.0 .0.into()).ok_or(Error::InvalidPublicInput)
    };
    let commitment_hash = hash_commitment(&zkp.proof_commitment)?;
    let mut inputs_hash = <[u8; 32]>::from(
        sha2::Sha256::new()
            .chain_update(
                vec![0u8; 32 - chain_id.len()]
                    .into_iter()
                    .chain(chain_id.bytes())
                    .collect::<Vec<_>>(),
            )
            .chain_update(
                U256::from(
                    u64::try_from(i64::from(header.height)).map_err(|_| Error::InvalidHeight)?,
                )
                .to_be_bytes(),
            )
            .chain_update(
                U256::from(
                    u64::try_from(i64::from(header.time.seconds))
                        .map_err(|_| Error::InvalidTimestamp)?,
                )
                .to_be_bytes(),
            )
            .chain_update(
                U256::from(
                    u64::try_from(i32::from(header.time.nanos))
                        .map_err(|_| Error::InvalidTimestamp)?,
                )
                .to_be_bytes(),
            )
            .chain_update(header.validators_hash)
            .chain_update(header.next_validators_hash)
            .chain_update(header.app_hash)
            .chain_update(trusted_validators_hash)
            .finalize(),
    );
    // drop the most significant byte to fit in bn254 F_r
    inputs_hash[0] = 0;
    let public_inputs: [substrate_bn::Fr; NB_PUBLIC_INPUTS] = [
        decode_scalar(U256::from_be_bytes(inputs_hash))?,
        decode_scalar(commitment_hash)?,
    ];
    let initial_point = substrate_bn::G1::from(GAMMA_ABC_G1[0]) + zkp.proof_commitment.into();
    let public_inputs_msm = public_inputs
        .into_iter()
        .zip(GAMMA_ABC_G1.into_iter().skip(1).map(substrate_bn::G1::from))
        .fold(initial_point, |s, (w_i, gamma_l_i)| s + gamma_l_i * w_i);

    let proof_a: G1 = zkp.proof.a.into();
    let proof_c: G1 = zkp.proof.c.into();
    let pc: G1 = zkp.proof_commitment.into();
    let pok: G1 = zkp.proof_commitment_pok.into();

    let pok_result = substrate_bn::pairing_batch(&[(pc, g.into()), (pok, g_root_sigma_neg.into())]);
    if pok_result != substrate_bn::Gt::one() {
        return Err(Error::InvalidPok);
    }

    let g16_result = substrate_bn::pairing_batch(&[
        (proof_a, zkp.proof.b.into()),
        (public_inputs_msm, -substrate_bn::G2::from(GAMMA_G2)),
        (proof_c, -substrate_bn::G2::from(DELTA_G2)),
        (G1::from(ALPHA_G1), -substrate_bn::G2::from(BETA_G2)),
    ]);
    if g16_result != substrate_bn::Gt::one() {
        Err(Error::InvalidProof)
    } else {
        Ok(())
    }
}
