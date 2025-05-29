use plume_arkworks::PrimeField;
use plume_bn254::{
    BigInteger, BlackBoxResolutionError, GenericFieldElement, pack_bytes, poseidon_hash,
};

use super::Fq;

const DST_PRIME: [u8; 50] = [
    81, 85, 85, 88, 45, 86, 48, 49, 45, 67, 83, 48, 50, 45, 119, 105, 116, 104, 45, 115, 101, 99,
    112, 50, 53, 54, 107, 49, 95, 88, 77, 68, 58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 83, 87, 85,
    95, 82, 79, 95, 49,
];
const MSG: &str =
    "if this fails it's probably a new Noir backend and the whole thing should be reworked";

pub(super) fn bytes_to_registers(ui: [u8; 48]) -> Fq {
    let shift = Fq::from_le_bytes_mod_order(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let mut small = [0 as u8; 32];
    let mut big = [0 as u8; 32];

    for i in 0..16 {
        small[i + 16] = ui[i + 32];
    }
    for i in 0..32 {
        big[i] = ui[i];
    }
    let res = Fq::from_be_bytes_mod_order(&big);
    res * shift + Fq::from_be_bytes_mod_order(&small)
}

pub(super) fn hash_bi(
    b_idx: u8,
    b0: &[u8; 32],
    b1: &[u8; 32],
) -> Result<[u8; 32], BlackBoxResolutionError> {
    assert!(b_idx < 8);

    let mut res = [0u8; 32];
    for i in 0..32 {
        res[i] = b0[i] ^ b1[i];
    }

    hash_b(b_idx, res)
}

pub(super) fn hash_b(b_idx: u8, b: [u8; 32]) -> Result<[u8; 32], BlackBoxResolutionError> {
    assert!(b_idx < 8);
    let mut preimage = [0; 32 + 1 + 50];

    for i in 0..32 {
        preimage[i] = b[i];
    }

    preimage[32] = b_idx;

    for i in 0..50 {
        preimage[32 + 1 + i] = DST_PRIME[i];
    }

    let packed_preimage = pack_bytes(&preimage);

    Ok(poseidon_hash(
        packed_preimage
            .into_iter()
            .map(|x| GenericFieldElement::from_repr(x))
            .collect::<Vec<_>>()
            .as_slice(),
        false,
    )?
    .into_repr()
    .into_bigint()
    .to_bytes_le()
    .try_into()
    .expect(MSG))
}

pub(super) fn msg_prime(msg: &[u8]) -> Result<[u8; 32], BlackBoxResolutionError> {
    let n = msg.len();
    // assert!(n <= u32::MAX as usize); // #u32

    let mut preimage = [0].repeat(64 + n + 2 + 1 + 50);

    for i in 0..n {
        preimage[64 + i] = msg[i];
    }

    let lib_str = [0, 96];
    for i in 0..lib_str.len() {
        preimage[64 + n + i] = lib_str[i];
    }

    preimage[64 + n + 2] = 0;

    for i in 0..50 {
        preimage[64 + n + 2 + 1 + i] = DST_PRIME[i];
    }

    Ok(poseidon_hash(
        pack_bytes(&preimage)
            .iter()
            .map(|x| GenericFieldElement::from_repr(*x))
            .collect::<Vec<_>>()
            .as_slice(),
        false,
    )?
    .into_repr()
    .into_bigint()
    .to_bytes_le()
    .try_into()
    .expect(MSG))
}
