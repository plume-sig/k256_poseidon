use plume_arkworks::{
    HashToCurve,
    secp256k1::{Config, fq::Fq},
};
use utils::{bytes_to_registers, hash_bi};

mod utils;

/// Errors on a `map_to_curve` `Error`.
pub fn hash_to_curve(
    msg: &[u8],
) -> Result<plume_arkworks::Affine, plume_arkworks::HashToCurveError> {
    // assert!(msg.len() <= u32::MAX as usize); // feels useless in reality because of verification costs, but added to mirror the origin yet #u32
    plume_arkworks::MapToCurveBasedHasher::<
        plume_arkworks::short_weierstrass::Projective<Config>,
        AztecFieldHasher,
        plume_arkworks::WBMap<Config>,
    >::new(Default::default())
    .expect("fallible only in `test`")
    .hash(msg)
}

struct AztecFieldHasher;
impl ark_ff::field_hashers::HashToField<Fq> for AztecFieldHasher {
    fn new(_domain: &[u8]) -> Self {
        Self
    }

    fn hash_to_field<const N: usize>(&self, msg: &[u8]) -> [Fq; N] {
        // assert!(msg.len() <= u32::MAX as usize); // #u32
        let expand_message_xmd =
            expand_message_xmd(msg).expect("`arkworks` panics due to `BlackBoxResolutionError`");

        let mut u0_bytes_to_registers = [0 as u8; 48];
        let mut u1_bytes_to_registers = [0 as u8; 48];

        for i in 0..48 {
            u0_bytes_to_registers[i] = expand_message_xmd[i];
            u1_bytes_to_registers[i] = expand_message_xmd[48 + i];
        }

        if 2 == N {
            vec![
                bytes_to_registers(u0_bytes_to_registers),
                bytes_to_registers(u1_bytes_to_registers),
            ]
            .try_into()
            .expect("checked in the condition")
        } else {
            panic!("N should be 2")
        }
    }
}

pub fn expand_message_xmd(msg: &[u8]) -> Result<[u8; 96], plume_bn254::BlackBoxResolutionError> {
    // assert!(msg.len() <= u32::MAX as usize); // #u32
    let b0 = utils::msg_prime(msg)?;
    let b1 = utils::hash_b(1, b0)?;
    let b2 = hash_bi(2, &b0, &b1)?;
    let b3 = hash_bi(3, &b0, &b2)?;

    let mut out = [0 as u8; 96];
    for i in 0..32 {
        out[i] = b1[i];
    }
    for i in 0..32 {
        out[32 + i] = b2[i];
    }
    for i in 0..32 {
        out[64 + i] = b3[i];
    }

    Ok(out)
}
