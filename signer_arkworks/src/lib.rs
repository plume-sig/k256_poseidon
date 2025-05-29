//! Matches <https://github.com/signorecello/zk-nullifier-sig/blob/main/circuits/noir/src/curves/secp256k1.nr>

pub mod hashing;

// use ark_ff::UniformRand;
pub use plume_arkworks::{
    secp256k1, Affine, BigInteger, CanonicalSerialize, Fr, PrimeField,
    PlumeSignaturePrivate, PlumeSignaturePublic, Zeroize
};
// for the `wasm_bindgen` based crate
pub use plume_arkworks::{AffineRepr, CurveGroup, affine_to_bytes};

// pub fn sign(is_v1: bool, msg: &[u8], sk: Fr) -> (PlumeSignaturePublic, PlumeSignaturePrivate) {
//     // TODO check `rand` is ok here
//     sign_with_r(is_v1, msg, sk, Fr::rand(&mut OsRng))
// }

// fn sign_with_r(is_v1: bool, msg: &[u8], sk: Fr, r: Fr) -> (PlumeSignaturePublic, PlumeSignaturePrivate) {
//     let s_point = <secp256k1::Config as plume_arkworks::SWCurveConfig>::GENERATOR * s;

//     let res = (
//         PlumeSignaturePublic(secp256k1::Config::GENERATOR * sk + secp256k1::Config::GENERATOR * r),
//         PlumeSignaturePrivate(sk, r),
//     );

//     sk.zeroize();
//     // TODO add all the others
//     r.zeroize();
// }

/// Returns `None` if `pk` is the identity element.
pub fn check_ec_equations(
    msg: &[u8],
    c: Fr,
    s: Fr,
    pk: Affine,
    nullifier: Affine,
) -> Option<Result<(Affine, Affine, Affine), plume_arkworks::HashToCurveError>> {
    let s_point = <secp256k1::Config as plume_arkworks::SWCurveConfig>::GENERATOR * s;
    let r_point = (s_point - pk * c).into();

    let plume_msg = form_plume_msg(msg, &pk)?;
    let hashed_to_curve = hashing::hash_to_curve(&plume_msg);
    if hashed_to_curve.is_err() {
        return Some(Err(hashed_to_curve
            .err()
            .expect("checked in the condition")));
    }
    let hashed_to_curve = hashed_to_curve.expect("just checked conditionally");
    let h_pow_s = hashed_to_curve * s;
    let hashed_to_curve_r = (h_pow_s - nullifier * c).into();

    Some(Ok((r_point, hashed_to_curve_r, hashed_to_curve)))
}

/// Returns `None` if `pk` is the identity element.
pub fn form_plume_msg(msg: &[u8], pk: &Affine) -> Option<Vec<u8>> {
    let mut writer = [0u8; 33];
    pk.serialize_compressed(writer.as_mut_slice()).expect("the type serialization is completely covered and the `writer` accomodates the `Result` completely");
    writer.reverse();
    writer[0] = 
        // 2 + plume_arkworks::AffineRepr::xy(pk)?
        //     .1
        //     .into_bigint()
        //     .to_bytes_le()[0]
        //     & 1;
        if plume_arkworks::AffineRepr::y(pk)?.into_bigint().is_odd() { 3 } else { 2 };
    Some([msg, &writer].concat().try_into().expect("`Vec` as the most ubiquitous one will always able to accomodate this, and the types are matched precisely"))
}

#[cfg(test)]
/// Matches <https://github.com/signorecello/zk-nullifier-sig/blob/main/circuits/noir/src/tests/secp256k1.nr>
mod tests;
