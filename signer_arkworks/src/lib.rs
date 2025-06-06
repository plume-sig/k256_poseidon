//! Matches <https://github.com/signorecello/zk-nullifier-sig/blob/main/circuits/noir/src/curves/secp256k1.nr>
//!
//! Signing functions are to be finished when test vectors will be agreeing.

pub mod format_message;
pub mod hashing;

pub use plume_arkworks::{
    Affine, BigInteger, CanonicalSerialize, Fr, PlumeSignaturePrivate, PlumeSignaturePublic,
    PrimeField, Zeroize, secp256k1,
};
// for the `wasm_bindgen` based crate
pub use plume_arkworks::{AffineRepr, CurveGroup, sec1_affine};

/// Sign a message.
/* @skaunov believe `OsRng` is a fine compromise here to simplify the API, and might cover all the need the lib will encounter since it provides a method
to pass the `r` by value anyway */
pub fn sign(is_v1: bool, sk: Fr, msg: &[u8]) -> (PlumeSignaturePublic, PlumeSignaturePrivate) {
    sign_with_r(
        is_v1,
        sk,
        msg,
        <Fr as ark_ff::UniformRand>::rand(&mut plume_arkworks::rand::rngs::OsRng),
    )
}

/// Sign a message using the specified `r` value.
///
/// # WARNING
/// Makes sense only in a constrained environment which lacks a secure RNG.
// TODO it'd be nice to feature flag this, but for current level of traction a warning is a more natural communication to an user
pub fn sign_with_r(
    is_v1: bool,
    sk: Fr,
    msg: &[u8],
    r: Fr,
) -> (PlumeSignaturePublic, PlumeSignaturePrivate) {
    let s_point = <secp256k1::Config as plume_arkworks::SWCurveConfig>::GENERATOR * sk;

    let res: (PlumeSignaturePublic, PlumeSignaturePrivate) = todo!(
        "
        PlumeSignaturePublic(secp256k1::Config::GENERATOR * sk + secp256k1::Config::GENERATOR * r),
        PlumeSignaturePrivate(sk, r),
    "
    );

    sk.zeroize();
    // TODO check nothing was left behind
    r.zeroize();

    res
}

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

    let plume_msg = format_message::form_plume_msg(msg, &pk)?;
    let hashed_to_curve = hashing::hash_to_curve(&plume_msg);
    if hashed_to_curve.is_err() {
        return Some(Err(hashed_to_curve.expect_err("checked in the condition")));
    }
    let hashed_to_curve = hashed_to_curve.expect("just checked conditionally");
    let h_pow_s = hashed_to_curve * s;
    let hashed_to_curve_r = (h_pow_s - nullifier * c).into();

    Some(Ok((r_point, hashed_to_curve_r, hashed_to_curve)))
}

#[cfg(test)]
/// Matches <https://github.com/signorecello/zk-nullifier-sig/blob/main/circuits/noir/src/tests/secp256k1.nr>
mod tests;
