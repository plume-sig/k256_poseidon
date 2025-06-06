use plume_arkworks::{secp256k1::fq::Fq, Affine, CurveGroup, Fr, PrimeField};

// use crate::hashing::hash_to_curve;

use super::*;

#[test]
fn test_plume_v2_secp256k1() {
    let msg = [115, 105, 103, 110, 84, 104, 105, 115];

    let c2 = Fr::from_be_bytes_mod_order(&[
        25, 48, 148, 152, 196, 123, 193, 9, 209, 58, 83, 106, 175, 140, 40, 48, 149, 237, 34, 2,
        125, 148, 106, 54, 114, 7, 22, 131, 174, 188, 105, 208,
    ]);

    let s2 = Fr::from_be_bytes_mod_order(&[
        232, 126, 194, 99, 71, 55, 87, 146, 72, 134, 247, 82, 158, 229, 140, 149, 111, 138, 153, 2,
        105, 222, 70, 22, 34, 41, 70, 212, 47, 29, 185, 219,
    ]);

    let sk = Fr::from_be_bytes_mod_order(&[
        172, 9, 116, 190, 195, 154, 23, 227, 107, 164, 166, 180, 210, 56, 255, 148, 75, 172, 180,
        120, 203, 237, 94, 252, 174, 120, 77, 123, 244, 242, 255, 128,
    ]);

    let r_recovered = dbg!(s2 - sk * c2);
    println!("{:X}", r_recovered.into_bigint());
    // dbg!(r_recovered.into_bigint())
    println!("{:X}", c2.into_bigint());
    println!("{:X}", s2.into_bigint());

    let pk = (<plume_arkworks::secp256k1::Config as plume_arkworks::SWCurveConfig>::GENERATOR * sk).into_affine();

    dbg!({
        let mut writer = [0u8; 33];
        pk.serialize_compressed(writer.as_mut_slice()).expect("the type serialization is completely covered and the `writer` accomodates the `Result` completely");
        writer.reverse();
        writer[0] = 
            if plume_arkworks::AffineRepr::y(&pk).unwrap().into_bigint().is_odd() { 
                3 
            } else { 2 };
        writer
    });
    
    let H = dbg!(Affine::new(
        dbg!(Fq::from_le_bytes_mod_order(&[
            101, 11, 128, 176, 13, 25, 162, 54, 17, 77, 197, 73, 188, 255, 42, 31, 192, 205, 171,
            149, 147, 136, 24, 194, 35, 159, 103, 18, 14, 45, 172, 188,
        ])),
        Fq::from_le_bytes_mod_order(&[
            110, 150, 112, 205, 240, 135, 93, 20, 82, 55, 43, 227, 83, 26, 169, 176, 35, 161, 144,
            31, 8, 72, 211, 87, 231, 192, 116, 201, 57, 179, 207, 59,
        ]),
    ));
    
    // assert_eq!(H, dbg!(plume_arkworks::hash_to_curve(&form_plume_msg(&msg, &pk).unwrap())).unwrap());
    
    // assert_eq!(H, dbg!(plume_arkworks::hash_to_curve(
    //     // [
    //         msg.as_slice(), 
    //         // {
    //         //     let mut writer: Vec<u8> = Vec::new();
    //             &pk//.serialize_compressed(&mut writer).unwrap();
    //         //     writer
    //         // }.as_slice()
    //     // ].concat().as_slice()
    // )).unwrap());
    
    // also it's not from `typescript`
    
    assert_eq!(H, dbg!(super::hashing::hash_to_curve(&format_message::form_plume_msg(&msg, &pk).unwrap())).unwrap());
    
    let nullifier = H * sk;

    let (_rp, _, htcurve) = check_ec_equations(&msg, c2, s2, pk, nullifier.into())
        .unwrap()
        .unwrap();
    assert_eq!(<secp256k1::Config as plume_arkworks::SWCurveConfig>::GENERATOR * r_recovered, _rp);
    assert_eq!(htcurve, H);
}
