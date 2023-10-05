mod creation;
mod cryptography;
mod polynomial_utils;
mod verificiation;

use num::BigUint;
use polynomen::Poly;

// use polynomials::poly;
use crate::{polynomial_utils::printpoly, verificiation::CreateChallengeResult};

type NumberType = u32;
type BigNumberType = BigUint;

const POLYNOMIAL_DEGREE: u32 = 5;

// fn big(n: NumberType) -> BigNumberType {
//     return BigUint::try_from(n).unwrap();
// }

fn main() {
    let t: Poly<f64> = Poly::new_from_coeffs(&[3.0, 4.0, 5.0]);
    printpoly(&t);
    let h: Poly<f64> = Poly::new_from_coeffs(&[6.0, 7.0]);
    printpoly(&h);
    let p: Poly<f64> = &t * &h;
    printpoly(&p);

    let public = Public {
        p: &t * &h,
        t: t,
        encryption_parameters: cryptography::get_encryption_parameters(),
    };

    let CreateChallengeResult {
        challenge,
        verifier_state,
    } = verificiation::create_challenge(&public);

    print!("challenge.encrypted_s_powers = ");
    challenge
        .encrypted_s_powers
        .iter()
        .for_each(|x| print!("{}, ", x));
    println!("");

    let proof = creation::prove(&public, &challenge);
    println!("proof.encrypted_p_at_s = {}", &proof.encrypted_p_at_s);
    println!("proof.encrypted_h_at_s = {}", &proof.encrypted_h_at_s);

    let validation = verificiation::verify(&public, &verifier_state, &challenge, &proof);

    println!("{}", validation);
}

struct VerifierState {
    s: f64,
}

struct Public {
    p: Poly<f64>,
    t: Poly<f64>,
    encryption_parameters: cryptography::EncryptionParameters,
}

struct Challenge {
    encrypted_s_powers: Vec<BigNumberType>,
}

struct Proof {
    encrypted_p_at_s: BigNumberType,
    encrypted_h_at_s: BigNumberType,
}
