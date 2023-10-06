mod creation;
mod cryptography;
mod print_utils;
mod verificiation;

use crate::{creation::Prover, print_utils::printpoly, verificiation::CreateChallengeResult};
use cryptography::EncryptedNumber;
use num::BigUint;
use polynomen::Poly;

type BigNumberType = BigUint;

const POLYNOMIAL_DEGREE: u32 = 5;

fn main() {
    let t: Poly<f64> = Poly::new_from_coeffs(&[3.0, 4.0, 5.0]);
    printpoly(&t);
    let h: Poly<f64> = Poly::new_from_coeffs(&[6.0, 7.0]);
    printpoly(&h);
    let p: Poly<f64> = &t * &h;
    printpoly(&p);

    let public = Public {
        t: t,
        encryption_parameters: cryptography::get_encryption_parameters(),
    };

    let prover = Prover::new(&public, p);

    let CreateChallengeResult {
        challenge,
        verifier_state,
    } = verificiation::create_challenge(&public);

    let proof = prover.prove(&challenge);

    let validation = verificiation::verify(&public, &verifier_state, &challenge, &proof);

    println!("{}", validation);
}

struct VerifierState {
    s: f64,
    alpha: f64,
}

struct Public {
    t: Poly<f64>,
    encryption_parameters: cryptography::EncryptionParameters,
}

struct Challenge {
    encrypted_s_powers: Vec<EncryptedNumber>,
    encrypted_alpha_times_s_powers: Vec<EncryptedNumber>,
}

struct Proof {
    encrypted_h_at_s: EncryptedNumber,
    encrypted_p_at_s: EncryptedNumber,
    encrypted_alpha_times_p_at_s: EncryptedNumber,
}
