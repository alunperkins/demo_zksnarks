mod creation;
mod cryptography;
mod how_to_use_zksnark_crate;
mod print_utils;
mod verificiation;

use crate::{creation::Prover, print_utils::printpoly, verificiation::CreateChallengeResult};
use polynomen::Poly;
use zksnark::groth16::fr::G1Local;

const POLYNOMIAL_DEGREE: u32 = 5;

fn main() {
    let t: Poly<usize> = Poly::new_from_coeffs(&[3, 4, 5]);
    printpoly(&t);
    let h: Poly<usize> = Poly::new_from_coeffs(&[6, 7]);
    printpoly(&h);
    let p: Poly<usize> = &t * &h;
    printpoly(&p);

    let public = Public { t: t };

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
    s: usize,
    alpha: usize,
}

struct Public {
    t: Poly<usize>,
}

struct Challenge {
    encrypted_s_powers: Vec<G1Local>,
    encrypted_alpha_times_s_powers: Vec<G1Local>,
}

struct Proof {
    encrypted_h_at_s: G1Local,
    encrypted_p_at_s: G1Local,
    encrypted_alpha_times_p_at_s: G1Local,
}
