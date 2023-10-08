mod creation;
mod cryptography;
mod how_to_use_zksnark_crate;
mod print_utils;
mod verificiation;

use crate::{creation::Prover, print_utils::printpoly, verificiation::CreateChallengeResult};
use polynomen::Poly;
use zksnark::groth16::fr::{G1Local, G2Local};

const POLYNOMIAL_DEGREE: u32 = 5;

fn main() {
    let t: Poly<usize> = Poly::new_from_coeffs(&[3, 4, 5]);
    printpoly(&t);
    let h: Poly<usize> = Poly::new_from_coeffs(&[6, 7]);
    printpoly(&h);
    let p: Poly<usize> = &t * &h;
    printpoly(&p);

    let CreateChallengeResult { public } = verificiation::create_challenge(t);

    let prover = Prover::new(&public, p);

    let proof = prover.prove(&public);

    let validation = verificiation::verify(&public, &proof);
    println!("{}", validation);

}

struct Public {
    t: Poly<usize>,
    encrypted_t_at_s: G2Local,
    encrypted_alpha: G2Local,
    encrypted_s_powers: Vec<G1Local>,
    encrypted_alpha_times_s_powers: Vec<G1Local>,
}

struct Proof {
    encrypted_h_at_s: G1Local,
    encrypted_p_at_s: G1Local,
    encrypted_alpha_times_p_at_s: G1Local,
}
