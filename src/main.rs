mod crs_player;
mod cryptography;
mod how_to_use_zksnark_crate;
mod prover;
mod verificiation;

use crate::{crs_player::CrsPlayer, prover::Prover};
use polynomen::Poly;
use zksnark::groth16::fr::{G1Local, G2Local};

const POLYNOMIAL_DEGREE: u32 = 5;

fn main() {
    let target_polynomial: Poly<usize> = Poly::new_from_coeffs(&[3, 4, 5]);

    // Create Prover
    let ratio_polynomial: Poly<usize> = Poly::new_from_coeffs(&[6, 7]);
    let provers_polynomial: Poly<usize> = &target_polynomial * &ratio_polynomial;
    let prover = Prover::new(provers_polynomial);

    // Create CRS ceremony participants
    let alice = CrsPlayer::new(12, 13);
    let bob = CrsPlayer::new(14, 15);
    let charlie = CrsPlayer::new(16, 17);

    // CRS ceremony
    let mut transcript = CrsCeremonyTranscript {
        history: vec![alice.start_crs_ceremony()],
    };

    transcript
        .history
        .push(bob.continue_crs_ceremony(&transcript));

    transcript
        .history
        .push(charlie.continue_crs_ceremony(&transcript));

    let public = PublicData {
        target_polynomial,
        crs: transcript.history.pop().expect("non-empty").accumulator,
    };

    // Prover creates a proof using only public data and their secret data in `self`

    let proof = prover.prove(&public);
    let erroneous_proof = prover.erroneous_prove(&public);

    // proof is validated using only public data and proof data

    let validation = verificiation::verify(&public, &proof);
    println!("Valid proof returns true: {}", validation);

    let validation2 = verificiation::verify(&public, &erroneous_proof);
    println!("Erroneous proof returns false: {}", validation2);
}

struct Proof {
    encrypted1_ratio_poly_at_s: G1Local,
    encrypted1_secret_poly_at_s: G1Local,
    encrypted1_alpha_times_secret_poly_at_s: G1Local,
}

struct PublicData {
    target_polynomial: Poly<usize>,
    crs: CRS,
}

struct CRS {
    // Common Reference String
    encrypted2_alpha: G2Local,
    encrypted2_s_powers: Vec<G2Local>,
    encrypted1_s_powers: Vec<G1Local>,
    encrypted1_alpha_times_s_powers: Vec<G1Local>,
}

struct CrsCeremonyTranscript {
    history: Vec<CrsCeremonyValues>,
}

struct CrsCeremonyValues {
    accumulator: CRS,
    step: CrsCeremonyStep,
}

struct CrsCeremonyStep {
    encrypted1_s_powers: Vec<G1Local>,
    encrypted1_alpha: G1Local,
    encrypted2_alpha_times_s_powers: Vec<G2Local>,
}
