mod prover;
mod crs_player;
mod cryptography;
mod how_to_use_zksnark_crate;
mod verificiation;

use crate::{prover::Prover, crs_player::CrsPlayer};
use polynomen::Poly;
use zksnark::groth16::fr::{G1Local, G2Local};

const POLYNOMIAL_DEGREE: u32 = 5;

fn main() {
    let t: Poly<usize> = Poly::new_from_coeffs(&[3, 4, 5]);
    let h: Poly<usize> = Poly::new_from_coeffs(&[6, 7]);
    let p: Poly<usize> = &t * &h;

    let prover = Prover::new(p);
    let alice = CrsPlayer::new(12, 13);
    let bob = CrsPlayer::new(14, 15);
    let charlie = CrsPlayer::new(16, 17);

    let mut transcript = Transcript {
        history: vec![alice.start_crs_ceremony()],
    };

    transcript
        .history
        .push(bob.continue_crs_ceremony(&transcript));

    transcript
        .history
        .push(charlie.continue_crs_ceremony(&transcript));

    let public = Public {
        t: t,
        crs: transcript.history.pop().expect("non-empty").accumulator,
    };

    let proof = prover.prove(&public);
    let erroneous_proof = prover.erroneous_prove(&public);

    let validation = verificiation::verify(&public, &proof);
    println!("{}", validation);

    let validation2 = verificiation::verify(&public, &erroneous_proof);
    println!("{}", validation2);
}

struct Public {
    t: Poly<usize>,
    crs: CRS,
}

struct Transcript {
    history: Vec<CrsCeremonyValues>,
}

struct CrsCeremonyValues {
    accumulator: CRS,
    step: CrsStepValues,
}

struct CrsStepValues {
    encrypted1_s_powers: Vec<G1Local>,
    encrypted1_alpha: G1Local,
    encrypted2_alpha_times_s_powers: Vec<G2Local>,
}

struct CRS {
    // encrypted1_alpha: G2Local,
    encrypted2_alpha: G2Local,
    encrypted2_s_powers: Vec<G2Local>,
    encrypted1_s_powers: Vec<G1Local>,
    encrypted1_alpha_times_s_powers: Vec<G1Local>,
}

struct Proof {
    encrypted1_h_at_s: G1Local,
    encrypted1_p_at_s: G1Local,
    encrypted1_alpha_times_p_at_s: G1Local,
}
