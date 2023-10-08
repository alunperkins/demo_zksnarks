use zksnark::groth16::fr::G1Local;

use crate::{
    cryptography::{encrypt_g1, homomorphic_multiply, mult_and_encrypt_g1},
    Challenge, Public, VerifierState, POLYNOMIAL_DEGREE,
};

fn choose_random_s() -> usize {
    return 17;
}

fn choose_random_alpha() -> usize {
    return 19;
}

pub(crate) fn verify(
    public: &Public,
    verifier_state: &VerifierState,
    _challenge: &crate::Challenge,
    proof: &crate::Proof,
) -> bool {
    let t_at_s = public.t.eval(&verifier_state.s);

    let provers_p_has_roots_of_t =
        proof.encrypted_p_at_s == homomorphic_multiply(proof.encrypted_h_at_s, t_at_s);

    let proof_created_by_polynomial_evaluation_of_limited_degree =
        homomorphic_multiply(proof.encrypted_p_at_s, verifier_state.alpha)
            == proof.encrypted_alpha_times_p_at_s;

    return provers_p_has_roots_of_t && proof_created_by_polynomial_evaluation_of_limited_degree;
}

pub(crate) fn create_challenge(public: &Public) -> CreateChallengeResult {
    let s: usize = choose_random_s();
    let alpha: usize = choose_random_alpha();

    let encrypted_powers: Vec<G1Local> = (0..POLYNOMIAL_DEGREE)
        .map(|k| s.checked_pow(k).expect("not to overflow"))
        .map(|s_to_kth_power: usize| encrypt_g1(s_to_kth_power))
        .collect();

    let encrypted_powers_shifted: Vec<G1Local> = (0..POLYNOMIAL_DEGREE)
        .map(|k| s.checked_pow(k).expect("not to overflow"))
        .map(|s_to_kth_power: usize| mult_and_encrypt_g1(s_to_kth_power, alpha))
        .collect();

    return CreateChallengeResult {
        challenge: Challenge {
            encrypted_s_powers: encrypted_powers,
            encrypted_alpha_times_s_powers: encrypted_powers_shifted,
        },
        verifier_state: VerifierState { s: s, alpha: alpha },
    };
}

pub(crate) struct CreateChallengeResult {
    pub(crate) challenge: Challenge,
    pub(crate) verifier_state: VerifierState,
}
