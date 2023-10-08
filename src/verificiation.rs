use polynomen::Poly;
use zksnark::groth16::fr::G1Local;

use crate::{
    cryptography::{crypto_pairing, encrypt_g1, encrypt_g2, mult_and_encrypt_g1},
    Public, POLYNOMIAL_DEGREE,
};

fn choose_random_s() -> usize {
    return 17;
}

fn choose_random_alpha() -> usize {
    return 19;
}

pub(crate) fn verify(public: &Public, proof: &crate::Proof) -> bool {
    let encrypted_identity = encrypt_g2(1);

    let provers_p_has_roots_of_t = crypto_pairing(proof.encrypted_p_at_s, encrypted_identity)
        == crypto_pairing(proof.encrypted_h_at_s, public.encrypted_t_at_s);

    let proof_created_by_polynomial_evaluation_of_limited_degree =
        crypto_pairing(proof.encrypted_p_at_s, public.encrypted_alpha)
            == crypto_pairing(proof.encrypted_alpha_times_p_at_s, encrypted_identity);

    return provers_p_has_roots_of_t && proof_created_by_polynomial_evaluation_of_limited_degree;
}

pub(crate) fn create_challenge(t: Poly<usize>) -> CreateChallengeResult {
    let s: usize = choose_random_s();
    let t_at_s = t.eval(&s);
    let encrypted_t_at_s = encrypt_g2(t_at_s);

    let alpha: usize = choose_random_alpha();
    let encrypted_alpha = encrypt_g2(alpha);

    let encrypted_s_powers: Vec<G1Local> = (0..POLYNOMIAL_DEGREE)
        .map(|k| s.checked_pow(k).expect("not to overflow"))
        .map(|s_to_kth_power: usize| encrypt_g1(s_to_kth_power))
        .collect();

    let encrypted_alpha_times_s_powers: Vec<G1Local> = (0..POLYNOMIAL_DEGREE)
        .map(|k| s.checked_pow(k).expect("not to overflow"))
        .map(|s_to_kth_power: usize| mult_and_encrypt_g1(s_to_kth_power, alpha))
        .collect();

    return CreateChallengeResult {
        public: Public {
            t,
            encrypted_t_at_s,
            encrypted_alpha,
            encrypted_s_powers,
            encrypted_alpha_times_s_powers,
        },
    };
}

pub(crate) struct CreateChallengeResult {
    pub(crate) public: Public,
}
