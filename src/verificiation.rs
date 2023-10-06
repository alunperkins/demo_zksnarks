use num::FromPrimitive;
use num_bigint::BigUint;

use crate::{
    cryptography::{encrypt, EncryptedNumber},
    Challenge, Public, VerifierState, POLYNOMIAL_DEGREE,
};

fn choose_random_s() -> f64 {
    return 17.0;
}

fn choose_random_alpha() -> f64 {
    return 19.0;
}

pub(crate) fn verify(
    public: &Public,
    verifier_state: &VerifierState,
    _challenge: &crate::Challenge,
    proof: &crate::Proof,
) -> bool {
    let t_at_s = public.t.eval(&verifier_state.s);

    let provers_p_has_roots_of_t = proof.encrypted_p_at_s
        == proof
            .encrypted_h_at_s
            .times_by(t_at_s, &public.encryption_parameters);

    let proof_created_by_polynomial_evaluation_of_limited_degree = proof
        .encrypted_p_at_s
        .times_by(verifier_state.alpha, &public.encryption_parameters)
        == proof.encrypted_alpha_times_p_at_s;

    return provers_p_has_roots_of_t && proof_created_by_polynomial_evaluation_of_limited_degree;
}

pub(crate) fn create_challenge(public: &Public) -> CreateChallengeResult {
    let s = choose_random_s();
    let s_big = BigUint::from_f64(s).expect("s should be integer-valued");
    let alpha = choose_random_alpha();
    let alpha_big = BigUint::from_f64(alpha).expect("Alpha should be integer-valued");

    let encrypted_powers: Vec<EncryptedNumber> = (0..POLYNOMIAL_DEGREE)
        .map(|k| s_big.pow(k))
        .map(|s_to_kth_power: BigUint| encrypt(&public.encryption_parameters, s_to_kth_power))
        .collect();

    let encrypted_powers_shifted: Vec<EncryptedNumber> = (0..POLYNOMIAL_DEGREE)
        .map(|k| s_big.pow(k))
        .map(|s_to_kth_power: BigUint| {
            encrypt(&public.encryption_parameters, s_to_kth_power * &alpha_big)
        })
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
