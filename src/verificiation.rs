use num::FromPrimitive;
use num_bigint::BigUint;

use crate::{
    cryptography::{self, encrypt, EncryptedNumber},
    Challenge, NumberType, VerifierState, POLYNOMIAL_DEGREE,
};

pub(crate) fn choose_random_s() -> f64 {
    return 17.0;
}

pub(crate) fn verify(
    public: &crate::Public,
    verifier_state: &VerifierState,
    _challenge: &crate::Challenge,
    proof: &crate::Proof,
) -> bool {
    let t_at_s = public.t.eval(&verifier_state.s);
    return proof.encrypted_p_at_s
        == cryptography::homomorphic_multiply(
            &public.encryption_parameters,
            &proof.encrypted_h_at_s,
            t_at_s,
        );
}

pub(crate) fn create_challenge(public: &crate::Public) -> CreateChallengeResult {
    let s = choose_random_s();

    let encrypted_powers: Vec<EncryptedNumber> = (0..POLYNOMIAL_DEGREE)
        .map(|k: NumberType| {
            BigUint::from_f64(s)
                .expect("Int range should be integer-valued")
                .pow(k)
        })
        .map(|s_to_kth_power: BigUint| encrypt(&public.encryption_parameters, s_to_kth_power))
        .collect();

    return CreateChallengeResult {
        challenge: Challenge {
            encrypted_s_powers: encrypted_powers,
        },
        verifier_state: VerifierState { s: s },
    };
}

pub(crate) struct CreateChallengeResult {
    pub challenge: Challenge,
    pub verifier_state: VerifierState,
}
