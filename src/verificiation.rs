use num::FromPrimitive;
use num_bigint::BigUint;

use crate::{
    cryptography::{encrypt, EncryptedNumber},
    Challenge, Public, VerifierState, POLYNOMIAL_DEGREE,
};

pub(crate) fn choose_random_s() -> f64 {
    return 17.0;
}

pub(crate) fn verify(
    public: &Public,
    verifier_state: &VerifierState,
    _challenge: &crate::Challenge,
    proof: &crate::Proof,
) -> bool {
    let t_at_s = public.t.eval(&verifier_state.s);
    return proof.encrypted_p_at_s
        == proof
            .encrypted_h_at_s
            .times_by(t_at_s, &public.encryption_parameters);
}

pub(crate) fn create_challenge(public: &Public) -> CreateChallengeResult {
    let s = choose_random_s();

    let encrypted_powers: Vec<EncryptedNumber> = (0..POLYNOMIAL_DEGREE)
        .map(|k| {
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
    pub(crate) challenge: Challenge,
    pub(crate) verifier_state: VerifierState,
}
