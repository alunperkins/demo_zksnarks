use crate::{
    cryptography::{crypto_pairing, encrypt2, homomorphic2_eval_polynomial},
    Public,
};

pub(crate) fn verify(public: &Public, proof: &crate::Proof) -> bool {
    let encrypted_t_at_s = homomorphic2_eval_polynomial(&public.crs.encrypted2_s_powers, &public.t);

    let provers_p_has_roots_of_t = crypto_pairing(proof.encrypted1_p_at_s, encrypt2(1))
        == crypto_pairing(proof.encrypted1_h_at_s, encrypted_t_at_s);

    let proof_created_by_polynomial_evaluation_of_limited_degree =
        crypto_pairing(proof.encrypted1_p_at_s, public.crs.encrypted2_alpha)
            == crypto_pairing(proof.encrypted1_alpha_times_p_at_s, encrypt2(1));

    return provers_p_has_roots_of_t && proof_created_by_polynomial_evaluation_of_limited_degree;
}
