use crate::{
    cryptography::{crypto_pairing, encrypt2, homomorphic2_eval_polynomial},
    PublicData,
};

pub(crate) fn verify(public: &PublicData, proof: &crate::Proof) -> bool {
    let encrypted_target_poly_at_s = homomorphic2_eval_polynomial(&public.crs.encrypted2_s_powers, &public.target_polynomial);

    let provers_secret_poly_has_roots_of_target_poly = crypto_pairing(proof.encrypted1_secret_poly_at_s, encrypt2(1))
        == crypto_pairing(proof.encrypted1_ratio_poly_at_s, encrypted_target_poly_at_s);

    let proof_was_created_only_by_polynomial_evaluation_only_of_restricted_degree =
        crypto_pairing(proof.encrypted1_secret_poly_at_s, public.crs.encrypted2_alpha)
            == crypto_pairing(proof.encrypted1_alpha_times_secret_poly_at_s, encrypt2(1));

    return provers_secret_poly_has_roots_of_target_poly
        && proof_was_created_only_by_polynomial_evaluation_only_of_restricted_degree;
}
