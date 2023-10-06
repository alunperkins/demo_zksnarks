use polynomen::Poly;

use crate::{cryptography, Challenge, Proof, Public};

pub(crate) fn prove(public: &Public, challenge: &Challenge) -> Proof {
    let h: Poly<f64> = &public.p / &public.t;
    return Proof {
        encrypted_p_at_s: cryptography::homomorphic_eval_polynomial(
            &public.encryption_parameters,
            &challenge.encrypted_s_powers,
            &public.p,
        ),
        encrypted_h_at_s: cryptography::homomorphic_eval_polynomial(
            &public.encryption_parameters,
            &challenge.encrypted_s_powers,
            &h,
        ),
    };
}
