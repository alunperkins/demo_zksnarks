use polynomen::Poly;

use crate::{cryptography, Challenge, Proof, Public};

pub(crate) struct Prover<'a> {
    public: &'a Public,
    p: Poly<f64>,
}

impl<'a> Prover<'a> {
    pub fn new(public: &'a Public, p: Poly<f64>) -> Self {
        Self { public, p }
    }

    pub(crate) fn prove(&self, challenge: &Challenge) -> Proof {
        let h: Poly<f64> = &self.p / &self.public.t;
        return Proof {
            encrypted_p_at_s: cryptography::homomorphic_eval_polynomial(
                &self.public.encryption_parameters,
                &challenge.encrypted_s_powers,
                &self.p,
            ),
            encrypted_h_at_s: cryptography::homomorphic_eval_polynomial(
                &self.public.encryption_parameters,
                &challenge.encrypted_s_powers,
                &h,
            ),
            encrypted_alpha_times_p_at_s: cryptography::homomorphic_eval_polynomial(
                &self.public.encryption_parameters,
                &challenge.encrypted_alpha_times_s_powers,
                &self.p,
            ),
        };
    }
}
