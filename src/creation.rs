use polynomen::Poly;

use crate::{cryptography, Challenge, Proof, Public};

pub(crate) fn cast_polynomial_to_f64(p: &Poly<usize>) -> Poly<f64> {
    return Poly::new_from_coeffs_iter(p.coeffs().iter().map(|x| *x as f64));
}

pub(crate) fn cast_polynomial_to_usize(p: Poly<f64>) -> Poly<usize> {
    return Poly::new_from_coeffs_iter(p.coeffs().iter().map(|x| *x as usize));
}

pub(crate) struct Prover<'a> {
    public: &'a Public,
    p: Poly<usize>,
}

impl<'a> Prover<'a> {
    pub fn new(public: &'a Public, p: Poly<usize>) -> Self {
        Self { public, p }
    }

    pub(crate) fn prove(&self, challenge: &Challenge) -> Proof {
        let h: Poly<usize> = cast_polynomial_to_usize(
            cast_polynomial_to_f64(&self.p) / cast_polynomial_to_f64(&self.public.t),
        );
        return Proof {
            encrypted_p_at_s: cryptography::homomorphic_eval_polynomial(
                &challenge.encrypted_s_powers,
                &self.p,
            ),
            encrypted_h_at_s: cryptography::homomorphic_eval_polynomial(
                &challenge.encrypted_s_powers,
                &h,
            ),
            encrypted_alpha_times_p_at_s: cryptography::homomorphic_eval_polynomial(
                &challenge.encrypted_alpha_times_s_powers,
                &self.p,
            ),
        };
    }
}
