use polynomen::Poly;

use crate::{
    cryptography::{self},
    Proof, Public,
};

pub(crate) struct Prover {
    p: Poly<usize>,
}

impl Prover {
    pub fn new(p: Poly<usize>) -> Self {
        Self { p }
    }

    pub(crate) fn prove(&self, public: &Public) -> Proof {
        let h: Poly<usize> = exact_divide_integer_polynomial(&self.p, &public.t);

        return Proof {
            encrypted_p_at_s: cryptography::homomorphic_eval_polynomial(
                &public.encrypted_s_powers,
                &self.p,
            ),
            encrypted_h_at_s: cryptography::homomorphic_eval_polynomial(
                &public.encrypted_s_powers,
                &h,
            ),
            encrypted_alpha_times_p_at_s: cryptography::homomorphic_eval_polynomial(
                &public.encrypted_alpha_times_s_powers,
                &self.p,
            ),
        };
    }

    pub(crate) fn erroneous_prove(&self, public: &Public) -> Proof {
        let h: Poly<usize> = cast_polynomial_to_usize(
            cast_polynomial_to_f64(&self.p) / cast_polynomial_to_f64(&public.t),
        );
        return Proof {
            encrypted_p_at_s: cryptography::homomorphic_eval_polynomial(
                &public.encrypted_s_powers,
                &self.p,
            ),
            encrypted_h_at_s: cryptography::homomorphic_eval_polynomial(
                &public.encrypted_s_powers,
                &h,
            ),
            encrypted_alpha_times_p_at_s: cryptography::erroneous_homomorphic_eval_polynomial(
                &public.encrypted_alpha_times_s_powers,
                &self.p,
            ),
        };
    }
}

fn exact_divide_integer_polynomial(p_top: &Poly<usize>, p_bottom: &Poly<usize>) -> Poly<usize> {
    return cast_polynomial_to_usize(
        cast_polynomial_to_f64(p_top) / cast_polynomial_to_f64(p_bottom),
    );
}

fn cast_polynomial_to_f64(p: &Poly<usize>) -> Poly<f64> {
    return Poly::new_from_coeffs_iter(p.coeffs().iter().map(|x| *x as f64));
}

fn cast_polynomial_to_usize(p: Poly<f64>) -> Poly<usize> {
    return Poly::new_from_coeffs_iter(p.coeffs().iter().map(|x| *x as usize));
}
