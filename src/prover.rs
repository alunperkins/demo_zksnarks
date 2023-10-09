use polynomen::Poly;

use crate::{
    cryptography::{
        erroneous1_homomorphic_eval_polynomial, homomorphic1_eval_polynomial, homomorphic1_multiply,
    },
    Proof, Public,
};

pub(crate) struct Prover {
    p: Poly<usize>,
    delta: usize,
}

impl Prover {
    pub fn new(p: Poly<usize>, delta: usize) -> Self {
        Self { p, delta }
    }

    pub(crate) fn prove(&self, public: &Public) -> Proof {
        let h: Poly<usize> = exact_divide_integer_polynomial(&self.p, &public.t);
        let crs = &public.crs;

        return Proof {
            encrypted1_p_at_s: homomorphic1_multiply(
                &homomorphic1_eval_polynomial(&crs.encrypted1_s_powers, &self.p),
                self.delta,
            ),
            encrypted1_h_at_s: homomorphic1_multiply(
                &homomorphic1_eval_polynomial(&crs.encrypted1_s_powers, &h),
                self.delta,
            ),
            encrypted1_alpha_times_p_at_s: homomorphic1_multiply(
                &homomorphic1_eval_polynomial(&crs.encrypted1_alpha_times_s_powers, &self.p),
                self.delta,
            ),
        };
    }

    pub(crate) fn erroneous_prove(&self, public: &Public) -> Proof {
        let h: Poly<usize> = exact_divide_integer_polynomial(&self.p, &public.t);
        let crs = &public.crs;

        return Proof {
            encrypted1_p_at_s: homomorphic1_multiply(
                &homomorphic1_eval_polynomial(&crs.encrypted1_s_powers, &self.p),
                self.delta,
            ),
            encrypted1_h_at_s: homomorphic1_multiply(
                &homomorphic1_eval_polynomial(&crs.encrypted1_s_powers, &h),
                self.delta,
            ),
            encrypted1_alpha_times_p_at_s: homomorphic1_multiply(
                &erroneous1_homomorphic_eval_polynomial(
                    &crs.encrypted1_alpha_times_s_powers,
                    &self.p,
                ),
                self.delta,
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
