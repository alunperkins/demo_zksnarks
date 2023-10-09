use polynomen::Poly;

use crate::{
    cryptography::{
        erroneous1_homomorphic_eval_polynomial, homomorphic1_eval_polynomial, homomorphic1_multiply,
    },
    Proof, PublicData,
};

pub(crate) struct Prover {
    my_secret_polynomial: Poly<usize>,
}

impl Prover {
    pub fn new(p: Poly<usize>) -> Self {
        Self {
            my_secret_polynomial: p,
        }
    }

    pub(crate) fn prove(&self, public: &PublicData) -> Proof {
        let random_entropy = 7 as usize;

        let h: Poly<usize> =
            exact_divide_integer_polynomial(&self.my_secret_polynomial, &public.target_polynomial);
        let crs = &public.crs;

        return Proof {
            encrypted1_secret_poly_at_s: homomorphic1_multiply(
                &homomorphic1_eval_polynomial(&crs.encrypted1_s_powers, &self.my_secret_polynomial),
                random_entropy,
            ),
            encrypted1_ratio_poly_at_s: homomorphic1_multiply(
                &homomorphic1_eval_polynomial(&crs.encrypted1_s_powers, &h),
                random_entropy,
            ),
            encrypted1_alpha_times_secret_poly_at_s: homomorphic1_multiply(
                &homomorphic1_eval_polynomial(
                    &crs.encrypted1_alpha_times_s_powers,
                    &self.my_secret_polynomial,
                ),
                random_entropy,
            ),
        };
    }

    pub(crate) fn erroneous_prove(&self, public: &PublicData) -> Proof {
        let random_entropy = 7 as usize;

        let h: Poly<usize> =
            exact_divide_integer_polynomial(&self.my_secret_polynomial, &public.target_polynomial);
        let crs = &public.crs;

        return Proof {
            encrypted1_secret_poly_at_s: homomorphic1_multiply(
                &homomorphic1_eval_polynomial(&crs.encrypted1_s_powers, &self.my_secret_polynomial),
                random_entropy,
            ),
            encrypted1_ratio_poly_at_s: homomorphic1_multiply(
                &homomorphic1_eval_polynomial(&crs.encrypted1_s_powers, &h),
                random_entropy,
            ),
            encrypted1_alpha_times_secret_poly_at_s: homomorphic1_multiply(
                &erroneous1_homomorphic_eval_polynomial(
                    &crs.encrypted1_alpha_times_s_powers,
                    &self.my_secret_polynomial,
                ),
                random_entropy,
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
