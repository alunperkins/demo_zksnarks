use polynomen::Poly;
use zksnark::groth16::{
    fr::{G1Local, G2Local, GtLocal},
    EllipticEncryptable, FrLocal,
};

pub(crate) fn crypto_pairing(e_a: G1Local, e_b: G2Local) -> GtLocal {
    return FrLocal::pairing(e_a, e_b);
}

// G1 functions

pub(crate) fn homomorphic1_eval_polynomial(
    encrypted_x_powers: &Vec<G1Local>,
    polynomial: &Poly<usize>,
) -> G1Local {
    return polynomial
        .coeffs()
        .into_iter()
        .zip(encrypted_x_powers)
        .map(|(coeff, encrypted_s_power)| homomorphic1_multiply(encrypted_s_power, coeff))
        .sum();
}

/// uses the wrong value for the third polynomial coefficient
pub(crate) fn erroneous1_homomorphic_eval_polynomial(
    encrypted_x_powers: &Vec<G1Local>,
    polynomial: &Poly<usize>,
) -> G1Local {
    return polynomial
        .coeffs()
        .into_iter()
        .zip(encrypted_x_powers)
        .enumerate()
        .map(|(index, (coeff, encrypted_s_power))| {
            if index == 2 {
                homomorphic1_multiply(encrypted_s_power, coeff + 1) // this is the error
            } else {
                homomorphic1_multiply(encrypted_s_power, coeff)
            }
        })
        .sum();
}

pub(crate) fn homomorphic1_multiply(e_a: &G1Local, b: usize) -> G1Local {
    return FrLocal::from(b).exp_encrypted_g1(*e_a);
}

pub(crate) fn encrypt1(n: usize) -> G1Local {
    return FrLocal::from(n).encrypt_g1();
}

pub(crate) fn mult_and_encrypt1(n: usize, m: usize) -> G1Local {
    return (FrLocal::from(n) * FrLocal::from(m)).encrypt_g1();
}

// G2 functions

pub(crate) fn homomorphic2_eval_polynomial(
    encrypted_x_powers: &Vec<G2Local>,
    polynomial: &Poly<usize>,
) -> G2Local {
    return polynomial
        .coeffs()
        .into_iter()
        .zip(encrypted_x_powers)
        .map(|(coeff, encrypted_s_power)| homomorphic2_multiply(encrypted_s_power, coeff))
        .sum();
}

/// uses the wrong value for the third polynomial coefficient
pub(crate) fn erroneous2_homomorphic_eval_polynomial(
    encrypted_x_powers: &Vec<G2Local>,
    polynomial: &Poly<usize>,
) -> G2Local {
    return polynomial
        .coeffs()
        .into_iter()
        .zip(encrypted_x_powers)
        .enumerate()
        .map(|(index, (coeff, encrypted_s_power))| {
            if index == 2 {
                homomorphic2_multiply(encrypted_s_power, coeff + 1) // this is the error
            } else {
                homomorphic2_multiply(encrypted_s_power, coeff)
            }
        })
        .sum();
}

pub(crate) fn homomorphic2_multiply(e_a: &G2Local, b: usize) -> G2Local {
    return FrLocal::from(b).exp_encrypted_g2(*e_a);
}

pub(crate) fn encrypt2(n: usize) -> G2Local {
    return FrLocal::from(n).encrypt_g2();
}

pub(crate) fn mult_and_encrypt2(n: usize, m: usize) -> G2Local {
    return (FrLocal::from(n) * FrLocal::from(m)).encrypt_g2();
}
