use polynomen::Poly;
use zksnark::groth16::{
    fr::{G1Local, G2Local, GtLocal},
    EllipticEncryptable, FrLocal,
};

pub(crate) fn homomorphic_eval_polynomial(
    encrypted_s_powers: &Vec<G1Local>,
    polynomial: &Poly<usize>,
) -> G1Local {
    return polynomial
        .coeffs()
        .into_iter()
        .zip(encrypted_s_powers)
        .map(|(coeff, encrypted_s_power)| homomorphic_multiply(encrypted_s_power, coeff))
        .sum();
}


pub(crate) fn homomorphic_multiply(e_a: &G1Local, b: usize) -> G1Local {
    return FrLocal::from(b).exp_encrypted_g1(*e_a);
}

pub(crate) fn crypto_pairing(e_a: G1Local, e_b: G2Local) -> GtLocal {
    return FrLocal::pairing(e_a, e_b);
}

pub(crate) fn encrypt_g1(n: usize) -> G1Local {
    return FrLocal::from(n).encrypt_g1();
}

pub(crate) fn encrypt_g2(n: usize) -> G2Local {
    return FrLocal::from(n).encrypt_g2();
}

pub(crate) fn mult_and_encrypt_g1(n: usize, m: usize) -> G1Local {
    return (FrLocal::from(n) * FrLocal::from(m)).encrypt_g1();
}
