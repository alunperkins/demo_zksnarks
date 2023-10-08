use polynomen::Poly;
use zksnark::groth16::{fr::G1Local, EllipticEncryptable, FrLocal};

pub(crate) fn homomorphic_eval_polynomial(
    encrypted_s_powers: &Vec<G1Local>,
    polynomial: &Poly<usize>,
) -> G1Local {
    return polynomial
        .coeffs()
        .into_iter()
        .zip(encrypted_s_powers)
        .map(|(coeff, encrypted_s_power)| FrLocal::from(coeff).exp_encrypted_g1(*encrypted_s_power))
        .sum();
}

pub(crate) fn homomorphic_multiply(e_a: G1Local, b: usize) -> G1Local {
    return FrLocal::from(b).exp_encrypted_g1(e_a);
}

pub(crate) fn encrypt_g1(n: usize) -> G1Local {
    return FrLocal::from(n).encrypt_g1();
}
pub(crate) fn mult_and_encrypt_g1(n: usize, m: usize) -> G1Local {
    return (FrLocal::from(n) * FrLocal::from(m)).encrypt_g1();
}
