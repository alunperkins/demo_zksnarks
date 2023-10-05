use std::ops::Rem;

use num::FromPrimitive;
use num_bigint::BigUint;
use polynomen::Poly;

use crate::BigNumberType;

pub struct EncryptionParameters {
    modulus: BigNumberType,
    g: BigNumberType,
}

pub fn get_encryption_parameters() -> EncryptionParameters {
    let modulus: BigNumberType = BigUint::parse_bytes(b"31", 10).unwrap();
    let g: BigNumberType = BigUint::parse_bytes(b"11", 10).unwrap();
    return EncryptionParameters {
        modulus: modulus,
        g: g,
    };
}

pub fn encrypt(
    encryption_parameters: &EncryptionParameters,
    cleartext: BigNumberType,
) -> BigNumberType {
    return encryption_parameters
        .g
        .modpow(&cleartext, &encryption_parameters.modulus);
}

pub fn homomorphic_eval_polynomial(
    encryption_parameters: &EncryptionParameters,
    encrypted_s_powers: &Vec<BigNumberType>,
    polynomial: &Poly<f64>,
) -> BigNumberType {
    return polynomial
        .coeffs()
        .into_iter()
        .zip(encrypted_s_powers)
        .map(|(coeff, encrypted_s_power)| {
            homomorphic_multiply(encryption_parameters, encrypted_s_power, coeff)
        })
        .reduce(|acc, e| (acc * e).rem(&encryption_parameters.modulus))
        .unwrap(); // won't panic unless the polynomial has no coefficients
}

pub fn homomorphic_multiply(
    encryption_parameters: &EncryptionParameters,
    ciphertext: &BigNumberType,
    multiplier: f64,
) -> BigNumberType {
    return ciphertext.modpow(
        &BigUint::from_f64(multiplier).unwrap(),
        &encryption_parameters.modulus,
    );
}
