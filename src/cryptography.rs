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
    let modulus: BigNumberType =
        BigUint::parse_bytes(b"31", 10).expect("hard-coded number string should be valid");
    let g: BigNumberType =
        BigUint::parse_bytes(b"11", 10).expect("hard-coded number string should be valid");
    return EncryptionParameters {
        modulus: modulus,
        g: g,
    };
}

/// Make encrypted and clear numbers be different types for stronger compile-time checking
#[derive(PartialEq, Eq, Hash)]
pub struct EncryptedNumber {
    val: BigNumberType,
}

impl EncryptedNumber {
    /// homomorphically add two encrypted numbers
    pub fn plus(
        &self,
        other: &EncryptedNumber,
        encryption_parameters: &EncryptionParameters,
    ) -> EncryptedNumber {
        return EncryptedNumber {
            val: (&self.val * &other.val).rem(&encryption_parameters.modulus),
        };
    }

    /// homomorphically multiply an encrypted number by a cleartext number
    pub fn times_by(
        &self,
        multiplier: f64, // must be integer-valued
        encryption_parameters: &EncryptionParameters,
    ) -> EncryptedNumber {
        return EncryptedNumber {
            val: self.val.modpow(
                &BigUint::from_f64(multiplier)
                    .expect("homomorphic_multiply should have multiplier be integer-valued..."),
                &encryption_parameters.modulus,
            ),
        };
    }
}

pub fn encrypt(
    encryption_parameters: &EncryptionParameters,
    cleartext: BigNumberType,
) -> EncryptedNumber {
    return EncryptedNumber {
        val: encryption_parameters
            .g
            .modpow(&cleartext, &encryption_parameters.modulus),
    };
}

pub fn homomorphic_eval_polynomial(
    encryption_parameters: &EncryptionParameters,
    encrypted_s_powers: &Vec<EncryptedNumber>,
    polynomial: &Poly<f64>,
) -> EncryptedNumber {
    return polynomial
        .coeffs()
        .into_iter()
        .zip(encrypted_s_powers)
        .map(|(coeff, encrypted_s_power)| encrypted_s_power.times_by(coeff, encryption_parameters))
        .reduce(|n1, n2| n1.plus(&n2, encryption_parameters))
        .expect("Polynomial not empty");
}
