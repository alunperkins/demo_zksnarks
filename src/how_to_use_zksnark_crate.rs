// the zksnark crate isn't totally totally obvious how to use it, but these tests can illustrate some of its functionality.

#[cfg(test)]
mod tests {
    use zksnark::groth16::{fr::GtLocal, EllipticEncryptable, FrLocal};

    #[test]
    fn homomorphic_addition() {
        let a = FrLocal::from(1024);
        let b = FrLocal::from(3333);
        let a_plus_b = FrLocal::from(4357);

        let e_a = a.encrypt_g1();
        let e_b = b.encrypt_g1();
        let e_a_plus_b = a_plus_b.encrypt_g1();

        assert!(e_a_plus_b == e_a + e_b); // G1Local type puts its homomorphic logic in its implementation of the Add trait
    }

    #[test]
    fn homomorphic_multiplication() {
        let a = FrLocal::from(1024);
        let b = FrLocal::from(3333);
        let a_times_b = FrLocal::from(3412992);

        let e_a = a.encrypt_g1();
        let e_a_times_b = a_times_b.encrypt_g1();

        assert!(e_a_times_b == b.exp_encrypted_g1(e_a));
    }

    fn pair(n: usize, m: usize) -> GtLocal {
        let fr_n = FrLocal::from(n);
        let fr_m = FrLocal::from(m);
        let pair_n_m = FrLocal::pairing(fr_n.encrypt_g1(), fr_m.encrypt_g2());
        return pair_n_m;
    }

    #[test]
    fn cryptographic_pairing() {
        // commutativity
        assert!(pair(1024, 3333) == pair(3333, 1024));

        // homomorphic multiplication
        assert!(pair(1024, 3333) == pair(1024 * 3333, 1));
        assert!(pair(1024, 33 * 101) == pair(1024 * 33, 101));

        // homomorphic addition
        assert!(pair(1025, 3333) + pair(1026, 4444) == pair(1025 * 3333 + 1026 * 4444, 1)); // GtLocal type puts its homomorphic logic in its implementation of the Add trait
        assert!(
            pair(1025, 3333) + pair(1026, 4444)
                == pair(1025, 3333) + pair(1026, 2222) + pair(1026, 2222)
        );
    }
}
