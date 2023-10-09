use zksnark::groth16::fr::{G1Local, G2Local};

use crate::{
    cryptography::{
        crypto_pairing, encrypt1, encrypt2, homomorphic1_multiply, homomorphic2_multiply,
        mult_and_encrypt1, mult_and_encrypt2,
    },
    CrsCeremonyStep, CrsCeremonyTranscript, CrsCeremonyValues, CRS, POLYNOMIAL_DEGREE,
};

pub(crate) struct CrsPlayer {
    s: usize,     // secret value at which the polynomial is to be evaluated
    alpha: usize, // value for scaling the polynomial as part proof/validation algorithm for restricting how the prover generates the proof
}

impl CrsPlayer {
    pub fn new(s: usize, alpha: usize) -> Self {
        Self { s, alpha }
    }

    fn get_crs_step_values(&self) -> CrsCeremonyStep {
        let step_encrypted1_s_powers: Vec<G1Local> = (0..POLYNOMIAL_DEGREE + 1)
            .map(|k| self.s.checked_pow(k).expect("not to overflow"))
            .map(|s_to_kth_power: usize| encrypt1(s_to_kth_power))
            .collect();

        let step_encrypted2_alpha_times_s_powers: Vec<G2Local> = (0..POLYNOMIAL_DEGREE + 1)
            .map(|k| self.s.checked_pow(k).expect("not to overflow"))
            .map(|s_to_kth_power: usize| mult_and_encrypt2(s_to_kth_power, self.alpha))
            .collect();

        return CrsCeremonyStep {
            encrypted1_s_powers: step_encrypted1_s_powers,
            encrypted1_alpha: encrypt1(self.alpha),
            encrypted2_alpha_times_s_powers: step_encrypted2_alpha_times_s_powers,
        };
    }

    pub(crate) fn start_crs_ceremony(&self) -> CrsCeremonyValues {
        let encrypted2_alpha = encrypt2(self.alpha);

        let encrypted2_s_powers: Vec<G2Local> = (0..POLYNOMIAL_DEGREE + 1)
            .map(|k| self.s.checked_pow(k).expect("not to overflow"))
            .map(|s_to_kth_power: usize| encrypt2(s_to_kth_power))
            .collect();

        let encrypted1_s_powers: Vec<G1Local> = (0..POLYNOMIAL_DEGREE + 1)
            .map(|k| self.s.checked_pow(k).expect("not to overflow"))
            .map(|s_to_kth_power: usize| encrypt1(s_to_kth_power))
            .collect();

        let encrypted1_alpha_times_s_powers: Vec<G1Local> = (0..POLYNOMIAL_DEGREE + 1)
            .map(|k| self.s.checked_pow(k).expect("not to overflow"))
            .map(|s_to_kth_power: usize| mult_and_encrypt1(s_to_kth_power, self.alpha))
            .collect();

        let retval = CrsCeremonyValues {
            accumulator: CRS {
                encrypted2_alpha,
                encrypted2_s_powers,
                encrypted1_s_powers,
                encrypted1_alpha_times_s_powers,
            },
            step: self.get_crs_step_values(),
        };

        self.secure_erase_my_secret_s_and_alpha_values();

        return retval;
    }

    ///
    pub(crate) fn continue_crs_ceremony(
        &self,
        transcript: &CrsCeremonyTranscript,
    ) -> CrsCeremonyValues {
        validate_ceremony_transcript(transcript);
        let retval = self.mix_my_secrets_into_ceremony_transcript(transcript);

        self.secure_erase_my_secret_s_and_alpha_values();

        return retval;
    }

    fn mix_my_secrets_into_ceremony_transcript(
        &self,
        transcript: &CrsCeremonyTranscript,
    ) -> CrsCeremonyValues {
        let crs_current = &transcript.history.last().expect("non-empty").accumulator;

        let new_encrypted2_alpha = homomorphic2_multiply(&crs_current.encrypted2_alpha, self.alpha);

        let new_encrypted2_s_powers: Vec<G2Local> = (0..POLYNOMIAL_DEGREE + 1)
            .map(|k| self.s.checked_pow(k).expect("not to overflow"))
            .zip(&crs_current.encrypted2_s_powers)
            .map(
                |(s_to_kth_power, ceremony_current_encrypted2_s_to_kth_power)| {
                    homomorphic2_multiply(
                        &ceremony_current_encrypted2_s_to_kth_power,
                        s_to_kth_power,
                    )
                },
            )
            .collect();

        let new_encrypted1_s_powers: Vec<G1Local> = (0..POLYNOMIAL_DEGREE + 1)
            .map(|k| self.s.checked_pow(k).expect("not to overflow"))
            .zip(&crs_current.encrypted1_s_powers)
            .map(
                |(s_to_kth_power, ceremony_current_encrypted1_s_to_kth_power)| {
                    homomorphic1_multiply(
                        &ceremony_current_encrypted1_s_to_kth_power,
                        s_to_kth_power,
                    )
                },
            )
            .collect();

        let new_encrypted1_alpha_times_s_powers: Vec<G1Local> = (0..POLYNOMIAL_DEGREE + 1)
            .map(|k| self.s.checked_pow(k).expect("not to overflow"))
            .zip(&crs_current.encrypted1_alpha_times_s_powers)
            .map(
                |(s_to_kth_power, ceremony_current_encrypted1_alpha_times_s_power)| {
                    homomorphic1_multiply(
                        &ceremony_current_encrypted1_alpha_times_s_power,
                        self.alpha * s_to_kth_power,
                    )
                },
            )
            .collect();

        return CrsCeremonyValues {
            accumulator: CRS {
                encrypted2_alpha: new_encrypted2_alpha,
                encrypted2_s_powers: new_encrypted2_s_powers,
                encrypted1_s_powers: new_encrypted1_s_powers,
                encrypted1_alpha_times_s_powers: new_encrypted1_alpha_times_s_powers,
            },
            step: self.get_crs_step_values(),
        };
    }

    fn secure_erase_my_secret_s_and_alpha_values(&self) {
        // this function is just for show, it doesn't really apply to this project as it is at the moment
    }
}

fn validate_ceremony_transcript(transcript: &CrsCeremonyTranscript) -> () {
    let all_internally_consistent = transcript
        .history
        .iter()
        .all(|ccv| current_crs_value_is_internally_consistent(&ccv.accumulator));

    let every_ccv_includes_entropy_from_previous_ccv = (1..transcript.history.len()).all(|index| {
        is_valid_crs_ceremony_step(&transcript.history[index - 1], &transcript.history[index])
    });

    if !(all_internally_consistent && every_ccv_includes_entropy_from_previous_ccv) {
        panic!("transcript not valid") // TOOD use Result instead
    };
}

fn current_crs_value_is_internally_consistent(accumulator: &CRS) -> bool {
    // the validation code only works if the lengths are correct so validate that first
    let correct_size = (POLYNOMIAL_DEGREE + 1) as usize;
    if !(accumulator.encrypted2_s_powers.len() == correct_size
        && accumulator.encrypted1_s_powers.len() == correct_size
        && accumulator.encrypted1_alpha_times_s_powers.len() == correct_size)
    {
        return false; // TODO ideally refactor to a pattern that returns more info, such as Result
    }

    let valid_alpha_relation = accumulator
        .encrypted1_s_powers
        .iter()
        .zip(&accumulator.encrypted1_alpha_times_s_powers)
        .all(|(e1_s_k, e1_a_s_k)| {
            crypto_pairing(*e1_s_k, accumulator.encrypted2_alpha)
                == crypto_pairing(*e1_a_s_k, encrypt2(1))
        });

    let both_encryptions_of_s_powers_match = accumulator
        .encrypted1_s_powers
        .iter()
        .zip(&accumulator.encrypted2_s_powers)
        .all(|(encrypted1_s_power, encrypted2_s_power)| {
            crypto_pairing(*encrypted1_s_power, encrypt2(1))
                == crypto_pairing(encrypt1(1), *encrypted2_s_power)
        });

    let both_vecs_of_s_powers_have_same_ratios =
        (1..(POLYNOMIAL_DEGREE + 1) as usize).all(|index1| {
            let expected_pairing = crypto_pairing(
                accumulator.encrypted1_s_powers[0],
                accumulator.encrypted2_s_powers[index1],
            );
            return (1..index1 + 1).all(|index2| {
                crypto_pairing(
                    accumulator.encrypted1_s_powers[index2],
                    accumulator.encrypted2_s_powers[index1 - index2],
                ) == expected_pairing
            });
        });

    return valid_alpha_relation
        && both_encryptions_of_s_powers_match
        && both_vecs_of_s_powers_have_same_ratios;
}

fn is_valid_crs_ceremony_step(before: &CrsCeremonyValues, after: &CrsCeremonyValues) -> bool {
    let alpha_was_transformed_by_stated_value =
        crypto_pairing(
            after.step.encrypted1_alpha,
            before.accumulator.encrypted2_alpha,
        ) == crypto_pairing(encrypt1(1), after.accumulator.encrypted2_alpha);

    let every_s_power_was_transformed_by_stated_value =
        (0..(POLYNOMIAL_DEGREE + 1) as usize).all(|index| {
            crypto_pairing(
                after.step.encrypted1_s_powers[index],
                before.accumulator.encrypted2_s_powers[index],
            ) == crypto_pairing(after.accumulator.encrypted1_s_powers[index], encrypt2(1))
        });

    let every_alpha_times_s_power_was_transformed_by_stated_value =
        (0..(POLYNOMIAL_DEGREE + 1) as usize).all(|index| {
            crypto_pairing(
                before.accumulator.encrypted1_alpha_times_s_powers[index],
                after.step.encrypted2_alpha_times_s_powers[index],
            ) == crypto_pairing(
                after.accumulator.encrypted1_alpha_times_s_powers[index],
                encrypt2(1),
            )
        });

    return alpha_was_transformed_by_stated_value
        && every_s_power_was_transformed_by_stated_value
        && every_alpha_times_s_power_was_transformed_by_stated_value;
}
