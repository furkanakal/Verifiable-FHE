use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use rand::random;

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Generate random secret_key, a1, and a2 vectors
    let secret_key: [F; 3] = [F::from_canonical_u64(random::<u64>()), F::from_canonical_u64(random::<u64>()), F::from_canonical_u64(random::<u64>())];
    let a1: [F; 3] = [F::from_canonical_u64(random::<u64>()), F::from_canonical_u64(random::<u64>()), F::from_canonical_u64(random::<u64>())];
    let a2: [F; 3] = [F::from_canonical_u64(random::<u64>()), F::from_canonical_u64(random::<u64>()), F::from_canonical_u64(random::<u64>())];

    let m1 = F::from_canonical_u64(1); // Encrypt bit 1
    let m2 = F::from_canonical_u64(0); // Encrypt bit 0
    let e1 = F::from_canonical_u64(38);
    let e2 = F::from_canonical_u64(133);

    let q = F::from_canonical_u64(18446744069414584320);
    let q_half = q / F::TWO;
    let b1 = inner_product(&a1, &secret_key) + e1 + m1 * q_half;
    let b2 = inner_product(&a2, &secret_key) + e2 + m2 * q_half;

    // Perform the ciphertext addition
    let a3: Vec<F> = a1.iter().zip(a2.iter()).map(|(&a1i, &a2i)| a1i + a2i).collect();
    let b3 = b1 + b2;

    // Build the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let initial_a1 = builder.add_virtual_target_arr::<3>();
    let initial_a2 = builder.add_virtual_target_arr::<3>();
    let initial_b1 = builder.add_virtual_target();
    let initial_b2 = builder.add_virtual_target();
    let secret_key_target = builder.add_virtual_target_arr::<3>();
    let error1 = builder.add_virtual_target();
    let error2 = builder.add_virtual_target();
    let plaintext1 = builder.add_virtual_target();
    let plaintext2 = builder.add_virtual_target();
    let q_half_target = builder.constant(q_half);

    let mut sum_a = builder.constant(F::ZERO);
    for i in 0..3 {
        let term = builder.mul(secret_key_target[i], initial_a1[i]);
        sum_a = builder.add(sum_a, term);
    }
    let plaintext1_scaled = builder.mul(plaintext1, q_half_target);
    let b1_calc = builder.add_many(&[sum_a, error1, plaintext1_scaled]);

    let mut sum_a2 = builder.constant(F::ZERO);
    for i in 0..3 {
        let term = builder.mul(secret_key_target[i], initial_a2[i]);
        sum_a2 = builder.add(sum_a2, term);
    }
    let plaintext2_scaled = builder.mul(plaintext2, q_half_target);
    let b2_calc = builder.add_many(&[sum_a2, error2, plaintext2_scaled]);

    let final_a = initial_a1.iter().zip(initial_a2.iter()).map(|(&a1i, &a2i)| builder.add(a1i, a2i)).collect::<Vec<_>>();
    let final_b = builder.add(initial_b1, initial_b2);

    let sum_error = builder.add(error1, error2);
    let sum_plaintext = builder.add(plaintext1, plaintext2);
    let mut sum_final_a = builder.constant(F::ZERO);
    for i in 0..3 {
        let term = builder.mul(secret_key_target[i], final_a[i]);
        sum_final_a = builder.add(sum_final_a, term);
    }
    let sum_plaintext_scaled = builder.mul(sum_plaintext, q_half_target);
    let b3_calc = builder.add_many(&[sum_final_a, sum_error, sum_plaintext_scaled]);

    builder.connect(final_b, b3_calc);
    builder.connect(initial_b1, b1_calc);
    builder.connect(initial_b2, b2_calc);

    for i in 0..3 {
        builder.register_public_input(initial_a1[i]);
        builder.register_public_input(initial_a2[i]);
        builder.register_public_input(final_a[i]);
    }
    builder.register_public_input(initial_b1);
    builder.register_public_input(initial_b2);
    builder.register_public_input(final_b);
    builder.register_public_input(b3_calc);

    // Provide initial values
    let mut pw = PartialWitness::new();
    for i in 0..3 {
        pw.set_target(initial_a1[i], a1[i]);
        pw.set_target(initial_a2[i], a2[i]);
        pw.set_target(secret_key_target[i], secret_key[i]);
    }
    pw.set_target(initial_b1, b1);
    pw.set_target(initial_b2, b2);
    pw.set_target(error1, e1);
    pw.set_target(error2, e2);
    pw.set_target(plaintext1, m1);
    pw.set_target(plaintext2, m2);

    let data = builder.build::<C>();
    let proof = data.prove(pw)?;

    println!("Final LWE ciphertext sum (a3, b3) is: ({:?}, {})", a3, b3);

    data.verify(proof)?;

    Ok(())
}

fn inner_product<F: Field>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b.iter()).map(|(&ai, &bi)| ai * bi).sum()
}
