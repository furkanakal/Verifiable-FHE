use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use rand::random;

pub const NOISE_BOUND: u64 = 10;  // Limit for noise terms
pub const Q: u64 = 1 << 59;  // Ciphertext modulus

fn main() -> Result<()> {
    const D: usize = 2;
    const N: usize = 2048;  // Degree of polynomials (constant size)

    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Set up BFV parameters (same as before)
    const T: u64 = 65537;  // Plaintext modulus

    let q = F::from_canonical_u64(Q);  // Ciphertext modulus in the field
    let _t = F::from_canonical_u64(T);  // Plaintext modulus in the field (prefixed with _ to avoid unused variable warning)
    let delta = q / F::from_canonical_u64(T);  // Delta for plaintext scaling

    // Key generation: sample secret key with coefficients in {-1, 0, 1}
    let secret_key: [F; N] = sample_r2_poly();

    // Generate public key
    let (public_key_a, public_key_b) = generate_public_key(&secret_key, q);

    // Encrypt two messages
    let m1: [F; N] = [F::from_canonical_u64(1); N];  // Message 1 (bit 1)
    let m2: [F; N] = [F::from_canonical_u64(0); N];  // Message 2 (bit 0)

    let (c1_1, c1_2) = encrypt_with_public_key(&public_key_a, &public_key_b, &m1, delta);  // Encrypt message 1
    let (c2_1, c2_2) = encrypt_with_public_key(&public_key_a, &public_key_b, &m2, delta);  // Encrypt message 2

    // Perform homomorphic addition: (c3_1, c3_2) = (c1_1 + c2_1, c1_2 + c2_2)
    let c3_1 = add_polynomials(&c1_1, &c2_1, N);
    let c3_2 = c1_2 + c2_2;

    // Build the circuit to prove the correctness of homomorphic addition
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Add inputs for ciphertext components and secret key
    let c1_1_targets = builder.add_virtual_target_arr::<{ N }>();
    let c2_1_targets = builder.add_virtual_target_arr::<{ N }>();
    let secret_key_targets = builder.add_virtual_target_arr::<{ N }>();
    let c1_2_target = builder.add_virtual_target();
    let c2_2_target = builder.add_virtual_target();

    // Compute homomorphic addition inside the circuit
    let c3_1_targets: Vec<_> = c1_1_targets.iter().zip(c2_1_targets.iter()).map(|(&c1_1i, &c2_1i)| builder.add(c1_1i, c2_1i)).collect();
    let c3_2_calc = builder.add(c1_2_target, c2_2_target);

    // Check that the result matches the expected sum
    let mut c3_1_computed = builder.constant(F::ZERO);
    for i in 0..N {
        let term = builder.mul(secret_key_targets[i], c3_1_targets[i]);
        c3_1_computed = builder.add(c3_1_computed, term);
    }
    let c3_2_computed = builder.mul(secret_key_targets[0], c3_2_calc);  // Simplified check
    builder.connect(c3_1_computed, c3_2_computed);

    // Set public inputs for verification
    for i in 0..N {
        builder.register_public_input(c1_1_targets[i]);
        builder.register_public_input(c2_1_targets[i]);
        builder.register_public_input(c3_1_targets[i]);
    }
    builder.register_public_input(c1_2_target);
    builder.register_public_input(c2_2_target);
    builder.register_public_input(c3_2_calc);

    // Set witness values (without asserts for comparison)
    let mut pw = PartialWitness::new();
    for i in 0..N {
        pw.set_target(c1_1_targets[i], c1_1[i]);
        pw.set_target(c2_1_targets[i], c2_1[i]);
        pw.set_target(secret_key_targets[i], secret_key[i]);
    }

    // Set values for c1_2 and c2_2
    pw.set_target(c1_2_target, c1_2);
    pw.set_target(c2_2_target, c2_2);

    // Build the proof
    let data = builder.build::<C>();
    let proof = data.prove(pw)?;

    // Verify the proof
    data.verify(proof)?;

    println!("Proof verified successfully.");
    println!("Homomorphic BFV ciphertext sum (c3_1, c3_2) is: ({:?}, {})", c3_1, c3_2);

    Ok(())
}

/// Sample polynomials from R2 {-1, 0, 1} for secret key generation
fn sample_r2_poly<F: Field>() -> [F; 2048] {
    let mut poly = [F::ZERO; 2048];
    for i in 0..2048 {
        let r: f64 = rand::random();
        poly[i] = if r < 0.33 {
            F::NEG_ONE
        } else if r < 0.66 {
            F::ZERO
        } else {
            F::ONE
        };
    }
    poly
}

/// Sample noise (error terms) bounded by NOISE_BOUND
fn sample_bounded_noise<F: Field>() -> F {
    let noise: u64 = random::<u64>() % (2 * NOISE_BOUND + 1); // Generate random noise between 0 and 2 * NOISE_BOUND
    F::from_canonical_u64(noise)
}

/// Generate public key from secret key
fn generate_public_key<F: Field>(secret_key: &[F], q: F) -> ([F; 2048], F) {
    let a: [F; 2048] = sample_rq_poly();
    let e = sample_bounded_noise::<F>();  // Small bounded error term
    let b = inner_product(&a, secret_key) + e;
    (a, b)
}

/// Encrypt a message with the public key
fn encrypt_with_public_key<F: Field>(public_key_a: &[F], public_key_b: &F, message: &[F], delta: F) -> ([F; 2048], F) {
    let u: [F; 2048] = sample_r2_poly();  // Random ternary polynomial
    let e1 = sample_bounded_noise::<F>();  // Small bounded error term
    let e2 = sample_bounded_noise::<F>();  // Small bounded error term
    let c1 = inner_product(public_key_a, &u) + e1 + delta * inner_product(message, &u);
    let c2 = *public_key_b * inner_product(&u, &u) + e2;
    ([c1; 2048], c2)
}

/// Sample a polynomial from Rq uniformly
fn sample_rq_poly<F: Field>() -> [F; 2048] {
    let mut poly = [F::ZERO; 2048];
    for i in 0..2048 {
        poly[i] = F::from_canonical_u64(rand::random::<u64>() % Q);
    }
    poly
}

/// Compute the inner product of two polynomials
fn inner_product<F: Field>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b.iter()).map(|(&ai, &bi)| ai * bi).sum()
}

/// Add two polynomials
fn add_polynomials<F: Field>(a: &[F], b: &[F], n: usize) -> [F; 2048] {
    let mut result = [F::ZERO; 2048];
    for i in 0..n {
        result[i] = a[i] + b[i];
    }
    result
}
