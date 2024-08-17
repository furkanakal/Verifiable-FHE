use num_bigint::BigInt;
use num_traits::{Zero, Num};

// Define the parameters for LWE
const Q: &str = "18446744069414584320"; // A prime number, typically chosen large

fn main() {
    // Example usage
    let a = vec![BigInt::from(7), BigInt::from(9), BigInt::from(11)];
    let b = BigInt::from(9223372034707292349u64);

    let secret_key = vec![BigInt::from(1), BigInt::from(0), BigInt::from(1)];

    let decrypted = decrypt_lwe_bit(&a, &b, &secret_key);
    println!("Decrypted bit: {}", decrypted);
}

fn decrypt_lwe_bit(a: &[BigInt], b: &BigInt, secret_key: &[BigInt]) -> u64 {
    let q = BigInt::from_str_radix(Q, 10).unwrap();
    
    // Compute the inner product of a and secret_key, modulo Q
    let inner_product: BigInt = a.iter()
        .zip(secret_key.iter())
        .map(|(ai, si)| (ai * si) % &q)
        .fold(BigInt::zero(), |sum, val| (sum + val) % &q);

    // Compute b - inner_product mod Q
    let mut result = (b - &inner_product) % &q;
    if result < BigInt::zero() {
        result += &q;
    }

    // Determine the decrypted bit
    let q_half = &q / 2;
    if result > q_half {
        1
    } else {
        0
    }
}
