# zkLWE

Plonky2 implementation to prove a homomorphic LWE addition

## Usage

### Running the Main Application

To run the main application (`main.rs`), use the following command:

```sh
cargo run
```

### Running the LWE Decryption Binary

To run the LWE decryption binary (`lwe_decrypt.rs`), use the following command:

```sh
cargo run --bin lwe_decrypt
```

## Dependencies

This project uses the following dependencies:

- `plonky2` - A library for zero-knowledge proofs and cryptographic circuits.
- `anyhow` - A simple error handling library.
- `num-bigint` - A library for big integer arithmetic.
- `num-traits` - Numeric traits for Rust.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.