# RustCrypto: SHA-2 (formally verified)

![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

Pure Rust implementation of the [SHA-2] cryptographic hash algorithms, refactored
for formal verification via [HAX] and [F*].

There are 6 standard algorithms specified in the SHA-2 standard:
`Sha224`, `Sha256`, `Sha512_224`, `Sha512_256`, `Sha384`, and `Sha512`.

Algorithmically, there are only 2 core algorithms: SHA-256 and SHA-512.
All other algorithms are just applications of these with different initial
hash values, and truncated to different digest bit lengths. The first two
algorithms in the list are based on SHA-256, while the last four are based
on SHA-512.

## Design

This fork simplifies the upstream `digest` trait-based API with a pure functional
API. The implementation exposes standalone functions that take and return plain data, with no trait objects or generics, making them amenable to F* extraction via hax.

F* proofs can be found in the `proofs/` directory.

## Examples

```rust
use hex_literal::hex;

let hash256 = sha2::sha256(b"hello world");
assert_eq!(hash256, hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));

let hash512 = sha2::sha512(b"hello world");
assert_eq!(hash512, hex!(
    "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f"
    "989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
));
```

## Backends

This fork retains only the following backends:
- `soft-compact`: portable implementation (default)
- `aarch64-sha2`: uses the AArch64 `sha2` extension
- `x86-shani`: uses the x86 SHA-NI extension (SHA-256 only)

The `soft`, `loongarch64-asm`, `riscv-zknh`, `riscv-zknh-compact`, and
`wasm32-simd` backends have been removed.

## License

The crate is licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg

[//]: # (general links)

[SHA-2]: https://en.wikipedia.org/wiki/SHA-2
[hax]: https://github.com/cryspen/hax
[F*]: https://www.fstar-lang.org/
