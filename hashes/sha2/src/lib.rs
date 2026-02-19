#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, unreachable_pub)]
#![allow(clippy::needless_range_loop)]

#[rustfmt::skip]
mod consts;

#[cfg(any(feature = "sha256", feature = "sha256_224"))]
mod sha256;

#[cfg(any(
    feature = "sha512",
    feature = "sha512_224",
    feature = "sha512_256",
    feature = "sha512_384"
))]
mod sha512;

// ---------------------------------------------------------------------------
// Inner helpers
// ---------------------------------------------------------------------------

#[cfg(any(feature = "sha256", feature = "sha256_224"))]
fn sha256_inner(iv: [u32; 8], data: &[u8]) -> [u8; 32] {
    let mut state = iv;
    // >> 6 is equivalent to / 64
    // & 63 is equivalent to % 64
    let blocks: usize = data.len() >> 6;
    let remaining: usize = data.len() & 63;
    for i in 0..blocks {
        let block: &[u8; 64] = data[i * 64..][..64].try_into().unwrap();
        sha256::compress256(&mut state, &[*block]);
    }
    let total_bits = (data.len() as u64) << 3;
    let mut final_block: [u8; 64] = [0u8; 64];
    final_block[..remaining].copy_from_slice(&data[blocks * 64..]);
    final_block[remaining] = 0x80;
    if remaining >= 56 {
        sha256::compress256(&mut state, &[final_block]);
        final_block = [0u8; 64];
    }
    final_block[56..64].copy_from_slice(&total_bits.to_be_bytes());
    sha256::compress256(&mut state, &[final_block]);
    let mut out = [0u8; 32];
    for i in 0..8 {
        let bytes = state[i].to_be_bytes();
        out[i * 4] = bytes[0];
        out[i * 4 + 1] = bytes[1];
        out[i * 4 + 2] = bytes[2];
        out[i * 4 + 3] = bytes[3];
    }
    out
}

#[cfg(any(
    feature = "sha512",
    feature = "sha512_224",
    feature = "sha512_256",
    feature = "sha512_384"
))]
fn sha512_inner(iv: [u64; 8], data: &[u8]) -> [u8; 64] {
    let mut state = iv;
    // >> 7 is equivalent to / 128
    // & 127 is equivalent to % 128
    let blocks: usize = data.len() >> 7;
    let remaining: usize = data.len() & 127;
    for i in 0..blocks {
        let block: &[u8; 128] = data[i * 128..][..128].try_into().unwrap();
        sha512::compress512(&mut state, &[*block]);
    }
    let total_bits = (data.len() as u128) << 3;
    let mut final_block: [u8; 128] = [0u8; 128];
    final_block[..remaining].copy_from_slice(&data[blocks * 128..]);
    final_block[remaining] = 0x80;
    if remaining >= 112 {
        sha512::compress512(&mut state, &[final_block]);
        final_block = [0u8; 128];
    }
    final_block[112..128].copy_from_slice(&total_bits.to_be_bytes());
    sha512::compress512(&mut state, &[final_block]);
    let mut out = [0u8; 64];
    for i in 0..8 {
        let bytes = state[i].to_be_bytes();
        out[i * 8] = bytes[0];
        out[i * 8 + 1] = bytes[1];
        out[i * 8 + 2] = bytes[2];
        out[i * 8 + 3] = bytes[3];
        out[i * 8 + 4] = bytes[4];
        out[i * 8 + 5] = bytes[5];
        out[i * 8 + 6] = bytes[6];
        out[i * 8 + 7] = bytes[7];
    }
    out
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hash of `data`, returning a 32-byte digest.
#[cfg(feature = "sha256")]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha256_inner(consts::H256_256, data)
}

/// Compute the SHA-224 hash of `data`, returning a 28-byte digest.
#[cfg(feature = "sha256_224")]
pub fn sha224(data: &[u8]) -> [u8; 28] {
    let full = sha256_inner(consts::H256_224, data);
    full[..28].try_into().unwrap()
}

/// Compute the SHA-512 hash of `data`, returning a 64-byte digest.
#[cfg(feature = "sha512")]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    sha512_inner(consts::H512_512, data)
}

/// Compute the SHA-512/224 hash of `data`, returning a 28-byte digest.
#[cfg(feature = "sha512_224")]
pub fn sha512_224(data: &[u8]) -> [u8; 28] {
    let full = sha512_inner(consts::H512_224, data);
    full[..28].try_into().unwrap()
}

/// Compute the SHA-512/256 hash of `data`, returning a 32-byte digest.
#[cfg(feature = "sha512_256")]
pub fn sha512_256(data: &[u8]) -> [u8; 32] {
    let full = sha512_inner(consts::H512_256, data);
    full[..32].try_into().unwrap()
}

/// Compute the SHA-384 hash of `data`, returning a 48-byte digest.
#[cfg(feature = "sha512_384")]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let full = sha512_inner(consts::H512_384, data);
    full[..48].try_into().unwrap()
}
