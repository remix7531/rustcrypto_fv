mod soft_compact;

cfg_if::cfg_if! {
    if #[cfg(any(sha2_backend = "soft-compact", not(target_arch = "aarch64")))] {
        use soft_compact::compress;
    } else {
        mod aarch64_sha2;
        use aarch64_sha2::compress;
    }
}

#[inline(always)]
#[allow(dead_code)]
fn to_u64s(block: &[u8; 128]) -> [u64; 16] {
    core::array::from_fn(|i| {
        let chunk = block[8 * i..][..8].try_into().unwrap();
        u64::from_be_bytes(chunk)
    })
}

/// Raw SHA-512 compression function.
///
/// This is a low-level "hazmat" API which provides direct access to the core
/// functionality of SHA-512.
pub fn compress512(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    compress(state, blocks)
}
