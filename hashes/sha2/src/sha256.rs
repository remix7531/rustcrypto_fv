mod soft_compact;

cfg_if::cfg_if! {
    if #[cfg(any(
        sha2_backend = "soft-compact",
        not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))
    ))] {
        use soft_compact::compress;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod x86_shani;
        use x86_shani::compress;
    } else {
        mod aarch64_sha2;
        use aarch64_sha2::compress;
    }
}

#[inline(always)]
#[allow(dead_code)]
fn to_u32s(block: &[u8; 64]) -> [u32; 16] {
    core::array::from_fn(|i| {
        let chunk = block[4 * i..][..4].try_into().unwrap();
        u32::from_be_bytes(chunk)
    })
}

/// Raw SHA-256 compression function.
///
/// This is a low-level "hazmat" API which provides direct access to the core
/// functionality of SHA-256.
pub(crate) fn compress256(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    compress(state, blocks)
}
