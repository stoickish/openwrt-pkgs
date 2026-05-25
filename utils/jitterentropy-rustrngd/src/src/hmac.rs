use crate::jent_ffi;
use zeroize::Zeroize;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

fn sha3_256(data: &[u8]) -> [u8; jent_ffi::JENT_SHA3_256_SIZE_DIGEST] {
    let mut digest = [0u8; jent_ffi::JENT_SHA3_256_SIZE_DIGEST];
    let mut ctx = jent_ffi::Sha3Ctx {
        state: [0u64; 25],
        partial: [0u8; jent_ffi::JENT_SHA3_256_SIZE_BLOCK],
        msg_len: 0,
        r: 0,
        rword: 0,
        digestsize: 0,
        padding: 0,
        initially_seeded: 0,
    };
    unsafe {
        jent_ffi::jent_sha3_256_init(&mut ctx);
        jent_ffi::jent_sha3_update(&mut ctx, data.as_ptr(), data.len());
        jent_ffi::jent_sha3_final(&mut ctx, digest.as_mut_ptr());
    }
    ctx.zeroize();
    digest
}

/// Compute HMAC-SHA3-256 per NIST SP 800-185 / RFC 2104.
///
/// Returns the full 32-byte digest. The caller may truncate to `mac_len_bits`
/// bytes (e.g. for NIST ACVP test vectors where `macLen` is specified in bits).
pub fn hmac_sha3_256(key: &[u8], msg: &[u8]) -> [u8; jent_ffi::JENT_SHA3_256_SIZE_DIGEST] {
    let mut k0 = [0u8; jent_ffi::JENT_SHA3_256_SIZE_BLOCK];

    if key.len() > jent_ffi::JENT_SHA3_256_SIZE_BLOCK {
        let hashed_key = sha3_256(key);
        k0[..jent_ffi::JENT_SHA3_256_SIZE_DIGEST].copy_from_slice(&hashed_key);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut i_key_pad = k0;
    for b in i_key_pad.iter_mut() {
        *b ^= IPAD;
    }

    let mut o_key_pad = [0u8; jent_ffi::JENT_SHA3_256_SIZE_BLOCK];
    for (i, b) in k0.iter().enumerate() {
        o_key_pad[i] = b ^ OPAD;
    }

    let inner = sha3_256(&[&i_key_pad[..], msg].concat());

    let mac = sha3_256(&[&o_key_pad[..], &inner[..]].concat());

    k0.zeroize();
    i_key_pad.zeroize();
    o_key_pad.zeroize();

    mac
}
