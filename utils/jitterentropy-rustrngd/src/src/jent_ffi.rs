//! FFI bindings for jitterentropy-library.
//!
//! Only the symbols required by this daemon are declared.

use libc::{c_char, c_int, c_uint, size_t, ssize_t};
use zeroize::Zeroize;

/// Minimum oversampling rate when JENT_CONF_DISABLE_LOOP_SHUFFLE is set (the
/// library default). Mirrors the C header define of the same name.
pub const JENT_MIN_OSR: c_uint = 3;

/// Force FIPS-140 / SP800-90B compliant mode.
/// This causes jent_read_entropy() to be used (instead of jent_read_entropy_safe),
/// which is required for SP800-90B compliance since _safe allows a changing
/// H_submitter, which the standard does not permit.
pub const JENT_FORCE_FIPS: c_uint = 1 << 5;

/// SHA3-256 digest size in bytes (256 bits / 8).
pub const JENT_SHA3_256_SIZE_DIGEST: usize = 32;

/// SHA3-256 block size (rate) in bytes: (1600 - 2*256) / 8 = 136.
pub const JENT_SHA3_256_SIZE_BLOCK: usize = 136;

/// Opaque entropy collector handle returned by jent_entropy_collector_alloc().
#[repr(C)]
pub struct RandData {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

/// SHA-3 hash context, matching `struct jent_sha_ctx` from jitterentropy-sha3.h.
///
/// Stack-allocated and passed to `jent_sha3_256_init` / `jent_sha3_update` /
/// `jent_sha3_final`. Layout is C-compatible (`#[repr(C)]`) so Rust and C
/// agree on field offsets and alignment for the target ABI.
#[repr(C)]
#[derive(Zeroize)]
pub struct Sha3Ctx {
    pub state: [u64; 25],
    pub partial: [u8; JENT_SHA3_256_SIZE_BLOCK],
    pub msg_len: usize,
    pub r: u8,
    pub rword: u8,
    pub digestsize: u8,
    pub padding: u8,
    pub initially_seeded: u8,
}

extern "C" {
    /// Run the SHA-3 known-answer test. Must be called before jent_entropy_init().
    /// Returns 0 on success, nonzero on failure.
    pub fn jent_sha3_tester() -> c_int;

    /// Run the jitterentropy self-test. Must be called before alloc().
    /// Returns 0 on success, nonzero on failure.
    pub fn jent_entropy_init() -> c_int;

    /// Allocate an entropy collector.
    ///
    /// # Parameters
    /// - `osr`: oversampling rate; pass JENT_MIN_OSR or higher
    /// - `flags`: bitfield; use JENT_FORCE_FIPS for SP800-90B compliance
    ///
    /// Returns NULL on failure.
    pub fn jent_entropy_collector_alloc(osr: c_uint, flags: c_uint) -> *mut RandData;

    /// Free an entropy collector.
    pub fn jent_entropy_collector_free(ec: *mut RandData);

    /// Read `len` bytes of entropy into `data`.
    ///
    /// Used (rather than jent_read_entropy_safe) when JENT_FORCE_FIPS is set,
    /// because _safe allows H_submitter to change, violating SP800-90B.
    ///
    /// Returns number of bytes written on success, negative error code on failure.
    pub fn jent_read_entropy(ec: *mut RandData, data: *mut c_char, len: size_t) -> ssize_t;

    /// Initialize a SHA3-256 hash context.
    pub fn jent_sha3_256_init(ctx: *mut Sha3Ctx);

    /// Absorb `inlen` bytes from `input` into the hash context.
    pub fn jent_sha3_update(ctx: *mut Sha3Ctx, input: *const u8, inlen: usize);

    /// Finalize the hash and write the 32-byte digest to `digest`.
    pub fn jent_sha3_final(ctx: *mut Sha3Ctx, digest: *mut u8);
}
