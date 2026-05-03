//! FFI bindings for jitterentropy-library.
//!
//! Only the symbols required by this daemon are declared.

use libc::{c_char, c_int, c_uint, size_t, ssize_t};

/// Minimum oversampling rate when JENT_CONF_DISABLE_LOOP_SHUFFLE is set (the
/// library default). Mirrors the C header define of the same name.
pub const JENT_MIN_OSR: c_uint = 3;

/// Force FIPS-140 / SP800-90B compliant mode.
/// This causes jent_read_entropy() to be used (instead of jent_read_entropy_safe),
/// which is required for SP800-90B compliance since _safe allows a changing
/// H_submitter, which the standard does not permit.
pub const JENT_FORCE_FIPS: c_uint = 1 << 5;

/// Opaque entropy collector handle returned by jent_entropy_collector_alloc().
#[repr(C)]
pub struct RandData {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
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
}
