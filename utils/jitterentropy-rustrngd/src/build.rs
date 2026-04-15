use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let jent_dir = manifest_dir.join("jitterentropy-library");
    let src_dir = jent_dir.join("src");

    if !src_dir.exists() {
        panic!(
            "jitterentropy-library sources not found at {:?}\n\
             The OpenWrt build system should unpack them there during Build/Prepare.",
            src_dir
        );
    }

    // Collect all .c sources from jitterentropy-library/src/
    let sources: Vec<PathBuf> = std::fs::read_dir(&src_dir)
        .unwrap_or_else(|e| panic!("cannot read {:?}: {}", src_dir, e))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|ext| ext == "c").unwrap_or(false))
        .collect();

    if sources.is_empty() {
        panic!("no .c sources found in {:?}", src_dir);
    }

    // Build with the exact flags required by jitterentropy.
    //
    // -O0 is MANDATORY. The entropy source relies on CPU timing jitter.
    // Any optimization can make the compiler eliminate or reorder the
    // timing-sensitive loops, destroying the entropy source entirely.
    //
    // These flags replicate the upstream jitterentropy-library Makefile
    // defaults exactly as documented in:
    //   https://github.com/smuellerDD/jitterentropy-library/blob/master/Makefile
    cc::Build::new()
        .files(&sources)
        .include(&jent_dir)  // jitterentropy.h lives in the repo root
        .include(&src_dir)   // internal headers
        // Optimization: none — mandatory for timing-jitter entropy correctness
        .opt_level(0)
        // Hardening and correctness flags from upstream Makefile
        .flag("-fwrapv")
        .flag("-fvisibility=hidden")
        .flag("-fPIE")
        .flag("-fstack-protector-strong")
        .flag("--param=ssp-buffer-size=4")
        .flag("-std=c11")
        // Enable the internal timer (used when CLOCK_REALTIME is unavailable)
        .define("JENT_CONF_ENABLE_INTERNAL_TIMER", None)
        // Keep warnings enabled — security-relevant diagnostics from the C
        // sources (uninitialised variables, signed overflow, UB) should be visible.
        .warnings(true)
        .compile("jitterentropy");

    println!("cargo:rerun-if-changed=jitterentropy-library/src/");
    println!("cargo:rerun-if-changed=jitterentropy-library/jitterentropy.h");
}
