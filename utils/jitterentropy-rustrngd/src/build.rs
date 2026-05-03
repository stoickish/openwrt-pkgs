use std::env;
use std::path::{Path, PathBuf};

/// Parse CFLAGS from the upstream jitterentropy-library Makefile.
///
/// Reads lines starting with `CFLAGS` followed by `=`, `:=`, `?=`, or `+=`.
/// Skips lines containing `$(...)` variable expansions and lines inside
/// conditional blocks (those are handled explicitly by the caller).
fn parse_cflags(makefile: &Path) -> Vec<String> {
    let content = match std::fs::read_to_string(makefile) {
        Ok(c) => c,
        Err(e) => {
            println!("cargo:warning=failed to read {:?}: {}", makefile, e);
            return Vec::new();
        }
    };

    let mut flags: Vec<String> = Vec::new();
    let mut in_conditional = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip conditional blocks — caller handles the known cases explicitly.
        if trimmed.starts_with("ifeq") || trimmed.starts_with("ifneq") || trimmed.starts_with("ifdef") {
            in_conditional = true;
            continue;
        }
        if in_conditional {
            if trimmed.starts_with("endif") {
                in_conditional = false;
            }
            continue;
        }

        // Match CFLAGS =, :=, ?=, or += assignments.
        let rest = match trimmed.strip_prefix("CFLAGS") {
            Some(r) => r,
            None => continue,
        };

        let flags_str = rest
            .strip_prefix(" +=")
            .or_else(|| rest.strip_prefix(" ?="))
            .or_else(|| rest.strip_prefix(" :="))
            .or_else(|| rest.strip_prefix("="))
            .map(|s| s.trim());

        let flags_str = match flags_str {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        // Skip lines with $(...) expansions (e.g. $(foreach ...) for -I flags).
        if flags_str.contains("$(") {
            continue;
        }

        for flag in flags_str.split_whitespace() {
            let flag = flag.to_string();
            if !flags.contains(&flag) {
                flags.push(flag);
            }
        }
    }

    flags
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let jent_dir = manifest_dir.join("jitterentropy-library");

    // Discard ALL OpenWrt CFLAGS.
    //
    // OpenWrt exports TARGET_CFLAGS into the Cargo build environment.  cc-rs
    // reads TARGET_CFLAGS (and CFLAGS as fallback) and appends them *after*
    // programmatic flags, so -Ofast and friends would override mandatory
    // jitterentropy flags.  There is no OpenWrt built-in way to opt a single
    // package out — clearing the env vars is the only mechanism.
    unsafe {
        std::env::set_var("TARGET_CFLAGS", "");
        std::env::set_var("CFLAGS", "");
    }

    let src_dir = jent_dir.join("src");

    if !src_dir.exists() {
        // Sources are unpacked by OpenWrt's Build/Prepare. Outside that
        // environment (e.g. cargo check / clippy in CI) skip C compilation.
        println!("cargo:warning=jitterentropy-library not found; skipping C compilation");
        return;
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

    let mut build = cc::Build::new();
    build
        .files(&sources)
        .include(&jent_dir)
        .include(&src_dir)
        .opt_level(0)
        .warnings(true);

    // Apply CFLAGS parsed from the upstream jitterentropy-library Makefile.
    // This avoids hard-coding flags and automatically picks up changes
    // made in future jitterentropy-library releases.
    let makefile_path = jent_dir.join("Makefile");
    let cflags = parse_cflags(&makefile_path);
    for flag in &cflags {
        build.flag(flag);
    }

    // Handle the stack-protector conditional from the upstream Makefile.
    //
    // The Makefile checks `ENABLE_STACK_PROTECTOR ?= 1` (default: on) and
    // GCC >= 4.9 for -fstack-protector-strong (else -fstack-protector-all).
    // GCC 4.9 was released in 2014 — any toolchain building Rust meets that
    // requirement, so we hard-code the stronger variant here.
    build.flag("-fstack-protector-strong");

    // JENT_CONF_ENABLE_INTERNAL_TIMER is also in the parsed Makefile flags,
    // but keeping the explicit .define() call ensures the symbol is present
    // even if Makefile parsing yields nothing.
    build.define("JENT_CONF_ENABLE_INTERNAL_TIMER", None);

    build.compile("jitterentropy");

    // Rebuild when sources or Makefile change.
    println!("cargo:rerun-if-changed=jitterentropy-library/src/");
    println!("cargo:rerun-if-changed=jitterentropy-library/jitterentropy.h");
    println!("cargo:rerun-if-changed=jitterentropy-library/Makefile");
}
