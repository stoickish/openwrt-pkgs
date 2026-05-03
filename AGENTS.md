# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Repository Purpose

Custom OpenWrt package feed hosted at `https://github.com/stoickish/openwrt-pkgs.git`. To use it, add to OpenWrt's `feeds.conf`:

```
src-git stoickish https://github.com/stoickish/openwrt-pkgs.git
```

Then run `./scripts/feeds update stoickish && ./scripts/feeds install -a -p stoickish` from an OpenWrt build tree.

## Building Packages

Packages are built inside an OpenWrt build tree — there is no standalone build. From the OpenWrt root:

```bash
# Build a specific package
make package/jitterentropy-rustrngd/compile V=s
make package/filogic-optimizer/compile V=s

# Download sources first (required for jitterentropy-rustrngd)
make package/jitterentropy-rustrngd/download
```

`V=s` shows full compiler output, useful for diagnosing cross-compile issues.

## Package Structure

Each package lives under `utils/<name>/` and follows standard OpenWrt conventions:

- `Makefile` — OpenWrt package definition (metadata, build steps, install rules)
- `files/` — runtime files installed verbatim (init scripts, shell scripts)
- `src/` — source code copied into `PKG_BUILD_DIR` during `Build/Prepare`

## Versioning — MANDATORY

**Every code change to any package MUST bump `PKG_RELEASE`.** This ensures OpenWrt's build system detects the change and rebuilds/reinstalls the package. No exceptions.

### PKG_RELEASE bump rules

- Bump `PKG_RELEASE` by 1 for every change, no matter how small.
- When `PKG_VERSION` is changed, reset `PKG_RELEASE` to 1.
- `PKG_VERSION` changes for significant releases only (feature addition, breaking change).

### Cargo.toml / PKG_VERSION consistency (Rust packages only)

For packages with a `Cargo.toml` (currently `jitterentropy-rustrngd`):
- `Cargo.toml` `version` field MUST match `PKG_VERSION` in the Makefile.
- When bumping `PKG_VERSION`, update `Cargo.toml` to the same value.
- When bumping only `PKG_RELEASE` (patch-level change), `Cargo.toml` version stays unchanged.

### Non-Rust packages

Packages without `Cargo.toml` (currently `filogic-optimizer`) only need `PKG_RELEASE` bumps — no other version file to sync.

## jitterentropy-rustrngd

Rust daemon replacing `urngd`. Requires OpenWrt 23.05+ (for `rust-package.mk` and `PKG_BUILD_DEPENDS:=rust/host`).

**rust-package.mk location:** `rust-package.mk` lives in the packages feed (`feeds/packages/lang/rust/`), not in `include/`. Third-party feeds must reference it via `$(TOPDIR)/feeds/packages/lang/rust/rust-package.mk` — using `$(INCLUDE_DIR)/rust-package.mk` silently drops the package from the feed index during `feeds update`.

**Build flow:**
1. `Build/Prepare` copies `src/` to `PKG_BUILD_DIR` and unpacks `jitterentropy-library-<ver>.tar.gz` from `DL_DIR` into `PKG_BUILD_DIR/jitterentropy-library/`
2. `build.rs` clears `TARGET_CFLAGS` and `CFLAGS` (to exclude all OpenWrt compiler flags), parses CFLAGS from `jitterentropy-library/Makefile`, then compiles the C sources into a static lib via the `cc` crate
3. Cargo links the static lib and produces the binary

**Critical constraints:**
- All OpenWrt `TARGET_CFLAGS`/`CFLAGS` are discarded — cc-rs appends environment flags *after* programmatic flags, which would override mandatory settings like `-O0`. There is no OpenWrt built-in way to opt a single package out, so the env vars are cleared in `build.rs`.
- CFLAGS are parsed from the upstream `jitterentropy-library/Makefile` at build time rather than hard-coded. The Makefile is a `cargo:rerun-if-changed` dependency so flag changes in future library releases trigger automatic rebuilds.
- `-O0` is mandatory — any optimization eliminates the CPU timing jitter that is the entropy source. Do not change this.
- `-fstack-protector-strong` is hard-coded separately because it lives inside a Makefile conditional block (`ENABLE_STACK_PROTECTOR=1` && GCC >= 4.9) that the simple Makefile parser cannot evaluate.

**jitterentropy-library version:** Declared as `JENT_LIB_VERSION` in the Makefile. After changing the version, update `JENT_LIB_HASH` with the actual SHA-256 of the downloaded tarball (currently `skip` for development).

**FFI surface** (`src/src/jent_ffi.rs`): only the four symbols needed — `jent_entropy_init`, `jent_entropy_collector_alloc`, `jent_entropy_collector_free`, `jent_read_entropy`. SP800-90B compliance requires `jent_read_entropy` (not `_safe`) and `JENT_FORCE_FIPS` flag.

**Reseed interval:** 512 seconds (fixed). Chosen because the `/dev/random` output drain is at most 256 bits/s and 384 bits/s injection rate means `384/256 × 512 = 768` seconds of safety margin — the kernel could run uninterrupted for ~768 seconds before depleting our entropy contribution.

## filogic-optimizer

Shell script package, no compilation. Runs once at boot (START=95, after network at START=90).

**Platform detection:** Fan trip-point tweaks run when `/proc/device-tree/compatible` matches `sdg-873[34]` (covers sdg-8733, sdg-8733a, sdg-8734). All other operations run on every Filogic platform.

**WED flow offload:** Handled by `/etc/hotplug.d/iface/20-filogic-wed-offload` (installed from `files/filogic-wed-offload.hotplug`), not the main script. Triggers on every `ifup` event — no interface filter. Each run does `destroy table` then recreates the flowtable with whatever `eth*`, `br-*`, `lan*`, `wan*` interfaces currently exist. This means the flowtable grows correctly as interfaces (including VLAN sub-interfaces like `br-lan.1`, `br-lan.3`) come up one by one.

**Init ordering:** `START=13` — fan and ASPM need no network, so the procd service runs right after `sysfsutils`/`sysctl` (both `START=11`).
