# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

## jitterentropy-rustrngd

Rust daemon replacing `urngd`. Requires OpenWrt 23.05+ (for `rust-package.mk` and `PKG_BUILD_DEPENDS:=rust/host`).

**Build flow:**
1. `Build/Prepare` copies `src/` to `PKG_BUILD_DIR` and unpacks `jitterentropy-library-<ver>.tar.gz` from `DL_DIR` into `PKG_BUILD_DIR/jitterentropy-library/`
2. `build.rs` compiles jitterentropy C sources into a static lib via the `cc` crate
3. Cargo links the static lib and produces the binary

**Critical constraint:** `build.rs` compiles jitterentropy with `-O0`. This is non-negotiable — any optimization eliminates the CPU timing jitter that is the entropy source. Do not change this.

**jitterentropy-library version:** Declared as `JENT_LIB_VERSION` in the Makefile. After changing the version, update `JENT_LIB_HASH` with the actual SHA-256 of the downloaded tarball (currently `skip` for development).

**FFI surface** (`src/src/jent_ffi.rs`): only the four symbols needed — `jent_entropy_init`, `jent_entropy_collector_alloc`, `jent_entropy_collector_free`, `jent_read_entropy`. SP800-90B compliance requires `jent_read_entropy` (not `_safe`) and `JENT_FORCE_FIPS` flag.

**Reseed interval math:** `2^44 / cpu_hz_seconds`. CPU frequency is read from cpufreq sysfs, then `/proc/cpuinfo`, then defaults to 1 GHz. The interval is logged to stderr on startup (captured by procd → visible in `logread`).

## filogic-optimizer

Shell script package, no compilation. Runs once at boot (START=95, after network at START=90).

**Platform detection:** Fan trip-point tweaks only run when `/tmp/sysinfo/model` contains `sdg-8733` (case-insensitive). All other operations run on every Filogic platform.

**WED flow offload:** Handled by `/etc/hotplug.d/iface/20-filogic-wed-offload` (installed from `files/filogic-wed-offload.hotplug`), not the main script. Triggers on every `ifup` event — no interface filter. Each run does `destroy table` then recreates the flowtable with whatever `eth*`, `br-*`, `lan*`, `wan*` interfaces currently exist. This means the flowtable grows correctly as interfaces (including VLAN sub-interfaces like `br-lan.1`, `br-lan.3`) come up one by one.

**Init ordering:** `START=13` — fan and ASPM need no network, so the procd service runs right after `sysfsutils`/`sysctl` (both `START=11`).
