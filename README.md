# openwrt-pkgs

Custom OpenWrt package feed for Filogic-based routers.

## Using this feed

Add to your OpenWrt build tree's `feeds.conf`:

```
src-git stoickish https://github.com/stoickish/openwrt-pkgs.git
```

Then install:

```bash
./scripts/feeds update stoickish
./scripts/feeds install -a -p stoickish
```

Packages will appear in `make menuconfig` under **Utilities**.

## Packages

### jitterentropy-rustrngd

A Rust-based RNG daemon intended to replace OpenWrt's default `urngd`. Uses the [jitterentropy-library](https://github.com/smuellerDD/jitterentropy-library) as its entropy source, operating in SP800-90B / FIPS-140 compliant mode.

**Behavior:**
- Runs at `START=00` — as early as possible in the boot cycle
- Injects 256 bits of entropy into `/dev/random` immediately on startup
- Periodically reseeds at an interval of `2^44 / cpu_hz` seconds (approximately every 2–5 hours depending on CPU speed), providing a 2× margin against the SP 800-90C output limit

**Requirements:** OpenWrt 23.05 or later (Rust toolchain support).

---

### filogic-optimizer

A boot-time configuration script for Filogic-based routers (MT7981, MT7986, MT7988, etc.).

**Applied on all platforms:**
- PCIe ASPM powersave
- WED hardware flow offload via nftables (`inet wed_offload` table with `FLOWOFFLOAD` for all ethernet and bridge interfaces)

**Applied on SDG-8733 only:**
- Aggressive fan trip-point profile (fans spin up earlier to keep the platform cool under load)

Platform detection is done at runtime via `/tmp/sysinfo/model`, so the same package works on all supported routers without per-device builds.
