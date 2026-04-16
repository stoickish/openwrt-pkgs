mod jent_ffi;

use std::io;
use std::thread;
use std::time::Duration;

use libc::{O_WRONLY, c_ulong, close, ioctl, open};

// RNDADDENTROPY = _IOW('R', 0x03, int[2])
// Computed explicitly so the derivation is auditable and a size change is obvious.
//   direction WRITE = 1  → bits 31:30
//   size = sizeof(int[2]) = 8 bytes → bits 29:16
//   type = 'R' = 0x52    → bits 15:8
//   nr   = 0x03           → bits 7:0
const RNDADDENTROPY: c_ulong =
    (1u64 << 30 | 8 << 16 | 0x52 << 8 | 0x03) as c_ulong;

/// Entropy injected per write: 256 bits (32 bytes).
const ENTROPY_BYTES: usize = 32;

/// Mirrors the kernel's struct rand_pool_info with a fixed 32-byte payload.
/// The kernel reads buf_size bytes starting at buf[0], so this layout is
/// equivalent to declaring `__u32 buf[]` with 32 bytes allocated after it.
#[repr(C)]
struct RandPoolInfo {
    entropy_count: i32,           // credited entropy in bits
    buf_size: i32,                 // payload size in bytes
    buf: [u8; ENTROPY_BYTES],
}

/// Read CPU frequency in Hz.
///
/// Tries (in order):
///  1. cpufreq sysfs — most reliable on embedded SoCs
///  2. /proc/cpuinfo "cpu MHz" / "BogoMIPS" fields
///  3. Falls back to 1 GHz if neither is available
fn cpu_hz() -> u64 {
    // cpufreq reports in kHz
    if let Ok(s) = std::fs::read_to_string(
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
    ) {
        if let Ok(khz) = s.trim().parse::<u64>() {
            return khz * 1_000;
        }
    }

    // /proc/cpuinfo fallback
    if let Ok(s) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in s.lines() {
            // "cpu MHz\t: 1800.000" or "BogoMIPS\t: 3600.00"
            if line.starts_with("cpu MHz") || line.starts_with("BogoMIPS") {
                if let Some(val) = line.splitn(2, ':').nth(1) {
                    if let Ok(mhz) = val.trim().parse::<f64>() {
                        return (mhz * 1_000_000.0) as u64;
                    }
                }
            }
        }
    }

    log("WARN: cannot determine CPU speed, defaulting to 1 GHz");
    1_000_000_000
}

/// Calculate the reseed interval in seconds.
///
/// Derivation:
///   SP 800-90C mandates max 2^64 output bits per RNG instance.
///   With max request size of 2^19 bits, that allows 2^45 requests.
///   We halve that to 2^44 for a 2× safety margin.
///   At one reseed per CPU clock cycle (worst case), after 2^44 cycles
///   we must reseed: interval = 2^44 / cpu_hz seconds.
fn reseed_interval_secs(hz: u64) -> u64 {
    let numerator: u64 = 1u64 << 44;
    (numerator / hz).max(1)
}

fn log(msg: &str) {
    eprintln!("jitterentropy-rustrngd: {}", msg);
}

/// Read up to 256 bits from jitterentropy and inject into /dev/random via RNDADDENTROPY.
///
/// Credits only the bytes actually returned by jent_read_entropy — a short read
/// is valid under health-test constraints, and over-crediting would mislead the
/// kernel's entropy accounting.
///
/// # Safety
/// `ec` must be a valid, non-null entropy collector pointer.
/// `fd` must be an open file descriptor to /dev/random.
unsafe fn inject_entropy(ec: *mut jent_ffi::RandData, fd: i32) -> Result<(), String> {
    let mut buf = [0u8; ENTROPY_BYTES];

    let ret = jent_ffi::jent_read_entropy(
        ec,
        buf.as_mut_ptr() as *mut libc::c_char,
        ENTROPY_BYTES,
    );
    if ret < 0 {
        return Err(format!("jent_read_entropy returned {}", ret));
    }

    // Credit only what was actually written — ret may be less than ENTROPY_BYTES.
    let actual = ret as usize;
    let rpi = RandPoolInfo {
        entropy_count: (actual * 8) as i32,
        buf_size: actual as i32,
        buf,
    };

    let ret = ioctl(fd, RNDADDENTROPY, &rpi as *const RandPoolInfo);
    if ret < 0 {
        return Err(format!(
            "RNDADDENTROPY ioctl failed: {}",
            io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Drop all Linux capabilities except CAP_SYS_ADMIN (required for RNDADDENTROPY)
/// and set PR_SET_NO_NEW_PRIVS to prevent re-escalation.
///
/// Called after /dev/random is opened so the fd is retained but the process
/// can no longer acquire new privileges.
fn drop_caps() -> Result<(), String> {
    // _LINUX_CAPABILITY_VERSION_3: opaque kernel magic number (not a bitfield —
    // it encodes the API version, defined in <linux/capability.h> as 0x20080522).
    // Selects the v3 ABI which represents capability sets as two 32-bit words,
    // covering caps 0–63.
    const CAP_VERSION_3: u32 = 0x20080522;
    const CAP_SYS_ADMIN: u32 = 21;

    #[repr(C)]
    struct CapHeader { version: u32, pid: i32 }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapData { effective: u32, permitted: u32, inheritable: u32 }

    let header = CapHeader { version: CAP_VERSION_3, pid: 0 };
    let mask = 1u32 << CAP_SYS_ADMIN;
    // Two entries: lower word (caps 0-31) keeps only CAP_SYS_ADMIN; upper word zero.
    let data = [
        CapData { effective: mask, permitted: mask, inheritable: 0 },
        CapData { effective: 0,    permitted: 0,    inheritable: 0 },
    ];

    let ret = unsafe {
        libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr())
    };
    if ret < 0 {
        return Err(format!("capset failed: {}", io::Error::last_os_error()));
    }

    // Prevent any exec in the future from regaining privileges via setuid bits.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret < 0 {
        return Err(format!("prctl(PR_SET_NO_NEW_PRIVS) failed: {}", io::Error::last_os_error()));
    }

    Ok(())
}

fn main() {
    let hz = cpu_hz();
    let interval = reseed_interval_secs(hz);

    log(&format!(
        "CPU ~{} MHz, reseed interval {}s ({:.1}h)",
        hz / 1_000_000,
        interval,
        interval as f64 / 3600.0,
    ));

    // jitterentropy self-test — must pass before any use
    let ret = unsafe { jent_ffi::jent_entropy_init() };
    if ret != 0 {
        log(&format!("jent_entropy_init failed: {} — aborting", ret));
        std::process::exit(1);
    }

    // Allocate collector in SP800-90B / FIPS-140 compliant mode.
    let ec = unsafe {
        jent_ffi::jent_entropy_collector_alloc(jent_ffi::JENT_MIN_OSR, jent_ffi::JENT_FORCE_FIPS)
    };
    if ec.is_null() {
        log("jent_entropy_collector_alloc failed — aborting");
        std::process::exit(1);
    }

    // Open /dev/random for entropy injection
    let path = b"/dev/random\0";
    let fd = unsafe { open(path.as_ptr() as *const libc::c_char, O_WRONLY) };
    if fd < 0 {
        log(&format!(
            "cannot open /dev/random: {}",
            io::Error::last_os_error()
        ));
        unsafe { jent_ffi::jent_entropy_collector_free(ec) };
        std::process::exit(1);
    }

    // Drop all capabilities except CAP_SYS_ADMIN (needed for RNDADDENTROPY).
    // Done after the fd is open so we retain the ability to ioctl but shed
    // everything else (CAP_NET_ADMIN, CAP_SYS_RAWIO, etc.).
    if let Err(e) = drop_caps() {
        log(&format!("capability drop failed: {} — aborting", e));
        unsafe {
            close(fd);
            jent_ffi::jent_entropy_collector_free(ec);
        }
        std::process::exit(1);
    }
    log("capabilities restricted to CAP_SYS_ADMIN");

    // Initial seed — written before the daemon enters its sleep loop so that
    // /dev/random is unblocked as early as possible in the boot cycle.
    match unsafe { inject_entropy(ec, fd) } {
        Ok(()) => log("injected initial 256 bits into /dev/random"),
        Err(e) => {
            log(&format!("initial seed failed: {} — aborting", e));
            unsafe {
                close(fd);
                jent_ffi::jent_entropy_collector_free(ec);
            }
            std::process::exit(1);
        }
    }

    // Periodic reseed loop
    loop {
        thread::sleep(Duration::from_secs(interval));
        match unsafe { inject_entropy(ec, fd) } {
            Ok(()) => log("reseeded /dev/random (256 bits)"),
            // Don't exit on periodic reseed failure — log and retry next interval
            Err(e) => log(&format!("reseed failed: {}", e)),
        }
    }
}
