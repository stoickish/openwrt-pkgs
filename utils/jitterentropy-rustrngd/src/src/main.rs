mod jent_ffi;

use std::ffi::CString;
use std::io;
use std::thread;
use std::time::Duration;

use libc::{
    close, ioctl, open, openlog, syslog, LOG_CONS, LOG_DAEMON, LOG_ERR, LOG_INFO, LOG_PID,
    LOG_WARNING, O_WRONLY,
};

// RNDADDENTROPY = _IOW('R', 0x03, int[2])
// Computed explicitly so the derivation is auditable and a size change is obvious.
//   direction WRITE = 1  → bits 31:30
//   size = sizeof(int[2]) = 8 bytes → bits 29:16
//   type = 'R' = 0x52    → bits 15:8
//   nr   = 0x03           → bits 7:0
// Result: 0x40085203 (bit 31 clear, positive i32). Cast to the ioctl type at
// the call site — c_int on musl, c_ulong on glibc.
const RNDADDENTROPY: i32 = (1i32 << 30) | (8 << 16) | (0x52 << 8) | 0x03;

/// Entropy injected per write: 384 bits (48 bytes).
const ENTROPY_BYTES: usize = 48;

/// Mirrors the kernel's struct rand_pool_info with a fixed 48-byte payload.
/// The kernel reads buf_size bytes starting at buf[0], so this layout is
/// equivalent to declaring `__u32 buf[]` with 48 bytes allocated after it.
#[repr(C)]
struct RandPoolInfo {
    entropy_count: i32, // credited entropy in bits
    buf_size: i32,      // payload size in bytes
    buf: [u8; ENTROPY_BYTES],
}

// ---------------------------------------------------------------------------
// Logging — syslog(3) via libc
// ---------------------------------------------------------------------------

macro_rules! log_err {
    ($($arg:tt)*) => (log(LOG_ERR, &format!($($arg)*)))
}
macro_rules! log_warn {
    ($($arg:tt)*) => (log(LOG_WARNING, &format!($($arg)*)))
}
macro_rules! log_info {
    ($($arg:tt)*) => (log(LOG_INFO, &format!($($arg)*)))
}

fn log(level: libc::c_int, msg: &str) {
    let cmsg = CString::new(msg).unwrap_or_else(|_| CString::new("").unwrap());
    unsafe {
        syslog(level, c"%s".as_ptr(), cmsg.as_ptr());
    }
}

// ---------------------------------------------------------------------------
// Entropy injection
// ---------------------------------------------------------------------------

/// Read up to 384 bits from jitterentropy and inject into /dev/random via RNDADDENTROPY.
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

    let ret = jent_ffi::jent_read_entropy(ec, buf.as_mut_ptr() as *mut libc::c_char, ENTROPY_BYTES);
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

    let ret = ioctl(fd, RNDADDENTROPY as _, &rpi as *const RandPoolInfo);
    if ret < 0 {
        return Err(format!(
            "RNDADDENTROPY ioctl failed: {}",
            io::Error::last_os_error()
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Capability dropping (Linux-only)
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
fn drop_caps() -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn drop_caps() -> Result<(), String> {
    const CAP_VERSION_3: u32 = 0x20080522;
    const CAP_SYS_ADMIN: u32 = 21;
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 36;
    const SYS_CAPSET: libc::c_int = 90;

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::c_int,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let header = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let mask = 1u32 << CAP_SYS_ADMIN;
    let data = [
        CapData {
            effective: mask,
            permitted: mask,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];

    let ret = unsafe {
        libc::syscall(
            SYS_CAPSET as libc::c_long,
            &header as *const CapHeader as *const libc::c_void,
            data.as_ptr() as *const libc::c_void,
        )
    };
    if ret < 0 {
        return Err(format!("capset failed: {}", io::Error::last_os_error()));
    }

    let ret = unsafe {
        libc::prctl(
            PR_SET_NO_NEW_PRIVS as libc::c_int,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if ret < 0 {
        return Err(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            io::Error::last_os_error()
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Reseed interval
// ---------------------------------------------------------------------------

/// Fixed reseed interval in seconds.
///
/// Derived from SP 800-90C max 2^17 output bits and the assumption that
/// /dev/random output drain is at most 256 bits/s.  2^17 / 256 = 512s.
const RESEED_INTERVAL_SECS: u64 = 512;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    // Set up syslog before any logging.
    // LOG_PID includes PID in each message; LOG_CONS routes to console on failure.
    let ident =
        CString::new("jitterentropy-rustrngd").unwrap_or_else(|_| CString::new("").unwrap());
    unsafe {
        openlog(ident.as_ptr(), LOG_CONS | LOG_PID, LOG_DAEMON);
    }

    log_info!(
        "jitterentropy-rustrngd starting, reseed interval {}s",
        RESEED_INTERVAL_SECS
    );

    // jitterentropy self-test — must pass before any use
    let ret = unsafe { jent_ffi::jent_entropy_init() };
    if ret != 0 {
        log_err!("jent_entropy_init failed: {} — aborting", ret);
        std::process::exit(1);
    }

    // Allocate collector in SP800-90B / FIPS-140 compliant mode.
    let ec = unsafe {
        jent_ffi::jent_entropy_collector_alloc(jent_ffi::JENT_MIN_OSR, jent_ffi::JENT_FORCE_FIPS)
    };
    if ec.is_null() {
        log_err!("jent_entropy_collector_alloc failed — aborting");
        std::process::exit(1);
    }

    // Open /dev/random for entropy injection
    let path = b"/dev/random\0";
    let fd = unsafe { open(path.as_ptr() as *const libc::c_char, O_WRONLY) };
    if fd < 0 {
        log_err!("cannot open /dev/random: {}", io::Error::last_os_error());
        unsafe { jent_ffi::jent_entropy_collector_free(ec) };
        std::process::exit(1);
    }

    // Drop all capabilities except CAP_SYS_ADMIN (needed for RNDADDENTROPY).
    // Done after the fd is open so we retain the ability to ioctl but shed
    // everything else (CAP_NET_ADMIN, CAP_SYS_RAWIO, etc.).
    if let Err(e) = drop_caps() {
        log_err!("capability drop failed: {} — aborting", e);
        unsafe {
            close(fd);
            jent_ffi::jent_entropy_collector_free(ec);
        }
        std::process::exit(1);
    }
    log_info!("capabilities restricted to CAP_SYS_ADMIN");

    // Initial seed — written before the daemon enters its sleep loop so that
    // /dev/random is unblocked as early as possible in the boot cycle.
    match unsafe { inject_entropy(ec, fd) } {
        Ok(()) => log_info!("injected initial 384 bits into /dev/random"),
        Err(e) => {
            log_err!("initial seed failed: {} — aborting", e);
            unsafe {
                close(fd);
                jent_ffi::jent_entropy_collector_free(ec);
            }
            std::process::exit(1);
        }
    }

    // Periodic reseed loop
    loop {
        thread::sleep(Duration::from_secs(RESEED_INTERVAL_SECS));
        match unsafe { inject_entropy(ec, fd) } {
            Ok(()) => log_info!("reseeded /dev/random (384 bits)"),
            // Don't exit on periodic reseed failure — log and retry next interval
            Err(e) => log_warn!("reseed failed: {}", e),
        }
    }
}
