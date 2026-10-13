//! Cryptographically secure random bytes from the operating system.
//!
//! Journal format v2 salts every content slot with 16 fresh random bytes so
//! that low-entropy content ("yes", an account number) cannot be recovered
//! by guessing once the content itself has been erased: the commitment that
//! stays behind is `SHA-256(tag ‖ salt ‖ len ‖ bytes)`, and without the salt
//! a dictionary attack has nothing to grind against. That property only
//! holds if the salt is unpredictable, so it must come from the operating
//! system's CSPRNG and never from a userspace PRNG seeded with the clock.
//!
//! The core crate is zero-dependency, so this module talks to the OS
//! directly instead of pulling in `getrandom`, using the same sources that
//! crate and Rust's standard library use:
//!
//! - **Linux and Android**: the `getrandom(2)` system call, which blocks
//!   until the kernel's CRNG has been seeded and never afterwards. Reading
//!   `/dev/urandom` instead would not wait, so an early-boot VM or container
//!   could get predictable salts. The call goes through `syscall(2)` rather
//!   than glibc's `getrandom` wrapper, which only exists from glibc 2.25 on
//!   and would stop the crate linking against the glibc 2.17 that
//!   manylinux2014 wheels target. On kernels older than 3.17 (no such
//!   system call), under a seccomp policy that refuses it, or on an
//!   architecture whose system call number is not listed here, it falls
//!   back to `/dev/urandom` after first waiting for `/dev/random` to become
//!   readable, which happens once the pool is initialized.
//! - **macOS and OpenBSD**: `getentropy(2)`, in chunks of at most 256
//!   bytes, the most it accepts per call.
//! - **Other Unix systems** (the BSDs, illumos, ...): reads `/dev/urandom`.
//! - **Windows**: calls `BCryptGenRandom` with
//!   `BCRYPT_USE_SYSTEM_PREFERRED_RNG`, the documented way to reach the
//!   system RNG without opening an algorithm provider.
//! - **Anything else** (for example `wasm32-unknown-unknown`): [`fill`]
//!   returns an [`io::ErrorKind::Unsupported`] error rather than failing to
//!   compile, so the rest of the crate still builds for targets that never
//!   write v2 journals.
//!
//! No file descriptor is kept open between calls. A cached descriptor
//! would silently read from an unrelated file in a daemon that closes all
//! descriptors after startup and gets the same number back from a later
//! `open`.

use std::io;

/// Fill `buf` with bytes from the operating system's CSPRNG.
///
/// Either the whole buffer is filled or an error is returned; a partial
/// fill is never reported as success. An empty buffer always succeeds
/// without touching the OS.
///
/// # Errors
///
/// Returns the underlying I/O error if the OS source cannot be opened or
/// read (for example a chroot or sandbox without `/dev/urandom`), and
/// [`io::ErrorKind::Unsupported`] on targets with no known OS RNG.
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    imp::fill(buf)
}

/// Sixteen fresh random bytes: the per-slot salt of journal format v2.
///
/// # Panics
///
/// Panics if the operating system's RNG is unavailable (see [`fill`]).
/// Writing a commitment with a predictable salt would silently weaken
/// erasure, so there is no sensible fallback; callers that must not panic
/// should call [`fill`] and handle the error.
pub fn salt16() -> [u8; 16] {
    let mut salt = [0u8; 16];
    if let Err(e) = fill(&mut salt) {
        panic!("operating system random number generator unavailable: {e}");
    }
    salt
}

/// Read `path` until `buf` is full. The file is opened for this call only.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "openbsd"))))]
fn read_device(path: &str, buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            // A character device that reports end of file is broken (or is
            // not really the device); refuse rather than spin.
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("{path} reported end of file"),
                ))
            }
            // Short reads are legal (Linux caps a single read at 32 MiB and a
            // signal can interrupt a large one); keep going.
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::ffi::{c_int, c_long, c_short, c_void};
    use std::io;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

    /// `__NR_getrandom` for the architectures Rust commonly targets, from
    /// the kernel's syscall tables. Anything else uses the fallback.
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    const SYS_GETRANDOM: Option<c_long> = Some(318);
    #[cfg(target_arch = "x86")]
    const SYS_GETRANDOM: Option<c_long> = Some(355);
    #[cfg(target_arch = "arm")]
    const SYS_GETRANDOM: Option<c_long> = Some(384);
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    ))]
    const SYS_GETRANDOM: Option<c_long> = Some(278);
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    const SYS_GETRANDOM: Option<c_long> = Some(359);
    #[cfg(target_arch = "s390x")]
    const SYS_GETRANDOM: Option<c_long> = Some(349);
    #[cfg(not(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        target_arch = "x86",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "s390x"
    )))]
    const SYS_GETRANDOM: Option<c_long> = None;

    /// `nfds_t`: `unsigned long` in glibc and musl, `unsigned int` in bionic.
    #[cfg(target_os = "linux")]
    type NfdsT = std::ffi::c_ulong;
    #[cfg(target_os = "android")]
    type NfdsT = std::ffi::c_uint;

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: c_short,
        revents: c_short,
    }

    const POLLIN: c_short = 0x1;

    unsafe extern "C" {
        fn syscall(number: c_long, ...) -> c_long;
        fn poll(fds: *mut PollFd, nfds: NfdsT, timeout: c_int) -> c_int;
    }

    const UNKNOWN: u8 = 0;
    const SYSCALL: u8 = 1;
    const FALLBACK: u8 = 2;

    /// Which source works here, decided by the first call.
    static SOURCE: AtomicU8 = AtomicU8::new(UNKNOWN);
    /// Set once `/dev/random` has been seen readable.
    static SEEDED: AtomicBool = AtomicBool::new(false);

    pub(super) fn fill(buf: &mut [u8]) -> io::Result<()> {
        if SOURCE.load(Ordering::Relaxed) != FALLBACK {
            if let Some(number) = SYS_GETRANDOM {
                match getrandom(number, buf) {
                    Ok(()) => {
                        SOURCE.store(SYSCALL, Ordering::Relaxed);
                        return Ok(());
                    }
                    // ENOSYS (kernel before 3.17) maps to Unsupported, and
                    // EPERM (a seccomp filter) to PermissionDenied. Neither
                    // can change while the process runs, so remember it.
                    Err(e)
                        if SOURCE.load(Ordering::Relaxed) == UNKNOWN
                            && matches!(
                                e.kind(),
                                io::ErrorKind::Unsupported | io::ErrorKind::PermissionDenied
                            ) =>
                    {
                        SOURCE.store(FALLBACK, Ordering::Relaxed);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        wait_until_seeded()?;
        super::read_device("/dev/urandom", buf)
    }

    /// `getrandom(buf, len, 0)` until `buf` is full. With no flags the call
    /// blocks only until the CRNG is first seeded.
    fn getrandom(number: c_long, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let rest = &mut buf[filled..];
            let flags: c_long = 0;
            // SAFETY: the pointer and length describe a live, writable
            // slice; the kernel writes at most `len` bytes into it.
            let ret = unsafe {
                syscall(
                    number,
                    rest.as_mut_ptr().cast::<c_void>(),
                    rest.len(),
                    flags,
                )
            };
            if ret < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            // Large requests may be cut short by a signal; keep going.
            filled += ret as usize;
        }
        Ok(())
    }

    /// Block until `/dev/random` is readable, which the kernel reports once
    /// the entropy pool behind `/dev/urandom` has been initialized. Polling
    /// does not consume entropy, unlike reading `/dev/random`.
    fn wait_until_seeded() -> io::Result<()> {
        if SEEDED.load(Ordering::Relaxed) {
            return Ok(());
        }
        let random = std::fs::File::open("/dev/random")?;
        let mut pfd = PollFd {
            fd: random.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: `pfd` is one valid, writable pollfd and `random` keeps
            // the descriptor open for the duration of the call. A negative
            // timeout waits indefinitely.
            let ret = unsafe { poll(&mut pfd, 1, -1) };
            if ret >= 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        SEEDED.store(true, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(any(target_os = "macos", target_os = "openbsd"))]
mod imp {
    use std::ffi::{c_int, c_void};
    use std::io;

    unsafe extern "C" {
        fn getentropy(buf: *mut c_void, len: usize) -> c_int;
    }

    pub(super) fn fill(buf: &mut [u8]) -> io::Result<()> {
        // getentropy(2) fails with EINVAL above 256 bytes, so larger
        // buffers are filled in 256-byte pieces.
        for chunk in buf.chunks_mut(256) {
            // SAFETY: the pointer and length describe a live, writable
            // slice of at most 256 bytes.
            let ret = unsafe { getentropy(chunk.as_mut_ptr().cast::<c_void>(), chunk.len()) };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "openbsd"
    ))
))]
mod imp {
    use std::io;

    pub(super) fn fill(buf: &mut [u8]) -> io::Result<()> {
        super::read_device("/dev/urandom", buf)
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::io;

    /// Use the system-preferred RNG; `hAlgorithm` must then be null.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }

    pub(super) fn fill(buf: &mut [u8]) -> io::Result<()> {
        // The length parameter is a ULONG, so very large buffers are filled
        // in u32-sized pieces.
        for chunk in buf.chunks_mut(u32::MAX as usize) {
            // SAFETY: the pointer and length describe a live, writable
            // slice, and a null algorithm handle is what the flag requires.
            let status = unsafe {
                BCryptGenRandom(
                    std::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            // NTSTATUS: negative values are errors (NT_SUCCESS is >= 0).
            if status < 0 {
                return Err(io::Error::other(format!(
                    "BCryptGenRandom failed with NTSTATUS {:#010x}",
                    status as u32
                )));
            }
        }
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::io;

    pub(super) fn fill(_buf: &mut [u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no operating system random number generator on this target",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_with_nonzero_bytes() {
        // All-zero output from 32 random bytes has probability 2^-256; seeing
        // it means the buffer was never written.
        let mut buf = [0u8; 32];
        fill(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn two_draws_differ() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(salt16(), salt16());
    }

    #[test]
    fn empty_buffer_is_ok() {
        fill(&mut []).unwrap();
    }

    #[test]
    fn fills_across_chunk_boundaries() {
        // getentropy(2) takes at most 256 bytes per call; the tail of every
        // buffer must still be written. A 32-byte tail of zeros has
        // probability 2^-256.
        for len in [1, 31, 32, 255, 256, 257, 511, 512, 513, 4096] {
            let mut buf = vec![0u8; len.max(32)];
            fill(&mut buf).unwrap();
            let tail = &buf[buf.len() - 32..];
            assert!(tail.iter().any(|&b| b != 0), "len {len}");
        }
    }

    /// No descriptor for a random device stays open after a call, so a
    /// daemon that closes every descriptor cannot later have `fill` read
    /// from whatever file reuses the number.
    #[cfg(target_os = "linux")]
    #[test]
    fn keeps_no_descriptor_open() {
        fill(&mut [0u8; 64]).unwrap();
        for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
            let Ok(target) = std::fs::read_link(entry.unwrap().path()) else {
                continue;
            };
            assert!(
                !target.starts_with("/dev/urandom") && !target.starts_with("/dev/random"),
                "{target:?} left open"
            );
        }
    }

    #[test]
    fn large_buffer_covers_every_byte_value() {
        // 64 KiB of uniform bytes misses a given value with probability
        // (255/256)^65536, about 10^-111, so every value must appear. This
        // also exercises the short-read loop on platforms that cap reads.
        let mut buf = vec![0u8; 64 * 1024];
        fill(&mut buf).unwrap();
        let mut seen = [false; 256];
        for &b in &buf {
            seen[b as usize] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn concurrent_callers_share_the_source() {
        let handles: Vec<_> = (0..8).map(|_| std::thread::spawn(salt16)).collect();
        let mut salts: Vec<[u8; 16]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        salts.sort();
        salts.dedup();
        assert_eq!(salts.len(), 8);
    }
}
