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
//! directly instead of pulling in `getrandom`:
//!
//! - **Unix**: reads `/dev/urandom`. It is present on every Unix target Rust
//!   supports (Linux, macOS, the BSDs, illumos), never blocks once the
//!   system has booted, and needs no `libc` bindings. The open file is
//!   cached for the life of the process, so steady-state cost is one
//!   `read(2)` per call.
//! - **Windows**: calls `BCryptGenRandom` with
//!   `BCRYPT_USE_SYSTEM_PREFERRED_RNG`, the documented way to reach the
//!   system RNG without opening an algorithm provider.
//! - **Anything else** (for example `wasm32-unknown-unknown`): [`fill`]
//!   returns an [`io::ErrorKind::Unsupported`] error rather than failing to
//!   compile, so the rest of the crate still builds for targets that never
//!   write v2 journals.

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

#[cfg(unix)]
mod imp {
    use std::fs::File;
    use std::io::{self, Read};
    use std::sync::OnceLock;

    /// The cached `/dev/urandom` handle.
    ///
    /// `&File` implements `Read`, and reads from `/dev/urandom` ignore the
    /// file offset, so concurrent callers can share one descriptor without
    /// a lock. Rust opens files with `O_CLOEXEC`, so the descriptor does not
    /// leak into child processes.
    static URANDOM: OnceLock<File> = OnceLock::new();

    fn urandom() -> io::Result<&'static File> {
        if let Some(file) = URANDOM.get() {
            return Ok(file);
        }
        // `OnceLock::get_or_try_init` is not stable, so open first and then
        // publish. Two threads racing here may both open the device; the
        // loser's handle is dropped (closed) by `set`, which is harmless.
        let file = File::open("/dev/urandom")?;
        let _ = URANDOM.set(file);
        Ok(URANDOM.get().expect("URANDOM was just set"))
    }

    pub(super) fn fill(buf: &mut [u8]) -> io::Result<()> {
        let mut file = urandom()?;
        let mut filled = 0;
        while filled < buf.len() {
            match file.read(&mut buf[filled..]) {
                // A character device that reports end of file is broken (or
                // is not really /dev/urandom); refuse rather than spin.
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "/dev/urandom reported end of file",
                    ))
                }
                // Short reads are legal (Linux caps a single read at 32 MiB
                // and a signal can interrupt a large one); keep going.
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::io;

    /// Use the system-preferred RNG; `hAlgorithm` must then be null.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    extern "system" {
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
