//! The few operating-system calls the journal and its storage need beyond
//! `std`, implemented without dependencies.
//!
//! - **Directory fsync.** After a rename, the directory entry itself must be
//!   made durable. Unix allows `fsync` on a directory; Windows does not, and
//!   uses `MOVEFILE_WRITE_THROUGH` on the rename instead.
//! - **Atomic replace.** `rename(2)` on Unix; `MoveFileExW` with
//!   `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` on Windows.
//! - **File identity.** `(dev, ino)` on Unix, `(volume serial, file index)`
//!   on Windows, to notice that a path now names a different file than an
//!   open handle.
//! - **Positioned writes**, so a frame lands exactly at the length the
//!   writer last saw.
//! - **Host name**, for lock-file diagnostics and local erasure notes.
//!
//! Descriptors and handles: `std` opens files with `O_CLOEXEC` on Unix and
//! with non-inheritable handles on Windows, so nothing opened here (lock
//! files included) leaks into child processes.

use std::fs::File;
use std::io;
use std::path::Path;

/// Milliseconds since the Unix epoch.
pub(crate) fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The identity of a file, independent of its path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileId {
    volume: u64,
    index: u64,
}

/// Make the directory entry changes in `dir` durable.
pub(crate) fn fsync_dir(dir: &Path) -> io::Result<()> {
    imp::fsync_dir(dir)
}

/// Atomically replace `to` with `from` (same directory).
pub(crate) fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    imp::rename_replace(from, to)
}

/// The identity of an open file.
pub(crate) fn file_id(file: &File) -> io::Result<FileId> {
    imp::file_id(file)
}

/// The identity of whatever file `path` names right now.
pub(crate) fn path_id(path: &Path) -> io::Result<FileId> {
    imp::path_id(path)
}

/// Write all of `buf` at `offset`, without moving any shared cursor.
pub(crate) fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    imp::write_all_at(file, buf, offset)
}

/// This machine's host name, or `"unknown"`.
pub(crate) fn host_name() -> String {
    imp::host_name().unwrap_or_else(|| "unknown".to_string())
}

/// True if a lock error means the filesystem has no file locks at all
/// (`ENOTSUP`, `EOPNOTSUPP`, `ENOLCK`), as opposed to a transient failure.
pub(crate) fn lock_unsupported(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Unsupported
        || err
            .raw_os_error()
            .is_some_and(|code| imp::LOCK_UNSUPPORTED.contains(&code))
}

#[cfg(unix)]
mod imp {
    use std::ffi::{c_char, c_int};
    use std::fs::File;
    use std::io;
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::path::Path;

    use super::FileId;

    /// `ENOLCK`, `ENOTSUP` and `EOPNOTSUPP` on each Unix family.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) const LOCK_UNSUPPORTED: &[i32] = &[37, 95];
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    pub(super) const LOCK_UNSUPPORTED: &[i32] = &[77, 45, 102];
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    pub(super) const LOCK_UNSUPPORTED: &[i32] = &[77, 45];
    #[cfg(target_os = "openbsd")]
    pub(super) const LOCK_UNSUPPORTED: &[i32] = &[77, 91, 45];
    #[cfg(target_os = "netbsd")]
    pub(super) const LOCK_UNSUPPORTED: &[i32] = &[77, 86, 45];
    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    pub(super) const LOCK_UNSUPPORTED: &[i32] = &[46, 48, 122];
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris"
    )))]
    pub(super) const LOCK_UNSUPPORTED: &[i32] = &[];

    pub(super) fn fsync_dir(dir: &Path) -> io::Result<()> {
        File::open(dir)?.sync_all()
    }

    pub(super) fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    pub(super) fn file_id(file: &File) -> io::Result<FileId> {
        let m = file.metadata()?;
        Ok(FileId {
            volume: m.dev(),
            index: m.ino(),
        })
    }

    pub(super) fn path_id(path: &Path) -> io::Result<FileId> {
        let m = std::fs::metadata(path)?;
        Ok(FileId {
            volume: m.dev(),
            index: m.ino(),
        })
    }

    pub(super) fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
        file.write_all_at(buf, offset)
    }

    extern "C" {
        fn gethostname(name: *mut c_char, len: usize) -> c_int;
    }

    pub(super) fn host_name() -> Option<String> {
        let mut buf = [0u8; 256];
        // SAFETY: the pointer and length describe a live, writable buffer;
        // gethostname writes at most `len` bytes into it.
        let rc = unsafe { gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if rc != 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let name = String::from_utf8_lossy(&buf[..end]).into_owned();
        (!name.is_empty()).then_some(name)
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::FileExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use super::FileId;

    /// `ERROR_NOT_SUPPORTED` and `ERROR_INVALID_FUNCTION`.
    pub(super) const LOCK_UNSUPPORTED: &[i32] = &[50, 1];

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct FileTime {
        dwLowDateTime: u32,
        dwHighDateTime: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct ByHandleFileInformation {
        dwFileAttributes: u32,
        ftCreationTime: FileTime,
        ftLastAccessTime: FileTime,
        ftLastWriteTime: FileTime,
        dwVolumeSerialNumber: u32,
        nFileSizeHigh: u32,
        nFileSizeLow: u32,
        nNumberOfLinks: u32,
        nFileIndexHigh: u32,
        nFileIndexLow: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        fn GetFileInformationByHandle(
            handle: *mut c_void,
            info: *mut ByHandleFileInformation,
        ) -> i32;
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    pub(super) fn fsync_dir(_dir: &Path) -> io::Result<()> {
        // Windows cannot fsync a directory; the rename was made durable with
        // MOVEFILE_WRITE_THROUGH instead.
        Ok(())
    }

    pub(super) fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
        let (from, to) = (wide(from), wide(to));
        // SAFETY: both pointers are NUL-terminated UTF-16 strings that live
        // for the duration of the call.
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn file_id(file: &File) -> io::Result<FileId> {
        // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid value of
        // a plain C struct.
        let mut info: ByHandleFileInformation = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is open for the duration of the call and `info`
        // is a valid, writable struct of the documented layout.
        let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(FileId {
            volume: u64::from(info.dwVolumeSerialNumber),
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }

    pub(super) fn path_id(path: &Path) -> io::Result<FileId> {
        file_id(&OpenOptions::new().read(true).open(path)?)
    }

    pub(super) fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
        while !buf.is_empty() {
            match file.seek_write(buf, offset) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write the whole buffer",
                    ))
                }
                Ok(n) => {
                    buf = &buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub(super) fn host_name() -> Option<String> {
        std::env::var("COMPUTERNAME").ok().filter(|h| !h.is_empty())
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::fs::File;
    use std::io;
    use std::path::Path;

    use super::FileId;

    pub(super) const LOCK_UNSUPPORTED: &[i32] = &[];

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "durable journal storage is not supported on this target",
        )
    }

    pub(super) fn fsync_dir(_dir: &Path) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn rename_replace(_from: &Path, _to: &Path) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn file_id(_file: &File) -> io::Result<FileId> {
        Err(unsupported())
    }

    pub(super) fn path_id(_path: &Path) -> io::Result<FileId> {
        Err(unsupported())
    }

    pub(super) fn write_all_at(_file: &File, _buf: &[u8], _offset: u64) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn host_name() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_name_is_not_empty() {
        assert!(!host_name().is_empty());
    }

    #[test]
    fn identity_follows_the_file_not_the_path() {
        let dir = crate::backend::test_dir("sys-identity");
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let fa = File::open(&a).unwrap();
        assert_eq!(file_id(&fa).unwrap(), path_id(&a).unwrap());
        assert_ne!(path_id(&a).unwrap(), path_id(&b).unwrap());
        rename_replace(&b, &a).unwrap();
        assert_ne!(file_id(&fa).unwrap(), path_id(&a).unwrap());
        fsync_dir(&dir).unwrap();
    }

    #[test]
    fn positioned_writes_land_at_the_offset() {
        let dir = crate::backend::test_dir("sys-write-at");
        let p = dir.join("f");
        std::fs::write(&p, b"0123456789").unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        write_all_at(&f, b"ab", 3).unwrap();
        write_all_at(&f, b"XY", 10).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"012ab56789XY");
    }

    #[test]
    fn lock_error_classification() {
        assert!(lock_unsupported(&io::Error::from(
            io::ErrorKind::Unsupported
        )));
        assert!(!lock_unsupported(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
        for &code in imp::LOCK_UNSUPPORTED {
            assert!(lock_unsupported(&io::Error::from_raw_os_error(code)));
        }
    }
}
