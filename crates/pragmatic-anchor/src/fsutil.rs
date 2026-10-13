//! Small durable-file helpers. Every file the anchor log publishes must
//! survive a power cut once a caller has been told it exists, so each
//! write ends in an `fsync` of the file and of its directory (the
//! directory entry is what makes a new file findable after a crash).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::error::AnchorError;

/// Create `path` (which must not exist), write `bytes`, and make both the
/// file and its directory entry durable. Fails with `AlreadyExists` rather
/// than overwrite. A crash can leave a partial file, so this is only for
/// files nothing reads back as a record (bytes moved aside during
/// recovery); records use [`publish_new_durable`].
pub(crate) fn create_new_durable(path: &Path, bytes: &[u8]) -> Result<(), AnchorError> {
    let ctx = || format!("creating {}", path.display());
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(AnchorError::io(ctx()))?;
    let written = f.write_all(bytes).and_then(|_| f.sync_all());
    if let Err(e) = written {
        // A partial file would read as a torn write at the next start;
        // removing it now keeps the directory clean when that is possible.
        drop(f);
        let _ = fs::remove_file(path);
        return Err(AnchorError::io(ctx())(e));
    }
    sync_parent(path)
}

/// Why [`publish_new_durable`] failed, and whether the file had already
/// appeared at its path when it did.
#[derive(Debug)]
pub(crate) struct PublishError {
    pub error: AnchorError,
    /// True when the complete file is at its path but its directory entry
    /// may not be durable (the directory fsync failed). A crash may or may
    /// not keep it, so the caller must treat it as possibly committed:
    /// nothing that contradicts it may be written, and nothing that
    /// depends on it may be shown to anyone, until the directory has been
    /// synced again (by reopening).
    pub published: bool,
}

impl From<PublishError> for AnchorError {
    fn from(e: PublishError) -> AnchorError {
        e.error
    }
}

/// Publish `bytes` at `path`, which must not exist, so that `path` never
/// holds a partial file: write a temporary file in the same directory,
/// fsync it, link it to `path` (a link never replaces an existing file),
/// drop the temporary name and fsync the directory.
///
/// A crash at any point leaves either no file at `path` or the complete
/// one. A reader that finds a file at `path` it cannot parse therefore
/// knows the file was damaged after it was written, never torn by a crash,
/// which is what lets recovery refuse such a file as corruption instead of
/// guessing (design 4.7). Fails with `AlreadyExists` rather than overwrite.
///
/// The temporary file is named `.<name>.tmp-<pid>`; one left by a crash is
/// harmless, and [`remove_temp_files`] clears it at the next open. On a
/// file system without hard links the file is renamed into place after
/// checking that `path` is free, which is just as atomic for the only
/// writer (the server holds `server.lock`).
pub(crate) fn publish_new_durable(path: &Path, bytes: &[u8]) -> Result<(), PublishError> {
    let unpublished = |error| PublishError {
        error,
        published: false,
    };
    let tmp = temp_path(path);
    let ctx = || format!("creating {}", path.display());
    let written = (|| -> io::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(unpublished(AnchorError::io(ctx())(e)));
    }
    if let Err(e) = link_no_replace(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(unpublished(AnchorError::io(ctx())(e)));
    }
    // After a link the temporary name is a second name for the same file;
    // one left behind costs nothing but a cleanup at the next open.
    let _ = fs::remove_file(&tmp);
    sync_parent(path).map_err(|error| PublishError {
        error,
        published: true,
    })
}

/// Give the file at `from` the name `to`, never replacing an existing
/// `to`. An error means `to` was not created.
fn link_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    match fs::hard_link(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(e),
        Err(_) if to.exists() => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
        // No hard links on this file system: after the check above, a
        // rename is atomic for the only writer.
        Err(_) => fs::rename(from, to),
    }
}

/// What every temporary file name contains.
const TEMP_MARKER: &str = ".tmp-";

/// The temporary name [`publish_new_durable`] and [`write_atomic`] write
/// `path` under before it gets its real name.
fn temp_path(path: &Path) -> PathBuf {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    dir.join(format!(".{name}{TEMP_MARKER}{}", std::process::id()))
}

/// Remove the temporary files a crash left in `dir` (names that start with
/// `.` and contain `.tmp-`). Returns the paths removed.
pub(crate) fn remove_temp_files(dir: &Path) -> Result<Vec<PathBuf>, AnchorError> {
    let ctx = || format!("listing {}", dir.display());
    let mut removed = Vec::new();
    for entry in fs::read_dir(dir).map_err(AnchorError::io(ctx()))? {
        let entry = entry.map_err(AnchorError::io(ctx()))?;
        let is_temp = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with('.') && n.contains(TEMP_MARKER));
        if is_temp && entry.file_type().is_ok_and(|t| t.is_file()) {
            let path = entry.path();
            fs::remove_file(&path)
                .map_err(AnchorError::io(format!("removing {}", path.display())))?;
            removed.push(path);
        }
    }
    if !removed.is_empty() {
        sync_dir(dir)?;
    }
    Ok(removed)
}

/// Write `bytes` to `path` atomically: a temporary file in the same
/// directory, fsync, rename over `path`, fsync the directory. Used for
/// files that are replaced as a whole, never for write-once records.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AnchorError> {
    let tmp = temp_path(path);
    let ctx = || format!("writing {}", path.display());
    let result = (|| -> io::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(AnchorError::io(ctx())(e));
    }
    sync_parent(path)
}

/// Create `dir` (and its parents) if missing, making each new entry
/// durable.
pub(crate) fn ensure_dir(dir: &Path) -> Result<(), AnchorError> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_dir(parent)?;
        }
    }
    match fs::create_dir(dir) {
        Ok(()) => sync_parent(dir),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
        Err(e) => Err(AnchorError::io(format!("creating {}", dir.display()))(e)),
    }
}

/// Fsync the directory holding `path`, so a create, rename or removal in
/// it is durable. Windows has no directory fsync; NTFS journals metadata.
pub(crate) fn sync_parent(path: &Path) -> Result<(), AnchorError> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    sync_dir(dir)
}

/// Fsync a directory (a no-op on Windows).
pub(crate) fn sync_dir(dir: &Path) -> Result<(), AnchorError> {
    #[cfg(unix)]
    {
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(AnchorError::io(format!(
                "syncing directory {}",
                dir.display()
            )))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Read exactly `buf.len()` bytes at `offset` without moving any shared
/// cursor, so readers need no lock against each other.
pub(crate) fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0usize;
        while done < buf.len() {
            let n = file.seek_read(&mut buf[done..], offset + done as u64)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "file ended early",
                ));
            }
            done += n;
        }
        Ok(())
    }
}

/// Milliseconds since the Unix epoch, for naming moved-aside files.
pub(crate) fn unix_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Seconds since the Unix epoch.
pub(crate) fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The file name of a numbered record: the number as 20 decimal digits
/// (enough for any `u64`), so names sort in numeric order.
pub(crate) fn seq_name(seq: u64, ext: &str) -> String {
    format!("{seq:020}{ext}")
}

/// The number in a file name written by [`seq_name`], or `None` for any
/// other name.
pub(crate) fn parse_seq_name(name: &str, ext: &str) -> Option<u64> {
    let digits = name.strip_suffix(ext)?;
    if digits.len() != 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// True when running as root, which ignores directory permissions, so
/// tests that inject failures through permissions skip there.
#[cfg(all(test, unix))]
pub(crate) fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_names_round_trip_and_sort() {
        assert_eq!(seq_name(41, ".json"), "00000000000000000041.json");
        assert_eq!(
            parse_seq_name("00000000000000000041.json", ".json"),
            Some(41)
        );
        assert_eq!(
            parse_seq_name(&seq_name(u64::MAX, ".json"), ".json"),
            Some(u64::MAX)
        );
        for bad in [
            "41.json",
            "0000000000000000004a.json",
            "00000000000000000041.txt",
        ] {
            assert_eq!(parse_seq_name(bad, ".json"), None, "{bad}");
        }
        assert!(seq_name(9, "") < seq_name(10, ""));
    }

    #[test]
    fn create_new_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.json");
        create_new_durable(&p, b"one").unwrap();
        let err = create_new_durable(&p, b"two").unwrap_err();
        assert!(
            matches!(err, AnchorError::Io { ref source, .. } if source.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(&p).unwrap(), b"one");
        write_atomic(&p, b"three").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"three");
        ensure_dir(&dir.path().join("x/y/z")).unwrap();
        assert!(dir.path().join("x/y/z").is_dir());
    }

    #[test]
    fn publishing_never_replaces_and_leaves_no_temporary_name() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("00000000000000000001.json");
        publish_new_durable(&p, b"one").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"one");
        let err = publish_new_durable(&p, b"two").unwrap_err();
        assert!(!err.published);
        assert!(
            matches!(err.error, AnchorError::Io { ref source, .. } if source.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(&p).unwrap(), b"one");
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    #[test]
    fn temporary_files_left_by_a_crash_are_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.json");
        fs::write(temp_path(&p), b"half").unwrap();
        fs::write(dir.path().join(".hidden"), b"kept").unwrap();
        fs::write(&p, b"kept").unwrap();
        let removed = remove_temp_files(dir.path()).unwrap();
        assert_eq!(removed, vec![temp_path(&p)]);
        assert!(p.exists() && dir.path().join(".hidden").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_directory_sync_reports_the_file_as_published() {
        use std::os::unix::fs::PermissionsExt;
        if super::is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sth");
        fs::create_dir(&sub).unwrap();
        // Write and search but no read: files can be created in it, but the
        // directory cannot be opened to fsync it.
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o300)).unwrap();
        let p = sub.join("x.json");
        let err = publish_new_durable(&p, b"x").unwrap_err();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(err.published, "{}", err.error);
        assert_eq!(fs::read(&p).unwrap(), b"x");
    }
}
