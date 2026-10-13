//! Small durable-file helpers. Every file the anchor log publishes must
//! survive a power cut once a caller has been told it exists, so each
//! write ends in an `fsync` of the file and of its directory (the
//! directory entry is what makes a new file findable after a crash).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use crate::error::AnchorError;

/// Create `path` (which must not exist), write `bytes`, and make both the
/// file and its directory entry durable. Fails with `AlreadyExists` rather
/// than overwrite, which is how checkpoint files stay write-once.
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

/// Write `bytes` to `path` atomically: a temporary file in the same
/// directory, fsync, rename over `path`, fsync the directory. Used for
/// files that are replaced as a whole, never for write-once records.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AnchorError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
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
}
