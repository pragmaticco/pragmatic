//! Writing output files without following links planted next to them.
//!
//! `render-evidence` writes next to the bundle by default, and a bundle
//! often arrives as an archive or a directory from the party being
//! audited. `std::fs::write` follows symbolic links, so a link named
//! `<stem>.html` shipped with the bundle would make rendering overwrite
//! whatever file it points at with text partly chosen by the bundle.
//!
//! Every file the CLI writes therefore goes through [`write`]: the content
//! is written to a fresh temporary file in the destination's directory
//! (created exclusively, so nothing planted under that name is opened),
//! then renamed over the destination. A rename replaces the directory entry
//! itself and never follows a link at the destination, and a reader never
//! sees half a file. A destination that is a symbolic link or anything
//! but a regular file is refused outright, so a planted link is reported
//! rather than silently replaced.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use pragmatic::encoding::hex_encode;

/// Write `content` to `path` (see the module documentation).
pub fn write(path: &Path, content: &[u8]) -> Result<(), String> {
    let shown = path.display();
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(format!(
                "{shown} is a symbolic link; refusing to write through it (choose another -o)"
            ))
        }
        Ok(m) if !m.is_file() => {
            return Err(format!(
                "{shown} exists and is not a regular file; refusing to replace it"
            ))
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot write {shown}: {e}")),
    }
    let temp = temp_path(path).map_err(|e| format!("cannot write {shown}: {e}"))?;
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .and_then(|mut f| {
            f.write_all(content)?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(&temp, path));
    if let Err(e) = result {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("cannot write {shown}: {e}"));
    }
    Ok(())
}

/// A name no one can have planted: `.<file name>.<random>.tmp` in the
/// destination's directory, so the rename stays on one filesystem.
fn temp_path(path: &Path) -> std::io::Result<PathBuf> {
    let mut random = [0u8; 8];
    pragmatic::rand::fill(&mut random)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".into());
    Ok(path.with_file_name(format!(".{name}.{}.tmp", hex_encode(&random))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pragmatic-output-{name}-{}-{}",
            std::process::id(),
            pragmatic::journal::system_clock()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn writes_and_replaces_regular_files() {
        let d = dir("plain");
        let p = d.join("out.csv");
        write(&p, b"one").unwrap();
        write(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1, "no temp left");
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn never_writes_through_a_planted_link() {
        let d = dir("link");
        let victim = d.join("victim.txt");
        std::fs::write(&victim, "the auditor's own file\n").unwrap();
        let link = d.join("x.evidence.csv");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(write(&link, b"cursor,...")
            .unwrap_err()
            .contains("symbolic link"));
        // A dangling link is refused too.
        let dangling = d.join("y.evidence.html");
        std::os::unix::fs::symlink(d.join("nowhere"), &dangling).unwrap();
        assert!(write(&dangling, b"<html>").is_err());
        assert!(!d.join("nowhere").exists());
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "the auditor's own file\n"
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn refuses_directories() {
        let d = dir("dir");
        assert!(write(&d, b"x").unwrap_err().contains("not a regular file"));
        std::fs::remove_dir_all(d).unwrap();
    }
}
