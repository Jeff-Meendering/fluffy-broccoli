use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::util::{collect_files, sha256_file, validate_relative_path};

const CHECKSUMS: &str = "SHA256SUMS";

pub fn verify(package: &Path) -> Result<()> {
    let checksum_path = package.join(CHECKSUMS);
    let checksum_metadata = fs::symlink_metadata(&checksum_path).with_context(|| {
        format!(
            "required checksum file {} is missing",
            checksum_path.display()
        )
    })?;
    if checksum_metadata.file_type().is_symlink() || !checksum_metadata.is_file() {
        bail!(
            "checksum manifest {} is not a regular file",
            checksum_path.display()
        );
    }
    let text = fs::read_to_string(&checksum_path)
        .with_context(|| format!("failed to read {}", checksum_path.display()))?;
    let manifest = parse_checksums(&text)?;

    // Walking without following links validates every directory entry before
    // any manifest-listed content is trusted or hashed.
    let mut actual = collect_files(package)?;
    actual.remove(CHECKSUMS);

    let mut problems = Vec::new();
    for required in ["LICENSE", "NOTICE"] {
        if !actual.contains_key(required) {
            problems.push(format!("required legal file is missing: {required}"));
        }
    }
    for path in manifest.keys() {
        if !actual.contains_key(path) {
            problems.push(format!("manifest-listed file is missing: {path}"));
        }
    }
    for path in actual.keys() {
        if !manifest.contains_key(path) {
            problems.push(format!("extra file is not listed in {CHECKSUMS}: {path}"));
        }
    }
    for (path, expected) in &manifest {
        if let Some(file) = actual.get(path) {
            match sha256_file(file) {
                Ok(actual_hash) if &actual_hash == expected => {}
                Ok(actual_hash) => problems.push(format!(
                    "checksum mismatch for {path}: expected {expected}, got {actual_hash}"
                )),
                Err(error) => problems.push(format!("could not hash {path}: {error:#}")),
            }
        }
    }

    if !problems.is_empty() {
        bail!("package verification failed:\n{}", problems.join("\n"));
    }
    println!(
        "Verified {} files in {} against {}.",
        manifest.len(),
        package.display(),
        CHECKSUMS
    );
    Ok(())
}

fn parse_checksums(text: &str) -> Result<BTreeMap<String, String>> {
    let mut entries = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let bytes = line.as_bytes();
        if bytes.len() < 67 || bytes.get(64) != Some(&b' ') || bytes.get(65) != Some(&b' ') {
            bail!("invalid {CHECKSUMS} line {line_number}; expected '<sha256>  <path>'");
        }
        let hash = std::str::from_utf8(&bytes[..64])
            .with_context(|| format!("invalid hash on {CHECKSUMS} line {line_number}"))?;
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("invalid SHA256 on {CHECKSUMS} line {line_number}");
        }
        let path = &line[66..];
        validate_relative_path(path)
            .with_context(|| format!("unsafe path on {CHECKSUMS} line {line_number}"))?;
        if path == CHECKSUMS {
            bail!("{CHECKSUMS} must not list itself");
        }
        let hash = hash.to_ascii_lowercase();
        if entries.insert(path.to_owned(), hash).is_some() {
            bail!("duplicate path {path:?} in {CHECKSUMS}");
        }
    }
    if entries.is_empty() {
        bail!("{CHECKSUMS} contains no files");
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::package::write_checksums;
    use crate::util::TempPath;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    fn test_directory(label: &str) -> Result<(PathBuf, TempPath)> {
        for _ in 0..100 {
            let sequence = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "pii-explorer-xtask-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    let cleanup = TempPath::new(path.clone());
                    return Ok((path, cleanup));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        bail!("could not create test directory")
    }

    fn write(path: &Path, contents: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
        Ok(())
    }

    fn manifest_line(path: &str) -> String {
        format!("{}  {path}\n", "a".repeat(64))
    }

    #[test]
    fn generated_checksums_verify_complete_package() -> Result<()> {
        let (package, _cleanup) = test_directory("round-trip")?;
        write(&package.join("LICENSE"), b"license")?;
        write(&package.join("NOTICE"), b"notice")?;
        write(&package.join("bin/tool"), b"binary")?;
        write_checksums(&package)?;
        verify(&package)?;
        Ok(())
    }

    #[test]
    fn rejects_traversal_absolute_and_duplicate_manifest_paths() {
        for manifest in [
            manifest_line("../secret"),
            manifest_line("/etc/passwd"),
            manifest_line("C:/Windows/system.ini"),
            manifest_line(r"bin\..\secret"),
            format!("{}{}", manifest_line("bin/tool"), manifest_line("bin/tool")),
            manifest_line(CHECKSUMS),
        ] {
            assert!(parse_checksums(&manifest).is_err(), "accepted {manifest:?}");
        }
    }

    #[test]
    fn rejects_tampering_missing_and_extra_files() -> Result<()> {
        let (package, _cleanup) = test_directory("changes")?;
        write(&package.join("LICENSE"), b"license")?;
        write(&package.join("NOTICE"), b"notice")?;
        write(&package.join("bin/tool"), b"binary")?;
        write_checksums(&package)?;

        write(&package.join("bin/tool"), b"tampered")?;
        let error = match verify(&package) {
            Err(error) => error,
            Ok(()) => bail!("tampering should fail verification"),
        };
        assert!(format!("{error:#}").contains("checksum mismatch"));

        write(&package.join("extra.txt"), b"extra")?;
        let error = match verify(&package) {
            Err(error) => error,
            Ok(()) => bail!("an extra file should fail verification"),
        };
        assert!(format!("{error:#}").contains("extra file"));

        fs::remove_file(package.join("NOTICE"))?;
        let error = match verify(&package) {
            Err(error) => error,
            Ok(()) => bail!("a missing file should fail verification"),
        };
        let message = format!("{error:#}");
        assert!(message.contains("required legal file is missing: NOTICE"));
        assert!(message.contains("manifest-listed file is missing: NOTICE"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_in_package() -> Result<()> {
        let (package, _cleanup) = test_directory("symlink")?;
        write(&package.join("LICENSE"), b"license")?;
        write(&package.join("NOTICE"), b"notice")?;
        write(&package.join("bin/tool"), b"binary")?;
        write_checksums(&package)?;
        std::os::unix::fs::symlink("tool", package.join("bin/link"))?;
        let error = match verify(&package) {
            Err(error) => error,
            Ok(()) => bail!("a symlink should fail verification"),
        };
        assert!(format!("{error:#}").contains("symlink"));
        Ok(())
    }
}
