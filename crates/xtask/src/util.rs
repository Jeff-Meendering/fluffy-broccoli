use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

pub fn project_root() -> Result<PathBuf> {
    fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .context("failed to locate the workspace root")
}

pub fn target_triple(target: Option<String>) -> Result<String> {
    let target = match target {
        Some(target) => target,
        None => {
            let output = Command::new("rustc")
                .arg("-vV")
                .output()
                .context("failed to start rustc -vV")?;
            if !output.status.success() {
                bail!("rustc -vV failed with {}", output.status);
            }
            let version = std::str::from_utf8(&output.stdout)
                .context("rustc -vV produced non-UTF-8 output")?;
            version
                .lines()
                .find_map(|line| line.strip_prefix("host: "))
                .context("rustc -vV did not report a host target")?
                .to_owned()
        }
    };
    validate_target(&target)?;
    Ok(target)
}

pub fn validate_target(target: &str) -> Result<()> {
    if target.is_empty()
        || target.len() > 128
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        bail!("invalid target triple {target:?}; use only ASCII letters, digits, '-' and '_'");
    }
    Ok(())
}

/// Validate a normalized, portable relative path used in a manifest.
///
/// Manifest paths always use '/'. Rejecting backslashes, drive prefixes, and
/// non-normal components also makes validation independent of the host OS.
pub fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty() {
        bail!("path is empty");
    }
    if path.chars().any(char::is_control) {
        bail!("path {path:?} contains a control character");
    }
    if path.contains('\\') {
        bail!("path {path:?} contains a backslash; manifest paths must use '/'");
    }
    if path.starts_with('/') || Path::new(path).is_absolute() || has_drive_prefix(path) {
        bail!("path {path:?} must be relative");
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            bail!("path {path:?} is not normalized or traverses its parent");
        }
    }
    if !Path::new(path)
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        bail!("path {path:?} contains a non-normal component");
    }
    Ok(())
}

fn has_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

pub fn relative_slashes(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{} is outside {}", path.display(), root.display()))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                parts.push(
                    part.to_str()
                        .with_context(|| format!("path {} is not valid UTF-8", path.display()))?,
                );
            }
            _ => bail!("path {} is not a normal relative path", path.display()),
        }
    }
    let relative = parts.join("/");
    validate_relative_path(&relative)?;
    Ok(relative)
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {} for hashing", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex(&hasher.finalize()))
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

pub fn copy_file(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::metadata(source)
        .with_context(|| format!("required file {} is missing", source.display()))?;
    if !metadata.is_file() {
        bail!("required input {} is not a file", source.display());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::copy(source, destination).with_context(|| {
        format!(
            "failed to copy {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

pub fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("required directory {} is missing", source.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "required input {} is not a real directory",
            source.display()
        );
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::create_dir(destination)
        .with_context(|| format!("failed to create {}", destination.display()))?;
    copy_directory_contents(source, destination)
}

fn copy_directory_contents(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source)
        .with_context(|| format!("failed to read directory {}", source.display()))?
    {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!("refusing to package symlink {}", source_path.display());
        } else if file_type.is_dir() {
            fs::create_dir(&destination_path)
                .with_context(|| format!("failed to create {}", destination_path.display()))?;
            copy_directory_contents(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
        } else {
            bail!("refusing to package non-file {}", source_path.display());
        }
    }
    Ok(())
}

pub fn collect_files(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("package directory {} is missing", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("package root {} is not a real directory", root.display());
    }
    let mut files = BTreeMap::new();
    collect_directory_files(root, root, &mut files)?;
    Ok(files)
}

fn collect_directory_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to read directory {}", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!("package contains a symlink: {}", path.display());
        } else if file_type.is_dir() {
            collect_directory_files(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = relative_slashes(root, &path)?;
            if files.insert(relative.clone(), path).is_some() {
                bail!("package contains duplicate path {relative:?}");
            }
        } else {
            bail!("package contains a non-regular file: {}", path.display());
        }
    }
    Ok(())
}

pub struct TempPath {
    path: PathBuf,
    keep: bool,
}

impl TempPath {
    pub fn new(path: PathBuf) -> Self {
        Self { path, keep: false }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        if !self.keep
            && let Ok(metadata) = fs::symlink_metadata(&self.path)
        {
            let result = if metadata.is_dir() && !metadata.file_type().is_symlink() {
                fs::remove_dir_all(&self.path)
            } else {
                fs::remove_file(&self.path)
            };
            if let Err(error) = result {
                let _ = writeln!(
                    std::io::stderr(),
                    "warning: failed to clean up {}: {error}",
                    self.path.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn accepts_normal_relative_paths() -> Result<()> {
        for path in ["LICENSE", "assets/models/model.onnx", "a-b/c_d/1.txt"] {
            validate_relative_path(path)?;
        }
        Ok(())
    }

    #[test]
    fn rejects_unsafe_or_nonportable_paths() {
        for path in [
            "",
            "/etc/passwd",
            "../secret",
            "models/../../secret",
            "./model",
            "models//model",
            "models/",
            r"models\model",
            r"\\server\share\model",
            "C:/Windows/system.ini",
            "C:model.onnx",
            "bad\nname",
        ] {
            assert!(
                validate_relative_path(path).is_err(),
                "unexpectedly accepted {path:?}"
            );
        }
    }

    #[test]
    fn validates_target_as_one_safe_directory_name() -> Result<()> {
        validate_target("aarch64-apple-darwin")?;
        validate_target("x86_64-pc-windows-msvc")?;
        for target in ["", "../escape", "x86_64/linux", ".hidden", "two words"] {
            assert!(validate_target(target).is_err(), "accepted {target:?}");
        }
        Ok(())
    }

    #[test]
    fn hashes_known_content() -> Result<()> {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pii-explorer-xtask-hash-{}-{sequence}",
            std::process::id()
        ));
        let mut cleanup = TempPath::new(path.clone());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(b"abc")?;
        drop(file);
        assert_eq!(
            sha256_file(&path)?,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        fs::remove_file(&path)?;
        cleanup.keep();
        Ok(())
    }

    #[test]
    fn encodes_sha256_as_lowercase_hex() {
        assert_eq!(hex(&[0, 1, 15, 16, 127, 128, 255]), "00010f107f80ff");
    }
}
