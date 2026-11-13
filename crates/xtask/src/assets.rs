use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::util::{TempPath, sha256_file, validate_relative_path};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    url: String,
    path: String,
    sha256: String,
}

pub fn download(root: &Path) -> Result<()> {
    let manifest_path = root.join("scripts/assets.json");
    let manifest = fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let assets = parse_manifest(&manifest)?;
    let assets_root = root.join("assets");

    for asset in &assets {
        prepare_parent(&assets_root, &asset.path)?;
        let destination = assets_root.join(&asset.path);
        match fs::symlink_metadata(&destination) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    bail!(
                        "asset destination {} is not a regular file",
                        destination.display()
                    );
                }
                verify_existing(asset, &destination)?;
                println!("verified {}", asset.path);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                download_asset(asset, &destination)?;
                println!("downloaded and verified {}", asset.path);
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect asset {}", destination.display()));
            }
        }
    }
    println!("{} pinned assets verified.", assets.len());
    Ok(())
}

/// Stage only checksum-pinned files, never unrelated local model experiments or case data.
pub fn stage(root: &Path, destination: &Path) -> Result<()> {
    let assets = parse_manifest(&fs::read_to_string(root.join("scripts/assets.json"))?)?;
    for asset in &assets {
        prepare_parent(&root.join("assets"), &asset.path)?;
        let source = root.join("assets").join(&asset.path);
        if !fs::symlink_metadata(&source)?.is_file() {
            bail!("asset {} is not a regular file", asset.path);
        }
        verify_existing(asset, &source)?;
        crate::util::copy_file(&source, &destination.join(&asset.path))?;
    }
    Ok(())
}

fn prepare_parent(root: &Path, relative: &str) -> Result<()> {
    ensure_directory(root)?;
    let mut path = root.to_path_buf();
    if let Some(parent) = Path::new(relative).parent() {
        for component in parent.components() {
            path.push(component);
            ensure_directory(&path)?;
        }
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => bail!(
            "asset parent {} must be a real directory, not a link or file",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(path)
            .with_context(|| format!("create asset directory {}", path.display())),
        Err(error) => Err(error).context("inspect asset directory"),
    }
}

fn parse_manifest(manifest: &str) -> Result<Vec<Asset>> {
    let mut assets: Vec<Asset> =
        serde_json::from_str(manifest).context("invalid assets manifest")?;
    let mut paths = HashSet::new();
    for asset in &mut assets {
        validate_relative_path(&asset.path)
            .with_context(|| format!("invalid asset destination {:?}", asset.path))?;
        if !paths.insert(asset.path.clone()) {
            bail!("duplicate asset destination {:?}", asset.path);
        }
        if !asset.url.starts_with("https://") || asset.url.chars().any(char::is_control) {
            bail!(
                "asset {:?} does not have a valid pinned HTTPS URL",
                asset.path
            );
        }
        if asset.sha256.len() != 64 || !asset.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!(
                "asset {:?} does not have a 64-digit SHA256 hash",
                asset.path
            );
        }
        asset.sha256.make_ascii_lowercase();
    }
    Ok(assets)
}

fn verify_existing(asset: &Asset, destination: &Path) -> Result<()> {
    let actual = sha256_file(destination)?;
    if actual != asset.sha256 {
        bail!(
            "checksum mismatch for existing asset {}: expected {}, got {}; remove or repair it explicitly before rerunning assets",
            destination.display(),
            asset.sha256,
            actual
        );
    }
    Ok(())
}

fn download_asset(asset: &Asset, destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .with_context(|| format!("asset {} has no parent directory", destination.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let (temp_path, mut temp_file) = create_temp(destination)?;
    let mut cleanup = TempPath::new(temp_path);

    let mut child = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "10",
            "--connect-timeout",
            "30",
            "--max-time",
            "600",
            "--max-filesize",
            "268435456",
            "--url",
            &asset.url,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start system curl for {}", asset.url))?;
    let mut stdout = child
        .stdout
        .take()
        .context("failed to capture curl output")?;
    let copy_result = io::copy(&mut stdout.by_ref().take(268_435_457), &mut temp_file);
    if !copy_result
        .as_ref()
        .is_ok_and(|bytes| *bytes <= 268_435_456)
    {
        let _ = child.kill();
    }
    let status = child.wait().context("failed to wait for curl")?;
    let copied =
        copy_result.with_context(|| format!("failed to write download for {}", asset.path))?;
    if copied > 268_435_456 {
        bail!("asset download exceeds the 256 MiB limit");
    }
    temp_file
        .flush()
        .with_context(|| format!("failed to flush download for {}", asset.path))?;
    temp_file
        .sync_all()
        .with_context(|| format!("failed to sync download for {}", asset.path))?;
    drop(temp_file);
    if !status.success() {
        bail!("curl failed for {} with {status}", asset.url);
    }

    let actual = sha256_file(cleanup.path())?;
    if actual != asset.sha256 {
        bail!(
            "checksum mismatch for downloaded asset {}: expected {}, got {}",
            asset.path,
            asset.sha256,
            actual
        );
    }

    // A hard link atomically publishes the verified inode without replacing a
    // destination that another process may have created while downloading.
    fs::hard_link(cleanup.path(), destination).with_context(|| {
        format!(
            "failed to publish {}; it may have been created concurrently",
            destination.display()
        )
    })?;
    fs::remove_file(cleanup.path()).with_context(|| {
        format!(
            "failed to remove temporary file {}",
            cleanup.path().display()
        )
    })?;
    cleanup.keep();
    Ok(())
}

fn create_temp(destination: &Path) -> Result<(PathBuf, fs::File)> {
    let parent = destination
        .parent()
        .with_context(|| format!("asset {} has no parent directory", destination.display()))?;
    let file_name = destination
        .file_name()
        .with_context(|| format!("asset {} has no file name", destination.display()))?;
    for _ in 0..100 {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = OsString::from(".");
        temp_name.push(file_name);
        temp_name.push(format!(".{}.{}.download", std::process::id(), sequence));
        let path = parent.join(temp_name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to create temporary file {}", path.display())
                });
            }
        }
    }
    bail!(
        "could not allocate a unique temporary file for {}",
        destination.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn parses_and_normalizes_valid_manifest() -> Result<()> {
        let assets = parse_manifest(
            r#"[{"url":"https://example.com/model.onnx","path":"models/model.onnx","sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]"#,
        )?;
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].sha256, "a".repeat(64));
        Ok(())
    }

    #[test]
    fn rejects_duplicate_asset_paths() {
        let error = parse_manifest(
            r#"[
                {"url":"https://example.com/a","path":"models/a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                {"url":"https://example.com/b","path":"models/a","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
            ]"#,
        );
        assert!(error.is_err());
    }

    #[test]
    fn rejects_invalid_manifest_fields_before_downloading() {
        for manifest in [
            r#"[{"url":"http://example.com/a","path":"models/a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#,
            r#"[{"url":"https://example.com/a","path":"../a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#,
            r#"[{"url":"https://example.com/a","path":"models/a","sha256":"not-a-hash"}]"#,
            r#"[{"url":"https://example.com/a","path":"models/a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}]"#,
        ] {
            assert!(parse_manifest(manifest).is_err(), "accepted {manifest}");
        }
    }

    #[test]
    fn package_staging_checks_pins_and_excludes_unlisted_assets() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        fs::create_dir_all(root.join("scripts"))?;
        fs::create_dir_all(root.join("assets/models"))?;
        fs::write(root.join("assets/models/model"), b"test")?;
        fs::write(
            root.join("assets/models/private-case.json"),
            b"must not ship",
        )?;
        fs::write(
            root.join("scripts/assets.json"),
            serde_json::to_vec(&serde_json::json!([{
                "url": "https://example.com/model", "path": "models/model", "sha256": crate::util::hex(&sha2::Sha256::digest(b"test"))
            }]))?,
        )?;
        let destination = root.join("staged");
        stage(root, &destination)?;
        assert_eq!(fs::read(destination.join("models/model"))?, b"test");
        assert!(!destination.join("models/private-case.json").exists());
        fs::write(root.join("assets/models/model"), b"tampered")?;
        assert!(stage(root, &root.join("tampered-output")).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn asset_parents_cannot_redirect_downloads_through_symlinks() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let external = tempfile::tempdir()?;
        let root = directory.path().join("assets");
        fs::create_dir(&root)?;
        std::os::unix::fs::symlink(external.path(), root.join("models"))?;
        assert!(prepare_parent(&root, "models/model").is_err());
        assert!(!external.path().join("model").exists());
        Ok(())
    }
}
