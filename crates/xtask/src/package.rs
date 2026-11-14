use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::util::{
    TempPath, collect_files, copy_directory, copy_file, sha256_file, validate_target,
};

static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);
const CHECKSUMS: &str = "SHA256SUMS";

#[derive(Deserialize)]
struct CargoMetadata {
    target_directory: PathBuf,
}

pub fn package(root: &Path, target: &str) -> Result<()> {
    validate_target(target)?;
    crate::assets::download(root)?;
    preflight_inputs(root)?;
    let inputs = crate::provenance::inputs(root)?;
    build_release(root, target)?;
    crate::provenance::verify_unchanged(root, &inputs)?;
    let target_directory = cargo_target_directory(root)?;
    let release = target_directory.join(target).join("release");

    let dist = prepare_dist(root)?;
    let staging = create_staging(&dist, target)?;
    let mut cleanup = TempPath::new(staging.clone());
    stage_package(root, &release, &staging, target)?;
    let support = if target.contains("apple-darwin") {
        staging.join("PII Explorer.app/Contents")
    } else {
        staging.clone()
    };
    crate::provenance::stage(root, &support, target, &inputs)?;
    write_checksums(&staging)?;

    let destination = dist.join(target);
    replace_staging(&dist, &staging, &destination)?;
    cleanup.keep();
    println!("Package staged at {}", destination.display());
    println!("Checksums: {}", destination.join(CHECKSUMS).display());
    Ok(())
}

fn preflight_inputs(root: &Path) -> Result<()> {
    for file in ["LICENSE", "NOTICE", "tests/fixtures/accuracy-smoke.jsonl"] {
        let path = root.join(file);
        let metadata = fs::metadata(&path)
            .with_context(|| format!("required package input {} is missing", path.display()))?;
        if !metadata.is_file() {
            bail!("required package input {} is not a file", path.display());
        }
    }
    for directory in ["assets/models", "assets/ocr/tessdata", "licenses"] {
        let path = root.join(directory);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("required package input {} is missing", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "required package input {} is not a real directory",
                path.display()
            );
        }
    }
    Ok(())
}

fn build_release(root: &Path, target: &str) -> Result<()> {
    let status = Command::new("cargo")
        .args([
            "build",
            "--locked",
            "--release",
            "--target",
            target,
            "--package",
            "pii-explorer-cli",
            "--package",
            "pii-explorer-app",
        ])
        .current_dir(root)
        .status()
        .context("failed to start cargo build")?;
    if !status.success() {
        bail!("release build failed with {status}");
    }
    Ok(())
}

fn cargo_target_directory(root: &Path) -> Result<PathBuf> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root)
        .output()
        .context("failed to start cargo metadata")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let metadata: CargoMetadata =
        serde_json::from_slice(&output.stdout).context("invalid cargo metadata output")?;
    Ok(metadata.target_directory)
}

fn prepare_dist(root: &Path) -> Result<PathBuf> {
    let dist = root.join("dist");
    match fs::symlink_metadata(&dist) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "{} must be a real directory, not a symlink or file",
                    dist.display()
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&dist)
                .with_context(|| format!("failed to create {}", dist.display()))?;
        }
        Err(error) => return Err(error).context("failed to inspect dist directory"),
    }
    let canonical = fs::canonicalize(&dist).context("failed to resolve dist directory")?;
    if canonical.parent() != Some(root) {
        bail!("refusing to stage outside the workspace dist directory");
    }
    Ok(dist)
}

fn create_staging(dist: &Path, target: &str) -> Result<PathBuf> {
    for _ in 0..100 {
        let sequence = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
        let path = dist.join(format!(
            ".{target}.staging-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create staging {}", path.display()));
            }
        }
    }
    bail!("could not allocate a fresh staging directory for {target}")
}

fn replace_staging(dist: &Path, staging: &Path, destination: &Path) -> Result<()> {
    if staging.parent() != Some(dist)
        || destination.parent() != Some(dist)
        || staging == destination
    {
        bail!("refusing to replace a path outside dist");
    }
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "refusing to replace non-directory or symlink {}",
                    destination.display()
                );
            }
            fs::remove_dir_all(destination).with_context(|| {
                format!("failed to replace old package {}", destination.display())
            })?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("failed to inspect package destination"),
    }
    fs::rename(staging, destination).with_context(|| {
        format!(
            "failed to publish fresh staging {} as {}",
            staging.display(),
            destination.display()
        )
    })
}

fn stage_package(root: &Path, release: &Path, staging: &Path, target: &str) -> Result<()> {
    let target_lower = target.to_ascii_lowercase();
    let windows = target_lower.contains("windows");
    let macos = target_lower.contains("apple-darwin");
    let executable_suffix = if windows { ".exe" } else { "" };

    let binary_directory = if macos {
        staging.join("PII Explorer.app/Contents/MacOS")
    } else {
        staging.to_path_buf()
    };
    fs::create_dir_all(&binary_directory)
        .with_context(|| format!("failed to create {}", binary_directory.display()))?;

    for binary in ["pii-explorer", "pii-explorer-app", "pii-explorer-worker"] {
        let file_name = format!("{binary}{executable_suffix}");
        copy_file(
            &release.join(&file_name),
            &binary_directory.join(&file_name),
        )?;
    }
    copy_onnxruntime_libraries(release, &binary_directory, &target_lower)?;

    let support_root = if macos {
        staging.join("PII Explorer.app/Contents")
    } else {
        staging.to_path_buf()
    };
    copy_runtime_assets(root, &support_root)?;
    copy_supporting_files(root, &support_root)?;
    crate::notices::collect(root, target, &support_root.join("licenses/rust"))?;

    if macos {
        write_info_plist(&support_root)?;
        // Verification requires legal files at the package root as well as in
        // the app bundle, without duplicating the large model assets.
        copy_file(&root.join("LICENSE"), &staging.join("LICENSE"))?;
        copy_file(&root.join("NOTICE"), &staging.join("NOTICE"))?;
    }
    Ok(())
}

fn copy_onnxruntime_libraries(release: &Path, destination: &Path, target: &str) -> Result<()> {
    let mut libraries = BTreeMap::new();
    for entry in fs::read_dir(release)
        .with_context(|| format!("failed to read release directory {}", release.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if is_onnxruntime_library(&name, target) {
            libraries.insert(entry.file_name(), entry.path());
        }
    }
    for (name, source) in libraries {
        let metadata = fs::metadata(&source)
            .with_context(|| format!("failed to inspect runtime library {}", source.display()))?;
        if metadata.is_file() {
            copy_file(&source, &destination.join(name))?;
        }
    }
    Ok(())
}

fn is_onnxruntime_library(name: &str, target: &str) -> bool {
    if target.contains("windows") {
        name.starts_with("onnxruntime") && name.ends_with(".dll")
    } else if target.contains("apple-darwin") {
        name.starts_with("libonnxruntime") && name.ends_with(".dylib")
    } else {
        name.starts_with("libonnxruntime") && name.contains(".so")
    }
}

fn copy_runtime_assets(root: &Path, destination: &Path) -> Result<()> {
    crate::assets::stage(root, &destination.join("assets"))
}

fn copy_supporting_files(root: &Path, destination: &Path) -> Result<()> {
    for file in [
        "LICENSE",
        "NOTICE",
        "THIRD-PARTY-NOTICES.md",
        "Cargo.lock",
        "README.md",
        "SECURITY.md",
        "PILOT-GUIDE.md",
        "CONTRIBUTING.md",
        "REVIEW.md",
    ] {
        copy_file(&root.join(file), &destination.join(file))?;
    }
    copy_directory(&root.join("licenses"), &destination.join("licenses"))?;

    let docs_source = root.join("docs");
    let docs_destination = destination.join("docs");
    match fs::symlink_metadata(&docs_source) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "documentation input {} is not a real directory",
                    docs_source.display()
                );
            }
            copy_directory(&docs_source, &docs_destination)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&docs_destination)
                .with_context(|| format!("failed to create {}", docs_destination.display()))?;
            for file in [
                "README.md",
                "SECURITY.md",
                "PILOT-GUIDE.md",
                "CONTRIBUTING.md",
                "REVIEW.md",
            ] {
                let source = root.join(file);
                if source.is_file() {
                    copy_file(&source, &docs_destination.join(file))?;
                }
            }
        }
        Err(error) => return Err(error).context("failed to inspect documentation directory"),
    }

    copy_file(
        &root.join("tests/fixtures/accuracy-smoke.jsonl"),
        &destination.join("tests/fixtures/accuracy-smoke.jsonl"),
    )
}

fn write_info_plist(contents: &Path) -> Result<()> {
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>pii-explorer-app</string>
    <key>CFBundleIdentifier</key><string>local.piiexplorer.desktop</string>
    <key>CFBundleName</key><string>PII Explorer</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>{}</string>
    <key>CFBundleVersion</key><string>{}</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
"#,
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_VERSION")
    );
    write_new(&contents.join("Info.plist"), plist.as_bytes())
}

pub fn write_checksums(package: &Path) -> Result<()> {
    let files = collect_files(package)?;
    if files.contains_key(CHECKSUMS) {
        bail!("package already contains {CHECKSUMS}; refusing to overwrite it");
    }
    let mut manifest = String::new();
    for (relative, path) in files {
        let digest = sha256_file(&path)?;
        manifest.push_str(&format!("{digest}  {relative}\n"));
    }
    write_new(&package.join(CHECKSUMS), manifest.as_bytes())
}

fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create new file {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_only_onnxruntime_libraries_for_the_target() {
        assert!(is_onnxruntime_library(
            "libonnxruntime.dylib",
            "aarch64-apple-darwin"
        ));
        assert!(is_onnxruntime_library(
            "onnxruntime.dll",
            "x86_64-pc-windows-msvc"
        ));
        assert!(is_onnxruntime_library(
            "onnxruntime_providers_shared.dll",
            "x86_64-pc-windows-msvc"
        ));
        assert!(is_onnxruntime_library(
            "libonnxruntime.so.1.23.2",
            "x86_64-unknown-linux-gnu"
        ));
        assert!(!is_onnxruntime_library(
            "libother.dylib",
            "aarch64-apple-darwin"
        ));
        assert!(!is_onnxruntime_library(
            "onnxruntime.pdb",
            "x86_64-pc-windows-msvc"
        ));
    }
}
