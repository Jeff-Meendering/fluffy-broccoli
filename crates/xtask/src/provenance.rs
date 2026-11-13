use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::util::{collect_files, copy_file, sha256_file};

/// Hash only enumerated build inputs, never arbitrary checkout files or case data.
pub fn inputs(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo/config.toml",
        "scripts/assets.json",
    ] {
        files.insert(name.to_owned(), sha256_file(&root.join(name))?);
    }
    for (relative, path) in collect_files(&root.join("crates"))? {
        let name = Path::new(&relative);
        let include = name.file_name().is_some_and(|name| name == "Cargo.toml")
            || name
                .extension()
                .is_some_and(|extension| extension == "rs" || extension == "sql")
            || relative == "core/assets/NotoSans-Regular.ttf"
            || relative == "core/assets/OFL.txt";
        if include {
            files.insert(format!("crates/{relative}"), sha256_file(&path)?);
        }
    }
    Ok(files)
}

pub fn verify_unchanged(root: &Path, expected: &BTreeMap<String, String>) -> Result<()> {
    if &inputs(root)? != expected {
        bail!(
            "source inputs changed during packaging; discard this build and retry with frozen sources"
        )
    }
    Ok(())
}

pub fn stage(
    root: &Path,
    destination: &Path,
    target: &str,
    expected: &BTreeMap<String, String>,
) -> Result<()> {
    verify_unchanged(root, expected)?;
    let source = destination.join("build-source");
    for (relative, hash) in expected {
        let target = source.join(relative);
        copy_file(&root.join(relative), &target)?;
        if sha256_file(&target)? != *hash {
            bail!("source changed while copying build snapshot")
        }
    }
    let source_sha256: String = Sha256::digest(serde_json::to_vec(expected)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let manifest = json!({
        "schema_version":1,
        "target":target,
        "source_tree_sha256":source_sha256,
        "source_files":expected,
        "compiler":command_output("rustc", &["-vV"] )?,
        "cargo":command_output("cargo", &["-vV"] )?,
        "build_arguments":["build","--locked","--release","--target",target,"--package","pii-explorer-cli","--package","pii-explorer-app"],
        "scope":"Enumerated Rust sources, manifests, schema, embedded report font and pinned runtime-asset manifest; copied under build-source. Input hashes checked before and after compilation and staging. Runtime assets, binaries, support libraries and this manifest are covered by package SHA256SUMS.",
        "limits":"Unsigned local build provenance, not publisher authentication or a bit-reproducible build claim. Host toolchain/native libraries, environment and dependency build scripts can affect output. The build-source snapshot supports release compilation; external test fixtures and documentation are distributed separately."
    });
    fs::write(
        destination.join("BUILD-PROVENANCE.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    verify_unchanged(root, expected)
}

fn command_output(program: &str, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program).args(arguments).output()?;
    if !output.status.success() {
        bail!("cannot record {program} version")
    }
    String::from_utf8(output.stdout).context("non-UTF-8 toolchain version")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_inputs_include_uncommitted_code_and_reject_changes_without_harvesting_cases() {
        let directory = tempfile::tempdir().expect("directory");
        let root = directory.path();
        for name in [
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo/config.toml",
            "scripts/assets.json",
            "crates/core/src/lib.rs",
            "crates/case/src/schema.sql",
            "crates/core/assets/NotoSans-Regular.ttf",
            "crates/core/assets/OFL.txt",
            "crates/private.piicase",
        ] {
            let path = root.join(name);
            fs::create_dir_all(path.parent().expect("parent")).expect("directories");
            fs::write(path, name).expect("source");
        }
        let before = inputs(root).expect("inputs");
        assert!(before.contains_key("crates/case/src/schema.sql"));
        assert!(!before.contains_key("crates/private.piicase"));
        verify_unchanged(root, &before).expect("frozen inputs");
        fs::write(root.join("crates/core/src/lib.rs"), "changed").expect("edit");
        assert!(verify_unchanged(root, &before).is_err());
    }
}
