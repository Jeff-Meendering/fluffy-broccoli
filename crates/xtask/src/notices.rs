//! Record the resolved Rust dependency graph and available upstream attribution files.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::util::{copy_file, relative_slashes};

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    resolve: Resolve,
}

#[derive(Deserialize)]
struct Resolve {
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
struct Node {
    id: String,
}

#[derive(Deserialize)]
struct Package {
    id: String,
    name: String,
    version: String,
    license: Option<String>,
    license_file: Option<String>,
    repository: Option<String>,
    source: Option<String>,
    manifest_path: PathBuf,
}

#[derive(Serialize)]
struct Entry {
    name: String,
    version: String,
    license: Option<String>,
    repository: Option<String>,
    source: Option<String>,
    attribution_files: Vec<String>,
}

pub fn collect(root: &Path, target: &str, destination: &Path) -> Result<()> {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--filter-platform",
            target,
        ])
        .current_dir(root)
        .output()
        .context("read locked dependency metadata")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed while collecting dependency notices: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let metadata: Metadata = serde_json::from_slice(&output.stdout)?;
    let resolved: BTreeSet<_> = metadata
        .resolve
        .nodes
        .into_iter()
        .map(|node| node.id)
        .collect();
    fs::create_dir_all(destination)?;
    let mut packages = metadata.packages;
    packages.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
    let mut entries = Vec::new();
    for package in packages {
        if package.source.is_none() || !resolved.contains(&package.id) {
            continue;
        }
        let directory = package
            .manifest_path
            .parent()
            .context("package manifest directory")?;
        let mut files = BTreeSet::new();
        collect_files(directory, 0, false, &mut files)?;
        if let Some(file) = &package.license_file {
            let path = directory.join(file);
            if path.starts_with(directory)
                && fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file())
            {
                files.insert(path);
            }
        }
        let name = format!("{}-{}", package.name, package.version);
        crate::util::validate_relative_path(&name)?;
        let mut attributions = Vec::new();
        for file in files {
            let filename = relative_slashes(directory, &file)?;
            let relative = format!("{name}/{filename}");
            copy_file(&file, &destination.join(&relative))?;
            attributions.push(relative);
        }
        entries.push(Entry {
            name: package.name,
            version: package.version,
            license: package.license,
            repository: package.repository,
            source: package.source,
            attribution_files: attributions,
        });
    }
    let inventory = serde_json::json!({
        "format_version": 1,
        "target": target,
        "scope": "Resolved workspace graph, including build and development dependencies; not a determination of which components are linked into each executable. Available licenses, notices, top-level READMEs and font attribution text are copied to a bounded nesting depth. Crates may omit license texts or carry other assets; review those separately before redistribution.",
        "packages": entries,
    });
    fs::write(
        destination.join("inventory.json"),
        serde_json::to_vec_pretty(&inventory)?,
    )?;
    Ok(())
}

fn collect_files(
    directory: &Path,
    depth: usize,
    font_directory: bool,
    files: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let name = entry.file_name().to_string_lossy().to_ascii_uppercase();
        if kind.is_dir() && depth < 6 {
            collect_files(
                &entry.path(),
                depth + 1,
                font_directory || name == "FONTS",
                files,
            )?;
        } else if kind.is_file()
            && ([
                "LICENSE",
                "LICENCE",
                "COPYING",
                "NOTICE",
                "COPYRIGHT",
                "OFL",
                "UFL",
            ]
            .iter()
            .any(|part| name.contains(part))
                || (depth == 0 && name.starts_with("README"))
                || (font_directory && name.ends_with(".TXT")))
        {
            files.insert(entry.path());
        }
    }
    Ok(())
}
