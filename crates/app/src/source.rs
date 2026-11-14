use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// Resolves a scanner resource ID without allowing it to escape the selected scan root.
pub fn source_path(root: &Path, resource_id: &str) -> io::Result<PathBuf> {
    let relative = Path::new(resource_id);
    if resource_id.is_empty()
        || relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The finding does not name a source inside the scanned folder.",
        ));
    }
    Ok(root.join(relative))
}

/// Opens the platform file manager directly. No shell or interpolated command line is involved.
pub fn reveal_source(root: &Path, resource_id: &str) -> io::Result<()> {
    let path = source_path(root, resource_id)?;
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "The source is no longer available at its scanned location.",
        ));
    }

    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("/usr/bin/open");
        command.arg("-R").arg(&path);
        command
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("explorer.exe");
        let mut select = std::ffi::OsString::from("/select,");
        select.push(&path);
        command.arg(select);
        command
    };
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        if path.is_dir() {
            command.arg(&path);
        } else {
            command.arg(path.parent().unwrap_or(root));
        }
        command
    };

    command.spawn().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_ids_resolve_beneath_the_root() {
        assert_eq!(
            source_path(Path::new("/scan/root"), "nested/file.txt").expect("valid resource"),
            PathBuf::from("/scan/root/nested/file.txt")
        );
        assert_eq!(
            source_path(Path::new("/scan/root"), "./file.txt").expect("current directory is safe"),
            PathBuf::from("/scan/root/./file.txt")
        );
    }

    #[test]
    fn absolute_and_parent_paths_are_rejected() {
        for resource in [
            "../outside.txt",
            "/etc/passwd",
            "nested/../../outside.txt",
            "",
        ] {
            assert!(
                source_path(Path::new("/scan/root"), resource).is_err(),
                "resource: {resource}"
            );
        }
    }
}
