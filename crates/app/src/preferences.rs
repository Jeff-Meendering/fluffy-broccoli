use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

use eframe::egui;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ThemeChoice {
    #[default]
    System,
    Light,
    Dark,
}

impl ThemeChoice {
    pub const ALL: [Self; 3] = [Self::System, Self::Light, Self::Dark];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Light => "Light",
            Self::Dark => "Dark",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "System" => Some(Self::System),
            "Light" => Some(Self::Light),
            "Dark" => Some(Self::Dark),
            _ => None,
        }
    }

    pub fn apply(self, context: &egui::Context) {
        let preference = match self {
            Self::System => egui::ThemePreference::System,
            Self::Light => egui::ThemePreference::Light,
            Self::Dark => egui::ThemePreference::Dark,
        };
        context.set_theme(preference);
    }
}

/// Reads only the small theme preference file. Scan settings and results are never restored.
#[must_use]
pub fn load_theme() -> ThemeChoice {
    let Some(path) = preference_path() else {
        return ThemeChoice::System;
    };
    let Ok(file) = File::open(path) else {
        return ThemeChoice::System;
    };
    let mut value = String::new();
    if file.take(32).read_to_string(&mut value).is_err() {
        return ThemeChoice::System;
    }
    ThemeChoice::parse(&value).unwrap_or_default()
}

/// Saves only the selected theme. Failure leaves the in-memory choice active.
pub fn save_theme(theme: ThemeChoice) -> io::Result<()> {
    let path = preference_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "No local configuration directory is available",
        )
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, theme.as_str())
}

fn preference_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME").map(|home| {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("PiiExplorer")
                .join("theme.txt")
        })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .map(|directory| {
                PathBuf::from(directory)
                    .join("PiiExplorer")
                    .join("theme.txt")
            })
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .map(|directory| directory.join("pii-explorer").join("theme.txt"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_theme_values_are_accepted() {
        for theme in ThemeChoice::ALL {
            assert_eq!(ThemeChoice::parse(theme.as_str()), Some(theme));
            assert_eq!(
                ThemeChoice::parse(&format!(" {}\n", theme.as_str())),
                Some(theme)
            );
        }
        assert_eq!(ThemeChoice::parse("dark"), None);
        assert_eq!(ThemeChoice::parse("../../other"), None);
        assert_eq!(ThemeChoice::parse("Light\0Dark"), None);
    }
}
