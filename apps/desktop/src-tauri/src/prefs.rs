// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-user UI preferences stored in `%AppData%\PacketWard\ui.json`.
//!
//! The file is owned by the desktop app (not the agent). Loading is tolerant: a missing or
//! corrupt file yields the defaults so the UI can always start. Saving validates the payload
//! and writes atomically (temp file + rename).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const PREFS_VERSION: u32 = 1;
const ALLOWED_TEXT_SIZES: [u16; 4] = [90, 100, 110, 125];

#[derive(Debug, thiserror::Error)]
pub enum PrefsError {
    #[error("unsupported text size {0}; expected 90, 100, 110 or 125")]
    InvalidTextSize(u16),
    #[error("unsupported preferences version {0}")]
    UnsupportedVersion(u32),
    #[error("could not resolve the configuration directory")]
    NoConfigDir,
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("could not serialize preferences: {0}")]
    Serialize(#[from] serde_json::Error),
}

// Tauri commands need a serializable error; the UI only displays the message.
impl Serialize for PrefsError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    Dark,
    Light,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MonoFont {
    Jetbrains,
    Geist,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Density {
    Comfortable,
    Compact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "en")]
    En,
    #[serde(rename = "es")]
    Es,
    #[serde(rename = "pt-BR")]
    PtBr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Appearance {
    pub theme: Theme,
    pub mono_font: MonoFont,
    pub density: Density,
    pub text_size: u16,
    pub reduce_motion: bool,
}

impl Default for Appearance {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            mono_font: MonoFont::Jetbrains,
            density: Density::Comfortable,
            text_size: 100,
            reduce_motion: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UiPrefs {
    pub version: u32,
    pub language: Language,
    pub appearance: Appearance,
}

impl Default for UiPrefs {
    fn default() -> Self {
        Self {
            version: PREFS_VERSION,
            language: Language::Auto,
            appearance: Appearance::default(),
        }
    }
}

impl UiPrefs {
    pub fn validate(&self) -> Result<(), PrefsError> {
        if self.version != PREFS_VERSION {
            return Err(PrefsError::UnsupportedVersion(self.version));
        }
        if !ALLOWED_TEXT_SIZES.contains(&self.appearance.text_size) {
            return Err(PrefsError::InvalidTextSize(self.appearance.text_size));
        }
        Ok(())
    }
}

/// Loads preferences from `path`. Missing, unreadable, corrupt or invalid files give defaults.
pub fn load_from(path: &Path) -> UiPrefs {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                tracing::warn!(%err, "could not read ui.json; using defaults");
            }
            return UiPrefs::default();
        }
    };
    match serde_json::from_str::<UiPrefs>(&text) {
        Ok(prefs) if prefs.validate().is_ok() => prefs,
        Ok(_) | Err(_) => {
            tracing::warn!("ui.json is invalid; using defaults");
            UiPrefs::default()
        }
    }
}

/// Validates and atomically writes preferences to `path`, creating parent folders.
pub fn save_to(path: &Path, prefs: &UiPrefs) -> Result<(), PrefsError> {
    prefs.validate()?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_string_pretty(prefs)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// `%AppData%\PacketWard\ui.json` (Roaming), resolved from the platform config directory.
pub fn prefs_path(config_dir: Option<PathBuf>) -> Result<PathBuf, PrefsError> {
    Ok(config_dir
        .ok_or(PrefsError::NoConfigDir)?
        .join("PacketWard")
        .join("ui.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("packetward-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("ui.json")
    }

    #[test]
    fn missing_file_gives_defaults() {
        let path = temp_file("missing");
        assert_eq!(load_from(&path), UiPrefs::default());
    }

    #[test]
    fn roundtrip_keeps_every_field() {
        let path = temp_file("roundtrip");
        let prefs = UiPrefs {
            version: PREFS_VERSION,
            language: Language::PtBr,
            appearance: Appearance {
                theme: Theme::System,
                mono_font: MonoFont::Geist,
                density: Density::Compact,
                text_size: 125,
                reduce_motion: true,
            },
        };
        save_to(&path, &prefs).unwrap();
        assert_eq!(load_from(&path), prefs);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn wire_format_matches_the_typescript_side() {
        let json = serde_json::to_value(UiPrefs::default()).unwrap();
        assert_eq!(json["language"], "auto");
        assert_eq!(json["appearance"]["monoFont"], "jetbrains");
        assert_eq!(json["appearance"]["textSize"], 100);
        assert_eq!(json["appearance"]["reduceMotion"], false);
    }

    #[test]
    fn corrupt_file_gives_defaults() {
        let path = temp_file("corrupt");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{ not json").unwrap();
        assert_eq!(load_from(&path), UiPrefs::default());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn partial_file_fills_missing_fields() {
        let path = temp_file("partial");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, r#"{"language":"es"}"#).unwrap();
        let prefs = load_from(&path);
        assert_eq!(prefs.language, Language::Es);
        assert_eq!(prefs.appearance, Appearance::default());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn invalid_text_size_is_rejected_on_save_and_ignored_on_load() {
        let path = temp_file("badsize");
        let mut prefs = UiPrefs::default();
        prefs.appearance.text_size = 300;
        assert!(matches!(
            save_to(&path, &prefs),
            Err(PrefsError::InvalidTextSize(300))
        ));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, r#"{"appearance":{"textSize":300}}"#).unwrap();
        assert_eq!(load_from(&path), UiPrefs::default());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn path_requires_a_config_dir() {
        assert!(matches!(prefs_path(None), Err(PrefsError::NoConfigDir)));
        let p = prefs_path(Some(PathBuf::from("cfg"))).unwrap();
        assert!(p.ends_with("PacketWard/ui.json") || p.ends_with("PacketWard\\ui.json"));
    }
}
