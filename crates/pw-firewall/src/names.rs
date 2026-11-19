// SPDX-License-Identifier: GPL-3.0-or-later
//! Rule group, reserved names, batch identifiers and name validation/sanitizing.

use std::fmt;

use crate::error::{FirewallError, Result};

/// The firewall rule group of every rule PacketWard creates. `purge` removes exactly this group.
pub const GROUP: &str = "PacketWard";
/// Appended to the description of every rule PacketWard creates.
pub const MARKER: &str = "[PacketWard]";
/// Names starting with this (case-insensitive) are reserved for PacketWard's own rules; user rules
/// created through `add_rule` may not use it.
pub const RESERVED_PREFIX: &str = "PW-";

pub const AUTOBLOCK_PREFIX: &str = "PW-AutoBlock";
pub const MANUAL_PREFIX: &str = "PW-Manual";
pub const LIST_PREFIX: &str = "PW-List";
/// The RDP Shield allow rules (TCP and UDP).
pub const RDP_ALLOW_TCP: &str = "PW-RDP-Allow";
pub const RDP_ALLOW_UDP: &str = "PW-RDP-Allow-UDP";

const MAX_NAME_LEN: usize = 128;
const MAX_COMPONENT_LEN: usize = 32;
const MAX_DESCRIPTION_LEN: usize = 512;

fn bad(name: &str, reason: &'static str) -> FirewallError {
    FirewallError::InvalidName {
        name: name.chars().take(64).collect(),
        reason,
    }
}

fn name_char_ok(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '(' | ')' | ',')
}

/// Validates a rule name. `allow_reserved` is only for PacketWard's own rules (`PW-...`).
///
/// Names are rejected (never silently changed) when they contain anything outside letters, digits,
/// space and `- _ . ( ) ,`; this rules out quotes, `|`, control characters, path separators and
/// the resource-string syntax (`@file.dll,-123`) so a name can never be interpreted by Windows.
pub fn validate_rule_name(name: &str, allow_reserved: bool) -> Result<()> {
    if name.is_empty() {
        return Err(bad(name, "empty"));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(bad(name, "too long"));
    }
    if name != name.trim() {
        return Err(bad(name, "leading or trailing whitespace"));
    }
    if !name.chars().all(name_char_ok) {
        return Err(bad(name, "contains a character that is not allowed"));
    }
    if name.eq_ignore_ascii_case("all") {
        return Err(bad(name, "reserved word"));
    }
    if !allow_reserved && is_reserved_name(name) {
        return Err(bad(name, "the PW- prefix is reserved for PacketWard"));
    }
    Ok(())
}

pub fn is_reserved_name(name: &str) -> bool {
    name.get(..RESERVED_PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(RESERVED_PREFIX))
}

/// Turns arbitrary text into a safe name component (`[a-z0-9_.-]`, at most 32 chars); `None` when
/// nothing usable remains.
pub fn sanitize_component(text: &str) -> Option<String> {
    let mut out = String::new();
    for c in text.chars() {
        let c = c.to_ascii_lowercase();
        let ok = c.is_ascii_alphanumeric() || c == '_' || c == '.';
        if ok {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
        if out.len() >= MAX_COMPONENT_LEN {
            break;
        }
    }
    let out = out.trim_matches('-').to_owned();
    (!out.is_empty()).then_some(out)
}

/// Removes control characters, collapses to one line, caps the length and makes sure the
/// PacketWard marker is present.
pub fn marked_description(text: &str) -> String {
    let mut clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    clean = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.chars().count() > MAX_DESCRIPTION_LEN {
        clean = clean.chars().take(MAX_DESCRIPTION_LEN).collect();
    }
    if clean.contains(MARKER) {
        clean
    } else if clean.is_empty() {
        MARKER.to_owned()
    } else {
        format!("{clean} {MARKER}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Kind {
    AutoBlock,
    Manual,
    List(String),
}

/// Identifies a family of numbered block rules: `PW-AutoBlock-001…`, `PW-Manual-001…` or
/// `PW-List-<name>-001…`. Manual blocks live in their own batch so a Guardian TTL reconcile of the
/// auto-block batch can never remove them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BatchId(Kind);

impl BatchId {
    pub fn auto_block() -> Self {
        Self(Kind::AutoBlock)
    }

    pub fn manual() -> Self {
        Self(Kind::Manual)
    }

    /// A public/shared blocklist named `name` (sanitized to `[a-z0-9_.-]`).
    pub fn list(name: &str) -> Result<Self> {
        let component = sanitize_component(name).ok_or_else(|| bad(name, "no usable characters"))?;
        Ok(Self(Kind::List(component)))
    }

    /// The rule name prefix without the trailing number, e.g. `PW-List-spamhaus`.
    pub fn prefix(&self) -> String {
        match &self.0 {
            Kind::AutoBlock => AUTOBLOCK_PREFIX.to_owned(),
            Kind::Manual => MANUAL_PREFIX.to_owned(),
            Kind::List(name) => format!("{LIST_PREFIX}-{name}"),
        }
    }

    /// Name of the `index`-th rule (1-based): `PW-AutoBlock-001`.
    pub fn rule_name(&self, index: u32) -> String {
        format!("{}-{index:03}", self.prefix())
    }

    /// The batch index when `rule_name` is a member of this batch.
    pub fn parse_index(&self, rule_name: &str) -> Option<u32> {
        let prefix = self.prefix();
        let head = rule_name.get(..prefix.len())?;
        if !head.eq_ignore_ascii_case(&prefix) {
            return None;
        }
        let digits = rule_name.get(prefix.len()..)?.strip_prefix('-')?;
        if digits.len() < 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok().filter(|n| *n >= 1)
    }

    pub fn description(&self) -> String {
        let what = match &self.0 {
            Kind::AutoBlock => "automatic blocks".to_owned(),
            Kind::Manual => "manual blocks".to_owned(),
            Kind::List(name) => format!("blocklist {name}"),
        };
        format!("PacketWard {what}. Managed automatically; edits are overwritten. {MARKER}")
    }
}

impl fmt::Display for BatchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.prefix())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_names_are_validated_not_rewritten() {
        for ok in ["My rule", "Web (443)", "a-b_c.d", "Regla ñandú"] {
            assert!(validate_rule_name(ok, false).is_ok(), "{ok}");
        }
        for bad in [
            "",
            " x",
            "x ",
            "a|b",
            "a\"b",
            "a\nb",
            "a\0b",
            "@firewallapi.dll,-28775",
            "a/b",
            "a\\b",
            "ALL",
            "all",
            "PW-AutoBlock-001",
            "pw-x",
        ] {
            assert!(validate_rule_name(bad, false).is_err(), "{bad:?}");
        }
        assert!(validate_rule_name("PW-AutoBlock-001", true).is_ok());
        assert!(validate_rule_name(&"x".repeat(129), false).is_err());
    }

    #[test]
    fn components_are_sanitized_to_a_safe_alphabet() {
        assert_eq!(
            sanitize_component("Spamhaus DROP!").as_deref(),
            Some("spamhaus-drop")
        );
        assert_eq!(
            sanitize_component("../..//x|\"y").as_deref(),
            Some("..-..-x-y")
        );
        assert_eq!(sanitize_component("   ").as_deref(), None);
        assert_eq!(sanitize_component("---").as_deref(), None);
        let long = sanitize_component(&"a".repeat(200)).unwrap();
        assert!(long.len() <= 32);
        // Whatever comes out is always a valid internal name part.
        for hostile in ["a\0b", "x\r\ny", "'; drop", "%PATH%", "名前", "a,b"] {
            if let Some(c) = sanitize_component(hostile) {
                assert!(validate_rule_name(&format!("PW-List-{c}-001"), true).is_ok());
            }
        }
    }

    #[test]
    fn batch_names_and_membership() {
        let auto = BatchId::auto_block();
        assert_eq!(auto.rule_name(1), "PW-AutoBlock-001");
        assert_eq!(auto.rule_name(1234), "PW-AutoBlock-1234");
        assert_eq!(auto.parse_index("PW-AutoBlock-007"), Some(7));
        assert_eq!(auto.parse_index("pw-autoblock-007"), Some(7));
        assert_eq!(auto.parse_index("PW-AutoBlock-000"), None);
        assert_eq!(auto.parse_index("PW-AutoBlock-7"), None);
        assert_eq!(auto.parse_index("PW-AutoBlock-00x"), None);
        assert_eq!(auto.parse_index("PW-Manual-001"), None);
        let list = BatchId::list("Spamhaus DROP").unwrap();
        assert_eq!(list.rule_name(2), "PW-List-spamhaus-drop-002");
        // A list called "spamhaus" does not own the rules of "spamhaus-drop".
        let other = BatchId::list("spamhaus").unwrap();
        assert_eq!(other.parse_index("PW-List-spamhaus-drop-002"), None);
        assert_eq!(other.parse_index("PW-List-spamhaus-002"), Some(2));
        assert!(BatchId::list("???").is_err());
    }

    #[test]
    fn descriptions_always_carry_the_marker_on_one_line() {
        let d = marked_description("hello\nworld\0 ");
        assert!(d.contains(MARKER));
        assert!(!d.contains('\n') && !d.contains('\0'));
        assert_eq!(marked_description(""), MARKER);
        assert_eq!(marked_description(&format!("x {MARKER}")), format!("x {MARKER}"));
        assert!(marked_description(&"y".repeat(5000)).chars().count() < 600);
    }
}
