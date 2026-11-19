// SPDX-License-Identifier: GPL-3.0-or-later
//! Network interface listing (read-only) and resolution of an [`InterfaceId`] to an adapter.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::backend::InterfaceId;
use crate::error::CaptureError;

/// Prefix of Npcap device names; the rest is the adapter GUID.
pub(crate) const NPF_PREFIX: &str = r"\Device\NPF_";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceInfo {
    /// Adapter name: the GUID in braces on Windows (`{...}`).
    pub id: InterfaceId,
    /// Friendly name, e.g. `Ethernet`.
    pub name: String,
    pub description: String,
    /// Unicast addresses.
    pub addrs: Vec<IpAddr>,
    /// Operational status is up.
    pub up: bool,
    pub loopback: bool,
}

impl InterfaceInfo {
    /// The Npcap device name of this adapter.
    pub fn npcap_device(&self) -> String {
        format!("{NPF_PREFIX}{}", self.id.0)
    }

    pub fn ipv4_addrs(&self) -> impl Iterator<Item = std::net::Ipv4Addr> + '_ {
        self.addrs.iter().filter_map(|a| match a {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
    }
}

/// Source of the interface list; the system implementation reads the adapters, tests use a fixed list.
pub trait InterfaceProvider: Send + Sync {
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, CaptureError>;
}

/// The adapters of this machine (`GetAdaptersAddresses`). Only available on Windows.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemInterfaces;

impl InterfaceProvider for SystemInterfaces {
    #[cfg(windows)]
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, CaptureError> {
        crate::sys::windows::list_adapters().map_err(CaptureError::from)
    }

    #[cfg(not(windows))]
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, CaptureError> {
        Err(CaptureError::Unsupported(
            "listing network adapters is only implemented on Windows",
        ))
    }
}

/// A fixed list, for tests and previews.
#[derive(Debug, Clone, Default)]
pub struct StaticInterfaces(pub Vec<InterfaceInfo>);

impl InterfaceProvider for StaticInterfaces {
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, CaptureError> {
        Ok(self.0.clone())
    }
}

/// Lists the adapters of this machine.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError> {
    SystemInterfaces.interfaces()
}

/// Finds the adapter an id refers to: its GUID (with or without braces and the `\Device\NPF_` prefix), its
/// friendly name (case-insensitive) or one of its addresses.
pub fn resolve_interface(
    id: &InterfaceId,
    provider: &dyn InterfaceProvider,
) -> Result<InterfaceInfo, CaptureError> {
    let wanted = id.as_str().trim();
    let bare = wanted
        .strip_prefix(NPF_PREFIX)
        .unwrap_or(wanted)
        .trim_matches(|c| c == '{' || c == '}');
    let as_ip = wanted.parse::<IpAddr>().ok().map(|a| a.to_canonical());
    provider
        .interfaces()?
        .into_iter()
        .find(|i| {
            i.id.0
                .trim_matches(|c| c == '{' || c == '}')
                .eq_ignore_ascii_case(bare)
                || i.name.eq_ignore_ascii_case(wanted)
                || as_ip.is_some_and(|ip| i.addrs.iter().any(|a| a.to_canonical() == ip))
        })
        .ok_or_else(|| CaptureError::InterfaceNotFound(wanted.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapters() -> StaticInterfaces {
        StaticInterfaces(vec![
            InterfaceInfo {
                id: InterfaceId("{AAAA-0001}".into()),
                name: "Ethernet".into(),
                description: "Red Hat VirtIO".into(),
                addrs: vec!["10.0.0.5".parse().unwrap(), "fe80::1".parse().unwrap()],
                up: true,
                loopback: false,
            },
            InterfaceInfo {
                id: InterfaceId("{BBBB-0002}".into()),
                name: "Loopback Pseudo-Interface 1".into(),
                description: String::new(),
                addrs: vec!["127.0.0.1".parse().unwrap()],
                up: true,
                loopback: true,
            },
        ])
    }

    fn resolve(text: &str) -> Result<InterfaceInfo, CaptureError> {
        resolve_interface(&InterfaceId::new(text), &adapters())
    }

    #[test]
    fn resolves_by_guid_device_name_friendly_name_and_address() {
        for text in [
            "{AAAA-0001}",
            "aaaa-0001",
            r"\Device\NPF_{AAAA-0001}",
            "ethernet",
            "10.0.0.5",
            "::ffff:10.0.0.5",
        ] {
            assert_eq!(resolve(text).unwrap().name, "Ethernet", "{text}");
        }
        assert!(resolve("127.0.0.1").unwrap().loopback);
    }

    #[test]
    fn unknown_interfaces_are_reported() {
        assert!(matches!(
            resolve("Wi-Fi"),
            Err(CaptureError::InterfaceNotFound(_))
        ));
        assert!(matches!(
            resolve("192.0.2.1"),
            Err(CaptureError::InterfaceNotFound(_))
        ));
    }

    #[test]
    fn npcap_device_name_wraps_the_guid() {
        assert_eq!(adapters().0[0].npcap_device(), r"\Device\NPF_{AAAA-0001}");
        assert_eq!(adapters().0[0].ipv4_addrs().count(), 1);
    }

    #[cfg(not(windows))]
    #[test]
    fn listing_is_unsupported_off_windows() {
        assert!(matches!(
            list_interfaces(),
            Err(CaptureError::Unsupported(_))
        ));
    }
}
