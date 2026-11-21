// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Which interfaces are "real adapters" whose traffic counts toward the totals.
//!
//! Windows lists several rows per physical NIC (filter and QoS layers, loopback, tunnels), so
//! summing every row over-counts. VPN adapters are shown in the per-adapter breakdown but never
//! summed: their traffic is already carried by a real adapter underneath.

use pw_proto::InterfaceKind;

use crate::{if_type, InterfaceSample};

/// Substrings (lower case) of names/descriptions that mark a software tunnel or virtual adapter.
const TUNNEL_MARKERS: &[&str] = &[
    "wireguard",
    "wintun",
    "zerotier",
    "radmin",
    "tap-windows",
    "tap-win",
    "openvpn",
    "tailscale",
    "nordlynx",
    "hamachi",
    "tunnel",
    "teredo",
    "isatap",
    "6to4",
    "vpn",
    "wan miniport",
    "pseudo-interface",
    "ppp",
];

fn looks_like_tunnel(sample: &InterfaceSample) -> bool {
    let text = format!("{} {}", sample.name, sample.description).to_lowercase();
    TUNNEL_MARKERS.iter().any(|marker| text.contains(marker))
}

pub fn classify_kind(sample: &InterfaceSample) -> InterfaceKind {
    if sample.if_type == if_type::LOOPBACK {
        return InterfaceKind::Loopback;
    }
    if sample.if_type == if_type::TUNNEL || looks_like_tunnel(sample) {
        return InterfaceKind::Tunnel;
    }
    match sample.if_type {
        if_type::ETHERNET => InterfaceKind::Ethernet,
        if_type::IEEE80211 => InterfaceKind::Wireless,
        _ => InterfaceKind::Other,
    }
}

/// A real adapter: Ethernet or Wi-Fi, up, not a filter layer, and either a hardware NIC with a
/// connector or an adapter that carries a default route.
///
/// The second branch matters on KVM/virtio guests and other virtual NICs: Windows does not always
/// flag them as hardware, but they hold the default gateway.
pub fn counts_toward_total(sample: &InterfaceSample, kind: InterfaceKind) -> bool {
    sample.oper_up
        && !sample.filter
        && matches!(kind, InterfaceKind::Ethernet | InterfaceKind::Wireless)
        && ((sample.hardware && sample.connector_present) || sample.has_default_gateway)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Counters;

    fn sample(name: &str, description: &str, if_type: u32) -> InterfaceSample {
        InterfaceSample {
            index: 1,
            name: name.into(),
            description: description.into(),
            if_type,
            oper_up: true,
            hardware: true,
            filter: false,
            connector_present: true,
            has_default_gateway: true,
            link_speed_bps: 1_000_000_000,
            counters: Counters::default(),
        }
    }

    fn counted(s: &InterfaceSample) -> bool {
        counts_toward_total(s, classify_kind(s))
    }

    #[test]
    fn a_physical_ethernet_nic_counts() {
        assert!(counted(&sample(
            "Ethernet",
            "Intel(R) I350 Gigabit",
            if_type::ETHERNET
        )));
    }

    #[test]
    fn a_virtio_nic_without_the_hardware_flag_counts_because_it_has_the_gateway() {
        let mut nic = sample(
            "Ethernet",
            "Red Hat VirtIO Ethernet Adapter",
            if_type::ETHERNET,
        );
        nic.hardware = false;
        nic.connector_present = false;
        assert!(counted(&nic));
    }

    #[test]
    fn a_virtual_nic_with_neither_hardware_nor_gateway_does_not_count() {
        let mut nic = sample(
            "vEthernet (Internal)",
            "Hyper-V Virtual Ethernet Adapter",
            if_type::ETHERNET,
        );
        nic.hardware = false;
        nic.has_default_gateway = false;
        assert!(!counted(&nic));
    }

    #[test]
    fn a_hardware_nic_without_a_gateway_still_counts() {
        let mut nic = sample("Ethernet 2", "Intel(R) I350 Gigabit", if_type::ETHERNET);
        nic.has_default_gateway = false;
        assert!(counted(&nic));
    }

    #[test]
    fn loopback_filter_layers_and_down_interfaces_do_not_count() {
        assert!(!counted(&sample(
            "Loopback Pseudo-Interface 1",
            "Software Loopback",
            if_type::LOOPBACK
        )));

        let mut filter = sample(
            "Ethernet-QoS Packet Scheduler-0000",
            "Intel(R) I350-QoS Packet Scheduler",
            if_type::ETHERNET,
        );
        filter.filter = true;
        assert!(!counted(&filter));

        let mut down = sample("Ethernet 3", "Intel(R) I350", if_type::ETHERNET);
        down.oper_up = false;
        assert!(!counted(&down));
    }

    #[test]
    fn vpn_and_tunnel_adapters_are_shown_but_never_summed() {
        for (name, description, kind) in [
            ("WireGuard", "WireGuard Tunnel", if_type::ETHERNET),
            (
                "ZeroTier One [8056c2e21c000001]",
                "ZeroTier Virtual Port",
                if_type::ETHERNET,
            ),
            (
                "Radmin VPN",
                "Famatech Radmin VPN Ethernet Adapter",
                if_type::ETHERNET,
            ),
            (
                "Local Area Connection",
                "TAP-Windows Adapter V9",
                if_type::ETHERNET,
            ),
            ("Tailscale", "Tailscale Tunnel", if_type::TUNNEL),
            (
                "Teredo Tunneling Pseudo-Interface",
                "Teredo Tunneling Pseudo-Interface",
                if_type::TUNNEL,
            ),
        ] {
            let adapter = sample(name, description, kind);
            assert_eq!(classify_kind(&adapter), InterfaceKind::Tunnel, "{name}");
            assert!(!counted(&adapter), "{name} must not be summed");
        }
    }

    #[test]
    fn wifi_is_classified_and_counted() {
        let wifi = sample("Wi-Fi", "Intel(R) Wi-Fi 6 AX201", if_type::IEEE80211);
        assert_eq!(classify_kind(&wifi), InterfaceKind::Wireless);
        assert!(counted(&wifi));
    }

    #[test]
    fn unknown_types_are_other_and_not_counted() {
        let other = sample("Cellular", "Mobile Broadband", 243);
        assert_eq!(classify_kind(&other), InterfaceKind::Other);
        assert!(!counted(&other));
    }
}
