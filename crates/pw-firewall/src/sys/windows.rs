// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The real Windows Firewall backend: COM `INetFwPolicy2` (never `netsh`).
//!
//! Every call enters a COM apartment, creates the policy object, does its work and drops every
//! interface pointer before leaving the apartment, so the backend is stateless (`Send + Sync`) and
//! cannot leak COM references. Writes need an elevated process (the agent service runs as
//! LocalSystem); without it Windows answers `E_ACCESSDENIED`, which is returned as a normal error.
//!
//! The write paths of this module are exercised only on a machine that may be changed; the unit
//! tests of this crate use the fake backend.

#![allow(unsafe_code)]

use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, VARIANT_BOOL};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION,
    NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_RULE_DIRECTION, NET_FW_RULE_DIR_IN,
    NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IDispatch, CLSCTX_INPROC_SERVER,
    COINIT_MULTITHREADED,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VT_DISPATCH};

use crate::addr;
use crate::error::{FirewallError, Result};
use crate::manager::FirewallBackend;
use crate::model::{normalize_profiles, Action, Direction, Protocol, Rule};

/// HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND): `Rules.Item` for a name that does not exist.
const E_NOT_FOUND: u32 = 0x8007_0002;

fn backend_err(op: &'static str, error: &windows::core::Error) -> FirewallError {
    FirewallError::Backend {
        op,
        code: error.code().0 as u32,
        message: error.message(),
    }
}

/// Keeps COM initialized for the current thread; uninitializes on drop (only if this guard
/// initialized it).
struct ComApartment {
    initialized: bool,
}

impl ComApartment {
    fn enter() -> Result<Self> {
        // SAFETY: CoInitializeEx with a null reserved pointer has no preconditions; the matching
        // CoUninitialize is issued in Drop when (and only when) it succeeded.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_ok() {
            Ok(Self { initialized: true })
        } else if hr == RPC_E_CHANGED_MODE {
            // The thread already has an STA; use it and leave it alone.
            Ok(Self { initialized: false })
        } else {
            Err(backend_err(
                "CoInitializeEx",
                &windows::core::Error::from(hr),
            ))
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: balances the successful CoInitializeEx in `enter`; every COM pointer created
            // under this guard is declared after it and therefore already dropped.
            unsafe { CoUninitialize() };
        }
    }
}

/// Runs `f` with the policy's rule collection. All interface pointers are released before the
/// apartment guard (declared first, dropped last).
fn with_rules<T>(op: &'static str, f: impl FnOnce(&INetFwRules) -> Result<T>) -> Result<T> {
    let _apartment = ComApartment::enter()?;
    // SAFETY: plain COM activation of a registered in-process class with no aggregation.
    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(
            &NetFwPolicy2,
            None::<&windows::core::IUnknown>,
            CLSCTX_INPROC_SERVER,
        )
    }
    .map_err(|e| backend_err(op, &e))?;
    // SAFETY: `policy` is a live INetFwPolicy2.
    let rules = unsafe { policy.Rules() }.map_err(|e| backend_err(op, &e))?;
    f(&rules)
}

fn text(value: windows::core::Result<BSTR>) -> String {
    value.map(|b| b.to_string()).unwrap_or_default()
}

fn or_any(value: String) -> String {
    if value.trim().is_empty() {
        "*".to_owned()
    } else {
        value
    }
}

fn optional(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn read_rule(rule: &INetFwRule) -> Result<Rule> {
    let op = "read rule";
    // SAFETY (whole function): `rule` is a live INetFwRule; each getter only reads a property.
    unsafe {
        let name = rule.Name().map_err(|e| backend_err(op, &e))?.to_string();
        let direction = rule.Direction().map_err(|e| backend_err(op, &e))?;
        let action = rule.Action().map_err(|e| backend_err(op, &e))?;
        let enabled = rule.Enabled().map_err(|e| backend_err(op, &e))?.as_bool();
        Ok(Rule {
            name,
            description: text(rule.Description()),
            grouping: text(rule.Grouping()),
            direction: if direction == NET_FW_RULE_DIR_OUT {
                Direction::Outbound
            } else {
                Direction::Inbound
            },
            action: if action == NET_FW_ACTION_ALLOW {
                Action::Allow
            } else {
                Action::Block
            },
            enabled,
            protocol: Protocol::from_number(rule.Protocol().unwrap_or(256)),
            local_ports: or_any(text(rule.LocalPorts())),
            remote_ports: or_any(text(rule.RemotePorts())),
            local_addresses: or_any(text(rule.LocalAddresses())),
            remote_addresses: or_any(text(rule.RemoteAddresses())),
            application: optional(text(rule.ApplicationName())),
            service: optional(text(rule.ServiceName())),
            profiles: crate::model::normalize_profiles(
                rule.Profiles().unwrap_or(0x7FFF_FFFF) as u32
            ),
        })
    }
}

fn dispatch_to_rule(variant: &VARIANT) -> Option<INetFwRule> {
    // SAFETY: the union member is read only after checking the discriminant is VT_DISPATCH; the
    // pointer stays owned by the VARIANT (we only QueryInterface it, which AddRefs a new pointer).
    unsafe {
        let inner = &variant.Anonymous.Anonymous;
        if inner.vt != VT_DISPATCH {
            return None;
        }
        let dispatch: &Option<IDispatch> = &inner.Anonymous.pdispVal;
        dispatch.as_ref()?.cast::<INetFwRule>().ok()
    }
}

/// Calls `visit` for every rule; stops early when it returns `Ok(false)`.
fn for_each_rule(
    rules: &INetFwRules,
    mut visit: impl FnMut(&INetFwRule) -> Result<bool>,
) -> Result<()> {
    let op = "enumerate rules";
    // SAFETY: `rules` is a live INetFwRules; `_NewEnum` returns an IEnumVARIANT behind IUnknown.
    let unknown = unsafe { rules._NewEnum() }.map_err(|e| backend_err(op, &e))?;
    let enumerator: IEnumVARIANT = unknown.cast().map_err(|e| backend_err(op, &e))?;
    loop {
        let mut slot = [VARIANT::default()];
        let mut fetched = 0u32;
        // SAFETY: `slot` has room for the one element requested and `fetched` is a valid out
        // pointer. The VARIANT is cleared by its Drop impl.
        let hr = unsafe { enumerator.Next(&mut slot, &mut fetched) };
        if hr.is_err() {
            return Err(backend_err(op, &windows::core::Error::from(hr)));
        }
        if hr.0 != 0 || fetched == 0 {
            return Ok(()); // S_FALSE: no more elements
        }
        if let Some(rule) = dispatch_to_rule(&slot[0]) {
            if !visit(&rule)? {
                return Ok(());
            }
        }
    }
}

fn find_rule(rules: &INetFwRules, name: &str) -> Result<Option<INetFwRule>> {
    // SAFETY: `rules` is live; Item takes a BSTR name and returns an owned interface pointer.
    match unsafe { rules.Item(&BSTR::from(name)) } {
        Ok(rule) => Ok(Some(rule)),
        Err(e) if e.code().0 as u32 == E_NOT_FOUND => Ok(None),
        Err(e) => Err(backend_err("find rule", &e)),
    }
}

fn direction_value(d: Direction) -> NET_FW_RULE_DIRECTION {
    match d {
        Direction::Inbound => NET_FW_RULE_DIR_IN,
        Direction::Outbound => NET_FW_RULE_DIR_OUT,
    }
}

fn action_value(a: Action) -> NET_FW_ACTION {
    match a {
        Action::Allow => NET_FW_ACTION_ALLOW,
        Action::Block => NET_FW_ACTION_BLOCK,
    }
}

/// Writes `new` onto the COM rule. With `current` set, only properties that differ are touched (so
/// unmodelled properties of a foreign rule survive and no spurious write is made).
fn apply_fields(com: &INetFwRule, current: Option<&Rule>, new: &Rule) -> Result<()> {
    let op = "write rule";
    let fail = |e: windows::core::Error| backend_err(op, &e);
    let same_addr = |a: &str, b: &str| addr::windows_readback(a) == addr::windows_readback(b);
    // SAFETY (whole function): `com` is a live INetFwRule; each call sets one scalar/BSTR property.
    unsafe {
        if current.is_none() {
            com.SetName(&BSTR::from(new.name.as_str())).map_err(fail)?;
        }
        if current.is_none_or(|c| c.description != new.description) {
            com.SetDescription(&BSTR::from(new.description.as_str()))
                .map_err(fail)?;
        }
        if current.is_none_or(|c| c.grouping != new.grouping) {
            com.SetGrouping(&BSTR::from(new.grouping.as_str()))
                .map_err(fail)?;
        }
        if current.is_none_or(|c| c.direction != new.direction) {
            com.SetDirection(direction_value(new.direction))
                .map_err(fail)?;
        }
        if current.is_none_or(|c| c.action != new.action) {
            com.SetAction(action_value(new.action)).map_err(fail)?;
        }
        // Ports are only valid with TCP/UDP: widen them before dropping the protocol, narrow them
        // after setting it.
        let ports_changed = current
            .is_none_or(|c| c.local_ports != new.local_ports || c.remote_ports != new.remote_ports);
        let protocol_changed = current.is_none_or(|c| c.protocol != new.protocol);
        let set_ports = |com: &INetFwRule| -> Result<()> {
            if ports_changed && (current.is_some() || !addr::ports_any(&new.local_ports)) {
                com.SetLocalPorts(&BSTR::from(new.local_ports.as_str()))
                    .map_err(fail)?;
            }
            if ports_changed && (current.is_some() || !addr::ports_any(&new.remote_ports)) {
                com.SetRemotePorts(&BSTR::from(new.remote_ports.as_str()))
                    .map_err(fail)?;
            }
            Ok(())
        };
        if new.protocol.has_ports() {
            if protocol_changed {
                com.SetProtocol(new.protocol.number()).map_err(fail)?;
            }
            set_ports(com)?;
        } else {
            set_ports(com)?;
            if protocol_changed {
                com.SetProtocol(new.protocol.number()).map_err(fail)?;
            }
        }
        if current.is_none_or(|c| !same_addr(&c.local_addresses, &new.local_addresses)) {
            com.SetLocalAddresses(&BSTR::from(new.local_addresses.as_str()))
                .map_err(fail)?;
        }
        if current.is_none_or(|c| !same_addr(&c.remote_addresses, &new.remote_addresses)) {
            com.SetRemoteAddresses(&BSTR::from(new.remote_addresses.as_str()))
                .map_err(fail)?;
        }
        if current.is_none_or(|c| c.application != new.application) {
            com.SetApplicationName(&BSTR::from(new.application.as_deref().unwrap_or("")))
                .map_err(fail)?;
        }
        if current.is_none_or(|c| c.service != new.service) {
            com.SetServiceName(&BSTR::from(new.service.as_deref().unwrap_or("")))
                .map_err(fail)?;
        }
        if current
            .is_none_or(|c| normalize_profiles(c.profiles) != normalize_profiles(new.profiles))
        {
            com.SetProfiles(new.profiles as i32).map_err(fail)?;
        }
        if current.is_none_or(|c| c.enabled != new.enabled) {
            com.SetEnabled(VARIANT_BOOL::from(new.enabled))
                .map_err(fail)?;
        }
    }
    Ok(())
}

/// The Windows Firewall of this machine. Stateless; create as many as you like.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsFirewall;

impl WindowsFirewall {
    pub fn new() -> Self {
        Self
    }
}

impl FirewallBackend for WindowsFirewall {
    fn list_rules(&self, group: Option<&str>) -> Result<Vec<Rule>> {
        with_rules("list rules", |rules| {
            let mut out = Vec::new();
            for_each_rule(rules, |com| {
                if let Some(group) = group {
                    // SAFETY: live INetFwRule; reading one property to skip rules cheaply.
                    let grouping = text(unsafe { com.Grouping() });
                    if !grouping.eq_ignore_ascii_case(group) {
                        return Ok(true);
                    }
                }
                out.push(read_rule(com)?);
                Ok(true)
            })?;
            Ok(out)
        })
    }

    fn get_rule(&self, name: &str) -> Result<Option<Rule>> {
        with_rules("get rule", |rules| match find_rule(rules, name)? {
            Some(com) => read_rule(&com).map(Some),
            None => Ok(None),
        })
    }

    fn add_rule(&self, rule: &Rule) -> Result<()> {
        with_rules("add rule", |rules| {
            if find_rule(rules, &rule.name)?.is_some() {
                return Err(FirewallError::AlreadyExists(rule.name.clone()));
            }
            // SAFETY: plain COM activation of the registered NetFwRule class.
            let com: INetFwRule = unsafe {
                CoCreateInstance(
                    &NetFwRule,
                    None::<&windows::core::IUnknown>,
                    CLSCTX_INPROC_SERVER,
                )
            }
            .map_err(|e| backend_err("add rule", &e))?;
            apply_fields(&com, None, rule)?;
            // SAFETY: `rules` and `com` are live; Add stores a reference to the finished rule.
            unsafe { rules.Add(&com) }.map_err(|e| backend_err("add rule", &e))
        })
    }

    fn update_rule(&self, name: &str, rule: &Rule) -> Result<()> {
        with_rules("update rule", |rules| {
            let com =
                find_rule(rules, name)?.ok_or_else(|| FirewallError::NotFound(name.to_owned()))?;
            let current = read_rule(&com)?;
            apply_fields(&com, Some(&current), rule)
        })
    }

    fn remove_rule(&self, name: &str) -> Result<()> {
        with_rules("remove rule", |rules| {
            if find_rule(rules, name)?.is_none() {
                return Err(FirewallError::NotFound(name.to_owned()));
            }
            // SAFETY: `rules` is live; Remove takes the rule name.
            unsafe { rules.Remove(&BSTR::from(name)) }.map_err(|e| backend_err("remove rule", &e))
        })
    }

    fn set_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        with_rules("set enabled", |rules| {
            let com =
                find_rule(rules, name)?.ok_or_else(|| FirewallError::NotFound(name.to_owned()))?;
            // SAFETY: `com` is a live INetFwRule.
            unsafe { com.SetEnabled(VARIANT_BOOL::from(enabled)) }
                .map_err(|e| backend_err("set enabled", &e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only smoke test against the real firewall: lists rules, writes nothing. Run on purpose:
    /// `PW_FIREWALL_SMOKE=1 cargo test -p pw-firewall -- --ignored smoke_list --nocapture`
    #[test]
    #[ignore = "touches the real Windows Firewall (read-only); needs PW_FIREWALL_SMOKE=1"]
    fn smoke_list_rules_is_read_only() {
        if std::env::var("PW_FIREWALL_SMOKE").as_deref() != Ok("1") {
            return;
        }
        let rules = WindowsFirewall::new()
            .list_rules(None)
            .expect("listing rules (read-only)");
        let pw = rules.iter().filter(|r| r.is_managed()).count();
        println!("rules: {} total, {pw} in group PacketWard", rules.len());
        for r in rules.iter().filter(|r| {
            r.grouping.to_lowercase().contains("remote desktop")
                || r.name.to_lowercase().contains("remote desktop")
                || r.grouping.contains("28752")
        }) {
            println!(
                "  name={:?} group={:?} dir={:?} action={:?} enabled={} proto={:?} lport={:?} builtin_rdp={}",
                r.name,
                r.grouping,
                r.direction,
                r.action,
                r.enabled,
                r.protocol,
                r.local_ports,
                crate::guard::is_builtin_rdp_rule(r)
            );
        }
        assert!(!rules.is_empty());
    }
}
