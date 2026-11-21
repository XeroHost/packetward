// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Who may use the agent's pipe: the `PacketWard Operators` local group, plus diagnosis of why a
//! user was refused so the UI can say what to do.

use std::io;

use crate::pipe::OPERATORS_GROUP;
use crate::sys::windows::{
    account_sid_string, current_user_sid_string, local_group_add, local_group_add_member,
    local_group_delete, local_group_has_member, local_group_member_sids, local_group_remove_member,
    token_has_group,
};

/// Why the pipe refused this user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessProblem {
    /// The operators group does not exist: the agent was not installed with it.
    GroupMissing,
    /// The group exists but this user is not a member. An administrator must add them.
    NotMember,
    /// The user is in the group but still cannot connect: either the agent was started before the
    /// user was added (it puts the members' own SIDs in the pipe ACL when it starts; restart the
    /// service) or, for an agent that predates that, this session's token predates the membership
    /// and the user must **sign out and back in** (disconnecting and reconnecting an RDP session
    /// is not enough).
    SignOutRequired,
    /// Member and the token has the group, yet access was denied: something else is wrong.
    Unexplained,
}

/// Call after the pipe open returned `PermissionDenied`.
pub fn diagnose() -> io::Result<AccessProblem> {
    let Some(group_sid) = account_sid_string(OPERATORS_GROUP)? else {
        return Ok(AccessProblem::GroupMissing);
    };
    if token_has_group(&group_sid)? {
        return Ok(AccessProblem::Unexplained);
    }
    let user = current_user_sid_string()?;
    match local_group_has_member(OPERATORS_GROUP, &user)? {
        None => Ok(AccessProblem::GroupMissing),
        Some(true) => Ok(AccessProblem::SignOutRequired),
        Some(false) => Ok(AccessProblem::NotMember),
    }
}

/// SID of the operators group, if it exists. Used to build the pipe ACL.
pub fn operators_group_sid() -> io::Result<Option<String>> {
    account_sid_string(OPERATORS_GROUP)
}

/// SIDs of the current members of the operators group (empty when the group does not exist).
/// The agent puts each one in the pipe ACL next to the group itself: an ACE for the user's own SID
/// matches the token they already have, so a member added during the current session can connect
/// without signing out (the group ACE only matches tokens created after the membership change).
pub fn operator_member_sids() -> io::Result<Vec<String>> {
    Ok(local_group_member_sids(OPERATORS_GROUP)?.unwrap_or_default())
}

/// SID string of the user running this process.
pub fn current_user_sid() -> io::Result<String> {
    current_user_sid_string()
}

/// SID string of a local or domain account name (`user` or `DOMAIN\user`).
pub fn account_sid(account: &str) -> io::Result<Option<String>> {
    account_sid_string(account)
}

/// Creates the operators group if needed. Returns `true` when it was created. Needs admin.
pub fn create_operators_group() -> io::Result<bool> {
    local_group_add(
        OPERATORS_GROUP,
        "Members may use the PacketWard desktop app and pwctl without being administrators.",
    )
}

/// Adds a user SID to the operators group. Returns `true` when it was added. Needs admin.
pub fn add_operator(sid: &str) -> io::Result<bool> {
    local_group_add_member(OPERATORS_GROUP, sid)
}

/// Removes a user SID from the operators group. Returns `true` when it was removed.
pub fn remove_operator(sid: &str) -> io::Result<bool> {
    local_group_remove_member(OPERATORS_GROUP, sid)
}

/// Deletes the operators group (members are not touched). Returns `true` when it existed.
pub fn delete_operators_group() -> io::Result<bool> {
    local_group_delete(OPERATORS_GROUP)
}
