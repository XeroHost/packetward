// SPDX-License-Identifier: GPL-3.0-or-later
//! Diagnoses why the current user cannot open the agent's pipe, so the UI can say what to do.

use std::io;

use crate::pipe::OPERATORS_GROUP;
use crate::sys::windows::{
    account_sid_string, current_user_sid_string, local_group_has_member, token_has_group,
};

/// Why the pipe refused this user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessProblem {
    /// The operators group does not exist: the agent was not installed with it.
    GroupMissing,
    /// The group exists but this user is not a member. An administrator must add them.
    NotMember,
    /// The user was added to the group, but this session's token predates it. Windows only
    /// applies group membership at logon: the user must **sign out and back in** (disconnecting
    /// and reconnecting an RDP session is not enough).
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
