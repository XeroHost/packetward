// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows named-pipe transport with a restricted ACL.

use std::io;
use std::time::Duration;

use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer};

use crate::server::Listener;
use crate::sys::windows::{create_pipe_instance, open_client, SecurityDescriptor};

/// The pipe the agent listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\packetward";

/// Local group whose members may use the pipe without being administrators. Created by the
/// agent installer. Group membership (unlike the Administrators group) is not filtered by UAC,
/// so an unelevated desktop app of a member can connect.
pub const OPERATORS_GROUP: &str = "PacketWard Operators";

const ERROR_PIPE_BUSY: i32 = 231;
const BUSY_RETRY: Duration = Duration::from_millis(50);
const BUSY_ATTEMPTS: u32 = 40;
const INSTANCE_RETRY: Duration = Duration::from_secs(1);

/// What a client asks for when opening the pipe: FILE_READ_DATA | FILE_WRITE_DATA |
/// FILE_READ_ATTRIBUTES | SYNCHRONIZE. Deliberately **not** GENERIC_WRITE: that would include
/// FILE_APPEND_DATA, which on a pipe means FILE_CREATE_PIPE_INSTANCE.
pub const CLIENT_ACCESS: u32 = 0x0010_0083;
/// Rights granted to the operators group: the client rights plus READ_CONTROL.
const OPERATOR_ACE_MASK: u32 = CLIENT_ACCESS | 0x0002_0000;

/// SDDL for the pipe: SYSTEM and Administrators get full control; the operators group (when its
/// SID is known) gets exactly the rights needed to talk to the agent. Nobody else gets any access
/// (protected DACL).
///
/// Operators must not get FILE_CREATE_PIPE_INSTANCE: with it, a member could create extra
/// instances of the pipe and answer clients in place of the agent.
pub fn pipe_sddl(operators_sid: Option<&str>) -> String {
    pipe_sddl_with_members(operators_sid, &[])
}

/// Like [`pipe_sddl`], plus one ACE with the same rights for each member's own SID.
///
/// Windows puts a group in a token only when the token is created (at sign-in), so the group ACE
/// alone leaves a user who was added to the group during their current session locked out until
/// they sign out and back in. The member's own SID is in the token they already have. Members have
/// the same trust as the group, so this grants nobody anything new; an entry that is not a plain
/// SID is ignored rather than put into the descriptor text.
pub fn pipe_sddl_with_members(operators_sid: Option<&str>, member_sids: &[String]) -> String {
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    if let Some(sid) = operators_sid {
        sddl.push_str(&format!("(A;;0x{OPERATOR_ACE_MASK:x};;;{sid})"));
    }
    for sid in member_sids.iter().filter(|sid| is_plain_sid(sid)) {
        if operators_sid.is_some_and(|group| group.eq_ignore_ascii_case(sid)) {
            continue;
        }
        sddl.push_str(&format!("(A;;0x{OPERATOR_ACE_MASK:x};;;{sid})"));
    }
    sddl
}

fn is_plain_sid(sid: &str) -> bool {
    sid.starts_with("S-1-")
        && sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
}

/// Accepts connections on a named pipe. Each accepted client gets its own server instance; a
/// fresh instance is created right away so the next client can connect.
///
/// Transient trouble (a client that vanishes mid-connect, a failure to create the next instance)
/// costs at most one connection and is retried: the listener never gives up on its own, because
/// the agent without its pipe is unreachable but would still look "running" to Windows.
pub struct PipeListener {
    name: String,
    descriptor: SecurityDescriptor,
    /// The instance clients currently connect to. `None` only while a replacement is being created.
    waiting: Option<NamedPipeServer>,
}

impl PipeListener {
    /// Creates the first pipe instance. Fails if another process already owns the pipe name.
    pub fn bind(name: &str, sddl: &str) -> io::Result<Self> {
        let descriptor = SecurityDescriptor::from_sddl(sddl)?;
        let waiting = create_pipe_instance(name, &descriptor, true)?;
        Ok(Self {
            name: name.to_owned(),
            descriptor,
            waiting: Some(waiting),
        })
    }
}

impl Listener for PipeListener {
    type Stream = NamedPipeServer;

    async fn accept(&mut self) -> io::Result<NamedPipeServer> {
        loop {
            let instance = match self.waiting.take() {
                Some(instance) => instance,
                None => match create_pipe_instance(&self.name, &self.descriptor, false) {
                    Ok(instance) => instance,
                    Err(err) => {
                        tracing::warn!(%err, "could not create a pipe instance; retrying");
                        tokio::time::sleep(INSTANCE_RETRY).await;
                        continue;
                    }
                },
            };
            match instance.connect().await {
                Ok(()) => {
                    // Create the next instance before handing this one out, so the pipe name never
                    // has zero instances (that would let another process take the name). A client
                    // arriving in between sees ERROR_PIPE_BUSY and retries.
                    match create_pipe_instance(&self.name, &self.descriptor, false) {
                        Ok(next) => self.waiting = Some(next),
                        Err(err) => {
                            tracing::warn!(%err, "could not create the next pipe instance; will retry")
                        }
                    }
                    return Ok(instance);
                }
                Err(err) => {
                    tracing::debug!(%err, "a client left before the connection completed");
                    // Replace the broken instance first, then drop it, for the same reason as above.
                    self.waiting = create_pipe_instance(&self.name, &self.descriptor, false).ok();
                    drop(instance);
                    if self.waiting.is_none() {
                        tokio::time::sleep(INSTANCE_RETRY).await;
                    }
                }
            }
        }
    }
}

/// Opens the pipe as a client, retrying briefly while every instance is busy.
///
/// Errors worth telling apart for the user: `NotFound` (the agent is not running),
/// `PermissionDenied` (the pipe ACL does not admit this user).
pub async fn connect(name: &str) -> io::Result<NamedPipeClient> {
    let mut attempts = 0;
    loop {
        match open_client(name) {
            Ok(client) => return Ok(client),
            Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < BUSY_ATTEMPTS => {
                attempts += 1;
                tokio::time::sleep(BUSY_RETRY).await;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use pw_proto::ClientKind;
    use serde_json::{json, Value};
    use tokio::sync::mpsc;

    use super::*;
    use crate::sys::windows::{current_user_sid_string, test_support, token_has_group};
    use crate::{serve, Client, EventReceiver, Handler};

    fn unique_name() -> String {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        format!(
            r"\\.\pipe\packetward-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        )
    }

    /// Opens the pipe with plain blocking file APIs from the calling thread, so the thread's
    /// token is what the ACL is checked against.
    fn open_blocking(name: &str) -> io::Result<std::fs::File> {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .access_mode(CLIENT_ACCESS)
            .open(name)
    }

    struct Echo;
    impl Handler for Echo {
        fn hello(&self) -> pw_proto::HelloResponse {
            pw_proto::HelloResponse {
                agent_version: "test".into(),
                protocol_major: pw_proto::PROTOCOL_MAJOR,
                protocol_minor: 0,
            }
        }
        async fn handle(
            &self,
            _ctx: crate::ConnCtx,
            _m: &str,
            payload: Value,
        ) -> Result<Value, pw_proto::ErrorPayload> {
            Ok(payload)
        }
        async fn subscribe(
            &self,
            _ctx: crate::ConnCtx,
            topic: &str,
        ) -> Result<EventReceiver, pw_proto::ErrorPayload> {
            let (_tx, rx) = mpsc::channel(1);
            let _ = topic;
            Ok(rx)
        }
    }

    #[test]
    fn sddl_has_system_admins_and_optionally_the_group() {
        assert_eq!(pipe_sddl(None), "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert_eq!(
            pipe_sddl(Some("S-1-5-21-1-2-3-1001")),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120083;;;S-1-5-21-1-2-3-1001)"
        );
    }

    #[test]
    fn sddl_adds_the_members_own_sids_with_the_same_rights() {
        let group = "S-1-5-21-1-2-3-1001";
        let members = vec![
            "S-1-5-21-1-2-3-1500".to_string(),
            "S-1-5-21-1-2-3-1001".to_string(), // the group itself: not repeated
            "S-1-5-21-1-2-3-1500)(A;;GA;;;WD".to_string(), // not a plain SID: ignored
        ];
        assert_eq!(
            pipe_sddl_with_members(Some(group), &members),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120083;;;S-1-5-21-1-2-3-1001)\
             (A;;0x120083;;;S-1-5-21-1-2-3-1500)"
        );
        assert_eq!(pipe_sddl_with_members(None, &[]), pipe_sddl(None));
    }

    #[tokio::test]
    async fn a_second_listener_cannot_squat_the_pipe_name() {
        let name = unique_name();
        let _first = PipeListener::bind(&name, &pipe_sddl(None)).unwrap();
        assert!(PipeListener::bind(&name, &pipe_sddl(None)).is_err());
    }

    #[tokio::test]
    async fn requests_work_over_a_real_named_pipe() {
        let name = unique_name();
        let listener = PipeListener::bind(&name, &pipe_sddl(None)).unwrap();
        tokio::spawn(serve(listener, Arc::new(Echo), std::future::pending()));
        for round in 0..3 {
            // Several sequential clients prove new instances are created after each accept.
            let stream = connect(&name).await.unwrap();
            let client = Client::connect(stream, ClientKind::Pwctl, "test")
                .await
                .unwrap();
            let echoed: Value = client.request("echo", &json!(round)).await.unwrap();
            assert_eq!(echoed, json!(round));
        }
    }

    #[tokio::test]
    async fn a_client_that_vanishes_before_accept_does_not_stop_the_listener() {
        // A client that opens the pipe and closes it again before the server calls connect() leaves
        // the waiting instance in a broken state. That must cost one connection, not the whole IPC.
        let name = unique_name();
        let listener = PipeListener::bind(&name, &pipe_sddl(None)).unwrap();
        drop(open_blocking(&name).unwrap());
        let server = tokio::spawn(serve(listener, Arc::new(Echo), std::future::pending()));

        let stream = connect(&name).await.unwrap();
        let client = Client::connect(stream, ClientKind::Pwctl, "test")
            .await
            .unwrap();
        let echoed: Value = client.request("echo", &json!(1)).await.unwrap();
        assert_eq!(echoed, json!(1));
        assert!(!server.is_finished(), "the listener must still be running");
    }

    #[tokio::test]
    async fn a_missing_pipe_is_not_found() {
        let err = connect(&unique_name()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn the_restricted_token_really_loses_administrators() {
        // Guards the other tests: they only mean something if the simulation works.
        let admin_in_process = token_has_group(test_support::BUILTIN_ADMINISTRATORS).unwrap();
        let admin_in_thread = test_support::run_without_administrators(|| {
            token_has_group(test_support::BUILTIN_ADMINISTRATORS).unwrap()
        });
        if admin_in_process {
            assert!(
                !admin_in_thread,
                "Administrators must be deny-only in the restricted thread"
            );
        }
    }

    #[tokio::test]
    async fn an_administrators_only_acl_locks_out_an_unelevated_admin() {
        // Documents why the ACL also needs the operators group: with SYSTEM + Administrators
        // alone, an administrator whose token is not elevated cannot open the pipe.
        let name = unique_name();
        let _listener = PipeListener::bind(&name, &pipe_sddl(None)).unwrap();
        let is_admin = token_has_group(test_support::BUILTIN_ADMINISTRATORS).unwrap();
        if !is_admin {
            return; // nothing to demonstrate for a non-admin runner
        }
        assert!(open_blocking(&name).is_ok(), "elevated admin is admitted");
        let name_for_thread = name.clone();
        let result =
            test_support::run_without_administrators(move || open_blocking(&name_for_thread));
        let err = result.expect_err("an unelevated admin must be denied");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn a_group_ace_admits_the_unelevated_token() {
        // The user's own SID stands in for "PacketWard Operators": ordinary SIDs stay enabled in a
        // restricted token, which is why group membership works where Administrators does not.
        let name = unique_name();
        let user = current_user_sid_string().unwrap();
        let _listener = PipeListener::bind(&name, &pipe_sddl(Some(&user))).unwrap();
        let name_for_thread = name.clone();
        let result =
            test_support::run_without_administrators(move || open_blocking(&name_for_thread));
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[tokio::test]
    async fn an_operator_cannot_create_extra_pipe_instances() {
        // With FILE_CREATE_PIPE_INSTANCE an operator could stand up a second server on the same
        // name and answer clients in place of the agent.
        let name = unique_name();
        let user = current_user_sid_string().unwrap();
        let _listener = PipeListener::bind(&name, &pipe_sddl(Some(&user))).unwrap();
        let name_for_thread = name.clone();
        let attempt = test_support::run_without_administrators(move || {
            // The runtime is needed only because tokio pipe servers register with a reactor.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                tokio::net::windows::named_pipe::ServerOptions::new()
                    .first_pipe_instance(false)
                    .create(&name_for_thread)
                    .map(|_| ())
            })
        });
        assert_eq!(attempt.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    // Multi-threaded: the test blocks its own thread while the restricted-token thread runs, and the
    // server task must keep being polled meanwhile.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_real_client_connects_with_the_narrow_access_mask() {
        // End to end through `connect`, as an unelevated administrator with only the group ACE.
        let name = unique_name();
        let user = current_user_sid_string().unwrap();
        let listener = PipeListener::bind(&name, &pipe_sddl(Some(&user))).unwrap();
        tokio::spawn(serve(listener, Arc::new(Echo), std::future::pending()));
        let name_for_thread = name.clone();
        let echoed = test_support::run_without_administrators(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let stream = connect(&name_for_thread).await?;
                let client = Client::connect(stream, ClientKind::Pwctl, "test")
                    .await
                    .unwrap();
                let echoed: Value = client.request("echo", &json!(42)).await.unwrap();
                io::Result::Ok(echoed)
            })
        });
        assert_eq!(echoed.unwrap(), json!(42));
    }

    #[tokio::test]
    async fn a_user_not_in_the_acl_is_denied() {
        // Same restricted token, but the ACL names an unrelated SID and no Administrators ACE.
        let name = unique_name();
        let _listener =
            PipeListener::bind(&name, "D:P(A;;GA;;;SY)(A;;0x120083;;;S-1-5-21-1-2-3-4242)")
                .unwrap();
        let name_for_thread = name.clone();
        let result =
            test_support::run_without_administrators(move || open_blocking(&name_for_thread));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}
