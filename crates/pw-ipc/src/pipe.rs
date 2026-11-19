// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows named-pipe transport with a restricted ACL.

use std::io;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};

use crate::server::Listener;
use crate::sys::windows::{create_pipe_instance, SecurityDescriptor};

/// The pipe the agent listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\packetward";

/// Local group whose members may use the pipe without being administrators. Created by the
/// agent installer. Group membership (unlike the Administrators group) is not filtered by UAC,
/// so an unelevated desktop app of a member can connect.
pub const OPERATORS_GROUP: &str = "PacketWard Operators";

const ERROR_PIPE_BUSY: i32 = 231;
const BUSY_RETRY: Duration = Duration::from_millis(50);
const BUSY_ATTEMPTS: u32 = 40;

/// SDDL for the pipe: SYSTEM and Administrators get full control, plus read/write for the
/// operators group when its SID is known. Nobody else gets any access (protected DACL).
pub fn pipe_sddl(operators_sid: Option<&str>) -> String {
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    if let Some(sid) = operators_sid {
        sddl.push_str(&format!("(A;;GRGW;;;{sid})"));
    }
    sddl
}

/// Accepts connections on a named pipe. Each accepted client gets its own server instance; a
/// fresh instance is created right away so the next client can connect.
pub struct PipeListener {
    name: String,
    descriptor: SecurityDescriptor,
    waiting: NamedPipeServer,
}

impl PipeListener {
    /// Creates the first pipe instance. Fails if another process already owns the pipe name.
    pub fn bind(name: &str, sddl: &str) -> io::Result<Self> {
        let descriptor = SecurityDescriptor::from_sddl(sddl)?;
        let waiting = create_pipe_instance(name, &descriptor, true)?;
        Ok(Self {
            name: name.to_owned(),
            descriptor,
            waiting,
        })
    }
}

impl Listener for PipeListener {
    type Stream = NamedPipeServer;

    async fn accept(&mut self) -> io::Result<NamedPipeServer> {
        self.waiting.connect().await?;
        // A client arriving between the line above and this one sees ERROR_PIPE_BUSY and retries.
        let next = create_pipe_instance(&self.name, &self.descriptor, false)?;
        Ok(std::mem::replace(&mut self.waiting, next))
    }
}

/// Opens the pipe as a client, retrying briefly while every instance is busy.
///
/// Errors worth telling apart for the user: `NotFound` (the agent is not running),
/// `PermissionDenied` (the pipe ACL does not admit this user).
pub async fn connect(name: &str) -> io::Result<NamedPipeClient> {
    let mut attempts = 0;
    loop {
        match ClientOptions::new().open(name) {
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
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
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
        async fn handle(&self, _m: &str, payload: Value) -> Result<Value, pw_proto::ErrorPayload> {
            Ok(payload)
        }
        async fn subscribe(&self, topic: &str) -> Result<EventReceiver, pw_proto::ErrorPayload> {
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
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-1-2-3-1001)"
        );
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
    async fn a_user_not_in_the_acl_is_denied() {
        // Same restricted token, but the ACL names an unrelated SID and no Administrators ACE.
        let name = unique_name();
        let _listener =
            PipeListener::bind(&name, "D:P(A;;GA;;;SY)(A;;GRGW;;;S-1-5-21-1-2-3-4242)").unwrap();
        let name_for_thread = name.clone();
        let result =
            test_support::run_without_administrators(move || open_blocking(&name_for_thread));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}
