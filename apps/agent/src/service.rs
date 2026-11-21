// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Command line, Windows service entry point and service management (install / uninstall / start /
//! stop / repair) through the service control manager API. No `sc.exe`.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use pw_ipc::access;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::{host, logging};

pub use pw_ipc::scm::SERVICE_NAME;
const DISPLAY_NAME: &str = "PacketWard Agent";
const DESCRIPTION: &str =
    "PacketWard network defense and diagnostics agent. Required by the PacketWard desktop app.";
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_ACCESS_DENIED: i32 = 5;
const STATE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Parser)]
#[command(
    name = "packetward-agent",
    version,
    about = "PacketWard agent: Windows service host"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent. Without --console this is the service entry point, started by Windows.
    Run {
        /// Run in this terminal instead of as a service (development; needs an elevated shell).
        #[arg(long)]
        console: bool,
        /// Do not start the live capture (development: to measure the agent without it).
        #[arg(long, requires = "console")]
        no_capture: bool,
    },
    /// Register the service, create the operators group and start the agent. Needs administrator.
    Install {
        /// SID of the user to add to "PacketWard Operators" (default: the user running this).
        #[arg(long)]
        operator_sid: Option<String>,
        /// Register without starting.
        #[arg(long)]
        no_start: bool,
    },
    /// Stop and remove the service and the operators group. Needs administrator.
    Uninstall,
    /// Start the service.
    Start,
    /// Stop the service.
    Stop,
    /// Make the installation consistent again (group, member, service) and start it.
    Repair {
        /// SID of the user to (re-)add to "PacketWard Operators".
        #[arg(long)]
        operator_sid: Option<String>,
    },
}

pub fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Run {
            console: true,
            no_capture,
        } => run_console(!no_capture),
        Command::Run { console: false, .. } => run_as_service(),
        Command::Install {
            operator_sid,
            no_start,
        } => admin_only(|| install(operator_sid, !no_start)),
        Command::Uninstall => admin_only(uninstall),
        Command::Start => {
            admin_only(|| start_service().map(|()| println!("PacketWard service started.")))
        }
        Command::Stop => {
            admin_only(|| stop_service().map(|()| println!("PacketWard service stopped.")))
        }
        Command::Repair { operator_sid } => admin_only(|| repair(operator_sid)),
    }
}

/// Turns an "access denied" from the service manager into a message that says what to do.
fn admin_only(action: impl FnOnce() -> anyhow::Result<()>) -> anyhow::Result<()> {
    action().map_err(|err| {
        let denied = err.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.raw_os_error() == Some(ERROR_ACCESS_DENIED))
                || cause
                    .downcast_ref::<windows_service::Error>()
                    .is_some_and(|e| matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(ERROR_ACCESS_DENIED)))
        });
        if denied {
            err.context("access denied: run this command from an elevated (Administrator) shell")
        } else {
            err
        }
    })
}

// ---------------------------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------------------------

fn run_console(capture: bool) -> anyhow::Result<()> {
    let _log = logging::init(true);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(host::run_agent(false, capture, async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Ctrl-C received; shutting down");
    }))
}

define_windows_service!(ffi_service_main, service_main);

fn run_as_service() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|err| {
        anyhow::Error::new(err).context(
            "could not connect to the service control manager; this entry point is started by \
             Windows. To run in a terminal use `run --console`",
        )
    })
}

fn service_main(_arguments: Vec<OsString>) {
    let _log = logging::init(false);
    if let Err(err) = run_service() {
        tracing::error!(error = ?err, "service failed");
    }
}

fn report(
    handle: &ServiceStatusHandle,
    state: ServiceState,
    accepts: ServiceControlAccept,
    exit_code: u32,
    checkpoint: u32,
    wait_hint: Duration,
) -> windows_service::Result<()> {
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepts,
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint,
        wait_hint,
        process_id: None,
    })
}

fn run_service() -> anyhow::Result<()> {
    let stop = Arc::new(tokio::sync::Notify::new());
    let handler_stop = Arc::clone(&stop);
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            handler_stop.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;

    report(
        &handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        0,
        1,
        Duration::from_secs(10),
    )?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    report(
        &handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
        0,
        Duration::default(),
    )?;

    let result = runtime.block_on(host::run_agent(
        true,
        true,
        async move { stop.notified().await },
    ));

    let exit_code = u32::from(result.is_err());
    if let Err(err) = &result {
        tracing::error!(error = ?err, "agent exited with an error");
    }
    report(
        &handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        0,
        Duration::default(),
    )?;
    result
}

// ---------------------------------------------------------------------------------------------
// Management
// ---------------------------------------------------------------------------------------------

fn manager(access: ServiceManagerAccess) -> anyhow::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access)
        .context("could not connect to the service control manager")
}

fn does_not_exist(err: &windows_service::Error) -> bool {
    matches!(err, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST))
}

fn service_info() -> anyhow::Result<ServiceInfo> {
    Ok(ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().context("could not locate this executable")?,
        launch_arguments: vec![OsString::from("run")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    })
}

/// Creates the service, or brings an existing registration back to the expected configuration.
fn register_service() -> anyhow::Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let info = service_info()?;
    let rights = ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::START;
    let service = match manager.open_service(SERVICE_NAME, rights) {
        Ok(existing) => {
            existing
                .change_config(&info)
                .context("could not update the service registration")?;
            println!("Service registration updated.");
            existing
        }
        Err(err) if does_not_exist(&err) => {
            let created = manager
                .create_service(&info, rights)
                .context("could not create the service")?;
            println!("Service registered.");
            created
        }
        Err(err) => return Err(err).context("could not open the service"),
    };
    service.set_description(DESCRIPTION)?;
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            };
            3
        ]),
    })?;
    Ok(())
}

fn wait_for(
    service: &windows_service::service::Service,
    wanted: ServiceState,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + STATE_TIMEOUT;
    loop {
        let status = service.query_status()?;
        if status.current_state == wanted {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for the service to reach {wanted:?} (now {:?})",
                status.current_state
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn start_service() -> anyhow::Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START,
        )
        .context("the PacketWard service is not installed (run `install` or `repair`)")?;
    if service.query_status()?.current_state != ServiceState::Running {
        service
            .start::<&str>(&[])
            .context("could not start the service")?;
    }
    wait_for(&service, ServiceState::Running)
}

fn stop_service() -> anyhow::Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
    ) {
        Ok(service) => service,
        Err(err) if does_not_exist(&err) => return Ok(()),
        Err(err) => return Err(err).context("could not open the service"),
    };
    if service.query_status()?.current_state != ServiceState::Stopped {
        // Stopping a service that is already stopping is fine; only report real failures.
        if let Err(err) = service.stop() {
            tracing::debug!(%err, "stop request");
        }
    }
    wait_for(&service, ServiceState::Stopped)
}

/// Creates the operators group and adds the operator, so the unelevated UI can use the pipe.
fn ensure_operators(operator_sid: Option<String>) -> anyhow::Result<()> {
    if access::create_operators_group()
        .context("could not create the 'PacketWard Operators' group")?
    {
        println!("Created local group 'PacketWard Operators'.");
    }
    let sid = match operator_sid {
        Some(sid) => sid,
        None => access::current_user_sid().context("could not determine the current user")?,
    };
    if access::add_operator(&sid).context("could not add the user to 'PacketWard Operators'")? {
        println!("Added {sid} to 'PacketWard Operators'.");
        println!(
            "The agent lists the group's members in its pipe permissions when it starts, so the \
             user can connect right away once the service is (re)started; no sign-out is needed."
        );
    } else {
        println!("{sid} is already in 'PacketWard Operators'.");
    }
    Ok(())
}

fn install(operator_sid: Option<String>, start: bool) -> anyhow::Result<()> {
    // Group first: the agent looks the group up when it creates the pipe.
    ensure_operators(operator_sid)?;
    register_service()?;
    if start {
        start_service()?;
        println!("PacketWard service is running.");
    }
    Ok(())
}

fn repair(operator_sid: Option<String>) -> anyhow::Result<()> {
    ensure_operators(operator_sid)?;
    register_service()?;
    // The pipe ACL is built at start-up, so a running agent has to restart to pick up the group.
    stop_service()?;
    start_service()?;
    println!("PacketWard service repaired and running.");
    Ok(())
}

fn uninstall() -> anyhow::Result<()> {
    stop_service()?;
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::DELETE) {
        Ok(service) => {
            service.delete().context("could not delete the service")?;
            println!("Service removed.");
        }
        Err(err) if does_not_exist(&err) => println!("Service was not installed."),
        Err(err) => return Err(err).context("could not open the service"),
    }
    if access::delete_operators_group().context("could not delete the operators group")? {
        println!("Removed local group 'PacketWard Operators'.");
    }
    Ok(())
}
