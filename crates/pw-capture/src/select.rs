// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Backend selection: Npcap if it is installed, otherwise the raw-socket backend, and a plain description
//! of what is missing for the UI to show. Nothing here fails: an absent Npcap is a normal state.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::backend::{BackendCaps, BackendKind, CaptureBackend};
use crate::error::CaptureError;
use crate::npcap::{detect_npcap, NpcapBackend, NPCAP_URL};
use crate::rawsock::RawSocketBackend;

/// What selection needs to know about the machine. The real one reads the system; tests inject one.
pub trait CaptureEnv {
    fn is_windows(&self) -> bool;
    /// The DLL of an installed Npcap.
    fn npcap_dll(&self) -> Option<PathBuf>;
    /// Whether this process may open raw sockets for `SIO_RCVALL`.
    fn is_elevated(&self) -> bool;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnv;

impl CaptureEnv for SystemEnv {
    fn is_windows(&self) -> bool {
        cfg!(windows)
    }

    fn npcap_dll(&self) -> Option<PathBuf> {
        detect_npcap()
    }

    #[cfg(windows)]
    fn is_elevated(&self) -> bool {
        crate::sys::windows::is_elevated()
    }

    #[cfg(not(windows))]
    fn is_elevated(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Availability {
    Available,
    Unavailable {
        reason: String,
        /// Where to get what is missing, when there is such a place.
        install_url: Option<String>,
    },
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendStatus {
    pub kind: BackendKind,
    pub availability: Availability,
    pub caps: BackendCaps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MissingKind {
    Npcap,
    Administrator,
    Windows,
}

/// Something absent that limits capturing, with whether capturing works without it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Missing {
    pub kind: MissingKind,
    /// No backend can run until this is provided.
    pub required: bool,
    pub message: String,
    pub install_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendSelection {
    /// The backend to use, if any.
    pub selected: Option<BackendKind>,
    pub npcap: BackendStatus,
    pub raw_socket: BackendStatus,
    /// What is missing, for the UI to explain (English; the UI localizes by `kind`).
    pub missing: Vec<Missing>,
    /// One-sentence description of the situation.
    pub summary: String,
}

impl BackendSelection {
    pub fn status(&self, kind: BackendKind) -> &BackendStatus {
        match kind {
            BackendKind::Npcap => &self.npcap,
            BackendKind::RawSocket => &self.raw_socket,
        }
    }
}

/// Chooses the capture backend for this machine.
pub fn select_backend(env: &dyn CaptureEnv) -> BackendSelection {
    let npcap_caps = NpcapBackend::static_caps();
    let raw_caps = RawSocketBackend::static_caps();
    let mut missing = Vec::new();

    if !env.is_windows() {
        let reason = "packet capture is only implemented on Windows".to_owned();
        missing.push(Missing {
            kind: MissingKind::Windows,
            required: true,
            message: reason.clone(),
            install_url: None,
        });
        let off = |kind, caps| BackendStatus {
            kind,
            availability: Availability::Unavailable {
                reason: reason.clone(),
                install_url: None,
            },
            caps,
        };
        return BackendSelection {
            selected: None,
            npcap: off(BackendKind::Npcap, npcap_caps),
            raw_socket: off(BackendKind::RawSocket, raw_caps),
            missing,
            summary: "No capture backend: this platform is not supported.".to_owned(),
        };
    }

    let npcap_ready = env.npcap_dll().is_some();
    let npcap_availability = if npcap_ready {
        Availability::Available
    } else {
        Availability::Unavailable {
            reason: "Npcap is not installed".to_owned(),
            install_url: Some(NPCAP_URL.to_owned()),
        }
    };

    let elevated = env.is_elevated();
    let raw_availability = if elevated {
        Availability::Available
    } else {
        Availability::Unavailable {
            reason: "the raw-socket backend needs administrator rights".to_owned(),
            install_url: None,
        }
    };

    let selected = if npcap_ready {
        Some(BackendKind::Npcap)
    } else if elevated {
        Some(BackendKind::RawSocket)
    } else {
        None
    };

    if !npcap_ready {
        missing.push(Missing {
            kind: MissingKind::Npcap,
            // Optional while the raw-socket backend works.
            required: !elevated,
            message:
                "Npcap is not installed. Installing it from npcap.com adds Ethernet-level capture \
                      and kernel filters; PacketWard works without it."
                    .to_owned(),
            install_url: Some(NPCAP_URL.to_owned()),
        });
    }
    if !elevated && !npcap_ready {
        missing.push(Missing {
            kind: MissingKind::Administrator,
            required: true,
            message: "Run the PacketWard agent as an administrator (the installed service does) to capture \
                      packets without Npcap."
                .to_owned(),
            install_url: None,
        });
    }

    let summary = match selected {
        Some(BackendKind::Npcap) => "Capturing with Npcap (Ethernet frames, kernel filters).".to_owned(),
        Some(BackendKind::RawSocket) => format!(
            "Capturing with the built-in raw-socket backend (IP level, filters applied in software). \
             Install Npcap from {NPCAP_URL} for full-fidelity capture."
        ),
        None => "No capture backend is available: install Npcap or run the agent as an administrator."
            .to_owned(),
    };

    BackendSelection {
        selected,
        npcap: BackendStatus {
            kind: BackendKind::Npcap,
            availability: npcap_availability,
            caps: npcap_caps,
        },
        raw_socket: BackendStatus {
            kind: BackendKind::RawSocket,
            availability: raw_availability,
            caps: raw_caps,
        },
        missing,
        summary,
    }
}

/// [`select_backend`] for the machine this runs on.
pub fn select_system_backend() -> BackendSelection {
    select_backend(&SystemEnv)
}

/// Creates the backend of the given kind. Fails with [`CaptureError::Unavailable`] when it cannot run
/// here (Npcap not installed, not on Windows).
pub fn create_backend(
    kind: BackendKind,
    env: &dyn CaptureEnv,
) -> Result<Box<dyn CaptureBackend>, CaptureError> {
    match kind {
        BackendKind::Npcap => match env.npcap_dll() {
            Some(dll) => Ok(Box::new(NpcapBackend::new(dll))),
            None => Err(CaptureError::Unavailable {
                reason: format!("Npcap is not installed (get it from {NPCAP_URL})"),
            }),
        },
        BackendKind::RawSocket if env.is_windows() => Ok(Box::new(RawSocketBackend::new())),
        BackendKind::RawSocket => Err(CaptureError::Unavailable {
            reason: "the raw-socket backend only exists on Windows".to_owned(),
        }),
    }
}

/// Creates the selected backend, or explains why there is none.
pub fn create_selected_backend(
    selection: &BackendSelection,
    env: &dyn CaptureEnv,
) -> Result<Box<dyn CaptureBackend>, CaptureError> {
    match selection.selected {
        Some(kind) => create_backend(kind, env),
        None => Err(CaptureError::Unavailable {
            reason: selection.summary.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Env {
        windows: bool,
        npcap: bool,
        elevated: bool,
    }

    impl CaptureEnv for Env {
        fn is_windows(&self) -> bool {
            self.windows
        }
        fn npcap_dll(&self) -> Option<PathBuf> {
            self.npcap
                .then(|| PathBuf::from(r"C:\Windows\System32\Npcap\wpcap.dll"))
        }
        fn is_elevated(&self) -> bool {
            self.elevated
        }
    }

    fn select(windows: bool, npcap: bool, elevated: bool) -> BackendSelection {
        select_backend(&Env {
            windows,
            npcap,
            elevated,
        })
    }

    #[test]
    fn npcap_wins_when_installed() {
        let s = select(true, true, true);
        assert_eq!(s.selected, Some(BackendKind::Npcap));
        assert!(s.npcap.availability.is_available());
        assert!(s.raw_socket.availability.is_available());
        assert!(s.missing.is_empty());
        // Npcap does not need the agent's elevation.
        let s = select(true, true, false);
        assert_eq!(s.selected, Some(BackendKind::Npcap));
        assert!(s.missing.is_empty());
    }

    #[test]
    fn raw_socket_is_the_fallback_and_npcap_is_reported_as_optional() {
        let s = select(true, false, true);
        assert_eq!(s.selected, Some(BackendKind::RawSocket));
        match &s.npcap.availability {
            Availability::Unavailable {
                reason,
                install_url,
            } => {
                assert!(reason.contains("Npcap"));
                assert_eq!(install_url.as_deref(), Some("https://npcap.com"));
            }
            Availability::Available => panic!("npcap should be unavailable"),
        }
        assert_eq!(s.missing.len(), 1);
        assert_eq!(s.missing[0].kind, MissingKind::Npcap);
        assert!(!s.missing[0].required);
        assert_eq!(
            s.missing[0].install_url.as_deref(),
            Some("https://npcap.com")
        );
        assert!(s.summary.contains("raw-socket"));
        assert!(!s.status(BackendKind::RawSocket).caps.bpf);
        assert!(s.status(BackendKind::Npcap).caps.bpf);
    }

    #[test]
    fn nothing_available_explains_both_gaps() {
        let s = select(true, false, false);
        assert_eq!(s.selected, None);
        let kinds: Vec<MissingKind> = s.missing.iter().map(|m| m.kind).collect();
        assert_eq!(kinds, [MissingKind::Npcap, MissingKind::Administrator]);
        assert!(s.missing.iter().all(|m| m.required));
        assert!(!s.raw_socket.availability.is_available());
    }

    #[test]
    fn other_platforms_have_no_backend() {
        let s = select(false, false, false);
        assert_eq!(s.selected, None);
        assert_eq!(s.missing[0].kind, MissingKind::Windows);
        assert!(!s.npcap.availability.is_available());
    }

    #[test]
    fn creating_an_unavailable_backend_is_an_error_not_a_panic() {
        let env = Env {
            windows: true,
            npcap: false,
            elevated: true,
        };
        assert!(matches!(
            create_backend(BackendKind::Npcap, &env),
            Err(CaptureError::Unavailable { .. })
        ));
        let backend = create_backend(BackendKind::RawSocket, &env).unwrap();
        assert_eq!(backend.caps().kind, BackendKind::RawSocket);
        let selection = select_backend(&env);
        assert_eq!(
            create_selected_backend(&selection, &env)
                .unwrap()
                .caps()
                .kind,
            BackendKind::RawSocket
        );
        let none = select(true, false, false);
        assert!(create_selected_backend(&none, &env).is_err());
    }

    #[test]
    fn the_system_selection_never_fails() {
        let s = select_system_backend();
        // Whatever this machine has, the answer is well-formed.
        assert_eq!(
            s.selected.is_some(),
            s.npcap.availability.is_available() || s.raw_socket.availability.is_available()
        );
    }
}
