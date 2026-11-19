// SPDX-License-Identifier: GPL-3.0-or-later
//! Stand-in for the Windows socket sender on other platforms: the modes report why they cannot
//! run instead of failing obscurely.

use std::net::IpAddr;

use crate::error::DiagError;
use crate::mtr_adv::capture::{BoundProbe, ProbeSender};
use crate::mtr_adv::{ModeUnavailable, ProbeMode, ProbeRequest};

/// A [`ProbeSender`] that cannot send anything.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedSender;

impl ProbeSender for UnsupportedSender {
    fn availability(&self, mode: ProbeMode, _target: IpAddr) -> Result<(), ModeUnavailable> {
        Err(ModeUnavailable::new(
            mode,
            "UDP and TCP-SYN probes are only implemented on Windows",
        ))
    }

    fn local_addr_for(&self, _target: IpAddr) -> Result<IpAddr, DiagError> {
        Err(DiagError::Unsupported("UDP/TCP probes"))
    }

    fn bind(&self, _request: &ProbeRequest) -> Result<Box<dyn BoundProbe>, DiagError> {
        Err(DiagError::Unsupported("UDP/TCP probes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_why() {
        let e = UnsupportedSender
            .availability(ProbeMode::Udp, "1.1.1.1".parse().unwrap())
            .unwrap_err();
        assert_eq!(e.mode, ProbeMode::Udp);
        assert!(e.reason.contains("Windows"));
    }
}
