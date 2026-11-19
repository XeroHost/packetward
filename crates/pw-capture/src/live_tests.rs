// SPDX-License-Identifier: GPL-3.0-or-later
//! Live tests of the Windows raw-socket backend. They only listen (nothing is sent) and skip themselves,
//! without failing, when the process is not elevated or the machine has no usable adapter.

use std::time::{Duration, Instant};

use crate::{
    list_interfaces, Capture, CaptureBackend, CaptureOpts, InterfaceId, PipelineConfig,
    RawSocketBackend, RecordSpec, Recorder,
};

fn primary_address() -> Option<String> {
    if !crate::sys::windows::is_elevated() {
        eprintln!("skipping raw-socket live test: the process is not elevated");
        return None;
    }
    let adapters = list_interfaces().ok()?;
    let found = adapters
        .iter()
        .filter(|a| a.up && !a.loopback)
        .flat_map(|a| a.ipv4_addrs())
        .find(|ip| !ip.is_link_local() && !ip.is_loopback());
    if found.is_none() {
        eprintln!("skipping raw-socket live test: no up adapter with a routable IPv4 address");
    }
    found.map(|ip| ip.to_string())
}

#[test]
fn lists_adapters() {
    let adapters = list_interfaces().expect("GetAdaptersAddresses");
    assert!(!adapters.is_empty());
    for a in &adapters {
        eprintln!(
            "adapter {} {:?} up={} addrs={:?}",
            a.id, a.name, a.up, a.addrs
        );
        assert!(a.id.as_str().starts_with('{'), "adapter names are GUIDs");
    }
}

#[test]
fn captures_for_one_second_when_elevated() {
    let Some(address) = primary_address() else {
        return;
    };
    let backend = RawSocketBackend::new();
    let source = match backend.open(&InterfaceId::new(address.clone()), &CaptureOpts::default()) {
        Ok(source) => source,
        Err(e) => {
            eprintln!("skipping raw-socket live test: {e}");
            return;
        }
    };
    let (cap, mut rx) = Capture::start(source, PipelineConfig::default()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    let (mut inbound, mut outbound) = (0u64, 0u64);
    let mut last_ts = 0u64;
    while Instant::now() < deadline {
        if let Ok(batch) = rx.try_recv() {
            for m in batch {
                match m.direction {
                    pw_core::Direction::Inbound => inbound += 1,
                    pw_core::Direction::Outbound => outbound += 1,
                }
                assert!(m.timestamp_ns >= last_ts, "timestamps never go backwards");
                last_ts = m.timestamp_ns;
            }
        } else {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let stats = cap.stop().expect("the capture ends cleanly");
    eprintln!("raw socket on {address}: inbound {inbound} outbound {outbound} stats {stats:?}");
    // Ambient traffic on a live host can legitimately contain odd packets or overflow a debug build, so
    // these are reported, not asserted.
    eprintln!(
        "dropped {} malformed {} non-ip {}",
        stats.dropped_packets(),
        stats.malformed,
        stats.non_ip
    );
}

#[test]
fn records_one_second_to_pcapng_when_elevated() {
    let Some(address) = primary_address() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let spec = RecordSpec::timed(dir.path(), "live", Duration::from_secs(1));
    let source =
        match RawSocketBackend::new().open(&InterfaceId::new(address), &spec.capture_opts()) {
            Ok(source) => source,
            Err(e) => {
                eprintln!("skipping raw-socket live recording test: {e}");
                return;
            }
        };
    let summary = Recorder::start(source, spec).unwrap().wait().unwrap();
    eprintln!(
        "recorded {} packets, {} bytes",
        summary.packets_written, summary.bytes_written
    );
    let file = &summary.files[0];
    let mut reader =
        pcap_file::pcapng::PcapNgReader::new(std::fs::File::open(file).unwrap()).unwrap();
    let mut packets = 0u64;
    while let Some(block) = reader.next_block() {
        if let pcap_file::pcapng::Block::EnhancedPacket(epb) = block.unwrap().0 {
            packets += 1;
            assert!(epb.data.len() <= 128, "headers only");
            assert!(epb.original_len as usize >= epb.data.len());
        }
    }
    assert_eq!(packets, summary.packets_written);
}
