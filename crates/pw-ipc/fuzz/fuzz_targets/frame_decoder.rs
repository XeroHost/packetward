// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
#![no_main]
//! Feeds arbitrary bytes to the IPC frame/envelope decoder. Run: `cargo +nightly fuzz run frame_decoder`
//! from `crates/pw-ipc/fuzz` (see docs/TESTING.md).

use libfuzzer_sys::fuzz_target;
use pw_ipc::framing::read_envelope;

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let mut reader = data;
        for _ in 0..data.len() + 2 {
            match read_envelope(&mut reader).await {
                Ok(Some(envelope)) => {
                    let _ = envelope.check_shape();
                }
                Ok(None) => break,
                Err(err) if err.is_recoverable() => {}
                Err(_) => break,
            }
        }
    });
});
