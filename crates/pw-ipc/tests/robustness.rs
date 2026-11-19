// SPDX-License-Identifier: GPL-3.0-or-later
//! The IPC decoder must survive any byte stream a hostile local process can write to the pipe: it may
//! return an error, never panic, hang or allocate more than the frame limit. This is a deterministic,
//! seeded stand-in that runs in CI; the coverage-guided target lives in `crates/pw-ipc/fuzz`.

use pw_ipc::framing::{read_envelope, read_frame, write_envelope};
use pw_ipc::FrameError;
use pw_proto::Envelope;

/// xorshift64*: no dependency, fully reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

async fn feed(bytes: &[u8]) {
    let mut reader = bytes;
    // Drain the stream: every call must make progress or stop.
    for _ in 0..bytes.len() + 2 {
        match read_envelope(&mut reader).await {
            Ok(None) => break,
            Ok(Some(envelope)) => {
                let _ = envelope.check_shape();
            }
            Err(err) if err.is_recoverable() => {}
            Err(_) => break,
        }
    }
}

#[tokio::test]
async fn random_bytes_never_panic_or_over_allocate() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..3000 {
        let len = rng.below(300);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        feed(&bytes).await;
    }
}

#[tokio::test]
async fn hostile_length_prefixes_are_refused_before_allocating() {
    for len in [
        0u32,
        u32::MAX,
        u32::MAX - 1,
        0x8000_0000,
        4 * 1024 * 1024 + 1,
    ] {
        let mut bytes = len.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        let mut reader = &bytes[..];
        let result = read_frame(&mut reader).await;
        match (len, result) {
            (0, Err(FrameError::Empty)) => {}
            (_, Err(FrameError::TooLarge(n))) => assert_eq!(n, len),
            (_, other) => panic!("length {len}: unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn mutated_valid_envelopes_never_panic() {
    let envelope = Envelope::request(
        7,
        "firewall.block",
        &serde_json::json!({ "targets": ["203.0.113.5"] }),
    )
    .expect("serialisable");
    let mut wire = Vec::new();
    write_envelope(&mut wire, &envelope).await.expect("writes");
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for _ in 0..3000 {
        let mut mutated = wire.clone();
        for _ in 0..=rng.below(4) {
            match rng.below(3) {
                0 => {
                    let at = rng.below(mutated.len());
                    mutated[at] = rng.byte();
                }
                1 => {
                    let at = rng.below(mutated.len());
                    mutated.truncate(at.max(1));
                }
                _ => mutated.push(rng.byte()),
            }
        }
        feed(&mutated).await;
    }
}
