// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Length-prefixed JSON framing: `u32` little-endian length, then that many bytes of JSON.

use std::io;

use pw_proto::{Envelope, MAX_FRAME_BYTES};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame of {0} bytes exceeds the {MAX_FRAME_BYTES} byte limit")]
    TooLarge(u32),
    #[error("empty frame")]
    Empty,
    #[error("connection closed in the middle of a frame")]
    Truncated,
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
}

impl FrameError {
    /// True when the byte stream is still aligned on a frame boundary, so reading can continue.
    pub fn is_recoverable(&self) -> bool {
        matches!(self, FrameError::Empty | FrameError::Json(_))
    }
}

/// Reads one frame body. `Ok(None)` means the peer closed the stream cleanly between frames.
///
/// The announced length is checked against [`MAX_FRAME_BYTES`] **before** any buffer is allocated.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len_buf = [0u8; 4];
    if reader.read(&mut len_buf[..1]).await? == 0 {
        return Ok(None);
    }
    read_exact(reader, &mut len_buf[1..]).await?;
    let len = u32::from_le_bytes(len_buf);
    if len == 0 {
        return Err(FrameError::Empty);
    }
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    read_exact(reader, &mut body).await?;
    Ok(Some(body))
}

async fn read_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<(), FrameError> {
    match reader.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(FrameError::Truncated),
        Err(err) => Err(err.into()),
    }
}

/// Writes one frame (length prefix + body) and flushes.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), FrameError> {
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if len == 0 {
        return Err(FrameError::Empty);
    }
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    // One buffer, one write: avoids interleaving a prefix with another writer's body.
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(body);
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads and decodes one envelope. `Ok(None)` on clean end of stream.
pub async fn read_envelope<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Envelope>, FrameError> {
    match read_frame(reader).await? {
        Some(body) => Ok(Some(serde_json::from_slice(&body)?)),
        None => Ok(None),
    }
}

pub async fn write_envelope<W: AsyncWrite + Unpin>(
    writer: &mut W,
    envelope: &Envelope,
) -> Result<(), FrameError> {
    write_frame(writer, &serde_json::to_vec(envelope)?).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip() {
        let (mut a, mut b) = duplex(1024);
        write_frame(&mut a, b"{\"x\":1}").await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"{\"x\":1}");
    }

    #[tokio::test]
    async fn prefix_is_little_endian() {
        let (mut a, mut b) = duplex(1024);
        write_frame(&mut a, &[b'x'; 258]).await.unwrap();
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(&raw[..4], &[2, 1, 0, 0]);
        assert_eq!(raw.len(), 4 + 258);
    }

    #[tokio::test]
    async fn clean_eof_between_frames_is_none() {
        let (a, mut b) = duplex(64);
        drop(a);
        assert!(read_frame(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn eof_inside_the_length_prefix_is_truncated() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&[5, 0]).await.unwrap();
        drop(a);
        assert!(matches!(
            read_frame(&mut b).await,
            Err(FrameError::Truncated)
        ));
    }

    #[tokio::test]
    async fn eof_inside_the_body_is_truncated() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&[10, 0, 0, 0]).await.unwrap();
        a.write_all(b"abc").await.unwrap();
        drop(a);
        assert!(matches!(
            read_frame(&mut b).await,
            Err(FrameError::Truncated)
        ));
    }

    #[tokio::test]
    async fn oversized_length_is_rejected_without_reading_the_body() {
        let (mut a, mut b) = duplex(64);
        // Announce a body larger than the limit; send no body at all. If the reader tried to
        // allocate and read it, this would hang or allocate gigabytes instead of failing.
        a.write_all(&(MAX_FRAME_BYTES + 1).to_le_bytes())
            .await
            .unwrap();
        assert!(matches!(
            read_frame(&mut b).await,
            Err(FrameError::TooLarge(n)) if n == MAX_FRAME_BYTES + 1
        ));
        a.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        assert!(matches!(
            read_frame(&mut b).await,
            Err(FrameError::TooLarge(u32::MAX))
        ));
    }

    #[tokio::test]
    async fn the_limit_itself_is_accepted() {
        let (mut a, mut b) = duplex(64 * 1024);
        let body = vec![b'x'; MAX_FRAME_BYTES as usize];
        let writer = tokio::spawn(async move { write_frame(&mut a, &body).await });
        let got = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(got.len(), MAX_FRAME_BYTES as usize);
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn writing_an_oversized_or_empty_body_fails() {
        let (mut a, _b) = duplex(64);
        let big = vec![0u8; MAX_FRAME_BYTES as usize + 1];
        assert!(matches!(
            write_frame(&mut a, &big).await,
            Err(FrameError::TooLarge(_))
        ));
        assert!(matches!(
            write_frame(&mut a, b"").await,
            Err(FrameError::Empty)
        ));
    }

    #[tokio::test]
    async fn zero_length_frame_is_empty_and_recoverable() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&[0, 0, 0, 0]).await.unwrap();
        write_frame(&mut a, b"{}").await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert!(matches!(err, FrameError::Empty) && err.is_recoverable());
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"{}");
    }

    #[tokio::test]
    async fn bad_json_is_recoverable_and_the_next_frame_still_reads() {
        let (mut a, mut b) = duplex(256);
        write_frame(&mut a, b"{ not json").await.unwrap();
        let good = Envelope::event("t", &()).unwrap();
        write_envelope(&mut a, &good).await.unwrap();
        let err = read_envelope(&mut b).await.unwrap_err();
        assert!(matches!(err, FrameError::Json(_)) && err.is_recoverable());
        assert_eq!(read_envelope(&mut b).await.unwrap().unwrap(), good);
    }

    #[tokio::test]
    async fn partial_reads_are_reassembled() {
        // A 1-byte pipe forces every read to be partial.
        let (mut a, mut b) = duplex(1);
        let env = Envelope::request(3, "system.info", &()).unwrap();
        let expected = env.clone();
        let writer = tokio::spawn(async move { write_envelope(&mut a, &env).await });
        let got = read_envelope(&mut b).await.unwrap().unwrap();
        assert_eq!(got, expected);
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn several_frames_back_to_back() {
        let (mut a, mut b) = duplex(4096);
        for i in 0..5u64 {
            write_envelope(&mut a, &Envelope::response(i, &i).unwrap())
                .await
                .unwrap();
        }
        for i in 0..5u64 {
            let env = read_envelope(&mut b).await.unwrap().unwrap();
            assert_eq!(env.id, Some(i));
        }
    }
}
