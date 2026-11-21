//! Length-prefixed postcard framing over any tokio byte stream.
//!
//! Local IPC, small control messages: postcard is the whole wire
//! dialect now (owner directive 2026-11-07: "can we use postcard
//! instead of serde?" — postcard is a serde FORMAT, so the serde
//! derives stay on the types and the compact no_std binary becomes
//! the encoding; the same dialect the mesh notify path already
//! speaks). Schema drift still shows up as an honest decode error on
//! ONE message, never a corrupted stream. The frame is `u32 LE
//! length + postcard bytes` — the length is capped so a hostile or
//! wedged peer cannot make the reader allocate by fiat.

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The frame cap: every message this protocol carries is a control
/// message (a state name, a payload of scalars). 4 MiB is generous
/// headroom; anything larger is a bug, not a message.
pub const MAX_FRAME: u32 = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum FrameError {
    /// The peer closed the stream mid-frame or before a frame.
    Closed,
    /// The declared length exceeds the cap or the bytes did not
    /// decode as the expected message.
    Malformed(String),
    /// The underlying transport failed.
    Io(std::io::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Closed => write!(f, "the peer closed the stream"),
            FrameError::Malformed(why) => write!(f, "malformed frame: {why}"),
            FrameError::Io(e) => write!(f, "frame transport failed: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Closed
        } else {
            FrameError::Io(e)
        }
    }
}

/// Serialize one message and write it as one frame. `M: Sync`
/// because the frame may be written from inside a spawned task (the
/// write holds `&M` across an await).
pub async fn encode_frame<W, M>(writer: &mut W, message: &M) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    M: Serialize + Sync,
{
    let bytes = postcard::to_allocvec(message)
        .map_err(|e| FrameError::Malformed(format!("the message refused to encode: {e}")))?;
    let len = u32::try_from(bytes.len()).map_err(|_| {
        FrameError::Malformed(format!(
            "frame of {} bytes exceeds the protocol",
            bytes.len()
        ))
    })?;
    if len > MAX_FRAME {
        return Err(FrameError::Malformed(format!(
            "frame of {len} bytes exceeds the {MAX_FRAME} cap"
        )));
    }
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one frame and decode it.
pub async fn decode_frame<R, M>(reader: &mut R) -> Result<M, FrameError>
where
    R: AsyncRead + Unpin,
    M: DeserializeOwned,
{
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes);
    if len > MAX_FRAME {
        return Err(FrameError::Malformed(format!(
            "peer declared a frame of {len} bytes, past the {MAX_FRAME} cap"
        )));
    }
    let mut bytes = vec![0u8; len as usize];
    reader.read_exact(&mut bytes).await?;
    postcard::from_bytes(&bytes)
        .map_err(|e| FrameError::Malformed(format!("the frame did not decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    // The derive macros, under their own names: the module's trait
    // imports stay, the derives come from serde's prelude.
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Probe {
        name: String,
        n: u32,
    }

    #[tokio::test]
    async fn a_frame_round_trips_through_a_pipe() {
        let (mut tx, mut rx) = tokio::io::duplex(64);
        let probe = Probe {
            name: "marker".into(),
            n: 7,
        };
        encode_frame(&mut tx, &probe).await.unwrap();
        let back: Probe = decode_frame(&mut rx).await.unwrap();
        assert_eq!(back, probe);
    }

    #[tokio::test]
    async fn an_oversized_declared_length_is_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut reader = &bytes[..];
        let back: Result<Probe, _> = decode_frame(&mut reader).await;
        assert!(matches!(back, Err(FrameError::Malformed(_))));
    }
}
