//! Streaming a file prefix as a response body, so a 1 GiB journal is never
//! held in memory to be served.

use std::fs::File;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use tokio::sync::mpsc;

use crate::fsutil;

/// Bytes read per chunk.
const CHUNK: u64 = 1 << 20;

/// The receiving end of a chunk channel, as a stream.
struct Chunks(mpsc::Receiver<io::Result<Bytes>>);

impl futures_core::Stream for Chunks {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

/// A body of the first `len` bytes of `file`, read on a blocking thread in
/// 1 MiB chunks. A read error ends the body with that error, which aborts
/// the response rather than sending a short file as if it were whole.
pub fn file_body(file: File, len: u64) -> Body {
    let (tx, rx) = mpsc::channel(4);
    tokio::task::spawn_blocking(move || {
        let mut offset = 0u64;
        while offset < len {
            let n = CHUNK.min(len - offset);
            let mut buf = vec![0u8; n as usize];
            let chunk = fsutil::read_exact_at(&file, &mut buf, offset).map(|_| Bytes::from(buf));
            let failed = chunk.is_err();
            if tx.blocking_send(chunk).is_err() || failed {
                return;
            }
            offset += n;
        }
    });
    Body::from_stream(Chunks(rx))
}
