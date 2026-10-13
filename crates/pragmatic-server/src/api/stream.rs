//! Streaming a journal's durable prefix as a response body, so a 1 GiB
//! journal is never held in memory to be served.
//!
//! Each chunk is read through [`DurableFile::read_at`], which takes the
//! run's file lock shared for that read and refuses once an erasure or a
//! deletion has replaced or removed the file: the response is then aborted
//! (a short body with an error, never a short file passed off as whole),
//! and nothing read after the erasure committed reaches the client. An
//! erasure therefore never waits for a slow download either.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use tokio::sync::mpsc;

use crate::store::{BudgetGuard, DurableFile};

/// Bytes read per chunk.
const CHUNK: u64 = 1 << 20;

/// Chunks read ahead of the client.
const AHEAD: usize = 2;

/// The receiving end of a chunk channel, as a stream.
struct Chunks(mpsc::Receiver<io::Result<Bytes>>);

impl futures_core::Stream for Chunks {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

/// A body of the journal's durable prefix, read on a blocking thread in
/// 1 MiB chunks. A read error (or an erasure in between) ends the body with
/// that error, which aborts the response.
pub fn file_body(durable: DurableFile) -> Body {
    let (tx, rx) = mpsc::channel(AHEAD);
    tokio::task::spawn_blocking(move || {
        let len = durable.byte_len;
        let mut offset = 0u64;
        while offset < len {
            let n = CHUNK.min(len - offset);
            let mut buf = vec![0u8; n as usize];
            let chunk = durable.read_at(&mut buf, offset).map(|_| Bytes::from(buf));
            let failed = chunk.is_err();
            if tx.blocking_send(chunk).is_err() || failed {
                return;
            }
            offset += n;
        }
    });
    Body::from_stream(Chunks(rx))
}

/// A body of bytes already in memory (an evidence bundle), sent in 1 MiB
/// chunks. `room` is the share of the store's byte budget the bytes were
/// built under; it is released when the body is dropped, sent or not.
pub fn bytes_body(bytes: Vec<u8>, room: BudgetGuard) -> Body {
    let (tx, rx) = mpsc::channel(AHEAD);
    tokio::spawn(async move {
        let _room = room;
        let bytes = Bytes::from(bytes);
        let mut offset = 0usize;
        while offset < bytes.len() {
            let end = (offset + CHUNK as usize).min(bytes.len());
            if tx.send(Ok(bytes.slice(offset..end))).await.is_err() {
                return;
            }
            offset = end;
        }
    });
    Body::from_stream(Chunks(rx))
}
