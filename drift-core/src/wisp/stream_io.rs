//! `WispStreamIo` — a `tokio::io::AsyncRead + AsyncWrite` adapter over a
//! `WispStream`. Bridges wisp's discrete DATA-packet delivery to
//! byte-granular I/O so `tokio_rustls`, `httparse`, `fastwebsockets`, and
//! `h2` can consume the stream.
//!
//! The adapter owns a `Bytes` buffer for partial reads, a write buffer for
//! coalescing small writes into larger DATA packets, and Box-pinned futures
//! for pending send/recv operations.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use flume::Receiver;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::mux::{Mux, MuxError};
use super::stream::WispStream;

/// Threshold for flushing the write buffer as a wisp DATA packet.
/// Small writes are accumulated until the buffer reaches this size,
/// reducing protocol overhead for write patterns like TLS handshakes
/// and HTTP headers. 16 KiB strikes a balance between latency and
/// coalescing efficiency.
const WRITE_FLUSH_THRESHOLD: usize = 16 * 1024;

/// Async I/O adapter over a `WispStream`.
///
/// Read side: pulls DATA packets from `inbound_rx`, buffers any leftover
/// after satisfying a partial read.
///
/// Write side: coalesces small writes into a local buffer, flushing as a
/// single wisp DATA packet when the buffer exceeds `WRITE_FLUSH_THRESHOLD`
/// or when `poll_flush` is called. A flush is async (awaits CONTINUE
/// credit via `Mux::send_data`), so the in-flight future is stored between
/// polls.
pub struct WispStreamIo {
    stream_id: u32,
    mux: Arc<Mux>,
    inbound_rx: Receiver<Bytes>,
    /// Leftover bytes from a previous DATA packet that didn't fit in the
    /// caller's buffer.
    read_leftover: Bytes,
    /// In-flight recv future.
    #[allow(clippy::type_complexity)]
    read_fut: Option<
        Pin<Box<dyn Future<Output = std::result::Result<Bytes, flume::RecvError>> + Send>>,
    >,
    /// In-flight send future.
    #[allow(clippy::type_complexity)]
    write_fut:
        Option<Pin<Box<dyn Future<Output = std::result::Result<(), MuxError>> + Send>>>,
    /// Coalescing write buffer. Bytes accumulate here until flushed.
    write_buf: Vec<u8>,
    /// Local closed flag.
    closed: bool,
}

impl WispStreamIo {
    /// Wrap a `WispStream`. The stream is consumed — its inner mux handle
    /// and receiver are cloned into the adapter, so the original
    /// `WispStream` is dropped (which is fine; we own everything we need).
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // We deliberately consume the stream.
    pub fn new(stream: WispStream) -> Self {
        let stream_id = stream.id();
        let mux = stream.mux();
        let inbound_rx = stream.inbound_receiver();
        Self {
            stream_id,
            mux,
            inbound_rx,
            read_leftover: Bytes::new(),
            read_fut: None,
            write_fut: None,
            write_buf: Vec::with_capacity(WRITE_FLUSH_THRESHOLD),
            closed: false,
        }
    }

    /// Flush the coalescing write buffer by sending it as a wisp DATA packet.
    /// Returns `Poll::Ready(Ok(()))` if nothing to flush or after the send
    /// future completes.
    fn poll_flush_buf(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // If there's already an in-flight send, drive it to completion.
        if let Some(fut) = self.write_fut.as_mut() {
            return match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {
                    self.write_fut = None;
                    // After the in-flight future completes, check if more data
                    // was buffered while we were waiting, and kick off a new send.
                    if self.write_buf.is_empty() {
                        Poll::Ready(Ok(()))
                    } else {
                        self.start_send(cx)
                    }
                }
                Poll::Ready(Err(e)) => {
                    self.write_fut = None;
                    Poll::Ready(Err(std::io::Error::other(format!("drift send: {e}"))))
                }
                Poll::Pending => Poll::Pending,
            };
        }

        if self.write_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        self.start_send(cx)
    }

    /// Kick off a send of the current write buffer.
    fn start_send(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let data = self.write_buf.split_off(0);
        let stream_id = self.stream_id;
        let mux = self.mux.clone();
        let _n = data.len();
        self.write_fut = Some(Box::pin(async move {
            mux.send_data(stream_id, &data).await
        }));
        let fut = self.write_fut.as_mut().expect("just set");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                self.write_fut = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.write_fut = None;
                Poll::Ready(Err(std::io::Error::other(format!("drift send: {e}"))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for WispStreamIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();

        // Serve from leftover first.
        if !me.read_leftover.is_empty() {
            let take = std::cmp::min(me.read_leftover.len(), buf.remaining());
            let chunk = me.read_leftover.split_to(take);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }

        if me.closed {
            // EOF.
            return Poll::Ready(Ok(()));
        }

        // Ensure an in-flight recv future.
        if me.read_fut.is_none() {
            let rx = me.inbound_rx.clone();
            me.read_fut = Some(Box::pin(async move { rx.recv_async().await }));
        }

        let fut = me.read_fut.as_mut().expect("just set");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(bytes)) => {
                me.read_fut = None;
                if bytes.is_empty() {
                    // Zero-length DATA — nothing to serve; wake ourselves so
                    // the caller polls again on next scheduled poll.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let take = std::cmp::min(bytes.len(), buf.remaining());
                if take < bytes.len() {
                    // Buffer the remainder for the next poll.
                    let mut b = bytes;
                    let chunk = b.split_to(take);
                    buf.put_slice(&chunk);
                    me.read_leftover = b;
                } else {
                    buf.put_slice(&bytes);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                // Sender dropped — EOF.
                me.read_fut = None;
                me.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WispStreamIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        if me.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "WispStreamIo: closed",
            )));
        }

        // If a send is in-flight, drive it to completion before accepting
        // new data (preserves ordering).
        if me.write_fut.is_some() {
            match me.poll_flush_buf(cx) {
                Poll::Ready(Ok(())) => {} // flush finished; continue
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Buffer the incoming bytes.
        me.write_buf.extend_from_slice(buf);
        let n = buf.len();

        // Flush if the buffer exceeds the threshold.
        if me.write_buf.len() >= WRITE_FLUSH_THRESHOLD {
            me.start_send(cx).map(|r| r.map(|()| n))
        } else {
            Poll::Ready(Ok(n))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().poll_flush_buf(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Best-effort: mark closed locally. `Mux::close_stream` is async
        // and AsyncWrite's shutdown contract makes it awkward to hold a
        // future across polls here; callers wanting a graceful CLOSE
        // should keep the original `WispStream` and call `close()` on it
        // instead of wrapping in `WispStreamIo`. Peer will observe close
        // via drop semantics as streams unwind.
        let me = self.get_mut();
        me.closed = true;
        Poll::Ready(Ok(()))
    }
}
