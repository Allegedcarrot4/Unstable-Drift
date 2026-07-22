//! `WispStreamIo` integration tests.
//!
//! Verify that the `AsyncRead + AsyncWrite` adapter over `WispStream`
//! correctly bridges byte I/O to the wisp DATA-packet protocol. Uses
//! `wisp-test-support`'s scripted mock server rather than a real one.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;

use drift_core::transport::WispTransport;
use drift_core::wisp::{
    encode_continue, encode_info, encode_packet_to_vec, Mux, StreamType, WispStream,
    WispStreamIo, HANDSHAKE_STREAM_ID, PacketType,
};
use drift_test_support::{make_paired_transport, MockWispServer, PairedTransport, ServerReceived};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn make_established_mux() -> (PairedTransport, Arc<Mux>) {
    let pair = make_paired_transport();
    let client: Arc<dyn WispTransport> = pair.client.clone();
    let mux = Arc::new(Mux::new(client.clone()));
    pair.server_tx
        .send(encode_packet_to_vec(
            PacketType::Info,
            HANDSHAKE_STREAM_ID,
            &encode_info(&[]),
        ))
        .unwrap();
    pair.server_tx
        .send(encode_packet_to_vec(
            PacketType::Continue,
            HANDSHAKE_STREAM_ID,
            &encode_continue(64),
        ))
        .unwrap();
    mux.run_handshake(&[]).await.unwrap();

    // Spawn an inbound pump: reads frames off the client transport and
    // dispatches them into the mux. The real high-level wisp client would
    // run something similar; the low-level `Mux` doesn't do it internally.
    let pump_mux = mux.clone();
    let pump_transport = client;
    tokio::spawn(async move {
        loop {
            match pump_transport.recv().await {
                Ok(frame) => {
                    if pump_mux.dispatch_inbound(frame).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    (pair, mux)
}

#[tokio::test]
async fn write_then_read_round_trip() {
    let (pair, mux) = make_established_mux().await;
    let server = MockWispServer::from_pair(&pair);

    let handle = mux
        .open("example.com", 80, StreamType::Tcp)
        .await
        .unwrap();
    let stream_id = handle.id;
    let ws_stream = WispStream::from_handle(mux.clone(), handle);
    let mut io = WispStreamIo::new(ws_stream);

    // Write "hello" to the transport.
    io.write_all(b"hello").await.unwrap();
    io.flush().await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    // Server should have observed a CONNECT + DATA packet with our bytes.
    let observed = server.received();
    let data = observed.iter().find_map(|s| match s {
        ServerReceived::Data {
            stream_id: sid,
            payload,
        } if *sid == stream_id => Some(payload.clone()),
        _ => None,
    });
    assert_eq!(data.as_deref(), Some(&b"hello"[..]));

    // Server sends back some bytes on the stream. Initial credit granted
    // at open time is already sufficient; we just push DATA.
    server.send_data(stream_id, b"world");

    let mut out = [0u8; 5];
    io.read_exact(&mut out).await.unwrap();
    assert_eq!(&out, b"world");
}

#[tokio::test]
async fn read_splits_across_partial_reads() {
    let (pair, mux) = make_established_mux().await;
    let server = MockWispServer::from_pair(&pair);

    let handle = mux.open("h", 1, StreamType::Tcp).await.unwrap();
    let stream_id = handle.id;
    let ws_stream = WispStream::from_handle(mux.clone(), handle);
    let mut io = WispStreamIo::new(ws_stream);

    server.send_data(stream_id, b"0123456789");

    let mut a = [0u8; 4];
    let mut b = [0u8; 4];
    let mut c = [0u8; 2];
    io.read_exact(&mut a).await.unwrap();
    io.read_exact(&mut b).await.unwrap();
    io.read_exact(&mut c).await.unwrap();
    assert_eq!(&a, b"0123");
    assert_eq!(&b, b"4567");
    assert_eq!(&c, b"89");
}
