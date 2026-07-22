//! wisp-test-support — mock wisp server + shared test utilities.
//!
//! Central place for testing infrastructure shared across the workspace:
//!   - `PairedTransport`: two ends of an in-memory `WispTransport`.
//!   - `MockWispServer`: a scripted server for driving Wisp through the
//!     full wisp v2 protocol without a real network.

pub mod paired_transport;
pub mod mock_server;

pub use mock_server::{MockWispServer, ServerReceived};
pub use paired_transport::{make_paired_transport, PairedTransport};
