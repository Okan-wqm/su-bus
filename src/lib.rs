//! # su-bus
//!
//! Async Modbus client and server for Tokio, supporting
//! Modbus TCP, Modbus RTU (any byte stream, e.g. a serial port) and RTU-over-TCP.
//!
//! Written from scratch from the public Modbus specifications
//! ("MODBUS Application Protocol" and "MODBUS over Serial Line").
//!
//! ## Features
//! - Function codes 01-08, 0B, 0F, 10, 11, 16, 17, 18, 2B/0E (device identification)
//!   and pass-through of any user-defined function code.
//! - Server-side communication counters (diagnostics 0x0B-0x0F, FC 0x0B).
//! - Typed register values ([`codec`]): `u32`/`i32`/`f32`/`u64`/`i64`/`f64` and text,
//!   in ABCD / CDAB / BADC / DCBA order.
//! - Client retries, custom transports with automatic reconnect
//!   ([`Client::with_connector`], e.g. TLS or a re-opened serial port) and raw frame tracing.
//! - Server over any stream ([`server::serve_tcp_stream`], [`server::serve_rtu`]) and a
//!   default handler for TCP devices that ignore the unit id.
//! - Only one dependency: `tokio`.
//!
//! ## Client
//! ```no_run
//! use su_bus::{Client, ClientConfig, UnitId};
//! # async fn demo() -> Result<(), su_bus::Error> {
//! let client = Client::tcp("192.168.1.10:502", ClientConfig::default());
//! let regs = client.read_holding_registers(UnitId(1), 0, 10).await?;
//! client.write_single_coil(UnitId(1), 3, true).await?;
//! # Ok(()) }
//! ```
//!
//! For a serial port, open it with any crate that yields an `AsyncRead + AsyncWrite`
//! stream (for example `tokio-serial`) and use
//! `Client::from_stream(port, Framing::Rtu, config)` / [`server::serve_rtu`].
//!
//! ## Server
//! ```no_run
//! use su_bus::server::{spawn_tcp_server, MemoryMap, ServerHandlers, TcpServerConfig};
//! use su_bus::UnitId;
//! # async fn demo() -> std::io::Result<()> {
//! let data = MemoryMap::new(100, 100, 100, 100).shared();
//! let handlers = ServerHandlers::new().with(UnitId(1), data.clone());
//! let server = spawn_tcp_server("0.0.0.0:502", handlers, TcpServerConfig::default()).await?;
//! data.lock().unwrap().input_registers[0] = 42; // update values while serving
//! # drop(server); Ok(()) }
//! ```

pub mod client;
pub mod codec;
pub mod device_id;
pub mod error;
pub mod frame;
pub mod pdu;
pub mod server;
pub mod trace;
pub mod types;

pub use client::{Client, ClientConfig};
pub use codec::{RegisterOrder, RegisterValue};
pub use device_id::{DeviceIdCode, DeviceIdReport, DeviceIdentification};
pub use error::{Error, ProtocolError};
pub use frame::Framing;
pub use pdu::{Request, Response};
pub use trace::{Direction, FrameTrace};
pub use types::{AddressRange, ExceptionCode, UnitId};
