//! # su-bus
//!
//! Async Modbus client and server for Tokio, supporting
//! Modbus TCP, Modbus RTU (any byte stream, e.g. a serial port) and RTU-over-TCP.
//!
//! Written from scratch from the public Modbus specifications
//! ("MODBUS Application Protocol" and "MODBUS over Serial Line").
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
pub mod error;
pub mod frame;
pub mod pdu;
pub mod server;
pub mod types;

pub use client::{Client, ClientConfig};
pub use error::{Error, ProtocolError};
pub use frame::Framing;
pub use pdu::{Request, Response};
pub use types::{AddressRange, ExceptionCode, UnitId};
