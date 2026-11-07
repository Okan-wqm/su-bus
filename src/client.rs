//! Async Modbus client (master).

use crate::error::{Error, ProtocolError};
use crate::frame::{encode_mbap, encode_rtu, read_mbap, Framing, MbapRead, RtuBuffer};
use crate::pdu::{response_len, Request, Response};
use crate::types::{AddressRange, UnitId};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{timeout, timeout_at, Instant};

/// Client behaviour settings.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// How long to wait for a response.
    pub response_timeout: Duration,
    /// How long to wait when (re)connecting a TCP socket.
    pub connect_timeout: Duration,
    /// Serial only: pause after a broadcast so slaves can process it before the next request.
    pub broadcast_delay: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            response_timeout: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(3),
            broadcast_delay: Duration::from_millis(100),
        }
    }
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

struct Session {
    framing: Framing,
    /// Address to (re)connect to; `None` for user-supplied streams.
    endpoint: Option<String>,
    stream: Option<Box<dyn Stream>>,
    transaction: u16,
    rtu: RtuBuffer,
    config: ClientConfig,
    tx_buf: Vec<u8>,
}

/// A Modbus client. Cheap to clone; clones share the same connection and requests
/// are executed one at a time (as required by serial lines and most TCP devices).
///
/// TCP clients connect lazily and transparently reconnect after a connection failure.
#[derive(Clone)]
pub struct Client {
    session: Arc<Mutex<Session>>,
}

impl Client {
    /// Modbus TCP client (MBAP framing) for `addr`, e.g. `"192.168.1.10:502"`.
    pub fn tcp(addr: impl Into<String>, config: ClientConfig) -> Client {
        Self::new(Framing::Tcp, Some(addr.into()), None, config)
    }

    /// RTU framing over a TCP socket (serial-to-Ethernet gateways in transparent mode).
    pub fn rtu_over_tcp(addr: impl Into<String>, config: ClientConfig) -> Client {
        Self::new(Framing::Rtu, Some(addr.into()), None, config)
    }

    /// Use any byte stream, e.g. a serial port from `tokio-serial` with [`Framing::Rtu`].
    /// No automatic reconnect: once the stream fails, requests return [`Error::NoConnection`].
    pub fn from_stream<S>(stream: S, framing: Framing, config: ClientConfig) -> Client
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new(framing, None, Some(Box::new(stream)), config)
    }

    fn new(
        framing: Framing,
        endpoint: Option<String>,
        stream: Option<Box<dyn Stream>>,
        config: ClientConfig,
    ) -> Client {
        Client {
            session: Arc::new(Mutex::new(Session {
                framing,
                endpoint,
                stream,
                transaction: 0,
                rtu: RtuBuffer::new(),
                config,
                tx_buf: Vec::with_capacity(260),
            })),
        }
    }

    /// Change the response timeout for subsequent requests.
    pub async fn set_response_timeout(&self, t: Duration) {
        self.session.lock().await.config.response_timeout = t;
    }

    /// Close the current connection (a TCP client reconnects on the next request).
    pub async fn disconnect(&self) {
        self.session.lock().await.stream = None;
    }

    /// Send any request and wait for its response.
    pub async fn request(&self, unit: UnitId, request: &Request) -> Result<Response, Error> {
        request.validate()?;
        let mut session = self.session.lock().await;
        if unit.is_broadcast() && session.framing == Framing::Rtu {
            return Err(Error::InvalidRequest(
                "unit 0 is the serial broadcast address; use Client::broadcast",
            ));
        }
        session.transact(unit, request).await
    }

    /// Serial-line broadcast (unit 0) of a write request. No response is expected.
    pub async fn broadcast(&self, request: &Request) -> Result<(), Error> {
        request.validate()?;
        if !request.is_write_only() {
            return Err(Error::InvalidRequest(
                "only write requests can be broadcast",
            ));
        }
        let mut session = self.session.lock().await;
        session.send_broadcast(request).await
    }

    // ---- convenience wrappers --------------------------------------------

    pub async fn read_coils(
        &self,
        unit: UnitId,
        start: u16,
        count: u16,
    ) -> Result<Vec<bool>, Error> {
        match self
            .request(unit, &Request::ReadCoils(AddressRange::new(start, count)))
            .await?
        {
            Response::ReadCoils(v) => Ok(v),
            _ => Err(unexpected()),
        }
    }

    pub async fn read_discrete_inputs(
        &self,
        unit: UnitId,
        start: u16,
        count: u16,
    ) -> Result<Vec<bool>, Error> {
        match self
            .request(
                unit,
                &Request::ReadDiscreteInputs(AddressRange::new(start, count)),
            )
            .await?
        {
            Response::ReadDiscreteInputs(v) => Ok(v),
            _ => Err(unexpected()),
        }
    }

    pub async fn read_holding_registers(
        &self,
        unit: UnitId,
        start: u16,
        count: u16,
    ) -> Result<Vec<u16>, Error> {
        match self
            .request(
                unit,
                &Request::ReadHoldingRegisters(AddressRange::new(start, count)),
            )
            .await?
        {
            Response::ReadHoldingRegisters(v) => Ok(v),
            _ => Err(unexpected()),
        }
    }

    pub async fn read_input_registers(
        &self,
        unit: UnitId,
        start: u16,
        count: u16,
    ) -> Result<Vec<u16>, Error> {
        match self
            .request(
                unit,
                &Request::ReadInputRegisters(AddressRange::new(start, count)),
            )
            .await?
        {
            Response::ReadInputRegisters(v) => Ok(v),
            _ => Err(unexpected()),
        }
    }

    pub async fn write_single_coil(
        &self,
        unit: UnitId,
        address: u16,
        value: bool,
    ) -> Result<(), Error> {
        self.request(unit, &Request::WriteSingleCoil { address, value })
            .await
            .map(drop)
    }

    pub async fn write_single_register(
        &self,
        unit: UnitId,
        address: u16,
        value: u16,
    ) -> Result<(), Error> {
        self.request(unit, &Request::WriteSingleRegister { address, value })
            .await
            .map(drop)
    }

    pub async fn write_multiple_coils(
        &self,
        unit: UnitId,
        start: u16,
        values: &[bool],
    ) -> Result<(), Error> {
        let req = Request::WriteMultipleCoils {
            start,
            values: values.to_vec(),
        };
        self.request(unit, &req).await.map(drop)
    }

    pub async fn write_multiple_registers(
        &self,
        unit: UnitId,
        start: u16,
        values: &[u16],
    ) -> Result<(), Error> {
        let req = Request::WriteMultipleRegisters {
            start,
            values: values.to_vec(),
        };
        self.request(unit, &req).await.map(drop)
    }

    pub async fn mask_write_register(
        &self,
        unit: UnitId,
        address: u16,
        and_mask: u16,
        or_mask: u16,
    ) -> Result<(), Error> {
        let req = Request::MaskWriteRegister {
            address,
            and_mask,
            or_mask,
        };
        self.request(unit, &req).await.map(drop)
    }

    /// Write `values` at `write_start`, then read `read_count` registers at `read_start`, atomically.
    pub async fn read_write_multiple_registers(
        &self,
        unit: UnitId,
        read_start: u16,
        read_count: u16,
        write_start: u16,
        values: &[u16],
    ) -> Result<Vec<u16>, Error> {
        let req = Request::ReadWriteMultipleRegisters {
            read: AddressRange::new(read_start, read_count),
            write_start,
            values: values.to_vec(),
        };
        match self.request(unit, &req).await? {
            Response::ReadWriteMultipleRegisters(v) => Ok(v),
            _ => Err(unexpected()),
        }
    }
}

fn unexpected() -> Error {
    Error::Protocol(ProtocolError::BadLength)
}

impl Session {
    async fn ensure_connected(&mut self) -> Result<(), Error> {
        if self.stream.is_some() {
            return Ok(());
        }
        let Some(addr) = &self.endpoint else {
            return Err(Error::NoConnection);
        };
        let stream = timeout(
            self.config.connect_timeout,
            TcpStream::connect(addr.as_str()),
        )
        .await
        .map_err(|_| Error::Timeout)??;
        stream.set_nodelay(true)?;
        self.stream = Some(Box::new(stream));
        self.rtu.clear();
        Ok(())
    }

    async fn transact(&mut self, unit: UnitId, request: &Request) -> Result<Response, Error> {
        self.ensure_connected().await?;
        let result = match self.framing {
            Framing::Tcp => self.transact_tcp(unit, request).await,
            Framing::Rtu => self.transact_rtu(unit, request).await,
        };
        // Drop the connection after I/O failures or framing desync; it will be re-opened.
        if matches!(
            result,
            Err(Error::Io(_)) | Err(Error::Protocol(ProtocolError::BadMbapHeader))
        ) {
            self.stream = None;
        }
        result
    }

    async fn write_frame(&mut self) -> Result<(), Error> {
        let stream = self.stream.as_mut().ok_or(Error::NoConnection)?;
        stream.write_all(&self.tx_buf).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn transact_tcp(&mut self, unit: UnitId, request: &Request) -> Result<Response, Error> {
        self.transaction = self.transaction.wrapping_add(1);
        let tx = self.transaction;
        self.tx_buf.clear();
        let mut pdu = Vec::with_capacity(256);
        request.encode(&mut pdu);
        encode_mbap(tx, unit.0, &pdu, &mut self.tx_buf);
        self.write_frame().await?;

        let deadline = Instant::now() + self.config.response_timeout;
        let stream = self.stream.as_mut().ok_or(Error::NoConnection)?;
        loop {
            let frame = match timeout_at(deadline, read_mbap(stream)).await {
                Err(_) => return Err(Error::Timeout),
                Ok(r) => match r? {
                    MbapRead::Frame(f) => f,
                    MbapRead::Invalid(e) => return Err(e.into()),
                },
            };
            if frame.transaction != tx {
                // Late answer to an earlier (timed-out) request: ignore it.
                continue;
            }
            if frame.unit != unit.0 {
                return Err(ProtocolError::UnexpectedUnit {
                    expected: unit.0,
                    actual: frame.unit,
                }
                .into());
            }
            return Response::decode(request, &frame.pdu);
        }
    }

    /// Discard any bytes already waiting (e.g. a late answer to a timed-out request).
    async fn drain_rtu(&mut self) -> Result<(), Error> {
        self.rtu.clear();
        let stream = self.stream.as_mut().ok_or(Error::NoConnection)?;
        let mut scratch = [0u8; 256];
        loop {
            match timeout(Duration::ZERO, stream.read(&mut scratch)).await {
                Err(_) => return Ok(()),
                Ok(Ok(0)) => {
                    return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
                }
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => return Err(e.into()),
            }
        }
    }

    async fn transact_rtu(&mut self, unit: UnitId, request: &Request) -> Result<Response, Error> {
        self.drain_rtu().await?;
        self.tx_buf.clear();
        let mut pdu = Vec::with_capacity(256);
        request.encode(&mut pdu);
        encode_rtu(unit.0, &pdu, &mut self.tx_buf);
        self.write_frame().await?;

        let deadline = Instant::now() + self.config.response_timeout;
        let mut scratch = [0u8; 256];
        loop {
            while let Some(frame) = self.rtu.next_frame(response_len, true) {
                if frame.unit == unit.0 {
                    return Response::decode(request, &frame.pdu);
                }
                // Another station's traffic (or echo on a 2-wire bus): ignore.
            }
            let stream = self.stream.as_mut().ok_or(Error::NoConnection)?;
            let n = match timeout_at(deadline, stream.read(&mut scratch)).await {
                Err(_) => return Err(Error::Timeout),
                Ok(r) => r?,
            };
            if n == 0 {
                return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
            }
            self.rtu.extend(&scratch[..n]);
        }
    }

    async fn send_broadcast(&mut self, request: &Request) -> Result<(), Error> {
        self.ensure_connected().await?;
        let mut pdu = Vec::with_capacity(256);
        request.encode(&mut pdu);
        self.tx_buf.clear();
        match self.framing {
            Framing::Rtu => {
                self.drain_rtu().await?;
                encode_rtu(0, &pdu, &mut self.tx_buf);
            }
            Framing::Tcp => {
                return Err(Error::InvalidRequest(
                    "broadcast is only defined for serial (RTU) framing",
                ))
            }
        }
        let r = self.write_frame().await;
        if r.is_err() {
            self.stream = None;
        }
        r?;
        tokio::time::sleep(self.config.broadcast_delay).await;
        Ok(())
    }
}
