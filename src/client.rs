//! Async Modbus client (master).

use crate::codec::{self, RegisterOrder, RegisterValue};
use crate::device_id::{DeviceIdCode, DeviceIdReport, DeviceIdentification};
use crate::error::{Error, ProtocolError};
use crate::frame::{encode_mbap, encode_rtu, read_mbap, Framing, MbapRead, RtuBuffer};
use crate::pdu::{response_len_for, response_needs_silence, Request, Response};
use crate::trace::{self, Direction, FrameTrace};
use crate::types::{AddressRange, UnitId};
use std::future::Future;
use std::pin::Pin;
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
    /// How often a request is repeated after a timeout or a connection failure
    /// (0 = never). Exceptions and protocol errors are never retried.
    pub retries: u32,
    /// Pause between retries.
    pub retry_delay: Duration,
    /// RTU only: line silence that ends a response whose length cannot be predicted
    /// (custom function codes).
    pub rtu_frame_gap: Duration,
    /// Called with every sent / received frame.
    pub trace: Option<FrameTrace>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            response_timeout: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(3),
            broadcast_delay: Duration::from_millis(100),
            retries: 0,
            retry_delay: Duration::from_millis(50),
            rtu_frame_gap: Duration::from_millis(50),
            trace: None,
        }
    }
}

/// A boxed byte stream the client talks over.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

type ConnectFuture = Pin<Box<dyn Future<Output = std::io::Result<Box<dyn Stream>>> + Send>>;
type Connector = Arc<dyn Fn() -> ConnectFuture + Send + Sync>;

struct Session {
    framing: Framing,
    /// Opens a fresh stream; `None` for a one-shot user-supplied stream.
    connector: Option<Connector>,
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
        Self::new(Framing::Tcp, Some(tcp_connector(addr.into())), None, config)
    }

    /// RTU framing over a TCP socket (serial-to-Ethernet gateways in transparent mode).
    pub fn rtu_over_tcp(addr: impl Into<String>, config: ClientConfig) -> Client {
        Self::new(Framing::Rtu, Some(tcp_connector(addr.into())), None, config)
    }

    /// A client that opens its stream with `connect` (lazily, and again after every failure).
    ///
    /// Use it for transports this crate does not open itself: TLS (Modbus/TCP Security),
    /// a serial port that should be re-opened after a USB adapter is unplugged, etc.
    pub fn with_connector<F, Fut, S>(framing: Framing, config: ClientConfig, connect: F) -> Client
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = std::io::Result<S>> + Send + 'static,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connector: Connector = Arc::new(move || {
            let fut = connect();
            Box::pin(async move { Ok(Box::new(fut.await?) as Box<dyn Stream>) })
        });
        Self::new(framing, Some(connector), None, config)
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
        connector: Option<Connector>,
        stream: Option<Box<dyn Stream>>,
        config: ClientConfig,
    ) -> Client {
        Client {
            session: Arc::new(Mutex::new(Session {
                framing,
                connector,
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
        let mut attempt = 0;
        loop {
            let result = session.transact(unit, request).await;
            let retryable = matches!(result, Err(Error::Timeout) | Err(Error::Io(_)));
            if !retryable || attempt >= session.config.retries {
                return result;
            }
            attempt += 1;
            tokio::time::sleep(session.config.retry_delay).await;
        }
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

impl Client {
    /// FC 0x07: the eight exception status bits of a serial device.
    pub async fn read_exception_status(&self, unit: UnitId) -> Result<u8, Error> {
        match self.request(unit, &Request::ReadExceptionStatus).await? {
            Response::ReadExceptionStatus(v) => Ok(v),
            _ => Err(unexpected()),
        }
    }

    /// FC 0x08 with any sub-function; returns the response data words.
    pub async fn diagnostics(
        &self,
        unit: UnitId,
        sub_function: u16,
        data: &[u16],
    ) -> Result<Vec<u16>, Error> {
        let req = Request::Diagnostics {
            sub_function,
            data: data.to_vec(),
        };
        match self.request(unit, &req).await? {
            Response::Diagnostics { data, .. } => Ok(data),
            _ => Err(unexpected()),
        }
    }

    /// Diagnostics "return query data": a loopback test of the whole link.
    pub async fn loopback(&self, unit: UnitId, data: &[u16]) -> Result<(), Error> {
        self.diagnostics(unit, 0x0000, data).await.map(drop)
    }

    /// FC 0x0B: `(status, event_count)`.
    pub async fn get_comm_event_counter(&self, unit: UnitId) -> Result<(u16, u16), Error> {
        match self.request(unit, &Request::GetCommEventCounter).await? {
            Response::GetCommEventCounter {
                status,
                event_count,
            } => Ok((status, event_count)),
            _ => Err(unexpected()),
        }
    }

    /// FC 0x11: device-specific identification bytes.
    pub async fn report_server_id(&self, unit: UnitId) -> Result<Vec<u8>, Error> {
        match self.request(unit, &Request::ReportServerId).await? {
            Response::ReportServerId(v) => Ok(v),
            _ => Err(unexpected()),
        }
    }

    /// FC 0x18: the content of the FIFO queue at `address`.
    pub async fn read_fifo_queue(&self, unit: UnitId, address: u16) -> Result<Vec<u16>, Error> {
        match self
            .request(unit, &Request::ReadFifoQueue { address })
            .await?
        {
            Response::ReadFifoQueue(v) => Ok(v),
            _ => Err(unexpected()),
        }
    }

    /// FC 0x2B / 0x0E stream access: collects every object of the category, following
    /// "more follows" across as many requests as needed.
    pub async fn read_device_identification(
        &self,
        unit: UnitId,
        code: DeviceIdCode,
    ) -> Result<DeviceIdReport, Error> {
        if code == DeviceIdCode::Specific {
            return Err(Error::InvalidRequest(
                "use read_device_identification_object for individual access",
            ));
        }
        let mut identification = DeviceIdentification::default();
        let mut object_id = 0u8;
        // At most 256 objects exist, and each response must advance.
        for _ in 0..=256 {
            let req = Request::ReadDeviceIdentification { code, object_id };
            let Response::ReadDeviceIdentification(resp) = self.request(unit, &req).await? else {
                return Err(unexpected());
            };
            let conformity_level = resp.conformity_level;
            for (id, value) in resp.objects {
                identification.insert(id, value);
            }
            if !resp.more_follows {
                return Ok(DeviceIdReport {
                    conformity_level,
                    identification,
                });
            }
            if resp.next_object_id <= object_id {
                return Err(ProtocolError::Malformed("next object id does not advance").into());
            }
            object_id = resp.next_object_id;
        }
        Err(ProtocolError::Malformed("device identification never ends").into())
    }

    /// FC 0x2B / 0x0E individual access: one object's value.
    pub async fn read_device_identification_object(
        &self,
        unit: UnitId,
        object_id: u8,
    ) -> Result<Vec<u8>, Error> {
        let req = Request::ReadDeviceIdentification {
            code: DeviceIdCode::Specific,
            object_id,
        };
        match self.request(unit, &req).await? {
            Response::ReadDeviceIdentification(mut r) => Ok(r.objects.remove(0).1),
            _ => Err(unexpected()),
        }
    }

    /// Send a raw request with any function code and return the raw response data.
    pub async fn custom(&self, unit: UnitId, function: u8, data: &[u8]) -> Result<Vec<u8>, Error> {
        let req = Request::Custom {
            function,
            data: data.to_vec(),
        };
        match self.request(unit, &req).await? {
            Response::Custom { data, .. } => Ok(data),
            _ => Err(unexpected()),
        }
    }

    // ---- typed values ------------------------------------------------------

    /// Read one `f32` / `u32` / `i64` / ... from holding registers.
    pub async fn read_holding<T: RegisterValue>(
        &self,
        unit: UnitId,
        address: u16,
        order: RegisterOrder,
    ) -> Result<T, Error> {
        Ok(self
            .read_holding_values::<T>(unit, address, 1, order)
            .await?[0])
    }

    /// Read `count` consecutive typed values from holding registers.
    pub async fn read_holding_values<T: RegisterValue>(
        &self,
        unit: UnitId,
        address: u16,
        count: u16,
        order: RegisterOrder,
    ) -> Result<Vec<T>, Error> {
        let words = typed_words::<T>(count)?;
        let regs = self.read_holding_registers(unit, address, words).await?;
        codec::decode_all(&regs, order).ok_or_else(unexpected)
    }

    /// Read one typed value from input registers.
    pub async fn read_input<T: RegisterValue>(
        &self,
        unit: UnitId,
        address: u16,
        order: RegisterOrder,
    ) -> Result<T, Error> {
        Ok(self.read_input_values::<T>(unit, address, 1, order).await?[0])
    }

    /// Read `count` consecutive typed values from input registers.
    pub async fn read_input_values<T: RegisterValue>(
        &self,
        unit: UnitId,
        address: u16,
        count: u16,
        order: RegisterOrder,
    ) -> Result<Vec<T>, Error> {
        let words = typed_words::<T>(count)?;
        let regs = self.read_input_registers(unit, address, words).await?;
        codec::decode_all(&regs, order).ok_or_else(unexpected)
    }

    /// Write typed values to consecutive holding registers (FC 0x10).
    pub async fn write_holding_values<T: RegisterValue>(
        &self,
        unit: UnitId,
        address: u16,
        values: &[T],
        order: RegisterOrder,
    ) -> Result<(), Error> {
        let regs = codec::encode_all(values, order);
        self.write_multiple_registers(unit, address, &regs).await
    }
}

fn typed_words<T: RegisterValue>(count: u16) -> Result<u16, Error> {
    u16::try_from(count as usize * T::WORDS).map_err(|_| Error::InvalidRequest("too many values"))
}

fn tcp_connector(addr: String) -> Connector {
    let addr = Arc::new(addr);
    Arc::new(move || {
        let addr = addr.clone();
        Box::pin(async move {
            let stream = TcpStream::connect(addr.as_str()).await?;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as Box<dyn Stream>)
        })
    })
}

fn unexpected() -> Error {
    Error::Protocol(ProtocolError::BadLength)
}

impl Session {
    async fn ensure_connected(&mut self) -> Result<(), Error> {
        if self.stream.is_some() {
            return Ok(());
        }
        let Some(connector) = &self.connector else {
            return Err(Error::NoConnection);
        };
        let stream = timeout(self.config.connect_timeout, connector())
            .await
            .map_err(|_| Error::Timeout)??;
        self.stream = Some(stream);
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
        trace::emit(&self.config.trace, Direction::Tx, &self.tx_buf);
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
            if self.config.trace.is_some() {
                let mut raw = Vec::with_capacity(frame.pdu.len() + 7);
                encode_mbap(frame.transaction, frame.unit, &frame.pdu, &mut raw);
                trace::emit(&self.config.trace, Direction::Rx, &raw);
            }
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

        // Some responses (custom function codes, device-specific diagnostics) have no
        // predictable length: their end is line silence.
        let by_silence = response_needs_silence(request);
        let predict = |p: &[u8]| response_len_for(request, p);
        let deadline = Instant::now() + self.config.response_timeout;
        let mut scratch = [0u8; 256];
        loop {
            while let Some(frame) = self.rtu.next_frame(&predict, !by_silence) {
                if let Some(r) = self.accept_rtu(unit, request, frame) {
                    return r;
                }
            }
            let gap_deadline = if by_silence && !self.rtu.is_empty() {
                deadline.min(Instant::now() + self.config.rtu_frame_gap)
            } else {
                deadline
            };
            let stream = self.stream.as_mut().ok_or(Error::NoConnection)?;
            let n = match timeout_at(gap_deadline, stream.read(&mut scratch)).await {
                Err(_) if gap_deadline < deadline => {
                    if let Some(frame) = self.rtu.take_on_silence() {
                        if let Some(r) = self.accept_rtu(unit, request, frame) {
                            return r;
                        }
                    }
                    continue;
                }
                Err(_) => return Err(Error::Timeout),
                Ok(r) => r?,
            };
            if n == 0 {
                return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
            }
            self.rtu.extend(&scratch[..n]);
        }
    }

    /// `Some` when `frame` is the answer we wait for.
    fn accept_rtu(
        &self,
        unit: UnitId,
        request: &Request,
        frame: crate::frame::RtuFrame,
    ) -> Option<Result<Response, Error>> {
        if self.config.trace.is_some() {
            let mut raw = Vec::with_capacity(frame.pdu.len() + 3);
            encode_rtu(frame.unit, &frame.pdu, &mut raw);
            trace::emit(&self.config.trace, Direction::Rx, &raw);
        }
        // Another station's traffic (or our own echo on a 2-wire bus) is ignored.
        (frame.unit == unit.0).then(|| Response::decode(request, &frame.pdu))
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
