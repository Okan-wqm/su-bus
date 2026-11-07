//! Async Modbus server (slave).

use crate::device_id::{DeviceIdCode, DeviceIdResponse, DeviceIdentification};
use crate::frame::{encode_mbap, encode_rtu, read_mbap, MbapRead, RtuBuffer, RtuFrame};
use crate::pdu::limits::{MAX_CUSTOM_DATA, MAX_FIFO_COUNT, MAX_PDU_LEN, MAX_SERVER_ID_LEN};
use crate::pdu::{apply_mask, request_len, Request, Response};
use crate::trace::{self, Direction, FrameTrace};
use crate::types::{AddressRange, ExceptionCode, UnitId};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::task::{JoinHandle, JoinSet};

/// Application callbacks for one unit id. Every method has a default implementation
/// returning `IllegalFunction`, so implement only what the device supports.
///
/// Read methods must return exactly `range.count` items; anything else is reported to
/// the client as `ServerDeviceFailure`.
pub trait RequestHandler: Send + 'static {
    fn read_coils(&mut self, _range: AddressRange) -> Result<Vec<bool>, ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    fn read_discrete_inputs(&mut self, _range: AddressRange) -> Result<Vec<bool>, ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    fn read_holding_registers(&mut self, _range: AddressRange) -> Result<Vec<u16>, ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    fn read_input_registers(&mut self, _range: AddressRange) -> Result<Vec<u16>, ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    fn write_single_coil(&mut self, _address: u16, _value: bool) -> Result<(), ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    fn write_single_register(&mut self, _address: u16, _value: u16) -> Result<(), ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    fn write_multiple_coils(&mut self, _start: u16, _values: &[bool]) -> Result<(), ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    fn write_multiple_registers(
        &mut self,
        _start: u16,
        _values: &[u16],
    ) -> Result<(), ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    /// Default: read the register, apply the mask, write it back.
    fn mask_write_register(
        &mut self,
        address: u16,
        and_mask: u16,
        or_mask: u16,
    ) -> Result<(), ExceptionCode> {
        let current = self.read_holding_registers(AddressRange::new(address, 1))?;
        let current = *current.first().ok_or(ExceptionCode::ServerDeviceFailure)?;
        self.write_single_register(address, apply_mask(current, and_mask, or_mask))
    }
    /// Default: write first, then read (as the specification requires).
    fn read_write_multiple_registers(
        &mut self,
        read: AddressRange,
        write_start: u16,
        values: &[u16],
    ) -> Result<Vec<u16>, ExceptionCode> {
        self.write_multiple_registers(write_start, values)?;
        self.read_holding_registers(read)
    }
    /// FC 0x07: eight device-specific status bits.
    fn read_exception_status(&mut self) -> Result<u8, ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    /// Value returned by diagnostics sub-function 0x02 ("return diagnostic register").
    fn diagnostic_register(&mut self) -> u16 {
        0
    }
    /// Diagnostics sub-functions not handled by the server core
    /// (the core handles 0x00, 0x01, 0x02, 0x0A and the counters 0x0B..=0x0F).
    fn diagnostics(
        &mut self,
        _sub_function: u16,
        _data: &[u16],
    ) -> Result<Vec<u16>, ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    /// FC 0x11: device-specific bytes (typically server id, run indicator 0xFF/0x00, extra data).
    fn report_server_id(&mut self) -> Result<Vec<u8>, ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    /// FC 0x18: the queued values (at most 31) at `address`.
    fn read_fifo_queue(&mut self, _address: u16) -> Result<Vec<u16>, ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
    /// FC 0x2B / 0x0E: identification objects; the core implements stream / individual access.
    fn device_identification(&mut self) -> Option<&DeviceIdentification> {
        None
    }
    /// Any function code without dedicated support (user-defined codes 65-72, 100-110, ...).
    /// Returns the response data (after the function code).
    fn custom_function(&mut self, _function: u8, _data: &[u8]) -> Result<Vec<u8>, ExceptionCode> {
        Err(ExceptionCode::IllegalFunction)
    }
}

// ---------------------------------------------------------------------------
// Communication counters (diagnostics sub-functions 0x0B..=0x0F, FC 0x0B)
// ---------------------------------------------------------------------------

/// Communication counters kept by a server, as defined for the diagnostics function.
/// All counters wrap at 0xFFFF.
#[derive(Debug, Default)]
pub struct CommCounters {
    bus_messages: AtomicU16,
    bus_comm_errors: AtomicU16,
    bus_exceptions: AtomicU16,
    server_messages: AtomicU16,
    server_no_response: AtomicU16,
    events: AtomicU16,
}

/// A copy of the counters at one point in time.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CounterSnapshot {
    /// Valid frames seen (to any unit).
    pub bus_messages: u16,
    /// CRC errors (serial lines).
    pub bus_comm_errors: u16,
    /// Exception responses sent.
    pub bus_exceptions: u16,
    /// Frames addressed to this server (including broadcasts).
    pub server_messages: u16,
    /// Frames addressed to this server that got no response (broadcasts).
    pub server_no_response: u16,
    /// Successfully completed requests (the "comm event counter" of FC 0x0B).
    pub events: u16,
}

fn inc(c: &AtomicU16) {
    c.fetch_add(1, Ordering::Relaxed);
}

impl CommCounters {
    pub fn snapshot(&self) -> CounterSnapshot {
        let g = |c: &AtomicU16| c.load(Ordering::Relaxed);
        CounterSnapshot {
            bus_messages: g(&self.bus_messages),
            bus_comm_errors: g(&self.bus_comm_errors),
            bus_exceptions: g(&self.bus_exceptions),
            server_messages: g(&self.server_messages),
            server_no_response: g(&self.server_no_response),
            events: g(&self.events),
        }
    }

    pub fn clear(&self) {
        for c in [
            &self.bus_messages,
            &self.bus_comm_errors,
            &self.bus_exceptions,
            &self.server_messages,
            &self.server_no_response,
            &self.events,
        ] {
            c.store(0, Ordering::Relaxed);
        }
    }

    fn add_comm_errors(&self, n: u32) {
        if n > 0 {
            self.bus_comm_errors
                .fetch_add(n.min(u16::MAX as u32) as u16, Ordering::Relaxed);
        }
    }

    fn by_sub_function(&self, sub: u16) -> Option<u16> {
        let s = self.snapshot();
        Some(match sub {
            0x0B => s.bus_messages,
            0x0C => s.bus_comm_errors,
            0x0D => s.bus_exceptions,
            0x0E => s.server_messages,
            0x0F => s.server_no_response,
            _ => return None,
        })
    }
}

/// Shared handle to a handler; keep a clone to update the data from your application.
pub type SharedHandler = Arc<Mutex<dyn RequestHandler>>;

/// Lock a handler, ignoring poisoning (a panicking callback must not kill the server).
pub fn lock<T: ?Sized>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Maps unit ids to handlers. Clones share the same handlers and counters.
#[derive(Clone, Default)]
pub struct ServerHandlers {
    map: HashMap<UnitId, SharedHandler>,
    fallback: Option<SharedHandler>,
    counters: Arc<CommCounters>,
}

impl ServerHandlers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler; returns `self` for chaining.
    pub fn with<H: RequestHandler>(mut self, unit: UnitId, handler: Arc<Mutex<H>>) -> Self {
        self.insert(unit, handler);
        self
    }

    pub fn insert<H: RequestHandler>(&mut self, unit: UnitId, handler: Arc<Mutex<H>>) {
        self.map.insert(unit, handler);
    }

    /// Answer requests for every unit id without its own handler (typical for a TCP
    /// device that ignores the unit id, which is often 0xFF or 0 on Modbus TCP).
    pub fn with_default<H: RequestHandler>(mut self, handler: Arc<Mutex<H>>) -> Self {
        self.fallback = Some(handler);
        self
    }

    /// Handler registered for exactly this unit.
    pub fn get(&self, unit: UnitId) -> Option<&SharedHandler> {
        self.map.get(&unit)
    }

    /// Handler that answers `unit` (its own one, else the default handler).
    pub fn resolve(&self, unit: UnitId) -> Option<&SharedHandler> {
        self.map.get(&unit).or(self.fallback.as_ref())
    }

    /// Communication counters of servers using these handlers.
    pub fn counters(&self) -> &Arc<CommCounters> {
        &self.counters
    }

    fn all(&self) -> impl Iterator<Item = &SharedHandler> {
        self.map.values().chain(self.fallback.iter())
    }
}

/// Process one request PDU and append the response PDU to `out` (no counters kept).
pub fn handle_pdu(handler: &mut dyn RequestHandler, pdu: &[u8], out: &mut Vec<u8>) {
    process_pdu(handler, &CommCounters::default(), pdu, out)
}

/// Process one request PDU addressed to this server, updating `counters`.
pub fn process_pdu(
    handler: &mut dyn RequestHandler,
    counters: &CommCounters,
    pdu: &[u8],
    out: &mut Vec<u8>,
) {
    inc(&counters.server_messages);
    let function = pdu.first().copied().unwrap_or(0);
    let result = Request::decode(pdu).and_then(|req| {
        let resp = execute(handler, counters, &req)?;
        // Polls of the event counter itself are not counted (as specified).
        if !matches!(req, Request::GetCommEventCounter) {
            inc(&counters.events);
        }
        Ok(resp)
    });
    match result {
        Ok(resp) => resp.encode(out),
        Err(code) => {
            inc(&counters.bus_exceptions);
            Response::encode_exception(function, code, out)
        }
    }
}

/// Build one device identification response (stream or individual access).
pub fn build_device_id_response(
    info: &DeviceIdentification,
    code: DeviceIdCode,
    object_id: u8,
) -> Result<DeviceIdResponse, ExceptionCode> {
    let conformity_level = info.conformity_level();
    if code == DeviceIdCode::Specific {
        let value = info
            .get(object_id)
            .ok_or(ExceptionCode::IllegalDataAddress)?;
        return Ok(DeviceIdResponse {
            code,
            conformity_level,
            more_follows: false,
            next_object_id: 0,
            objects: vec![(object_id, value.to_vec())],
        });
    }
    let max = code.max_object();
    // An unknown starting object restarts the stream at the beginning.
    let start = if object_id <= max && info.get(object_id).is_some() {
        object_id
    } else {
        0
    };
    const HEADER: usize = 7;
    let mut size = HEADER;
    let mut objects = Vec::new();
    let mut more_follows = false;
    let mut next_object_id = 0;
    for (id, value) in info.iter().filter(|(id, _)| (start..=max).contains(id)) {
        if size + 2 + value.len() > MAX_PDU_LEN {
            more_follows = true;
            next_object_id = id;
            break;
        }
        size += 2 + value.len();
        objects.push((id, value.to_vec()));
    }
    if objects.is_empty() && !more_follows {
        // Nothing in this category (e.g. no mandatory basic objects configured).
        return Err(ExceptionCode::IllegalDataAddress);
    }
    Ok(DeviceIdResponse {
        code,
        conformity_level,
        more_follows,
        next_object_id,
        objects,
    })
}

fn diagnostics(
    h: &mut dyn RequestHandler,
    counters: &CommCounters,
    sub: u16,
    data: &[u16],
) -> Result<Vec<u16>, ExceptionCode> {
    let single_zero = || {
        if data == [0] {
            Ok(())
        } else {
            Err(ExceptionCode::IllegalDataValue)
        }
    };
    Ok(match sub {
        // Return query data
        0x00 => data.to_vec(),
        // Restart communications option (data 0x0000 or 0xFF00 = also clear the event log)
        0x01 => {
            if data != [0x0000] && data != [0xFF00] {
                return Err(ExceptionCode::IllegalDataValue);
            }
            counters.clear();
            data.to_vec()
        }
        0x02 => {
            single_zero()?;
            vec![h.diagnostic_register()]
        }
        0x0A => {
            single_zero()?;
            counters.clear();
            data.to_vec()
        }
        0x0B..=0x0F => {
            single_zero()?;
            vec![counters.by_sub_function(sub).unwrap_or(0)]
        }
        other => h.diagnostics(other, data)?,
    })
}

fn exact<T>(v: Vec<T>, count: u16) -> Result<Vec<T>, ExceptionCode> {
    if v.len() == count as usize {
        Ok(v)
    } else {
        Err(ExceptionCode::ServerDeviceFailure)
    }
}

fn execute(
    h: &mut dyn RequestHandler,
    counters: &CommCounters,
    req: &Request,
) -> Result<Response, ExceptionCode> {
    Ok(match req {
        Request::ReadCoils(r) => Response::ReadCoils(exact(h.read_coils(*r)?, r.count)?),
        Request::ReadDiscreteInputs(r) => {
            Response::ReadDiscreteInputs(exact(h.read_discrete_inputs(*r)?, r.count)?)
        }
        Request::ReadHoldingRegisters(r) => {
            Response::ReadHoldingRegisters(exact(h.read_holding_registers(*r)?, r.count)?)
        }
        Request::ReadInputRegisters(r) => {
            Response::ReadInputRegisters(exact(h.read_input_registers(*r)?, r.count)?)
        }
        Request::WriteSingleCoil { address, value } => {
            h.write_single_coil(*address, *value)?;
            Response::WriteSingleCoil {
                address: *address,
                value: *value,
            }
        }
        Request::WriteSingleRegister { address, value } => {
            h.write_single_register(*address, *value)?;
            Response::WriteSingleRegister {
                address: *address,
                value: *value,
            }
        }
        Request::WriteMultipleCoils { start, values } => {
            h.write_multiple_coils(*start, values)?;
            Response::WriteMultipleCoils {
                start: *start,
                count: values.len() as u16,
            }
        }
        Request::WriteMultipleRegisters { start, values } => {
            h.write_multiple_registers(*start, values)?;
            Response::WriteMultipleRegisters {
                start: *start,
                count: values.len() as u16,
            }
        }
        Request::MaskWriteRegister {
            address,
            and_mask,
            or_mask,
        } => {
            h.mask_write_register(*address, *and_mask, *or_mask)?;
            Response::MaskWriteRegister {
                address: *address,
                and_mask: *and_mask,
                or_mask: *or_mask,
            }
        }
        Request::ReadWriteMultipleRegisters {
            read,
            write_start,
            values,
        } => {
            let v = h.read_write_multiple_registers(*read, *write_start, values)?;
            Response::ReadWriteMultipleRegisters(exact(v, read.count)?)
        }
        Request::ReadExceptionStatus => Response::ReadExceptionStatus(h.read_exception_status()?),
        Request::Diagnostics { sub_function, data } => Response::Diagnostics {
            sub_function: *sub_function,
            data: diagnostics(h, counters, *sub_function, data)?,
        },
        Request::GetCommEventCounter => Response::GetCommEventCounter {
            status: 0x0000,
            event_count: counters.snapshot().events,
        },
        Request::ReportServerId => {
            let bytes = h.report_server_id()?;
            if bytes.len() > MAX_SERVER_ID_LEN {
                return Err(ExceptionCode::ServerDeviceFailure);
            }
            Response::ReportServerId(bytes)
        }
        Request::ReadFifoQueue { address } => {
            let values = h.read_fifo_queue(*address)?;
            if values.len() > MAX_FIFO_COUNT {
                return Err(ExceptionCode::IllegalDataValue);
            }
            Response::ReadFifoQueue(values)
        }
        Request::ReadDeviceIdentification { code, object_id } => {
            let info = h
                .device_identification()
                .ok_or(ExceptionCode::IllegalFunction)?;
            Response::ReadDeviceIdentification(build_device_id_response(info, *code, *object_id)?)
        }
        Request::Custom { function, data } => {
            let data = h.custom_function(*function, data)?;
            if data.len() > MAX_CUSTOM_DATA {
                return Err(ExceptionCode::ServerDeviceFailure);
            }
            Response::Custom {
                function: *function,
                data,
            }
        }
    })
}

// ---------------------------------------------------------------------------
// TCP server
// ---------------------------------------------------------------------------

/// TCP server settings.
#[derive(Clone, Debug)]
pub struct TcpServerConfig {
    /// Maximum simultaneous client connections. When full, the *oldest* connection is
    /// closed to make room (dead half-open connections otherwise lock clients out).
    pub max_sessions: usize,
    /// Close a connection that sends nothing for this long (`None` = never).
    pub idle_timeout: Option<Duration>,
    /// Called with every received / sent MBAP frame.
    pub trace: Option<FrameTrace>,
}

impl Default for TcpServerConfig {
    fn default() -> Self {
        TcpServerConfig {
            max_sessions: 16,
            idle_timeout: Some(Duration::from_secs(120)),
            trace: None,
        }
    }
}

/// A running TCP server. Dropping the handle (or calling [`ServerHandle::shutdown`])
/// stops the listener and closes every connection.
pub struct ServerHandle {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl ServerHandle {
    /// The address actually bound (useful with port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn shutdown(self) {}
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Bind and start a Modbus TCP server in the background.
pub async fn spawn_tcp_server(
    addr: impl ToSocketAddrs,
    handlers: ServerHandlers,
    config: TcpServerConfig,
) -> std::io::Result<ServerHandle> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let task = tokio::spawn(run_tcp_server(listener, Arc::new(handlers), config));
    Ok(ServerHandle { local_addr, task })
}

async fn run_tcp_server(
    listener: TcpListener,
    handlers: Arc<ServerHandlers>,
    config: TcpServerConfig,
) {
    let max = config.max_sessions.max(1);
    let mut sessions: JoinSet<()> = JoinSet::new();
    // Accept order, used to evict the oldest session.
    let mut order: std::collections::VecDeque<tokio::task::AbortHandle> = Default::default();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (socket, _peer) = match accepted {
                    Ok(v) => v,
                    Err(_) => {
                        // e.g. too many open files: back off instead of spinning.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                order.retain(|h| !h.is_finished());
                while order.len() >= max {
                    if let Some(oldest) = order.pop_front() {
                        oldest.abort();
                    }
                }
                let _ = socket.set_nodelay(true);
                let h = sessions.spawn(tcp_session(socket, handlers.clone(), config.clone()));
                order.push_back(h);
            }
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
        }
    }
}

async fn tcp_session(socket: TcpStream, handlers: Arc<ServerHandlers>, config: TcpServerConfig) {
    let _ = serve_tcp_stream(socket, &handlers, &config).await;
}

/// Serve Modbus TCP (MBAP framing) on one already-accepted stream until it closes.
///
/// Use this to run the server over any transport, e.g. a TLS stream for Modbus/TCP Security.
pub async fn serve_tcp_stream<S>(
    mut stream: S,
    handlers: &ServerHandlers,
    config: &TcpServerConfig,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pdu_out = Vec::with_capacity(256);
    let mut frame_out = Vec::with_capacity(264);
    let counters = handlers.counters();
    loop {
        let read = read_mbap(&mut stream);
        let frame = match config.idle_timeout {
            Some(t) => match tokio::time::timeout(t, read).await {
                Ok(r) => r?,
                Err(_) => return Ok(()),
            },
            None => read.await?,
        };
        let frame = match frame {
            MbapRead::Frame(f) => f,
            MbapRead::Invalid(_) => return Ok(()), // cannot resynchronise a TCP stream
        };
        if config.trace.is_some() {
            frame_out.clear();
            encode_mbap(frame.transaction, frame.unit, &frame.pdu, &mut frame_out);
            trace::emit(&config.trace, Direction::Rx, &frame_out);
        }
        inc(&counters.bus_messages);
        let Some(handler) = handlers.resolve(UnitId(frame.unit)) else {
            continue; // not ours: stay silent, like an absent serial device
        };
        pdu_out.clear();
        process_pdu(&mut *lock(handler), counters, &frame.pdu, &mut pdu_out);
        frame_out.clear();
        encode_mbap(frame.transaction, frame.unit, &pdu_out, &mut frame_out);
        trace::emit(&config.trace, Direction::Tx, &frame_out);
        stream.write_all(&frame_out).await?;
        stream.flush().await?;
    }
}

// ---------------------------------------------------------------------------
// RTU server
// ---------------------------------------------------------------------------

/// RTU server settings.
#[derive(Clone, Debug)]
pub struct RtuServerConfig {
    /// A gap this long inside a partial frame ends it (the 3.5-character rule, with margin).
    pub frame_gap: Duration,
    /// Called with every received / sent RTU frame (with CRC).
    pub trace: Option<FrameTrace>,
}

impl Default for RtuServerConfig {
    fn default() -> Self {
        RtuServerConfig {
            frame_gap: Duration::from_millis(50),
            trace: None,
        }
    }
}

impl RtuServerConfig {
    /// Frame gap for a baud rate: 3.5 characters of 11 bits, at least 1.75 ms (as the
    /// specification recommends above 19200 baud), plus a margin for OS / USB adapter latency.
    pub fn for_baud_rate(baud: u32) -> Self {
        let char_time_us = 11_000_000u64 / baud.max(1) as u64;
        let gap_us = (char_time_us * 7 / 2).max(1_750);
        RtuServerConfig {
            frame_gap: Duration::from_micros(gap_us) + Duration::from_millis(20),
            trace: None,
        }
    }
}

/// Serve Modbus RTU on a byte stream (a serial port, or a TCP socket for RTU-over-TCP).
/// Runs until the stream reaches EOF or fails.
pub async fn serve_rtu<S>(
    mut stream: S,
    handlers: ServerHandlers,
    config: RtuServerConfig,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut rtu = RtuBuffer::new();
    let mut scratch = [0u8; 256];
    let mut out = Vec::with_capacity(260);

    let counters = handlers.counters().clone();
    loop {
        while let Some(frame) = rtu.next_frame(&request_len, false) {
            respond_rtu(&handlers, &config, frame, &mut stream, &mut out).await?;
        }
        counters.add_comm_errors(rtu.take_crc_errors());
        let n = if rtu.is_empty() {
            stream.read(&mut scratch).await?
        } else {
            match tokio::time::timeout(config.frame_gap, stream.read(&mut scratch)).await {
                Ok(r) => r?,
                Err(_) => {
                    if let Some(frame) = rtu.take_on_silence() {
                        respond_rtu(&handlers, &config, frame, &mut stream, &mut out).await?;
                    }
                    counters.add_comm_errors(rtu.take_crc_errors());
                    continue;
                }
            }
        };
        if n == 0 {
            return Ok(());
        }
        rtu.extend(&scratch[..n]);
    }
}

async fn respond_rtu<S: AsyncWrite + Unpin>(
    handlers: &ServerHandlers,
    config: &RtuServerConfig,
    frame: RtuFrame,
    stream: &mut S,
    out: &mut Vec<u8>,
) -> std::io::Result<()> {
    let counters = handlers.counters();
    if config.trace.is_some() {
        out.clear();
        encode_rtu(frame.unit, &frame.pdu, out);
        trace::emit(&config.trace, Direction::Rx, out);
    }
    inc(&counters.bus_messages);
    let unit = UnitId(frame.unit);
    if unit.is_broadcast() {
        // Execute write requests on every unit; never answer.
        inc(&counters.server_messages);
        inc(&counters.server_no_response);
        if let Ok(req) = Request::decode(&frame.pdu) {
            if req.is_write_only() {
                for h in handlers.all() {
                    if execute(&mut *lock(h), counters, &req).is_ok() {
                        inc(&counters.events);
                    }
                }
            }
        }
        return Ok(());
    }
    let Some(handler) = handlers.resolve(unit) else {
        return Ok(());
    };
    let mut pdu = Vec::with_capacity(256);
    process_pdu(&mut *lock(handler), counters, &frame.pdu, &mut pdu);
    out.clear();
    encode_rtu(frame.unit, &pdu, out);
    trace::emit(&config.trace, Direction::Tx, out);
    stream.write_all(out).await?;
    stream.flush().await
}

/// Serve RTU-over-TCP: accept connections and run [`serve_rtu`] on each of them.
pub async fn spawn_rtu_over_tcp_server(
    addr: impl ToSocketAddrs,
    handlers: ServerHandlers,
    config: RtuServerConfig,
) -> std::io::Result<ServerHandle> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    if let Ok((socket, _)) = accepted {
                        let _ = socket.set_nodelay(true);
                        sessions.spawn(serve_rtu(socket, handlers.clone(), config.clone()));
                    } else {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
                Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            }
        }
    });
    Ok(ServerHandle { local_addr, task })
}

// ---------------------------------------------------------------------------
// Ready-made in-memory handler
// ---------------------------------------------------------------------------

/// A simple in-memory data model: four tables starting at address 0.
/// Accesses beyond a table's size return `IllegalDataAddress`.
#[derive(Clone, Debug, Default)]
pub struct MemoryMap {
    pub coils: Vec<bool>,
    pub discrete_inputs: Vec<bool>,
    pub holding_registers: Vec<u16>,
    pub input_registers: Vec<u16>,
    /// Answered by FC 0x2B / 0x0E when set.
    pub device_identification: Option<DeviceIdentification>,
    /// Answered by FC 0x11 when set.
    pub server_id: Option<Vec<u8>>,
    /// Answered by FC 0x07 when set.
    pub exception_status: Option<u8>,
    /// Queues answered by FC 0x18, keyed by FIFO pointer address.
    pub fifo_queues: HashMap<u16, Vec<u16>>,
}

impl MemoryMap {
    pub fn new(
        coils: usize,
        discrete_inputs: usize,
        holding_registers: usize,
        input_registers: usize,
    ) -> Self {
        MemoryMap {
            coils: vec![false; coils],
            discrete_inputs: vec![false; discrete_inputs],
            holding_registers: vec![0; holding_registers],
            input_registers: vec![0; input_registers],
            ..Default::default()
        }
    }

    /// Builder: set the device identification objects.
    pub fn with_device_identification(mut self, info: DeviceIdentification) -> Self {
        self.device_identification = Some(info);
        self
    }

    /// Store a register value of any width (`f32`, `u32`, ...) into the holding registers.
    pub fn set_holding<T: crate::codec::RegisterValue>(
        &mut self,
        address: u16,
        value: T,
        order: crate::codec::RegisterOrder,
    ) -> Result<(), ExceptionCode> {
        write_slice(
            &mut self.holding_registers,
            address,
            &crate::codec::encode(value, order),
        )
    }

    /// Store a register value of any width into the input registers.
    pub fn set_input<T: crate::codec::RegisterValue>(
        &mut self,
        address: u16,
        value: T,
        order: crate::codec::RegisterOrder,
    ) -> Result<(), ExceptionCode> {
        write_slice(
            &mut self.input_registers,
            address,
            &crate::codec::encode(value, order),
        )
    }

    /// Wrap into the shared form expected by [`ServerHandlers`].
    pub fn shared(self) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(self))
    }
}

fn read_slice<T: Copy>(table: &[T], range: AddressRange) -> Result<Vec<T>, ExceptionCode> {
    table
        .get(range.to_std())
        .map(<[T]>::to_vec)
        .ok_or(ExceptionCode::IllegalDataAddress)
}

fn write_slice<T: Copy>(table: &mut [T], start: u16, values: &[T]) -> Result<(), ExceptionCode> {
    let s = start as usize;
    table
        .get_mut(s..s.saturating_add(values.len()))
        .ok_or(ExceptionCode::IllegalDataAddress)?
        .copy_from_slice(values);
    Ok(())
}

impl RequestHandler for MemoryMap {
    fn read_coils(&mut self, r: AddressRange) -> Result<Vec<bool>, ExceptionCode> {
        read_slice(&self.coils, r)
    }
    fn read_discrete_inputs(&mut self, r: AddressRange) -> Result<Vec<bool>, ExceptionCode> {
        read_slice(&self.discrete_inputs, r)
    }
    fn read_holding_registers(&mut self, r: AddressRange) -> Result<Vec<u16>, ExceptionCode> {
        read_slice(&self.holding_registers, r)
    }
    fn read_input_registers(&mut self, r: AddressRange) -> Result<Vec<u16>, ExceptionCode> {
        read_slice(&self.input_registers, r)
    }
    fn write_single_coil(&mut self, address: u16, value: bool) -> Result<(), ExceptionCode> {
        write_slice(&mut self.coils, address, &[value])
    }
    fn write_single_register(&mut self, address: u16, value: u16) -> Result<(), ExceptionCode> {
        write_slice(&mut self.holding_registers, address, &[value])
    }
    fn write_multiple_coils(&mut self, start: u16, values: &[bool]) -> Result<(), ExceptionCode> {
        write_slice(&mut self.coils, start, values)
    }
    fn write_multiple_registers(
        &mut self,
        start: u16,
        values: &[u16],
    ) -> Result<(), ExceptionCode> {
        write_slice(&mut self.holding_registers, start, values)
    }
    fn read_write_multiple_registers(
        &mut self,
        read: AddressRange,
        write_start: u16,
        values: &[u16],
    ) -> Result<Vec<u16>, ExceptionCode> {
        // Validate the read before writing, so a bad request has no side effect.
        if self.holding_registers.get(read.to_std()).is_none() {
            return Err(ExceptionCode::IllegalDataAddress);
        }
        self.write_multiple_registers(write_start, values)?;
        self.read_holding_registers(read)
    }
    fn read_exception_status(&mut self) -> Result<u8, ExceptionCode> {
        self.exception_status.ok_or(ExceptionCode::IllegalFunction)
    }
    fn report_server_id(&mut self) -> Result<Vec<u8>, ExceptionCode> {
        self.server_id.clone().ok_or(ExceptionCode::IllegalFunction)
    }
    fn read_fifo_queue(&mut self, address: u16) -> Result<Vec<u16>, ExceptionCode> {
        self.fifo_queues
            .get(&address)
            .cloned()
            .ok_or(ExceptionCode::IllegalDataAddress)
    }
    fn device_identification(&mut self) -> Option<&DeviceIdentification> {
        self.device_identification.as_ref()
    }
}
