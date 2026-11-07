//! Async Modbus server (slave).

use crate::frame::{encode_mbap, encode_rtu, read_mbap, MbapRead, RtuBuffer, RtuFrame};
use crate::pdu::{apply_mask, request_len, Request, Response};
use crate::types::{AddressRange, ExceptionCode, UnitId};
use std::collections::HashMap;
use std::net::SocketAddr;
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
}

/// Shared handle to a handler; keep a clone to update the data from your application.
pub type SharedHandler = Arc<Mutex<dyn RequestHandler>>;

/// Lock a handler, ignoring poisoning (a panicking callback must not kill the server).
pub fn lock<T: ?Sized>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Maps unit ids to handlers.
#[derive(Clone, Default)]
pub struct ServerHandlers {
    map: HashMap<UnitId, SharedHandler>,
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

    pub fn get(&self, unit: UnitId) -> Option<&SharedHandler> {
        self.map.get(&unit)
    }
}

/// Process one request PDU and append the response PDU to `out`.
pub fn handle_pdu(handler: &mut dyn RequestHandler, pdu: &[u8], out: &mut Vec<u8>) {
    let function = pdu.first().copied().unwrap_or(0);
    match Request::decode(pdu).and_then(|req| execute(handler, &req)) {
        Ok(resp) => resp.encode(out),
        Err(code) => Response::encode_exception(function, code, out),
    }
}

fn exact<T>(v: Vec<T>, count: u16) -> Result<Vec<T>, ExceptionCode> {
    if v.len() == count as usize {
        Ok(v)
    } else {
        Err(ExceptionCode::ServerDeviceFailure)
    }
}

fn execute(h: &mut dyn RequestHandler, req: &Request) -> Result<Response, ExceptionCode> {
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
}

impl Default for TcpServerConfig {
    fn default() -> Self {
        TcpServerConfig {
            max_sessions: 16,
            idle_timeout: Some(Duration::from_secs(120)),
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
                let h = sessions.spawn(tcp_session(socket, handlers.clone(), config.idle_timeout));
                order.push_back(h);
            }
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
        }
    }
}

async fn tcp_session(mut socket: TcpStream, handlers: Arc<ServerHandlers>, idle: Option<Duration>) {
    let mut pdu_out = Vec::with_capacity(256);
    let mut frame_out = Vec::with_capacity(264);
    loop {
        let read = read_mbap(&mut socket);
        let frame = match idle {
            Some(t) => match tokio::time::timeout(t, read).await {
                Ok(r) => r,
                Err(_) => return,
            },
            None => read.await,
        };
        let frame = match frame {
            Ok(MbapRead::Frame(f)) => f,
            _ => return, // I/O error, EOF or unrecoverable header
        };
        let Some(handler) = handlers.get(UnitId(frame.unit)) else {
            continue; // not ours: stay silent, like an absent serial device
        };
        pdu_out.clear();
        handle_pdu(&mut *lock(handler), &frame.pdu, &mut pdu_out);
        frame_out.clear();
        encode_mbap(frame.transaction, frame.unit, &pdu_out, &mut frame_out);
        if socket.write_all(&frame_out).await.is_err() {
            return;
        }
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
}

impl Default for RtuServerConfig {
    fn default() -> Self {
        RtuServerConfig {
            frame_gap: Duration::from_millis(50),
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

    loop {
        while let Some(frame) = rtu.next_frame(request_len, false) {
            respond_rtu(&handlers, frame, &mut stream, &mut out).await?;
        }
        let n = if rtu.is_empty() {
            stream.read(&mut scratch).await?
        } else {
            match tokio::time::timeout(config.frame_gap, stream.read(&mut scratch)).await {
                Ok(r) => r?,
                Err(_) => {
                    if let Some(frame) = rtu.take_on_silence() {
                        respond_rtu(&handlers, frame, &mut stream, &mut out).await?;
                    }
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
    frame: RtuFrame,
    stream: &mut S,
    out: &mut Vec<u8>,
) -> std::io::Result<()> {
    let unit = UnitId(frame.unit);
    if unit.is_broadcast() {
        // Execute write requests on every unit; never answer.
        if let Ok(req) = Request::decode(&frame.pdu) {
            if req.is_write_only() {
                for h in handlers.map.values() {
                    let _ = execute(&mut *lock(h), &req);
                }
            }
        }
        return Ok(());
    }
    let Some(handler) = handlers.get(unit) else {
        return Ok(());
    };
    let mut pdu = Vec::with_capacity(256);
    handle_pdu(&mut *lock(handler), &frame.pdu, &mut pdu);
    out.clear();
    encode_rtu(frame.unit, &pdu, out);
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
        }
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
        .get_mut(s..s + values.len())
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
}
