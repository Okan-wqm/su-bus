//! End-to-end tests of the extended function codes and client / server features.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use su_bus::device_id::object;
use su_bus::frame::encode_rtu;
use su_bus::server::{
    serve_rtu, serve_tcp_stream, spawn_rtu_over_tcp_server, spawn_tcp_server, MemoryMap,
    RequestHandler, RtuServerConfig, ServerHandlers, TcpServerConfig,
};
use su_bus::{
    Client, ClientConfig, DeviceIdCode, DeviceIdentification, Direction, Error, ExceptionCode,
    FrameTrace, Framing, RegisterOrder, UnitId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn fast() -> ClientConfig {
    ClientConfig {
        response_timeout: Duration::from_millis(300),
        connect_timeout: Duration::from_millis(500),
        broadcast_delay: Duration::from_millis(20),
        rtu_frame_gap: Duration::from_millis(20),
        ..Default::default()
    }
}

fn fast_rtu_server() -> RtuServerConfig {
    RtuServerConfig {
        frame_gap: Duration::from_millis(20),
        ..Default::default()
    }
}

fn device_info() -> DeviceIdentification {
    DeviceIdentification::new("Suderra", "SB-100", "2.1")
        .with(object::VENDOR_URL, "https://example.invalid")
        .with(object::PRODUCT_NAME, "su-bus test device")
        .with(object::MODEL_NAME, "SB")
        // two large private objects force the stream to span several responses
        .with(0x80, vec![b'a'; 200])
        .with(0x81, vec![b'b'; 200])
        .with(0x90, "tail")
}

fn full_memory() -> Arc<Mutex<MemoryMap>> {
    let mut m = MemoryMap::new(32, 32, 64, 64).with_device_identification(device_info());
    m.server_id = Some(vec![0x2A, 0xFF, b'S', b'U']);
    m.exception_status = Some(0b1010_0101);
    m.fifo_queues.insert(0x04DE, vec![0x01B8, 0x1284]);
    m.shared()
}

/// A handler exercising the custom-function and extra diagnostics hooks.
struct Custom;

impl RequestHandler for Custom {
    fn custom_function(&mut self, function: u8, data: &[u8]) -> Result<Vec<u8>, ExceptionCode> {
        match function {
            // reverse the payload
            0x41 => Ok(data.iter().rev().copied().collect()),
            0x64 if data.is_empty() => Err(ExceptionCode::IllegalDataValue),
            0x64 => Ok(vec![data.len() as u8]),
            _ => Err(ExceptionCode::IllegalFunction),
        }
    }
    fn diagnostics(&mut self, sub: u16, data: &[u16]) -> Result<Vec<u16>, ExceptionCode> {
        match sub {
            0x0100 => Ok(data.iter().map(|v| v.wrapping_add(1)).collect()),
            _ => Err(ExceptionCode::IllegalFunction),
        }
    }
}

async fn tcp_server(handlers: ServerHandlers) -> (su_bus::server::ServerHandle, Client) {
    let server = spawn_tcp_server("127.0.0.1:0", handlers, TcpServerConfig::default())
        .await
        .unwrap();
    let client = Client::tcp(server.local_addr().to_string(), fast());
    (server, client)
}

fn rtu_pair(handlers: ServerHandlers) -> Client {
    let (client_side, server_side) = tokio::io::duplex(4096);
    tokio::spawn(serve_rtu(server_side, handlers, fast_rtu_server()));
    Client::from_stream(client_side, Framing::Rtu, fast())
}

async fn check_identification(client: &Client, unit: UnitId) {
    let basic = client
        .read_device_identification(unit, DeviceIdCode::Basic)
        .await
        .unwrap();
    assert_eq!(basic.conformity_level, 0x83);
    assert_eq!(basic.identification.len(), 3);
    assert_eq!(
        basic.identification.get_str(object::VENDOR_NAME).unwrap(),
        "Suderra"
    );

    let regular = client
        .read_device_identification(unit, DeviceIdCode::Regular)
        .await
        .unwrap();
    assert_eq!(regular.identification.len(), 6);

    // 3 + 3 regular + 3 private objects, needs more than one response
    let extended = client
        .read_device_identification(unit, DeviceIdCode::Extended)
        .await
        .unwrap();
    assert_eq!(extended.identification, device_info());

    assert_eq!(
        client
            .read_device_identification_object(unit, object::MODEL_NAME)
            .await
            .unwrap(),
        b"SB"
    );
    assert!(matches!(
        client.read_device_identification_object(unit, 0x55).await,
        Err(Error::Exception(ExceptionCode::IllegalDataAddress))
    ));
}

#[tokio::test]
async fn device_identification_over_tcp_and_rtu() {
    let handlers = ServerHandlers::new().with(UnitId(1), full_memory());
    let (_server, tcp) = tcp_server(handlers.clone()).await;
    check_identification(&tcp, UnitId(1)).await;

    let rtu = rtu_pair(handlers);
    check_identification(&rtu, UnitId(1)).await;
}

#[tokio::test]
async fn device_identification_not_supported() {
    let handlers = ServerHandlers::new().with(UnitId(1), MemoryMap::new(1, 1, 1, 1).shared());
    let (_server, client) = tcp_server(handlers).await;
    assert!(matches!(
        client
            .read_device_identification(UnitId(1), DeviceIdCode::Basic)
            .await,
        Err(Error::Exception(ExceptionCode::IllegalFunction))
    ));
    assert!(matches!(
        client
            .read_device_identification(UnitId(1), DeviceIdCode::Specific)
            .await,
        Err(Error::InvalidRequest(_))
    ));
}

#[tokio::test]
async fn serial_line_functions_over_rtu() {
    let handlers = ServerHandlers::new().with(UnitId(9), full_memory());
    let client = rtu_pair(handlers);
    let u = UnitId(9);

    assert_eq!(client.read_exception_status(u).await.unwrap(), 0b1010_0101);
    assert_eq!(
        client.report_server_id(u).await.unwrap(),
        [0x2A, 0xFF, b'S', b'U']
    );
    assert_eq!(
        client.read_fifo_queue(u, 0x04DE).await.unwrap(),
        [0x01B8, 0x1284]
    );
    assert!(matches!(
        client.read_fifo_queue(u, 1).await,
        Err(Error::Exception(ExceptionCode::IllegalDataAddress))
    ));
}

#[tokio::test]
async fn diagnostics_and_counters_over_rtu() {
    let handlers = ServerHandlers::new()
        .with(UnitId(1), MemoryMap::new(8, 8, 8, 8).shared())
        .with(UnitId(2), Arc::new(Mutex::new(Custom)));
    let counters = handlers.counters().clone();
    let (mut raw, server_side) = tokio::io::duplex(4096);
    tokio::spawn(serve_rtu(server_side, handlers, fast_rtu_server()));

    // A corrupted frame first: counted as a bus communication error.
    let mut bad = Vec::new();
    encode_rtu(1, &[0x03, 0, 0, 0, 1], &mut bad);
    *bad.last_mut().unwrap() ^= 0xFF;
    raw.write_all(&bad).await.unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;

    let client = Client::from_stream(raw, Framing::Rtu, fast());
    let u = UnitId(1);

    // loopback with arbitrary data ("return query data" has no length prefix on RTU)
    client.loopback(u, &[0xA537, 0x0102, 0xBEEF]).await.unwrap();

    client.read_coils(u, 0, 8).await.unwrap();
    assert!(client.read_coils(u, 100, 1).await.is_err()); // exception

    let snap = counters.snapshot();
    assert_eq!(snap.bus_comm_errors, 1);
    assert_eq!(snap.bus_exceptions, 1);
    assert_eq!(snap.server_messages, 3);
    assert_eq!(snap.events, 2);

    assert_eq!(client.diagnostics(u, 0x0C, &[0]).await.unwrap(), [1]);
    assert_eq!(client.diagnostics(u, 0x0D, &[0]).await.unwrap(), [1]);
    // includes this very request
    assert_eq!(client.diagnostics(u, 0x0E, &[0]).await.unwrap(), [6]);
    assert_eq!(client.diagnostics(u, 0x02, &[0]).await.unwrap(), [0]);

    // FC 0x0B: successful requests so far (loopback, read, 4 diagnostics)
    assert_eq!(client.get_comm_event_counter(u).await.unwrap(), (0, 6));
    // ...and polling it is not counted
    assert_eq!(client.get_comm_event_counter(u).await.unwrap(), (0, 6));

    // clear counters
    assert_eq!(client.diagnostics(u, 0x0A, &[0]).await.unwrap(), [0]);
    assert_eq!(client.diagnostics(u, 0x0D, &[0]).await.unwrap(), [0]);

    // bad data for a counter sub-function
    assert!(matches!(
        client.diagnostics(u, 0x0B, &[1]).await,
        Err(Error::Exception(ExceptionCode::IllegalDataValue))
    ));
    // unknown sub-function on a handler without support
    assert!(matches!(
        client.diagnostics(u, 0x0100, &[0]).await,
        Err(Error::Exception(ExceptionCode::IllegalFunction))
    ));
    // ...and on one that implements it
    assert_eq!(
        client
            .diagnostics(UnitId(2), 0x0100, &[1, 2])
            .await
            .unwrap(),
        [2, 3]
    );
}

#[tokio::test]
async fn broadcast_counts_no_response() {
    let mem = MemoryMap::new(8, 8, 8, 8).shared();
    let handlers = ServerHandlers::new().with(UnitId(3), mem.clone());
    let counters = handlers.counters().clone();
    let client = rtu_pair(handlers);
    client
        .broadcast(&su_bus::Request::WriteSingleRegister {
            address: 1,
            value: 99,
        })
        .await
        .unwrap();
    assert_eq!(
        client
            .read_holding_registers(UnitId(3), 1, 1)
            .await
            .unwrap(),
        [99]
    );
    assert_eq!(counters.snapshot().server_no_response, 1);
}

async fn check_custom(client: &Client, unit: UnitId) {
    assert_eq!(
        client.custom(unit, 0x41, &[1, 2, 3, 4]).await.unwrap(),
        [4, 3, 2, 1]
    );
    assert_eq!(client.custom(unit, 0x64, &[7; 9]).await.unwrap(), [9]);
    assert!(matches!(
        client.custom(unit, 0x64, &[]).await,
        Err(Error::Exception(ExceptionCode::IllegalDataValue))
    ));
    assert!(matches!(
        client.custom(unit, 0x42, &[]).await,
        Err(Error::Exception(ExceptionCode::IllegalFunction))
    ));
    assert!(matches!(
        client.custom(unit, 0x90, &[]).await,
        Err(Error::InvalidRequest(_))
    ));
}

#[tokio::test]
async fn custom_function_codes_on_every_transport() {
    let handlers = ServerHandlers::new().with(UnitId(4), Arc::new(Mutex::new(Custom)));
    let (_server, tcp) = tcp_server(handlers.clone()).await;
    check_custom(&tcp, UnitId(4)).await;

    // RTU: the response end is found by line silence
    let rtu = rtu_pair(handlers.clone());
    check_custom(&rtu, UnitId(4)).await;

    let server = spawn_rtu_over_tcp_server("127.0.0.1:0", handlers, fast_rtu_server())
        .await
        .unwrap();
    let rot = Client::rtu_over_tcp(server.local_addr().to_string(), fast());
    check_custom(&rot, UnitId(4)).await;
}

#[tokio::test]
async fn default_handler_answers_any_unit() {
    let mem = MemoryMap::new(4, 4, 4, 4).shared();
    mem.lock().unwrap().input_registers[2] = 1234;
    let handlers = ServerHandlers::new()
        .with(UnitId(1), MemoryMap::new(4, 4, 4, 4).shared())
        .with_default(mem);
    let (_server, client) = tcp_server(handlers).await;
    assert_eq!(
        client
            .read_input_registers(UnitId(0xFF), 2, 1)
            .await
            .unwrap(),
        [1234]
    );
    assert_eq!(
        client.read_input_registers(UnitId(0), 2, 1).await.unwrap(),
        [1234]
    );
    // a specific handler still wins
    assert_eq!(
        client.read_input_registers(UnitId(1), 2, 1).await.unwrap(),
        [0]
    );
}

#[tokio::test]
async fn typed_values_roundtrip() {
    let mem = MemoryMap::new(0, 0, 32, 32).shared();
    {
        let mut m = mem.lock().unwrap();
        m.set_input(0, 21.5f32, RegisterOrder::ABCD).unwrap();
        m.set_input(2, -40_000i32, RegisterOrder::CDAB).unwrap();
        m.set_holding(10, 1.25f64, RegisterOrder::DCBA).unwrap();
        assert!(m.set_holding(31, 1u32, RegisterOrder::ABCD).is_err());
    }
    let handlers = ServerHandlers::new().with(UnitId(1), mem.clone());
    let (_server, client) = tcp_server(handlers).await;
    let u = UnitId(1);

    assert_eq!(
        client
            .read_input::<f32>(u, 0, RegisterOrder::ABCD)
            .await
            .unwrap(),
        21.5
    );
    assert_eq!(
        client
            .read_input::<i32>(u, 2, RegisterOrder::CDAB)
            .await
            .unwrap(),
        -40_000
    );
    assert_eq!(
        client
            .read_holding::<f64>(u, 10, RegisterOrder::DCBA)
            .await
            .unwrap(),
        1.25
    );

    client
        .write_holding_values(u, 0, &[0x1122_3344u32, 7], RegisterOrder::CDAB)
        .await
        .unwrap();
    assert_eq!(
        client.read_holding_registers(u, 0, 4).await.unwrap(),
        [0x3344, 0x1122, 7, 0]
    );
    assert_eq!(
        client
            .read_holding_values::<u32>(u, 0, 2, RegisterOrder::CDAB)
            .await
            .unwrap(),
        [0x1122_3344, 7]
    );
    // 63 u32 values = 126 registers: over the limit
    assert!(matches!(
        client
            .read_holding_values::<u32>(u, 0, 63, RegisterOrder::ABCD)
            .await,
        Err(Error::InvalidRequest(_))
    ));
}

/// A TCP server whose first connection is closed without an answer; later connections
/// are served normally through the generic `serve_tcp_stream` entry point.
async fn flaky_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handlers = ServerHandlers::new().with(UnitId(1), MemoryMap::new(4, 4, 4, 4).shared());
    tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let _ = first.read(&mut buf).await;
        drop(first);
        loop {
            let (s, _) = listener.accept().await.unwrap();
            let h = handlers.clone();
            tokio::spawn(async move {
                let _ = serve_tcp_stream(s, &h, &TcpServerConfig::default()).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn retries_recover_from_a_dropped_connection() {
    let no_retry = Client::tcp(flaky_server().await.to_string(), fast());
    assert!(no_retry.read_coils(UnitId(1), 0, 1).await.is_err());
    // without retries the next call reconnects and works
    assert!(no_retry.read_coils(UnitId(1), 0, 1).await.is_ok());

    let retrying = Client::tcp(
        flaky_server().await.to_string(),
        ClientConfig {
            retries: 2,
            retry_delay: Duration::from_millis(10),
            ..fast()
        },
    );
    assert_eq!(
        retrying.read_coils(UnitId(1), 0, 2).await.unwrap(),
        [false, false]
    );
}

#[tokio::test]
async fn retries_do_not_repeat_exceptions() {
    let handlers = ServerHandlers::new().with(UnitId(1), MemoryMap::new(1, 1, 1, 1).shared());
    let counters = handlers.counters().clone();
    let server = spawn_tcp_server("127.0.0.1:0", handlers, TcpServerConfig::default())
        .await
        .unwrap();
    let client = Client::tcp(
        server.local_addr().to_string(),
        ClientConfig {
            retries: 5,
            ..fast()
        },
    );
    assert!(matches!(
        client.read_coils(UnitId(1), 50, 1).await,
        Err(Error::Exception(ExceptionCode::IllegalDataAddress))
    ));
    assert_eq!(counters.snapshot().server_messages, 1);
}

#[tokio::test]
async fn connector_reconnects_custom_transport() {
    let handlers = ServerHandlers::new().with(UnitId(1), MemoryMap::new(4, 4, 4, 4).shared());
    let server = spawn_tcp_server("127.0.0.1:0", handlers, TcpServerConfig::default())
        .await
        .unwrap();
    let addr = server.local_addr();
    let opened = Arc::new(AtomicUsize::new(0));
    let counter = opened.clone();
    let client = Client::with_connector(Framing::Tcp, fast(), move || {
        counter.fetch_add(1, Ordering::SeqCst);
        tokio::net::TcpStream::connect(addr)
    });
    client.read_coils(UnitId(1), 0, 1).await.unwrap();
    client.read_coils(UnitId(1), 0, 1).await.unwrap();
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    client.disconnect().await;
    client.read_coils(UnitId(1), 0, 1).await.unwrap();
    assert_eq!(opened.load(Ordering::SeqCst), 2);
}

type FrameLog = Arc<Mutex<Vec<(Direction, Vec<u8>)>>>;

#[tokio::test]
async fn frame_trace_sees_both_directions() {
    let frames: FrameLog = Default::default();
    let sink = frames.clone();
    let trace = FrameTrace::new(move |d, b| sink.lock().unwrap().push((d, b.to_vec())));

    let server_frames: FrameLog = Default::default();
    let server_sink = server_frames.clone();
    let server_cfg = TcpServerConfig {
        trace: Some(FrameTrace::new(move |d, b| {
            server_sink.lock().unwrap().push((d, b.to_vec()))
        })),
        ..Default::default()
    };
    let handlers = ServerHandlers::new().with(UnitId(1), MemoryMap::new(4, 4, 4, 4).shared());
    let server = spawn_tcp_server("127.0.0.1:0", handlers, server_cfg)
        .await
        .unwrap();
    let client = Client::tcp(
        server.local_addr().to_string(),
        ClientConfig {
            trace: Some(trace),
            ..fast()
        },
    );
    client
        .write_single_register(UnitId(1), 2, 0xABCD)
        .await
        .unwrap();

    let f = frames.lock().unwrap();
    assert_eq!(f.len(), 2);
    assert_eq!(f[0].0, Direction::Tx);
    assert_eq!(&f[0].1[2..], [0, 0, 0, 6, 1, 0x06, 0, 2, 0xAB, 0xCD]);
    assert_eq!(f[1].0, Direction::Rx);
    assert_eq!(f[1].1, f[0].1); // write single register echoes the request

    let s = server_frames.lock().unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s[0], (Direction::Rx, f[0].1.clone()));
    assert_eq!(s[1], (Direction::Tx, f[1].1.clone()));
}

#[test]
fn rtu_frame_gap_from_baud_rate() {
    let slow = RtuServerConfig::for_baud_rate(9600);
    let fast = RtuServerConfig::for_baud_rate(115_200);
    // 3.5 chars at 9600 baud = ~4 ms (+20 ms margin); fast lines use the 1.75 ms floor
    assert_eq!(slow.frame_gap, Duration::from_micros(4_007 + 20_000));
    assert_eq!(fast.frame_gap, Duration::from_micros(1_750 + 20_000));
}
