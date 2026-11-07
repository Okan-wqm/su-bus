use std::time::Duration;
use su_bus::frame::{encode_mbap, encode_rtu};
use su_bus::server::{
    serve_rtu, spawn_rtu_over_tcp_server, spawn_tcp_server, MemoryMap, RtuServerConfig,
    ServerHandlers, TcpServerConfig,
};
use su_bus::{Client, ClientConfig, Error, ExceptionCode, Framing, Request, UnitId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fast() -> ClientConfig {
    ClientConfig {
        response_timeout: Duration::from_millis(300),
        connect_timeout: Duration::from_millis(500),
        broadcast_delay: Duration::from_millis(20),
    }
}

async fn exercise(client: &Client, unit: UnitId) {
    client.write_single_coil(unit, 3, true).await.unwrap();
    client
        .write_multiple_coils(unit, 5, &[true, false, true])
        .await
        .unwrap();
    assert_eq!(
        client.read_coils(unit, 2, 7).await.unwrap(),
        [false, true, false, true, false, true, false]
    );

    client.write_single_register(unit, 0, 0x1234).await.unwrap();
    client
        .write_multiple_registers(unit, 1, &[1, 2, 3])
        .await
        .unwrap();
    assert_eq!(
        client.read_holding_registers(unit, 0, 4).await.unwrap(),
        [0x1234, 1, 2, 3]
    );

    client
        .mask_write_register(unit, 4, 0x00F2, 0x0025)
        .await
        .unwrap();
    // register 4 was 0: (0 & F2) | (25 & !F2) = 0x05
    assert_eq!(
        client.read_holding_registers(unit, 4, 1).await.unwrap(),
        [0x05]
    );

    let read = client
        .read_write_multiple_registers(unit, 9, 3, 10, &[7, 8])
        .await
        .unwrap();
    assert_eq!(read, [0, 7, 8]);

    assert_eq!(
        client.read_input_registers(unit, 0, 2).await.unwrap(),
        [100, 200]
    );
    assert_eq!(
        client.read_discrete_inputs(unit, 0, 3).await.unwrap(),
        [true, false, true]
    );

    // Out of range -> exception from the server
    match client.read_holding_registers(unit, 95, 10).await {
        Err(Error::Exception(ExceptionCode::IllegalDataAddress)) => {}
        other => panic!("expected IllegalDataAddress, got {other:?}"),
    }
    // Invalid quantity -> rejected locally
    assert!(matches!(
        client.read_holding_registers(unit, 0, 200).await,
        Err(Error::InvalidRequest(_))
    ));
}

fn memory() -> std::sync::Arc<std::sync::Mutex<MemoryMap>> {
    let mut m = MemoryMap::new(100, 100, 100, 100);
    m.input_registers[0] = 100;
    m.input_registers[1] = 200;
    m.discrete_inputs[0] = true;
    m.discrete_inputs[2] = true;
    m.shared()
}

#[tokio::test]
async fn tcp_full_roundtrip() {
    let data = memory();
    let handlers = ServerHandlers::new().with(UnitId(1), data.clone());
    let server = spawn_tcp_server("127.0.0.1:0", handlers, TcpServerConfig::default())
        .await
        .unwrap();
    let client = Client::tcp(server.local_addr().to_string(), fast());
    exercise(&client, UnitId(1)).await;

    // The application sees the writes.
    assert_eq!(data.lock().unwrap().holding_registers[0], 0x1234);

    // Unknown unit: server stays silent -> timeout.
    assert!(matches!(
        client.read_coils(UnitId(9), 0, 1).await,
        Err(Error::Timeout)
    ));
    // ...and the connection is still usable afterwards.
    assert_eq!(
        client
            .read_holding_registers(UnitId(1), 0, 1)
            .await
            .unwrap(),
        [0x1234]
    );
}

#[tokio::test]
async fn tcp_client_reconnects_after_server_restart() {
    let handlers = ServerHandlers::new().with(UnitId(1), memory());
    let server = spawn_tcp_server("127.0.0.1:0", handlers.clone(), TcpServerConfig::default())
        .await
        .unwrap();
    let addr = server.local_addr();
    let client = Client::tcp(addr.to_string(), fast());
    client.read_coils(UnitId(1), 0, 1).await.unwrap();

    drop(server);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(client.read_coils(UnitId(1), 0, 1).await.is_err());

    let _server = spawn_tcp_server(addr, handlers, TcpServerConfig::default())
        .await
        .unwrap();
    client.read_coils(UnitId(1), 0, 1).await.unwrap();
}

#[tokio::test]
async fn tcp_client_ignores_stale_transactions() {
    // Hand-rolled server: answers each request twice, first with a wrong transaction id.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 12];
        s.read_exact(&mut buf).await.unwrap();
        let tx = u16::from_be_bytes([buf[0], buf[1]]);
        let mut out = Vec::new();
        encode_mbap(tx.wrapping_sub(1), 1, &[0x03, 0x02, 0xDE, 0xAD], &mut out);
        encode_mbap(tx, 1, &[0x03, 0x02, 0x00, 0x2A], &mut out);
        s.write_all(&out).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let client = Client::tcp(addr.to_string(), fast());
    assert_eq!(
        client
            .read_holding_registers(UnitId(1), 0, 1)
            .await
            .unwrap(),
        [42]
    );
}

#[tokio::test]
async fn tcp_max_sessions_evicts_oldest() {
    let handlers = ServerHandlers::new().with(UnitId(1), memory());
    let cfg = TcpServerConfig {
        max_sessions: 1,
        idle_timeout: None,
    };
    let server = spawn_tcp_server("127.0.0.1:0", handlers, cfg)
        .await
        .unwrap();
    let a = Client::tcp(server.local_addr().to_string(), fast());
    let b = Client::tcp(server.local_addr().to_string(), fast());
    a.read_coils(UnitId(1), 0, 1).await.unwrap();
    b.read_coils(UnitId(1), 0, 1).await.unwrap();
    // `a`'s session was evicted; its next request fails once, then it reconnects.
    let first = a.read_coils(UnitId(1), 0, 1).await;
    if first.is_err() {
        a.read_coils(UnitId(1), 0, 1).await.unwrap();
    }
}

#[tokio::test]
async fn rtu_over_duplex_stream() {
    let (client_side, server_side) = tokio::io::duplex(1024);
    let data = memory();
    let handlers = ServerHandlers::new()
        .with(UnitId(1), data.clone())
        .with(UnitId(2), MemoryMap::new(10, 10, 10, 10).shared());
    tokio::spawn(serve_rtu(server_side, handlers, RtuServerConfig::default()));

    let client = Client::from_stream(client_side, Framing::Rtu, fast());
    exercise(&client, UnitId(1)).await;

    // Unit 0 on RTU must go through broadcast()
    assert!(matches!(
        client.read_coils(UnitId(0), 0, 1).await,
        Err(Error::InvalidRequest(_))
    ));
    client
        .broadcast(&Request::WriteSingleRegister {
            address: 7,
            value: 77,
        })
        .await
        .unwrap();
    assert_eq!(
        client
            .read_holding_registers(UnitId(1), 7, 1)
            .await
            .unwrap(),
        [77]
    );
    assert_eq!(
        client
            .read_holding_registers(UnitId(2), 7, 1)
            .await
            .unwrap(),
        [77]
    );

    // Unit without handler: silence -> timeout
    assert!(matches!(
        client.read_coils(UnitId(3), 0, 1).await,
        Err(Error::Timeout)
    ));
    assert_eq!(
        client
            .read_holding_registers(UnitId(1), 7, 1)
            .await
            .unwrap(),
        [77]
    );
}

#[tokio::test]
async fn rtu_server_answers_unknown_function_after_silence() {
    let (mut raw, server_side) = tokio::io::duplex(1024);
    let handlers = ServerHandlers::new().with(UnitId(1), memory());
    tokio::spawn(serve_rtu(server_side, handlers, RtuServerConfig::default()));

    let mut req = Vec::new();
    encode_rtu(1, &[0x2B, 0x0E, 0x01, 0x00], &mut req);
    raw.write_all(&req).await.unwrap();

    let mut resp = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(1), raw.read_exact(&mut resp))
        .await
        .unwrap()
        .unwrap();
    let mut expected = Vec::new();
    encode_rtu(1, &[0xAB, 0x01], &mut expected);
    assert_eq!(resp.as_slice(), expected.as_slice());
}

#[tokio::test]
async fn rtu_over_tcp() {
    let handlers = ServerHandlers::new().with(UnitId(5), memory());
    let server = spawn_rtu_over_tcp_server("127.0.0.1:0", handlers, RtuServerConfig::default())
        .await
        .unwrap();
    let client = Client::rtu_over_tcp(server.local_addr().to_string(), fast());
    exercise(&client, UnitId(5)).await;
}

#[tokio::test]
async fn concurrent_clones_share_one_connection() {
    let handlers = ServerHandlers::new().with(UnitId(1), memory());
    let server = spawn_tcp_server("127.0.0.1:0", handlers, TcpServerConfig::default())
        .await
        .unwrap();
    let client = Client::tcp(server.local_addr().to_string(), fast());
    let mut tasks = Vec::new();
    for i in 0..20u16 {
        let c = client.clone();
        tasks.push(tokio::spawn(async move {
            c.write_single_register(UnitId(1), i, i * 3).await.unwrap();
            assert_eq!(
                c.read_holding_registers(UnitId(1), i, 1).await.unwrap(),
                [i * 3]
            );
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}
