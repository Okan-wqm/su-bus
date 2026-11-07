//! Starts a Modbus TCP server on 127.0.0.1:5020 and talks to it with a client.
//! Run: cargo run --example tcp_demo
use su_bus::server::{spawn_tcp_server, MemoryMap, ServerHandlers, TcpServerConfig};
use su_bus::{Client, ClientConfig, UnitId};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = MemoryMap::new(64, 64, 64, 64).shared();
    data.lock().unwrap().input_registers[0] = 2150; // e.g. 21.50 °C

    let handlers = ServerHandlers::new().with(UnitId(1), data.clone());
    let server = spawn_tcp_server("127.0.0.1:5020", handlers, TcpServerConfig::default()).await?;
    println!("server listening on {}", server.local_addr());

    let client = Client::tcp("127.0.0.1:5020", ClientConfig::default());
    let temp = client.read_input_registers(UnitId(1), 0, 1).await?;
    println!("input register 0 = {}", temp[0]);

    client
        .write_multiple_registers(UnitId(1), 10, &[1, 2, 3])
        .await?;
    println!(
        "holding 10..13 = {:?}",
        client.read_holding_registers(UnitId(1), 10, 3).await?
    );
    Ok(())
}
