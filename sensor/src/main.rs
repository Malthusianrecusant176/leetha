mod buffer;
mod config;
mod protocol;

use buffer::RingBuffer;
use config::SensorConfig;
use protocol::serialize_frame;

use clap::Parser;
use log::{error, info, warn};
use pcap::Capture;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(
    name = "leetha-sensor",
    about = "Remote packet capture sensor for leetha"
)]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "/etc/leetha-sensor/config.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    let config = SensorConfig::from_file(&args.config)?;

    info!(
        "leetha-sensor starting — interface: {}, server: {}",
        config.interface, config.server
    );

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(10_000);
    let ring = Arc::new(Mutex::new(RingBuffer::new(config.buffer_size_bytes())));

    // Capture thread (blocking — libpcap)
    let iface = config.interface.clone();
    let tx_capture = tx.clone();
    std::thread::spawn(move || {
        let mut cap = Capture::from_device(iface.as_str())
            .expect("failed to open capture device")
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()
            .expect("failed to activate capture");

        info!("capture started on {}", iface);

        while let Ok(packet) = cap.next_packet() {
            let ts_ns = packet.header.ts.tv_sec as i64 * 1_000_000_000
                + packet.header.ts.tv_usec as i64 * 1_000;
            let frame = serialize_frame(packet.data, ts_ns, 0);
            if tx_capture.blocking_send(frame).is_err() {
                warn!("channel full, dropping packet");
            }
        }
    });

    // Drop the extra sender so rx closes when capture thread exits
    drop(tx);

    // WebSocket send loop with reconnect
    let ring_ws = ring.clone();
    let mut backoff_secs = 1u64;
    loop {
        match connect_and_stream(&config, &mut rx, &ring_ws).await {
            Ok(()) => {
                info!("connection closed normally");
                break;
            }
            Err(e) => {
                error!(
                    "connection error: {} — reconnecting in {}s",
                    e, backoff_secs
                );
                // Buffer packets while disconnected
                while let Ok(frame) = rx.try_recv() {
                    ring_ws.lock().unwrap().push(frame);
                }
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        }
    }

    Ok(())
}

async fn connect_and_stream(
    config: &SensorConfig,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    ring: &Arc<Mutex<RingBuffer>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // Load TLS certs
    let cert_pem = std::fs::read(&config.cert)?;
    let key_pem = std::fs::read(&config.key)?;
    let ca_pem = std::fs::read(&config.ca)?;

    // Build TLS connector with client cert
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?.unwrap();
    let mut root_store = rustls::RootCertStore::empty();
    for ca in rustls_pemfile::certs(&mut &ca_pem[..]) {
        root_store.add(ca?)?;
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls_config));

    let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
        &config.server,
        None,
        false,
        Some(connector),
    )
    .await?;

    let (mut write, _read) = futures_util::StreamExt::split(ws_stream);

    info!("connected to {}", config.server);

    // Drain ring buffer first (historical packets)
    let buffered = ring.lock().unwrap().drain();
    if !buffered.is_empty() {
        info!("draining {} buffered frames", buffered.len());
        for frame in buffered {
            write.send(Message::Binary(frame.into())).await?;
        }
    }

    // Stream live packets
    while let Some(frame) = rx.recv().await {
        write.send(Message::Binary(frame.into())).await?;
    }

    Ok(())
}
