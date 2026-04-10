mod buffer;
mod embedded;
mod protocol;

use buffer::RingBuffer;
use protocol::serialize_frame;

use clap::Parser;
use log::{debug, error, info, warn, LevelFilter};
use pcap::Capture;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(
    name = "leetha-sensor",
    about = "Remote packet capture sensor for leetha",
    long_about = "Captures raw network packets and streams them to a central leetha instance \
                  over WebSocket/TLS.\n\n\
                  Config and certificates are embedded at build time. Use CLI flags to override \
                  the server address or capture interface.\n\n\
                  Examples:\n  \
                  leetha-sensor                        Run with embedded config\n  \
                  leetha-sensor -v                     Verbose output\n  \
                  leetha-sensor -s 10.0.0.5:9443       Override server\n  \
                  leetha-sensor -i wlan0 -vv           Override interface, extra verbose\n  \
                  leetha-sensor -d                     Run as daemon (Linux only)"
)]
struct Args {
    /// Override embedded server address (IP:PORT)
    #[arg(short, long)]
    server: Option<String>,

    /// Override embedded capture interface
    #[arg(short, long)]
    interface: Option<String>,

    /// Run as background daemon (Linux only)
    #[arg(short, long)]
    daemon: bool,

    /// Increase verbosity (-v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Show version and embedded config
    #[arg(short = 'V', long)]
    version: bool,
}

fn effective_server(args: &Args) -> String {
    args.server
        .clone()
        .unwrap_or_else(|| embedded::SERVER_ADDR.to_string())
}

fn effective_interface(args: &Args) -> String {
    args.interface
        .clone()
        .unwrap_or_else(|| embedded::INTERFACE.to_string())
}

fn print_version_info(args: &Args) {
    let server = effective_server(args);
    let iface = effective_interface(args);
    eprintln!("leetha-sensor v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  Sensor name:  {}", embedded::SENSOR_NAME);
    eprintln!("  Server:       {}", server);
    eprintln!("  Interface:    {}", iface);
    eprintln!("  Buffer:       {} MB", embedded::BUFFER_SIZE_MB);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Set log level based on verbosity
    let level = match args.verbose {
        0 => LevelFilter::Error,
        1 => LevelFilter::Info,
        _ => LevelFilter::Debug,
    };
    env_logger::Builder::new()
        .filter_level(level)
        .format_timestamp_secs()
        .init();

    // Handle --version flag
    if args.version {
        print_version_info(&args);
        return Ok(());
    }

    let server = effective_server(&args);
    let iface = effective_interface(&args);

    // Print startup banner
    print_version_info(&args);

    // Daemonize if requested (Linux only)
    #[cfg(unix)]
    if args.daemon {
        use daemonize::Daemonize;
        let daemonize = Daemonize::new().working_directory("/tmp");
        match daemonize.start() {
            Ok(_) => info!("daemonized successfully"),
            Err(e) => {
                error!("failed to daemonize: {}", e);
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(unix))]
    if args.daemon {
        error!("daemon mode is not supported on Windows — use sc.exe or NSSM");
        std::process::exit(1);
    }

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(10_000);
    let ring = Arc::new(Mutex::new(RingBuffer::new(
        embedded::BUFFER_SIZE_MB * 1024 * 1024,
    )));

    // Capture thread (blocking — libpcap)
    let iface_capture = iface.clone();
    let tx_capture = tx.clone();
    let verbose = args.verbose;
    std::thread::spawn(move || {
        let cap_device = match Capture::from_device(iface_capture.as_str()) {
            Ok(c) => c,
            Err(e) => {
                let devs = pcap::Device::list()
                    .map(|d| {
                        d.iter()
                            .map(|dev| dev.name.clone())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_else(|_| "unknown".into());
                error!(
                    "capture interface '{}' not found — available: [{}]",
                    iface_capture, devs
                );
                error!("original error: {}", e);
                std::process::exit(1);
            }
        };

        let mut cap = match cap_device.promisc(true).snaplen(65535).timeout(1000).open() {
            Ok(c) => c,
            Err(e) => {
                error!(
                    "cannot open {}: {} — run with sudo or add CAP_NET_RAW",
                    iface_capture, e
                );
                std::process::exit(1);
            }
        };

        info!("capture started on {} (promiscuous)", iface_capture);

        let mut stats_interval = Instant::now();
        let mut pkt_count: u64 = 0;
        let mut byte_count: u64 = 0;

        while let Ok(packet) = cap.next_packet() {
            let ts_ns = packet.header.ts.tv_sec as i64 * 1_000_000_000
                + packet.header.ts.tv_usec as i64 * 1_000;
            let frame = serialize_frame(packet.data, ts_ns, 0);
            pkt_count += 1;
            byte_count += packet.data.len() as u64;

            if verbose >= 2 {
                debug!("packet: {} bytes, ts={}", packet.data.len(), ts_ns);
            }

            if tx_capture.blocking_send(frame).is_err() {
                warn!("channel full, dropping packet");
            }

            // Periodic stats at -v level
            if verbose >= 1 && stats_interval.elapsed() >= Duration::from_secs(10) {
                let elapsed = stats_interval.elapsed().as_secs_f64();
                info!(
                    "streaming: {:.0} pkts/s, {:.1} KB/s",
                    pkt_count as f64 / elapsed,
                    byte_count as f64 / elapsed / 1024.0,
                );
                pkt_count = 0;
                byte_count = 0;
                stats_interval = Instant::now();
            }
        }
    });

    drop(tx);

    // WebSocket send loop with reconnect
    let ring_ws = ring.clone();
    let mut backoff_secs = 1u64;
    loop {
        info!("connecting to {}...", server);
        match connect_and_stream(&server, &mut rx, &ring_ws, args.verbose).await {
            Ok(()) => {
                info!("connection closed normally");
                break;
            }
            Err(e) => {
                error!(
                    "cannot reach {} — retrying in {}s ({})",
                    server, backoff_secs, e
                );
                while let Ok(frame) = rx.try_recv() {
                    ring_ws.lock().unwrap().push(frame);
                }
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        }
    }

    Ok(())
}

async fn connect_and_stream(
    server: &str,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    ring: &Arc<Mutex<RingBuffer>>,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // Use embedded certs
    let certs: Vec<_> = rustls_pemfile::certs(&mut &embedded::CERT_PEM[..])
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut &embedded::KEY_PEM[..])?
        .ok_or("no private key found in embedded PEM")?;
    let mut root_store = rustls::RootCertStore::empty();
    for ca in rustls_pemfile::certs(&mut &embedded::CA_PEM[..]) {
        root_store.add(ca?)?;
    }

    if verbose >= 2 {
        debug!(
            "TLS: loaded {} cert(s), CA store has {} root(s)",
            certs.len(),
            root_store.len()
        );
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls_config));

    let ws_url = format!(
        "wss://{}/api/v1/capture/remote?name={}",
        server, embedded::SENSOR_NAME
    );

    let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
        &ws_url,
        None,
        false,
        Some(connector),
    )
    .await?;

    let (mut write, _read) = futures_util::StreamExt::split(ws_stream);

    info!(
        "TLS handshake complete, cert: {}",
        embedded::SENSOR_NAME
    );

    // Drain ring buffer first (historical packets)
    let buffered = ring.lock().unwrap().drain();
    if !buffered.is_empty() {
        info!("draining {} buffered frames", buffered.len());
        for (i, frame) in buffered.iter().enumerate() {
            write
                .send(Message::Binary(frame.clone().into()))
                .await?;
            if verbose >= 2 {
                debug!("buffer drain: {}/{}", i + 1, buffered.len());
            }
        }
    }

    // Stream live packets
    while let Some(frame) = rx.recv().await {
        write.send(Message::Binary(frame.into())).await?;
    }

    Ok(())
}
