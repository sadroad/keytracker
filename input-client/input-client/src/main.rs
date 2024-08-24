use aya::maps::ring_buf::RingBuf;
use aya::maps::MapData;
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use clap::Parser;
use log::{debug, info};
use serde_json::json;
use std::env;
use std::ops::Deref;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::watch;
use tokio::time::sleep;

static SERVER_CONFIG: OnceLock<ServerConfig> = OnceLock::new();

#[derive(Debug)]
struct ServerConfig {
    server_ip: String,
    token: String,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    server_ip: String,

    #[arg(short, long)]
    token: String,
}

#[derive(Debug, Clone)]
#[repr(C)]
struct KeyEvent {
    key_type: u32,
    code: u32,
    value: u32,
}

#[derive(Debug, Clone)]
struct TimestampedKeyEvent {
    event: KeyEvent,
    relative_time: Duration,
}

async fn process_ring_buffer_event(
    ring_buf: &mut RingBuf<MapData>,
    batch: &mut Vec<TimestampedKeyEvent>,
    last_event_time: &mut Instant,
) {
    if let Some(event) = ring_buf.next() {
        let buf = event.deref();
        let ptr = buf.as_ptr() as *const KeyEvent;
        let data = unsafe { ptr.read() };
        let now = Instant::now();
        let relative_time = now.duration_since(*last_event_time);
        *last_event_time = now;

        if data.value == 0 {
            let timestamped_event = TimestampedKeyEvent {
                event: data,
                relative_time,
            };
            batch.push(timestamped_event);

            if batch.len() >= 10 {
                if let Err(e) = send_batch_to_server(batch.clone()).await {
                    eprintln!("Failed to send batch to server: {}", e);
                }
                batch.clear();
            }
        }
    }
}

async fn send_batch_to_server(
    batch: Vec<TimestampedKeyEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = SERVER_CONFIG.get().expect("Server config not initialized");
    let client = reqwest::Client::new();

    let payload = json!({
        "events": batch.iter().map(|e| json!({
            "event": {
                "key_type": e.event.key_type,
                "code": e.event.code,
                "value": e.event.value,
            },
            "relative_time": e.relative_time.as_millis(),
        })).collect::<Vec<_>>()
    });

    let endpoint = format!("{}/ingest", config.server_ip);

    let response = client
        .post(&endpoint)
        .header("Authorization", &config.token)
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        println!("Batch successfully sent to server");
    } else {
        println!("Failed to send batch to server: {}", response.status());
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env::set_var("RUST_LOG", "info");
    env_logger::init();

    // Parse command-line arguments
    let args = Args::parse();

    // Initialize the global ServerConfig
    SERVER_CONFIG
        .set(ServerConfig {
            server_ip: args.server_ip,
            token: args.token,
        })
        .expect("Failed to set ServerConfig");

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/input-client"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/input-client"
    ))?;
    let program: &mut KProbe = bpf.program_mut("input_client").unwrap().try_into()?;
    program.load()?;
    program.attach("input_handle_event", 0)?;

    let mut ring_buf =
        RingBuf::try_from(bpf.take_map("EVENTS").expect("failed to get events map"))?;

    let (tx, mut rx) = watch::channel(false);

    let handle = tokio::spawn(async move {
        let mut batch = Vec::new();
        let mut last_event_time = Instant::now();

        loop {
            tokio::select! {
                _ = rx.changed() => {
                    if *rx.borrow() {
                        if !batch.is_empty() {
                            if let Err(e) = send_batch_to_server(batch.clone()).await {
                                eprintln!("Failed to send batch to server: {}", e);
                            }
                        }
                        break;
                    }
                }
                _ = process_ring_buffer_event(&mut ring_buf, &mut batch, &mut last_event_time) => {}
                _ = sleep(Duration::from_secs(5)) => {
                    if !batch.is_empty() {
                        if let Err(e) =send_batch_to_server(batch.clone()).await {
                            eprintln!("Failed to send batch to server: {}", e);
                        }
                        batch.clear();
                    }
                }
            }
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    tx.send(true)?;
    handle.await?;

    Ok(())
}
