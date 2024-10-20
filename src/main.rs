mod cache;
mod config;
mod resolver;
mod server;

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use hickory_proto::op;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use config::Config;
use resolver::Resolver;

async fn respond(msg: &op::Message, sock: &UdpSocket, addr: &SocketAddr) -> Result<()> {
    let bytes = msg.to_vec()?;
    sock.send_to(&bytes, addr)
        .await
        .context("Failed to send DNS response packet.")?;
    for ans in msg.answers() {
        info!("{ans}");
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_file(true)
        .with_line_number(true)
        .without_time()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = match std::env::args().nth(1) {
        Some(path) => {
            Config::from_file(&path).context(format!("Failed to parse config file: {path}"))?
        }
        None => {
            warn!("Using default configuration.");
            Config::default()
        }
    };

    let sock = Arc::new(
        UdpSocket::bind(&config.address)
            .await
            .context(format!("Failed to bind socket to {}", config.address))?,
    );
    let resolver = Arc::new(Resolver::new(config, 2048));

    // maximum size of the DNS message, from https://datatracker.ietf.org/doc/html/rfc8484#section-6
    let mut buf = vec![0u8; 65535];

    loop {
        let (len, addr) = sock
            .recv_from(&mut buf)
            .await
            .context("Failed to read data from socket.")?;
        let msg = match op::Message::from_vec(&buf[..len]) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to parse DNS message, {e}.");
                continue;
            }
        };

        let sock = sock.clone();
        let resolver = resolver.clone();

        tokio::spawn(async move {
            match resolver.resolve(msg).await {
                Ok(rsp) => {
                    if let Err(e) = respond(&rsp, &sock, &addr).await {
                        error!("Failed to send response: {:?}.", e);
                    }
                }
                Err(e) => error!("Failed to resolve: {:?}.", e),
            }
        });
    }
}
