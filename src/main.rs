mod cache;
mod config;
mod resolver;
mod server;

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use log::{error, info, warn};
use tokio::net::UdpSocket;
use trust_dns_proto::op;

use config::Config;
use resolver::Resolver;

async fn respond(msg: &op::Message, sock: &UdpSocket, addr: &SocketAddr) -> Result<()> {
    let bytes = msg.to_vec()?;
    sock.send_to(&bytes, addr).await?;
    for ans in msg.answers() {
        info!("{ans}");
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::io::Result<()> {
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env)
        .format_timestamp_micros()
        .init();

    let config = match std::env::args().nth(1) {
        Some(path) => match Config::from_file(&path) {
            Ok(cfg) => cfg,
            Err(e) => panic!("Failed to parse config file: {path}, error: {e}"),
        },
        None => {
            warn!("Using default configuration.");
            Config::default()
        }
    };

    let resolver = Arc::new(Resolver::new(config, 2048));

    let sock = Arc::new(UdpSocket::bind("127.0.0.1:53").await?);

    // maximum size of the DNS message, from https://datatracker.ietf.org/doc/html/rfc8484#section-6
    let mut buf = vec![0u8; 65535];

    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        let bytes = buf[..len].to_vec();

        let sock = sock.clone();
        let resolver = resolver.clone();

        tokio::spawn(async move {
            match resolver.resolve(bytes).await {
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
