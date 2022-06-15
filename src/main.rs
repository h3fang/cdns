mod cache;
mod config;
mod resolver;
mod server;

use crate::resolver::Resolver;
use config::Config;
use log::{error, info};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use trust_dns_proto::op;

async fn respond(msg: &op::Message, sock: &UdpSocket, addr: &SocketAddr) {
    match msg.to_vec() {
        Ok(bytes) => match sock.send_to(&bytes, addr).await {
            Ok(_) => {
                for ans in msg.answers() {
                    info!("{ans}");
                }
            }
            Err(e) => error!("Failed to send DNS response. Error: {e}"),
        },
        Err(e) => error!("Failed to encode DNS response. Error: {e}"),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env)
        .format_timestamp_micros()
        .init();

    let cfg_path = std::env::args()
        .nth(1)
        .expect("Expected configuration file path.");

    let config = Config::from_file(&cfg_path).unwrap_or_default();
    let resolver = Arc::new(Resolver::new(config, 2048));

    let sock = Arc::new(
        UdpSocket::bind("127.0.0.1:53")
            .await
            .unwrap_or_else(|e| panic!("Failed to create and bind socket. Error: {e}")),
    );

    let mut buf = vec![0u8; 512];

    loop {
        let (len, addr) = sock
            .recv_from(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("Failed to receive packet. Error: {e}"));
        let bytes = buf[..len].to_vec();

        let sock = sock.clone();
        let resolver = resolver.clone();

        tokio::spawn(async move {
            match resolver.handle_packet(bytes).await {
                Ok(rsp) => respond(&rsp, &sock, &addr).await,
                Err(e) => error!("{:?}", e),
            }
        });
    }
}
