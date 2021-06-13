mod cache;
mod resolver;
mod upstream;

use crate::cache::DNSCache;
use crate::resolver::Resolver;
use log::{error, info, warn};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::Mutex};
use trust_dns_proto::op;

async fn respond(msg: &op::Message, sock: &UdpSocket, addr: &SocketAddr) {
    match msg.to_vec() {
        Ok(bytes) => match sock.send_to(&bytes, addr).await {
            Ok(_) => {
                for ans in msg.answers() {
                    info!("{}", ans);
                }
            }
            Err(e) => error!("Failed to send DNS response. Error: {}", e),
        },
        Err(e) => error!("Failed to encode DNS response. Error: {}", e),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> io::Result<()> {
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env)
        .format_timestamp_micros()
        .init();

    let sock = Arc::new(UdpSocket::bind("127.0.0.1:53").await?);

    let resolver = Arc::new(Resolver::new());

    let mut cache = DNSCache::new(2048);
    cache.bootstrap(&resolver.upstreams);
    let cache = Arc::new(Mutex::new(cache));

    let mut buf = vec![0u8; 1024];

    let cache_clone = cache.clone();

    tokio::spawn(async move {
        let mut expire_timer = tokio::time::interval(tokio::time::Duration::from_secs(10));
        loop {
            expire_timer.tick().await;
            cache_clone.lock().await.remove_expired();
        }
    });

    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        let bytes = buf[..len].to_vec();

        let sock = sock.clone();
        let cache = cache.clone();
        let resolver = resolver.clone();

        tokio::spawn(async move {
            let mut msg = match op::Message::from_vec(&bytes) {
                Ok(m) => m,
                Err(e) => {
                    error!("Failed to decode DNS message, error: {}", e);
                    return;
                }
            };

            // ensure there is one and only one query in DNS message
            let n = msg.queries().iter().count();
            if n != 1 {
                warn!("{} question(s) found in DNS query datagram.", n);
                msg.set_message_type(op::MessageType::Response);
                msg.set_response_code(op::ResponseCode::FormErr);
                respond(&msg, &sock, &addr).await;
                return;
            }
            let q = msg.queries()[0].to_owned();

            info!("query {}", q);

            // try to get response from cache
            {
                let mut cache = cache.lock().await;
                match cache.get(&q, &msg) {
                    Some(rsp) => {
                        respond(rsp, &sock, &addr).await;
                        return;
                    }
                    None => {
                        cache.pop(&q);
                    }
                }
            }

            // resolve from multiple DNS servers
            match resolver.resolve(&q, &msg).await {
                Ok(rsp) => {
                    respond(&rsp, &sock, &addr).await;
                    cache.lock().await.put(q, rsp);
                }
                Err(e) => {
                    error!("Failed to resolve for {}, error: {:?}", q, e);
                    msg.set_message_type(op::MessageType::Response);
                    msg.set_response_code(op::ResponseCode::FormErr);
                    respond(&msg, &sock, &addr).await;
                }
            }
        });
    }
}
