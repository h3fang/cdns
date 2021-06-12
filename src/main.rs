mod cache;
mod resolver;

use cache::DNSCache;
use log::{error, info, warn};
use reqwest::header::{HeaderMap, HeaderValue};
use resolver::{resolve, Upstream};
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env)
        .format_timestamp_micros()
        .init();

    let sock = Arc::new(UdpSocket::bind("127.0.0.1:53").await?);

    let upstreams = Arc::new(Upstream::defaults());

    let mut cache = DNSCache::new(4096);
    cache.bootstrap(&upstreams);
    let cache = Arc::new(Mutex::new(cache));

    let mut buf = vec![0u8; 2048];

    let mut headers = HeaderMap::new();
    headers.insert(
        "accept",
        HeaderValue::from_static("application/dns-message"),
    );
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/dns-message"),
    );

    let client = Arc::new(
        reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(std::time::Duration::from_secs(1))
            .timeout(std::time::Duration::from_secs(3))
            .pool_max_idle_per_host(128)
            .https_only(true)
            .build()
            .expect("Failed to create reqwest::Client."),
    );

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
        let upstreams = upstreams.clone();
        let client = client.clone();

        tokio::spawn(async move {
            let mut msg;
            match op::Message::from_vec(&bytes) {
                Ok(m) => msg = m,
                Err(e) => {
                    error!("Failed to decode DNS message, error: {}", e);
                    return;
                }
            }

            // get the only query in DNS message
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
            match resolve(&upstreams, &client, &q, &msg).await {
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
