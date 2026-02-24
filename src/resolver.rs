use crate::cache::DNSCache;
use crate::config::Config;

use std::net::SocketAddr;
use std::sync::Arc;

use ahash::HashMap;
use anyhow::Result;
use bytes::Bytes;
use tokio::sync::{Mutex, broadcast};
use tracing::{error, info, trace, warn};

use futures::{StreamExt, stream};
use hickory_proto::op;
use reqwest::header::{HeaderMap, HeaderValue};

pub struct Resolver {
    config: Config,
    https_client: reqwest::Client,
    cache: DNSCache,
    ongoing: Arc<Mutex<HashMap<op::Query, broadcast::Sender<op::Message>>>>,
}

impl Resolver {
    pub fn new(config: Config, cache_size: usize) -> Resolver {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/dns-message"),
        );
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/dns-message"),
        );

        let mut builder = reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(std::time::Duration::from_secs(1))
            .timeout(std::time::Duration::from_secs(3))
            .pool_idle_timeout(std::time::Duration::from_secs(5))
            .tcp_keepalive(Some(std::time::Duration::from_secs(5)))
            .https_only(true)
            .no_hickory_dns();

        for s in config.groups.values().flatten() {
            if s.ips.is_empty() {
                continue;
            }
            if let Some(d) = s.url.domain() {
                let addrs = s
                    .ips
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, 443))
                    .collect::<Vec<_>>();
                builder = builder.resolve_to_addrs(d, &addrs);
            }
        }

        let https_client = builder
            .build()
            .unwrap_or_else(|e| panic!("Failed to create reqwest::Client, error: {e}"));

        Resolver {
            config,
            https_client,
            cache: DNSCache::new(cache_size),
            ongoing: Arc::new(Mutex::new(Default::default())),
        }
    }

    pub async fn query_with_doh(
        &self,
        url: &url::Url,
        q: &op::Query,
        msg: Bytes,
    ) -> Result<(String, op::Message)> {
        info!("lookup {q} with {url}");
        let rsp = self.https_client.post(url.clone()).body(msg).send().await?;
        trace!("query={q:?}, url={url}, response={rsp:?}");
        let bytes = rsp.error_for_status()?.bytes().await?;
        let msg = op::Message::from_vec(&bytes)?;
        Ok((url.to_string(), msg))
    }

    pub async fn query(&self, q: &op::Query, mut msg: op::Message) -> op::Message {
        // Try to get response from cache first
        if let Some(rsp) = self.cache.get(q) {
            return rsp;
        }

        // Try to subscribe to an existing query or start a new one
        let (mut rx, sender) = {
            // It is important that we keep the Mutex locked until we insert into it.
            // Otherwise there may be multiple queries inserting for the same query.
            let mut ongoing = self.ongoing.lock().await;
            match ongoing.get(q).map(|ongoing| ongoing.subscribe()) {
                Some(rx) => {
                    // Another task is already handling this query
                    (rx, None)
                }
                None => {
                    // We're the first to query this, create a new entry
                    let (tx, rx) = broadcast::channel(1);
                    ongoing.insert(q.clone(), tx.clone());
                    (rx, Some(tx))
                }
            }
        };

        // If we're the first one, perform the query
        if let Some(sender) = sender {
            let result = self.get_fastest_response(q, &msg).await;

            let rsp = match result {
                Ok(rsp) => {
                    self.cache.insert(q.to_owned(), rsp.clone());
                    rsp
                }
                Err(e) => {
                    error!("Resolve for {q} failed with error: {e}");
                    msg.set_message_type(op::MessageType::Response)
                        .set_response_code(op::ResponseCode::ServFail);
                    msg
                }
            };

            // An unsuccessful send would be one where all associated Receiver handles
            // have already been dropped, which is fine.
            let _ = sender.send(rsp.clone());

            self.ongoing.lock().await.remove(q);
            return rsp;
        }

        match rx.recv().await {
            Ok(rsp) => rsp,
            Err(e) => {
                // Channel closed without sending - this shouldn't happen normally
                // but we handle it gracefully by returning a ServFail
                // Or lagged - this shouldn't happen with capacity 1, but we handle it
                error!("Query channel for {q} failed with error {e}");
                msg.set_message_type(op::MessageType::Response)
                    .set_response_code(op::ResponseCode::ServFail);
                msg
            }
        }
    }

    async fn get_fastest_response(&self, q: &op::Query, msg: &op::Message) -> Result<op::Message> {
        let domain = q.name().to_utf8().to_lowercase();
        let recursive = self.config.is_recursive(&domain);
        let servers = self.config.match_rule(&domain);

        let msg = Bytes::from(msg.to_vec()?);

        let futures = servers
            .iter()
            .filter(|s| !recursive || s.resolved)
            .map(|s| self.query_with_doh(&s.url, q, msg.clone()))
            .collect::<Vec<_>>();

        let mut buffered = stream::iter(futures).buffer_unordered(32);

        while let Some(r) = buffered.next().await {
            if let Ok((url, rsp)) = r {
                info!("Fastest response from {url}");
                return Ok(rsp);
            }
        }

        Err(anyhow::anyhow!("All servers failed"))
    }

    pub async fn resolve(&self, mut msg: op::Message) -> op::Message {
        // ensure there is one and only one query in DNS message
        let n = msg.queries().iter().count();
        if n != 1 {
            warn!("{n} question(s) found in DNS query datagram.");
            msg.set_message_type(op::MessageType::Response)
                .set_response_code(op::ResponseCode::FormErr);
            return msg;
        }
        let q = msg.queries()[0].to_owned();

        info!("query {q}");

        /*
        In order to maximize HTTP cache friendliness, DoH clients using media
        formats that include the ID field from the DNS message header, such
        as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS request.
        From https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
        */
        let id = msg.id();
        msg.set_id(0);

        // resolve from multiple DNS servers
        let mut rsp = self.query(&q, msg).await;
        rsp.set_id(id);
        rsp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;
    use hickory_proto::rr;
    use std::sync::atomic::{AtomicU16, Ordering};

    static QUERY_ID: AtomicU16 = AtomicU16::new(0);

    async fn resolve_domain(domain: &str, resolver: &Resolver) -> anyhow::Result<()> {
        let name = rr::Name::from_ascii(domain)
            .unwrap_or_else(|e| panic!("Invalid domain: {domain}, error: {e}"));
        let q = op::Query::query(name.to_owned(), rr::RecordType::A);
        let id = QUERY_ID.fetch_add(1, Ordering::Relaxed);
        let mut msg = op::Message::new();
        msg.set_id(id)
            .add_query(q.to_owned())
            .set_message_type(op::MessageType::Query)
            .set_recursion_desired(true);

        let r = resolver.resolve(msg).await;

        assert_eq!(id, r.id());
        assert_eq!(q, r.queries()[0]);
        r.answers().iter().for_each(|a| println!("{a}"));
        assert_eq!(name, *r.answers()[0].name());
        Ok(())
    }

    async fn resolve_domains(repeat: usize) {
        let config = Config::default();
        let resolver = Resolver::new(config, 2048);

        // Alexa Top 10
        let domains = [
            "google.com.",
            "youtube.com.",
            "tmall.com.",
            "qq.com.",
            "baidu.com.",
            "sohu.com.",
            "facebook.com.",
            "taobao.com.",
            "360.cn.",
            "jd.com.",
        ];

        join_all(
            domains
                .iter()
                .cycle()
                .take(repeat * domains.len())
                .map(|d| resolve_domain(d, &resolver)),
        )
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_domains_current_thread() {
        resolve_domains(1).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_domains_multi_thread() {
        resolve_domains(1).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn request_coalescing() {
        resolve_domains(100).await;
    }
}
