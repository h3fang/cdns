use crate::cache::DNSCache;
use crate::config::Config;

use std::net::SocketAddr;
use std::time::Duration;

use ahash::AHashMap as HashMap;
use anyhow::Result;
use log::{error, info, trace, warn};

use futures::{stream, StreamExt};
use hickory_proto::op;
use reqwest::header::{HeaderMap, HeaderValue};
use tokio::sync::{watch, Mutex};
use tokio::time::timeout;

pub struct Resolver {
    config: Config,
    https_client: reqwest::Client,
    cache: Mutex<DNSCache>,
    ongoing: Mutex<HashMap<op::Query, watch::Receiver<op::Message>>>,
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
            cache: Mutex::new(DNSCache::new(cache_size)),
            ongoing: Default::default(),
        }
    }

    pub async fn query_with_doh(
        &self,
        url: &url::Url,
        q: &op::Query,
        msg: Vec<u8>,
    ) -> Result<(String, op::Message)> {
        info!("lookup {q} with {url}");
        let rsp = self.https_client.post(url.clone()).body(msg).send().await?;
        trace!("query={q:?}, url={url}, response={rsp:?}");
        let bytes = rsp.error_for_status()?.bytes().await?;
        let msg = op::Message::from_vec(&bytes)?;
        Ok((url.to_string(), msg))
    }

    pub async fn query(&self, q: &op::Query, msg: &op::Message) -> Result<op::Message> {
        // query is ongoing, wait for the result
        if let Some(mut rx) = { self.ongoing.lock().await.get(q).cloned() } {
            if let Ok(Ok(())) = timeout(Duration::from_secs(3), rx.changed()).await {
                return Ok(rx.borrow().clone());
            }
        }

        // try to get response from cache
        {
            let mut cache = self.cache.lock().await;
            match cache.get(q) {
                Some(mut rsp) => {
                    if let Some(edns) = msg.extensions() {
                        rsp.set_edns(edns.clone());
                    }
                    return Ok(rsp);
                }
                None => {
                    cache.pop(q);
                }
            }
        }

        let (tx, rx) = watch::channel(op::Message::new());
        self.ongoing.lock().await.insert(q.clone(), rx);

        let domain = q.name().to_utf8().to_lowercase();
        let recursive = self.config.is_recursive(&domain);
        let servers = self.config.match_rule(&domain);

        let msg = msg.to_vec()?;

        let futures = servers
            .iter()
            .filter(|s| !recursive || s.resolved)
            .map(|s| self.query_with_doh(&s.url, q, msg.clone()))
            .collect::<Vec<_>>();

        let mut buffered = stream::iter(futures).buffer_unordered(32);

        while let Some(r) = buffered.next().await {
            if let Ok((url, rsp)) = r {
                info!("Fastest response from {url}");
                self.cache.lock().await.put(q.to_owned(), rsp.to_owned());
                let _ = tx.send(rsp.clone());
                self.ongoing.lock().await.remove(q);
                return Ok(rsp);
            }
        }

        self.ongoing.lock().await.remove(q);
        Err(anyhow::anyhow!("All servers failed"))
    }

    pub async fn resolve(&self, mut msg: op::Message) -> Result<op::Message> {
        // ensure there is one and only one query in DNS message
        let n = msg.queries().iter().count();
        if n != 1 {
            warn!("{n} question(s) found in DNS query datagram.");
            msg.set_message_type(op::MessageType::Response)
                .set_response_code(op::ResponseCode::FormErr);
            return Ok(msg);
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
        let mut rsp = self.query(&q, &msg).await.unwrap_or_else(|e| {
            error!("Failed to resolve for {q}, error: {e:?}");
            msg.set_message_type(op::MessageType::Response)
                .set_response_code(op::ResponseCode::FormErr);
            msg
        });
        rsp.set_id(id);
        Ok(rsp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;
    use hickory_proto::rr;

    async fn resolve_domain(domain: &str, resolver: &Resolver) -> anyhow::Result<()> {
        let name = rr::Name::from_ascii(domain)
            .unwrap_or_else(|e| panic!("Invalid domain: {domain}, error: {e}"));
        let q = op::Query::query(name.to_owned(), rr::RecordType::A);
        let id = rand::random::<u16>();
        let mut msg = op::Message::new();
        msg.set_id(id)
            .add_query(q.to_owned())
            .set_message_type(op::MessageType::Query)
            .set_recursion_desired(true);

        let r = resolver
            .resolve(msg)
            .await
            .unwrap_or_else(|e| panic!("Failed to resolve, error: {e:?}"));

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
        let domains = vec![
            "google.com.",
            "youtube.com.",
            "tmall.com.",
            "qq.com",
            "baidu.com",
            "sohu.com",
            "facebook.com",
            "taobao.com",
            "360.cn",
            "jd.com",
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
        resolve_domains(10).await;
    }
}
