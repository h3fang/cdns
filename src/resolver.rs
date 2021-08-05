use crate::cache::DNSCache;
use crate::upstream::Upstream;
use futures::{stream, StreamExt};
use log::{error, info, trace, warn};
use reqwest::header::{HeaderMap, HeaderValue};
use std::collections::HashMap;
use std::net::IpAddr;
use std::result::Result;
use tokio::sync::Mutex;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::{op, rr};

pub struct Resolver {
    upstreams: Vec<Upstream>,
    https_client: reqwest::Client,
    presets: HashMap<op::Query, op::Message>,
    cache: Mutex<DNSCache>,
}

#[derive(Debug)]
pub enum ResolveError {
    Reqwest(reqwest::Error),
    Proto(ProtoError),
    ErrorResponse,
    AllFailed,
}

impl From<reqwest::Error> for ResolveError {
    fn from(err: reqwest::Error) -> ResolveError {
        ResolveError::Reqwest(err)
    }
}

impl From<ProtoError> for ResolveError {
    fn from(err: ProtoError) -> ResolveError {
        ResolveError::Proto(err)
    }
}

impl Resolver {
    pub fn new(cache_size: usize) -> Resolver {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/dns-message"),
        );
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/dns-message"),
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(std::time::Duration::from_secs(1))
            .timeout(std::time::Duration::from_secs(3))
            .pool_max_idle_per_host(128)
            .https_only(true)
            .build()
            .expect("Failed to create reqwest::Client.");

        let upstreams = Upstream::defaults();

        Resolver {
            presets: bootstrap(&upstreams),
            upstreams,
            https_client: client,
            cache: Mutex::new(DNSCache::new(cache_size)),
        }
    }

    pub async fn resolve_with_doh(
        &self,
        url: &str,
        q: &op::Query,
        msg: &op::Message,
    ) -> Result<(String, op::Message), ResolveError> {
        info!("lookup {} with {}", q, url);
        let rsp = self
            .https_client
            .post(url)
            .body(msg.to_vec()?)
            .send()
            .await?;
        trace!("response = {:?}", rsp);
        let bytes = rsp.error_for_status()?.bytes().await?;
        let msg = op::Message::from_vec(&bytes)?;
        if msg.response_code() != op::ResponseCode::NoError {
            Err(ResolveError::ErrorResponse)
        } else {
            Ok((url.to_string(), msg))
        }
    }

    pub async fn resolve(
        &self,
        q: &op::Query,
        msg: &op::Message,
    ) -> Result<op::Message, ResolveError> {
        if let Some(msg) = self.presets.get(q) {
            return Ok(msg.to_owned());
        }

        // try to get response from cache
        {
            let mut cache = self.cache.lock().await;
            match cache.get(q, msg) {
                Some(rsp) => {
                    return Ok(rsp.to_owned());
                }
                None => {
                    cache.pop(q);
                }
            }
        }

        let domain = q.name().to_utf8().to_lowercase();
        let recursive = self.upstreams.iter().any(|ups| ups.domain == domain);
        let results: Vec<_> = self
            .upstreams
            .iter()
            .filter(|ups| !recursive || (ups.domain == "." || !ups.ips.is_empty()))
            .map(|ups| async move { self.resolve_with_doh(&ups.url, q, msg).await })
            .collect();

        let mut buffered = stream::iter(results).buffer_unordered(32);

        while let Some(r) = buffered.next().await {
            if let Ok((url, rsp)) = r {
                info!("Fastest response from {}", url);
                self.cache.lock().await.put(q.to_owned(), rsp.to_owned());
                return Ok(rsp);
            }
        }

        Err(ResolveError::AllFailed)
    }

    pub async fn handle_packet(&self, bytes: Vec<u8>) -> Result<op::Message, ResolveError> {
        let mut msg = op::Message::from_vec(&bytes)?;

        // ensure there is one and only one query in DNS message
        let n = msg.queries().iter().count();
        if n != 1 {
            warn!("{} question(s) found in DNS query datagram.", n);
            msg.set_message_type(op::MessageType::Response)
                .set_response_code(op::ResponseCode::FormErr);
            return Ok(msg);
        }
        let q = msg.queries()[0].to_owned();

        info!("query {}", q);

        // resolve from multiple DNS servers
        match self.resolve(&q, &msg).await {
            Ok(rsp) => Ok(rsp),
            Err(e) => {
                error!("Failed to resolve for {}, error: {:?}", q, e);
                msg.set_message_type(op::MessageType::Response)
                    .set_response_code(op::ResponseCode::FormErr);
                Ok(msg)
            }
        }
    }
}

fn bootstrap(upstreams: &[Upstream]) -> HashMap<op::Query, op::Message> {
    let mut presets = HashMap::new();
    upstreams.iter().for_each(|x| {
        if !x.ips.is_empty() {
            let name = rr::Name::from_utf8(&x.domain)
                .unwrap_or_else(|_| panic!("Invalid domain name {}", x.domain));
            let v4: Vec<_> = x
                .ips
                .iter()
                .filter_map(|&ip| match ip {
                    IpAddr::V4(addr) => Some(addr),
                    _ => None,
                })
                .collect();
            if !v4.is_empty() {
                let q = op::Query::query(name.to_owned(), rr::record_type::RecordType::A);
                let mut msg = op::Message::new();
                msg.set_message_type(op::MessageType::Response)
                    .set_authoritative(true)
                    .set_recursion_available(true)
                    .set_response_code(op::ResponseCode::NoError)
                    .add_query(q.to_owned());
                v4.iter().for_each(|&ip| {
                    msg.add_answer(rr::Record::from_rdata(
                        name.to_owned(),
                        std::u32::MAX,
                        rr::RData::A(ip),
                    ));
                });
                presets.insert(q, msg);
            }

            let v6: Vec<_> = x
                .ips
                .iter()
                .filter_map(|&ip| match ip {
                    IpAddr::V6(addr) => Some(addr),
                    _ => None,
                })
                .collect();
            if !v6.is_empty() {
                let q = op::Query::query(name.to_owned(), rr::record_type::RecordType::AAAA);
                let mut msg = op::Message::new();
                msg.set_message_type(op::MessageType::Response)
                    .set_authoritative(true)
                    .set_recursion_available(true)
                    .set_response_code(op::ResponseCode::NoError)
                    .add_query(q.to_owned());
                v6.iter().for_each(|&ip| {
                    msg.add_answer(rr::Record::from_rdata(
                        name.to_owned(),
                        std::u32::MAX,
                        rr::RData::AAAA(ip),
                    ));
                });
                presets.insert(q, msg);
            }
        }
    });

    let has_ip_host = upstreams.iter().any(|ups| {
        let u = url::Url::parse(&ups.url).unwrap_or_else(|e| panic!("Invalid url, {}", e));
        matches!(
            u.host(),
            Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_))
        )
    });

    if !has_ip_host && presets.is_empty() {
        panic!("Failed to bootstrap upstream servers, at least one upstream with IP addresses should be specified.");
    }

    presets
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;
    use trust_dns_proto::rr;

    async fn resolve_domain(domain: &str, resolver: &Resolver) {
        let name = rr::Name::from_ascii(domain).expect("Invalid domain name.");
        let q = op::Query::query(name.to_owned(), rr::RecordType::A);
        let mut msg = op::Message::new();
        msg.set_id(rand::random::<u16>())
            .add_query(q.to_owned())
            .set_message_type(op::MessageType::Query)
            .set_recursion_desired(true);

        let r = resolver
            .resolve(&q, &msg)
            .await
            .expect("Failed to resolve.");

        assert_eq!(q, r.queries()[0]);
        assert_eq!(name, *r.answers()[0].name());
    }

    async fn resolve_domains() {
        let resolver = Resolver::new(2048);

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

        join_all(domains.into_iter().map(|d| resolve_domain(d, &resolver))).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_domains_current_thread() {
        resolve_domains().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_domains_multi_thread() {
        resolve_domains().await;
    }
}
