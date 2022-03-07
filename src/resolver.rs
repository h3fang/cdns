use crate::cache::DNSCache;
use crate::upstream::Upstream;
use ahash::AHashMap as HashMap;
use futures::{stream, StreamExt};
use log::{error, info, trace, warn};
use reqwest::header::{HeaderMap, HeaderValue};
use std::net::IpAddr;
use std::result::Result;
use tokio::sync::{watch, Mutex};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::{op, rr};

pub struct Resolver {
    upstreams: Vec<Upstream>,
    https_client: reqwest::Client,
    presets: HashMap<op::Query, op::Message>,
    cache: Mutex<DNSCache>,
    ongoing: Mutex<HashMap<op::Query, watch::Receiver<op::Message>>>,
}

#[derive(Debug)]
pub enum ResolveError {
    // Https error.
    Reqwest(reqwest::Error),
    // Failed to deserialize server response.
    Proto(ProtoError),
    // Error status code in server responded DNS message.
    ErrorResponse,
    // All servers failed to give valid response.
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
            .pool_idle_timeout(std::time::Duration::from_secs(5))
            .tcp_keepalive(Some(std::time::Duration::from_secs(5)))
            .https_only(true)
            .build()
            .expect("Failed to create reqwest::Client.");

        let upstreams = Upstream::defaults();

        Resolver {
            presets: bootstrap(&upstreams),
            upstreams,
            https_client: client,
            cache: Mutex::new(DNSCache::new(cache_size)),
            ongoing: Default::default(),
        }
    }

    pub async fn resolve_with_doh(
        &self,
        url: &str,
        q: &op::Query,
        msg: &op::Message,
    ) -> Result<(String, op::Message), ResolveError> {
        info!("lookup {q} with {url}");
        let rsp = self
            .https_client
            .post(url)
            .body(msg.to_vec()?)
            .send()
            .await?;
        trace!("response = {rsp:?}");
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
        if let Some(rsp) = self.presets.get(q) {
            let mut rsp = rsp.to_owned();
            if let Some(edns) = msg.edns() {
                rsp.set_edns(edns.to_owned());
            }
            return Ok(rsp);
        }

        // query is ongoing, wait for the result
        if let Some(mut rx) = { self.ongoing.lock().await.get(q).cloned() } {
            if rx.changed().await.is_ok() {
                return Ok(rx.borrow().clone());
            }
        }

        // try to get response from cache
        {
            let mut cache = self.cache.lock().await;
            match cache.get(q) {
                Some(mut rsp) => {
                    rsp.set_id(msg.id());
                    if let Some(edns) = msg.edns() {
                        rsp.set_edns(edns.to_owned());
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
                info!("Fastest response from {url}");
                self.cache.lock().await.put(q.to_owned(), rsp.to_owned());
                let _ = tx.send(rsp.clone());
                self.ongoing.lock().await.remove(q);
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
        let mut rsp = self.resolve(&q, &msg).await.unwrap_or_else(|e| {
            error!("Failed to resolve for {q}, error: {e:?}");
            msg.set_message_type(op::MessageType::Response)
                .set_response_code(op::ResponseCode::FormErr);
            msg
        });
        rsp.set_id(id);
        Ok(rsp)
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
        let u = url::Url::parse(&ups.url).unwrap_or_else(|e| panic!("Invalid url, {e}"));
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
        r.answers().iter().for_each(|a| println!("{a}"));
        assert_eq!(name, *r.answers()[0].name());
    }

    async fn resolve_domains(repeat: usize) {
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
