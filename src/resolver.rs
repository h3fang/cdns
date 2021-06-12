use futures::{stream, StreamExt};
use log::{info, trace};
use reqwest::Url;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::result::Result;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op;

pub struct Upstream {
    pub url: String,
    pub domain: String,
    pub ips: Vec<IpAddr>,
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

impl Upstream {
    pub fn new(url: &str, ips: &[IpAddr]) -> Upstream {
        let u = Url::parse(url).expect(&format!("Invalid upstream URL {}", url));
        Upstream {
            url: url.to_string(),
            domain: u.domain().unwrap_or("").to_lowercase() + ".",
            ips: ips.to_vec(),
        }
    }

    pub fn defaults() -> Vec<Upstream> {
        vec![
            Upstream::new("https://dns.rubyfish.cn/dns-query", &[]),
            Upstream::new("https://doh.pub/dns-query", &[]),
            Upstream::new("https://101.6.6.6:8443/dns-query", &[]),
            Upstream::new(
                "https://dns.alidns.com/dns-query",
                &[
                    IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
                    IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
                    IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x1)),
                    IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x1)),
                ],
            ),
            // Upstream::new(
            //     "https://cloudflare-dns.com/dns-query",
            //     &[
            //         IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            //         IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            //         IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            //         IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
            //     ],
            // ),
            Upstream::new(
                "https://security.cloudflare-dns.com/dns-query",
                &[
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
                    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2)),
                    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1112)),
                    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1002)),
                ],
            ),
            // Upstream::new(
            //     "https://dns.google/dns-query",
            //     &[
            //         IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            //         IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            //         IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
            //         IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
            //     ],
            // ),
        ]
    }
}

pub async fn resolve_with_doh(
    url: &str,
    client: &reqwest::Client,
    q: &op::Query,
    msg: &op::Message,
) -> Result<(String, op::Message), ResolveError> {
    info!("lookup {} with {}", q, url);
    let rsp = client.post(url).body(msg.to_vec()?).send().await?;
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
    upstreams: &[Upstream],
    client: &reqwest::Client,
    q: &op::Query,
    msg: &op::Message,
) -> Result<op::Message, ResolveError> {
    let domain = q.name().to_utf8().to_lowercase();
    let recursive = upstreams.iter().any(|ups| ups.domain == domain);
    let results: Vec<_> = upstreams
        .iter()
        .filter(|ups| !recursive || (ups.domain == "." || !ups.ips.is_empty()))
        .map(|ups| async move { resolve_with_doh(&ups.url, client, q, msg).await })
        .collect();

    if let Some((url, rsp)) = stream::iter(results)
        .buffer_unordered(32)
        .filter_map(|r| async { r.ok() })
        .take(1)
        .collect::<Vec<_>>()
        .await
        .pop()
    {
        info!("Fastest response from {}", url);
        return Ok(rsp);
    }

    Err(ResolveError::AllFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_proto::rr;

    async fn resolve_domain(domain: &str, upstreams: &[Upstream], client: &reqwest::Client) {
        let name = rr::Name::from_ascii(domain).expect("Invalid domain name.");
        let q = op::Query::query(name.to_owned(), rr::RecordType::A);
        let mut msg = op::Message::new();
        msg.set_id(rand::random::<u16>());
        msg.add_query(q.to_owned());
        msg.set_message_type(op::MessageType::Query);
        msg.set_recursion_desired(true);

        let r = resolve(&upstreams, &client, &q, &msg)
            .await
            .expect("Failed to resolve.");

        assert_eq!(q, r.queries()[0]);
        assert_eq!(name, *r.answers()[0].name());
    }

    async fn resolve_domains() {
        let upstreams = Upstream::defaults();
        let client = reqwest::Client::new();

        let domains = vec!["www.baidu.com.", "github.com.", "www.google.com."];
        for d in &domains {
            resolve_domain(d, &upstreams, &client).await;
        }
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
