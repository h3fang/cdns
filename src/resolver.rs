use crate::upstream::Upstream;
use futures::{stream, StreamExt};
use log::{info, trace};
use reqwest::header::{HeaderMap, HeaderValue};
use std::result::Result;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op;

pub struct Resolver {
    pub upstreams: Vec<Upstream>,
    pub https_client: reqwest::Client,
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
    pub fn new() -> Resolver {
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

        Resolver {
            upstreams: Upstream::defaults(),
            https_client: client,
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
        let domain = q.name().to_utf8().to_lowercase();
        let recursive = self.upstreams.iter().any(|ups| ups.domain == domain);
        let results: Vec<_> = self
            .upstreams
            .iter()
            .filter(|ups| !recursive || (ups.domain == "." || !ups.ips.is_empty()))
            .map(|ups| async move { self.resolve_with_doh(&ups.url, q, msg).await })
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_proto::rr;

    async fn resolve_domain(domain: &str, resolver: &Resolver) {
        let name = rr::Name::from_ascii(domain).expect("Invalid domain name.");
        let q = op::Query::query(name.to_owned(), rr::RecordType::A);
        let mut msg = op::Message::new();
        msg.set_id(rand::random::<u16>());
        msg.add_query(q.to_owned());
        msg.set_message_type(op::MessageType::Query);
        msg.set_recursion_desired(true);

        let r = resolver
            .resolve(&q, &msg)
            .await
            .expect("Failed to resolve.");

        assert_eq!(q, r.queries()[0]);
        assert_eq!(name, *r.answers()[0].name());
    }

    async fn resolve_domains() {
        let resolver = Resolver::new();

        let domains = vec!["www.baidu.com.", "github.com.", "www.google.com."];
        for d in &domains {
            resolve_domain(d, &resolver).await;
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
