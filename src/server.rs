use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize)]
pub struct Server {
    pub url: Url,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<IpAddr>,
    #[serde(skip)]
    pub resolved: bool,
}

impl Server {
    pub fn new(url: Url, ips: Vec<IpAddr>) -> Self {
        Self {
            url,
            resolved: !ips.is_empty(),
            ips,
        }
    }

    pub fn is_resolved(&self) -> bool {
        !self.ips.is_empty()
            || match self.url.host() {
                Some(h) => match h {
                    url::Host::Domain(_) => false,
                    url::Host::Ipv4(_) | url::Host::Ipv6(_) => true,
                },
                None => false,
            }
    }
}
