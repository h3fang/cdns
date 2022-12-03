use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize)]
pub struct Server {
    pub url: Url,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<IpAddr>,
}

impl Server {
    pub fn resolved(&self) -> bool {
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
