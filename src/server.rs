use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Default, Serialize, Deserialize)]
pub struct Server {
    pub url: String,

    // domain of the server url with the trailing full stop (a period)
    #[serde(default, skip_serializing)]
    pub domain: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<IpAddr>,

    // the server does not need to resolv the domain
    // which means the domain is an IP address or the ips field is not empty
    #[serde(default, skip_serializing)]
    pub resolved: bool,
}

impl Server {
    pub fn extract_domain(&mut self) {
        let url = &self.url;
        let u = url::Url::parse(url).unwrap_or_else(|_| panic!("Invalid Server URL: {url}"));
        self.domain = u.domain().unwrap_or("").to_lowercase() + ".";
        self.resolved = self.domain == "." || !self.ips.is_empty();
    }
}
