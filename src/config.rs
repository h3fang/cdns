use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ahash::HashMap;
use ahash::HashSet;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::server::Server;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub groups: HashMap<String, Vec<Server>>,
    #[serde(default)]
    pub rules: Vec<(String, String)>,
    #[serde(skip)]
    unresolved_domains: HashSet<String>,
}

impl Config {
    fn collect_unresolved_domains(&mut self) {
        self.unresolved_domains = self
            .groups
            .values()
            .flat_map(|g| g.iter().filter_map(|s| s.url.domain().map(String::from)))
            .collect();
    }

    fn is_valid(&self) -> bool {
        self.groups.values().flatten().any(|s| s.resolved())
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        let mut config: Config = serde_json::from_str(&s)?;
        config.collect_unresolved_domains();
        if config.is_valid() {
            Ok(config)
        } else {
            panic!("Failed to bootstrap DOH servers, at least one server with IP addresses should be specified.");
        }
    }

    pub fn match_rule(&self, domain: &str) -> &Vec<Server> {
        let domain = domain.trim_end_matches('.');
        for (rule, group) in &self.rules {
            if let Some(r) = domain.strip_suffix(rule) {
                if r.is_empty() || r.ends_with('.') {
                    return self.groups.get(group).unwrap();
                }
            }
        }
        self.groups
            .get("default")
            .unwrap_or_else(|| self.groups.values().next().unwrap())
    }

    pub fn is_recursive(&self, fqdn: &str) -> bool {
        self.unresolved_domains.contains(fqdn.trim_end_matches('.'))
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut groups = HashMap::default();

        groups.insert(
            "default".to_string(),
            vec![
                Server {
                    url: Url::parse("https://doh.pub/dns-query").unwrap(),
                    ips: vec![],
                },
                Server {
                    url: Url::parse("https://dns.alidns.com/dns-query").unwrap(),
                    ips: vec![
                        IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
                        IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
                        IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x1)),
                        IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x1)),
                    ],
                },
                Server {
                    url: Url::parse("https://cloudflare-dns.com/dns-query").unwrap(),
                    ips: vec![
                        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
                        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
                    ],
                },
                Server {
                    url: Url::parse("https://dns.google/dns-query").unwrap(),
                    ips: vec![
                        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                        IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
                        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
                    ],
                },
            ],
        );

        let mut config = Config {
            groups,
            rules: vec![],
            unresolved_domains: Default::default(),
        };
        config.collect_unresolved_domains();
        assert!(config.is_valid());
        config
    }
}
