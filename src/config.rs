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
    unresolved_servers: HashSet<String>,
}

impl Config {
    fn collect_unresolved_servers(&mut self) {
        self.unresolved_servers = self
            .groups
            .values_mut()
            .flat_map(|g| {
                g.iter_mut().filter_map(|s| {
                    s.resolved = s.is_resolved();
                    if !s.resolved {
                        s.url.domain().map(String::from)
                    } else {
                        None
                    }
                })
            })
            .collect();
    }

    fn is_valid(&self) -> bool {
        self.groups.values().flatten().any(|s| s.resolved)
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        let mut config: Config = serde_json::from_str(&s)?;
        config.collect_unresolved_servers();
        if config.is_valid() {
            Ok(config)
        } else {
            Err(anyhow::anyhow!(
                "Invalid config file. At least one server with IP addresses should be specified."
            ))
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
        self.unresolved_servers.contains(fqdn.trim_end_matches('.'))
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut groups = HashMap::default();

        groups.insert(
            "default".to_string(),
            vec![
                Server::new(
                    Url::parse("https://doh.pub/dns-query").unwrap(),
                    vec![
                        IpAddr::V4(Ipv4Addr::new(1, 12, 12, 12)),
                        IpAddr::V4(Ipv4Addr::new(120, 53, 53, 53)),
                    ],
                ),
                Server::new(
                    Url::parse("https://dns.alidns.com/dns-query").unwrap(),
                    vec![
                        IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
                        IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
                        IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x1)),
                        IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x1)),
                    ],
                ),
                Server::new(
                    Url::parse("https://cloudflare-dns.com/dns-query").unwrap(),
                    vec![
                        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
                        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
                    ],
                ),
                Server::new(
                    Url::parse("https://dns.google/dns-query").unwrap(),
                    vec![
                        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                        IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
                        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
                    ],
                ),
            ],
        );

        let mut config = Config {
            groups,
            rules: vec![],
            unresolved_servers: Default::default(),
        };
        config.collect_unresolved_servers();
        assert!(config.is_valid());
        config
    }
}
