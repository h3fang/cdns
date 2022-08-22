use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ahash::AHashMap as HashMap;
use ahash::AHashSet as HashSet;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::server::Server;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub groups: HashMap<String, Vec<Server>>,
    #[serde(default)]
    pub rules: Vec<(String, String)>,
    #[serde(default, skip_serializing)]
    server_domains: HashSet<String>,
}

impl Config {
    fn set_domains(&mut self) {
        self.groups
            .values_mut()
            .for_each(|g| g.iter_mut().for_each(|s| s.extract_domain()));

        self.server_domains = self
            .groups
            .values()
            .flat_map(|g| {
                g.iter().filter_map(|s| {
                    if s.domain != "." {
                        Some(s.domain.to_string())
                    } else {
                        None
                    }
                })
            })
            .collect();
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        let mut config: Config = serde_json::from_str(&s)?;
        config.set_domains();
        Ok(config)
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

    pub fn is_recursive(&self, domain: &str) -> bool {
        self.server_domains.contains(domain)
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut groups = HashMap::new();

        groups.insert(
            "default".to_string(),
            vec![
                Server {
                    url: "https://doh.pub/dns-query".into(),
                    ..Default::default()
                },
                Server {
                    url: "https://dns.alidns.com/dns-query".into(),
                    ips: vec![
                        IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
                        IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
                        IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x1)),
                        IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x1)),
                    ],
                    ..Default::default()
                },
                Server {
                    url: "https://cloudflare-dns.com/dns-query".into(),
                    ips: vec![
                        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
                        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
                    ],
                    ..Default::default()
                },
                Server {
                    url: "https://dns.google/dns-query".into(),
                    ips: vec![
                        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                        IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
                        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
                    ],
                    ..Default::default()
                },
            ],
        );

        let mut config = Self {
            groups,
            rules: Default::default(),
            server_domains: Default::default(),
        };
        config.set_domains();
        config
    }
}
