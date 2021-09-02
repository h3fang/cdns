use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct Upstream {
    pub url: String,
    pub domain: String,
    pub ips: Vec<IpAddr>,
}

impl Upstream {
    pub fn new(url: &str, ips: &[IpAddr]) -> Upstream {
        let u = url::Url::parse(url).unwrap_or_else(|_| panic!("Invalid upstream URL {}", url));
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
            // Upstream::new("https://101.6.6.6:8443/dns-query", &[]),
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
            Upstream::new(
                "https://dns.adguard.com/dns-query",
                &[
                    IpAddr::V4(Ipv4Addr::new(94, 140, 14, 140)),
                    IpAddr::V4(Ipv4Addr::new(94, 140, 14, 141)),
                    IpAddr::V6(Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0x1, 0xff)),
                    IpAddr::V6(Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0x2, 0xff)),
                ],
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_upstreams() {
        let ups = Upstream::defaults();
        assert_eq!(ups.len() > 0, true);
    }
}
