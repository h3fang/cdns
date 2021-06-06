use crate::resolver::Upstream;
use log::info;
use lru::LruCache;
use std::net::IpAddr;
use std::time::Instant;
use trust_dns_proto::{op, rr};

pub struct DNSEntry {
    pub time: Instant,
    pub response: op::Message,
}

/// LRU DNS cache
pub struct DNSCache {
    cache: LruCache<op::Query, DNSEntry>,
}

impl DNSCache {
    pub fn new(cap: usize) -> DNSCache {
        DNSCache {
            cache: LruCache::new(cap),
        }
    }

    pub fn get(&mut self, q: &op::Query, msg: &op::Message) -> Option<&op::Message> {
        match self.cache.get_mut(q) {
            Some(entry) => {
                let ttl = entry
                    .response
                    .all_sections()
                    .map(|a| a.ttl())
                    .min()
                    .unwrap_or(0) as i64;
                let remaining = ttl - entry.time.elapsed().as_secs() as i64;
                if remaining >= 0 {
                    entry.response.set_id(msg.id());
                    if let Some(edns) = msg.edns() {
                        entry.response.set_edns(edns.to_owned());
                    }
                    entry.response.answers_mut().iter_mut().for_each(|a| {
                        a.set_ttl(remaining as u32);
                    });
                    info!("Cache hit, {}", q);
                    return Some(&entry.response);
                } else {
                    info!("Cache invalid, {}", q);
                }
            }
            None => {
                info!("Cache miss, {}", q);
            }
        }
        None
    }

    pub fn put(&mut self, q: op::Query, rsp: op::Message) {
        self.cache.put(
            q,
            DNSEntry {
                time: Instant::now(),
                response: rsp,
            },
        );
        info!("cache size: {}", self.len());
    }

    pub fn pop(&mut self, q: &op::Query) {
        self.cache.pop(q);
        info!("cache size: {}", self.len());
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn bootstrap(&mut self, resolvers: &[Upstream]) {
        resolvers.iter().for_each(|x| {
            if !x.ips.is_empty() {
                let name = rr::Name::from_utf8(&x.domain).unwrap();
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
                    msg.add_query(q.to_owned());
                    v4.iter().for_each(|&ip| {
                        msg.add_answer(rr::Record::from_rdata(
                            name.to_owned(),
                            std::u32::MAX,
                            rr::RData::A(ip),
                        ));
                    });
                    msg.set_message_type(op::MessageType::Response);
                    msg.set_authoritative(true);
                    msg.set_recursion_available(true);
                    msg.set_response_code(op::ResponseCode::NoError);
                    self.put(q, msg);
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
                    msg.add_query(q.to_owned());
                    v6.iter().for_each(|&ip| {
                        msg.add_answer(rr::Record::from_rdata(
                            name.to_owned(),
                            std::u32::MAX,
                            rr::RData::AAAA(ip),
                        ));
                    });
                    msg.set_message_type(op::MessageType::Response);
                    msg.set_authoritative(true);
                    msg.set_recursion_available(true);
                    msg.set_response_code(op::ResponseCode::NoError);
                    self.put(q, msg);
                }
            }
        });

        if self.is_empty() {
            panic!("Failed to bootstrap upstream servers, at least one server with IP addresses should be specified.");
        }
    }

    pub fn remove_expired(&mut self) {
        let invalid: Vec<_> = self
            .cache
            .iter()
            .filter_map(|(q, entry)| {
                let ttl = entry
                    .response
                    .all_sections()
                    .map(|a| a.ttl())
                    .min()
                    .unwrap_or(0) as i64;
                let remaining = ttl - entry.time.elapsed().as_secs() as i64;
                if remaining <= 0 {
                    return Some(q.to_owned());
                }
                None
            })
            .collect();

        for q in invalid {
            self.cache.pop(&q);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Alphanumeric, Rng};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use trust_dns_proto::rr;

    #[test]
    fn bootstrap_cache() {
        let mut cache = DNSCache::new(4096);
        let upstreams = Upstream::defaults();
        cache.bootstrap(&upstreams);
        let n = upstreams.iter().fold(0, |n, ups| {
            let mut c = 0;
            if ups.ips.iter().any(|ip| ip.is_ipv4()) {
                c += 1;
            }
            if ups.ips.iter().any(|ip| ip.is_ipv6()) {
                c += 1;
            }
            n + c
        });
        assert_eq!(n, cache.len());
    }

    #[test]
    fn populate_cache() {
        let n = 4096;
        let mut cache = DNSCache::new(n);
        for _ in 0..n {
            let name = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect::<String>()
                + ".com.";
            let name = rr::Name::from_ascii(name).unwrap();
            let mut msg = op::Message::new();
            let type_a = rand::random::<bool>();
            for _ in 1..(rand::thread_rng().gen_range(1..5)) {
                let rdata = if type_a {
                    rr::RData::A(Ipv4Addr::new(
                        1,
                        rand::random::<u8>(),
                        rand::random::<u8>(),
                        1,
                    ))
                } else {
                    rr::RData::AAAA(Ipv6Addr::new(
                        1,
                        rand::random::<u16>(),
                        rand::random::<u16>(),
                        rand::random::<u16>(),
                        0,
                        0,
                        rand::random::<u16>(),
                        1,
                    ))
                };
                msg.add_answer(rr::Record::from_rdata(name.to_owned(), 600, rdata));
            }
            cache.put(
                op::Query::query(
                    name,
                    if type_a {
                        rr::RecordType::A
                    } else {
                        rr::RecordType::AAAA
                    },
                ),
                msg,
            );
        }
        assert_eq!(cache.len() > 0, true);
        assert_eq!(cache.len() <= n, true);
    }
}
