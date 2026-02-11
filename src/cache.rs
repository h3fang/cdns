use std::time::Instant;

use hickory_proto::op;
use quick_cache::sync::Cache;
use tracing::info;

#[derive(Clone)]
struct DNSEntry {
    timestamp: Instant,
    message: op::Message,
}

/// LRU DNS cache
pub struct DNSCache {
    cache: Cache<op::Query, DNSEntry>,
}

impl DNSCache {
    pub fn new(cap: usize) -> DNSCache {
        DNSCache {
            cache: Cache::new(cap),
        }
    }

    pub fn get(&self, q: &op::Query) -> Option<op::Message> {
        match self.cache.get(q) {
            Some(entry) => {
                let ttl = entry
                    .message
                    .all_sections()
                    .map(|a| a.ttl())
                    .min()
                    .unwrap_or(0) as u64;
                let elapsed = entry.timestamp.elapsed().as_secs();
                if ttl > elapsed {
                    let remaining = (ttl - elapsed) as u32;
                    let mut msg = entry.message.to_owned();
                    msg.answers_mut().iter_mut().for_each(|a| {
                        a.set_ttl(remaining);
                    });
                    msg.additionals_mut().iter_mut().for_each(|a| {
                        a.set_ttl(remaining);
                    });
                    msg.name_servers_mut().iter_mut().for_each(|a| {
                        a.set_ttl(remaining);
                    });
                    info!("Cache hit, {q}");
                    Some(msg)
                } else {
                    self.cache.remove(q);
                    info!("Cache expired, {q}");
                    info!("Cache size: {}", self.len());
                    None
                }
            }
            None => {
                info!("Cache miss, {q}");
                None
            }
        }
    }

    pub fn insert(&self, q: op::Query, message: op::Message) {
        self.cache.insert(
            q,
            DNSEntry {
                timestamp: Instant::now(),
                message,
            },
        );
        info!("Cache size: {}", self.len());
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{
        self,
        rdata::{A, AAAA},
    };
    use rand::{RngExt, distr::Alphanumeric};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn populate_cache() {
        let n = 4096;
        let mut rng = rand::rng();
        let cache = DNSCache::new(n);
        for i in 0..n {
            let domain = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect::<String>()
                + format!("{i}.com.").as_str();
            let name = rr::Name::from_ascii(&domain)
                .unwrap_or_else(|e| panic!("Invalid domain: {domain}, error: {e}"));
            let mut msg = op::Message::new();
            msg.set_message_type(op::MessageType::Response);
            let type_a = rand::random::<bool>();
            for _ in 0..(rng.random_range(1..5)) {
                let rdata = if type_a {
                    rr::RData::A(A(Ipv4Addr::from(rand::random::<u32>())))
                } else {
                    rr::RData::AAAA(AAAA(Ipv6Addr::from(rand::random::<u128>())))
                };
                msg.add_answer(rr::Record::from_rdata(
                    name.to_owned(),
                    rand::random::<u32>(),
                    rdata,
                ));
            }
            cache.insert(
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

        assert!(cache.len() <= n);
    }
}
