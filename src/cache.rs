use log::info;
use lru::LruCache;
use std::time::Instant;
use trust_dns_proto::op;

struct DNSEntry {
    timestamp: Instant,
    response: op::Message,
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

    pub fn get(&mut self, q: &op::Query) -> Option<op::Message> {
        match self.cache.get_mut(q) {
            Some(entry) => {
                let ttl = entry
                    .response
                    .all_sections()
                    .map(|a| a.ttl())
                    .min()
                    .unwrap_or(0) as i64;
                let remaining = ttl - entry.timestamp.elapsed().as_secs() as i64;
                if remaining >= 0 {
                    let mut rsp = entry.response.to_owned();
                    rsp.answers_mut().iter_mut().for_each(|a| {
                        a.set_ttl(remaining as u32);
                    });
                    info!("Cache hit, {q}");
                    return Some(rsp);
                } else {
                    info!("Cache invalid, {q}");
                }
            }
            None => {
                info!("Cache miss, {q}");
            }
        }
        None
    }

    pub fn put(&mut self, q: op::Query, rsp: op::Message) {
        self.cache.put(
            q,
            DNSEntry {
                timestamp: Instant::now(),
                response: rsp,
            },
        );
        info!("cache size: {}", self.len());
    }

    pub fn pop(&mut self, q: &op::Query) {
        self.cache.pop(q);
        info!("cache size: {}", self.len());
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Alphanumeric, Rng};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use trust_dns_proto::rr;

    #[test]
    fn populate_cache() {
        let n = 4096;
        let mut rng = rand::thread_rng();
        let mut cache = DNSCache::new(n);
        for i in 0..n {
            let name = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect::<String>()
                + format!("{i}.com.").as_str();
            let name = rr::Name::from_ascii(&name)
                .unwrap_or_else(|_| panic!("Invalid domain name {name}"));
            let mut msg = op::Message::new();
            msg.set_message_type(op::MessageType::Response);
            let type_a = rand::random::<bool>();
            for _ in 0..(rng.gen_range(1..5)) {
                let rdata = if type_a {
                    rr::RData::A(Ipv4Addr::from(rand::random::<u32>()))
                } else {
                    rr::RData::AAAA(Ipv6Addr::from(rand::random::<u128>()))
                };
                msg.add_answer(rr::Record::from_rdata(
                    name.to_owned(),
                    rand::random::<u32>(),
                    rdata,
                ));
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

        assert_eq!(cache.len(), n);
    }
}
