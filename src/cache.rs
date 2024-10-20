use std::time::Instant;

use hickory_proto::op;
use tracing::info;
use lru::LruCache;

struct DNSEntry {
    timestamp: Instant,
    message: op::Message,
}

/// LRU DNS cache
pub struct DNSCache {
    cache: LruCache<op::Query, DNSEntry>,
}

impl DNSCache {
    pub fn new(cap: usize) -> DNSCache {
        DNSCache {
            cache: LruCache::new(cap.try_into().expect("Cache capacity can not be zero.")),
        }
    }

    pub fn get(&mut self, q: &op::Query) -> Option<op::Message> {
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
                    return Some(msg);
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

    pub fn put(&mut self, q: op::Query, message: op::Message) {
        self.cache.put(
            q,
            DNSEntry {
                timestamp: Instant::now(),
                message,
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
    use hickory_proto::rr::{
        self,
        rdata::{A, AAAA},
    };
    use rand::{distributions::Alphanumeric, Rng};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn populate_cache() {
        let n = 4096;
        let mut rng = rand::thread_rng();
        let mut cache = DNSCache::new(n);
        for i in 0..n {
            let domain = rand::thread_rng()
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
            for _ in 0..(rng.gen_range(1..5)) {
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
