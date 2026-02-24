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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::{
        op::{Message, MessageType, Query},
        rr::{
            Name, RData, Record, RecordType,
            rdata::{A, AAAA},
        },
    };

    #[test]
    fn test_cache_miss() {
        let cache = DNSCache::new(100);
        let name = Name::from_ascii("example.com.").unwrap();
        let query = Query::query(name, RecordType::A);

        assert!(cache.get(&query).is_none());
    }

    #[test]
    fn test_cache_hit() {
        let cache = DNSCache::new(100);
        let name = Name::from_ascii("example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);

        // Insert A record
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(2, 2, 2, 2))),
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(2, 2, 2, 3))),
        ));

        let ans = msg.answers().to_vec();

        cache.insert(query.clone(), msg);

        // Insert AAAA record
        let query_aaaa = Query::query(name.clone(), RecordType::AAAA);

        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::AAAA(AAAA(Ipv6Addr::new(0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2))),
        ));

        let ans_aaaa = msg.answers().to_vec();

        cache.insert(query_aaaa.clone(), msg);

        assert_eq!(cache.len(), 2);

        assert!(cache.get(&query).is_some_and(|msg| msg.answers() == ans));
        assert!(
            cache
                .get(&query_aaaa)
                .is_some_and(|msg| msg.answers() == ans_aaaa)
        );
    }

    #[test]
    fn test_ttl_preserved_in_cached_response() {
        let cache = DNSCache::new(100);
        let name = Name::from_ascii("example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);

        let original_ttl = 300u32;
        let mut msg = Message::new();
        msg.add_answer(Record::from_rdata(
            name.clone(),
            original_ttl,
            RData::A(A(Ipv4Addr::new(2, 2, 2, 2))),
        ));

        cache.insert(query.clone(), msg);

        let cached_msg = cache.get(&query).unwrap();
        // TTL should be <= original_ttl (may have decreased slightly due to elapsed time)
        let cached_ttl = cached_msg.answers()[0].ttl();
        assert!(cached_ttl <= original_ttl);
        assert!(cached_ttl > 0); // Should not be expired yet
    }

    #[test]
    fn test_zero_ttl_expired() {
        let cache = DNSCache::new(100);
        let name = Name::from_ascii("example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);

        let mut msg = Message::new();
        msg.add_answer(Record::from_rdata(
            name.clone(),
            0, // Zero TTL
            RData::A(A(Ipv4Addr::new(2, 2, 2, 2))),
        ));

        cache.insert(query.clone(), msg);

        // Should return None because TTL is 0 (expired)
        let result = cache.get(&query);
        assert!(result.is_none());
        // Entry should be removed from cache
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_capacity_respected() {
        let capacity = 10;
        let cache = DNSCache::new(capacity);

        // Insert more items than capacity
        for i in 0..20 {
            let name = Name::from_ascii(format!("test{i}.example.com.")).unwrap();
            let query = Query::query(name.clone(), RecordType::A);
            let mut msg = Message::new();
            msg.add_answer(Record::from_rdata(
                name,
                300,
                RData::A(A(Ipv4Addr::new(2, 2, 2, i as u8))),
            ));
            cache.insert(query, msg);
        }

        // Cache size should not exceed capacity
        assert!(cache.len() <= capacity);
    }

    #[test]
    fn test_same_query_replaces_cache() {
        let cache = DNSCache::new(100);
        let name = Name::from_ascii("example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);

        // Insert first response
        let mut msg1 = Message::new();
        msg1.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(2, 2, 2, 2))),
        ));
        cache.insert(query.clone(), msg1);

        // Different response for the same query
        let mut msg2 = Message::new();
        msg2.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(2, 2, 2, 3))),
        ));
        let ans = msg2.answers().to_vec();
        cache.insert(query.clone(), msg2);

        // Should have only one entry
        assert_eq!(cache.len(), 1);

        // Should get the second response
        assert!(cache.get(&query).is_some_and(|msg| msg.answers() == ans));
    }

    #[test]
    fn test_min_ttl_determines_expiry() {
        let cache = DNSCache::new(100);
        let name = Name::from_ascii("example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);

        // Create a message with multiple records having different TTLs
        let mut msg = Message::new();
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(2, 2, 2, 2))),
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(A(Ipv4Addr::new(2, 2, 2, 3))),
        ));

        cache.insert(query.clone(), msg);

        let result = cache.get(&query).unwrap();
        // Both answers should have TTL <= 60 (the minimum)
        for answer in result.answers() {
            assert!(answer.ttl() <= 60);
        }
    }
}
