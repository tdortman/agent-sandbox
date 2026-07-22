//! Extract policy-relevant IP→hostname mappings from DNS response packets.

use std::collections::HashSet;

use hickory_proto::{
    op::{Message, MessageType},
    rr::{Name, RData, rdata::svcb::SvcParamValue},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMapping {
    pub ip: String,
    pub hostname: String,
    pub ttl: u32,
}

fn query_name(message: &Message) -> Option<String> {
    let query = message.queries.first()?;
    Some(normalize_owner(query.name()))
}

fn normalize_owner(name: &Name) -> String {
    name.to_ascii().trim_end_matches('.').to_lowercase()
}

fn ip_from_rdata(rdata: &RData) -> Option<String> {
    match rdata {
        RData::A(addr) => Some(addr.0.to_string()),
        RData::AAAA(addr) => Some(addr.0.to_string()),
        _ => None,
    }
}

fn allowed_owner_names(message: &Message, qname: &str) -> HashSet<String> {
    let mut allowed = HashSet::from([qname.to_string()]);
    loop {
        let mut added = false;
        for record in &message.answers {
            let owner = normalize_owner(&record.name);
            if !allowed.contains(&owner) {
                continue;
            }
            if let RData::CNAME(cname) = &record.data {
                let target = normalize_owner(&cname.0);
                if allowed.insert(target) {
                    added = true;
                }
            }
        }
        if !added {
            break;
        }
    }
    allowed
}

fn mappings_from_svcb_rdata(rdata: &RData, ttl: u32, qname: &str) -> Vec<DnsMapping> {
    let svcb = match rdata {
        RData::HTTPS(https) => &https.0,
        RData::SVCB(svcb) => svcb,
        _ => return Vec::new(),
    };
    let mut mappings = Vec::new();
    for (_key, value) in &svcb.svc_params {
        match value {
            SvcParamValue::Ipv4Hint(hint) => {
                for addr in &hint.0 {
                    mappings.push(DnsMapping {
                        ip: addr.0.to_string(),
                        hostname: qname.to_string(),
                        ttl,
                    });
                }
            }
            SvcParamValue::Ipv6Hint(hint) => {
                for addr in &hint.0 {
                    mappings.push(DnsMapping {
                        ip: addr.0.to_string(),
                        hostname: qname.to_string(),
                        ttl,
                    });
                }
            }
            _ => {}
        }
    }
    mappings
}

/// DNS response mapping used to correlate transport-layer destinations with
/// hostnames.
#[must_use]
pub fn mappings_from_response(data: &[u8]) -> Vec<DnsMapping> {
    let Ok(message) = Message::from_vec(data) else {
        return Vec::new();
    };
    if message.metadata.message_type != MessageType::Response {
        return Vec::new();
    }
    let Some(qname) = query_name(&message) else {
        return Vec::new();
    };
    let allowed = allowed_owner_names(&message, &qname);
    let mut mappings = Vec::new();
    for record in &message.answers {
        let owner = normalize_owner(&record.name);
        if !allowed.contains(&owner) {
            continue;
        }
        let ttl = record.ttl;
        let rdata = &record.data;
        if let Some(ip) = ip_from_rdata(rdata) {
            mappings.push(DnsMapping {
                ip,
                hostname: qname.clone(),
                ttl,
            });
        } else {
            mappings.extend(mappings_from_svcb_rdata(rdata, ttl, &qname));
        }
    }
    mappings
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{
            Name, RData, Record, RecordType,
            rdata::{
                A, AAAA, CNAME, HTTPS,
                svcb::{IpHint, SVCB, SvcParamKey, SvcParamValue},
            },
        },
    };

    use super::{DnsMapping, mappings_from_response};

    fn build_a_response(qname: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let name = Name::from_ascii(format!("{qname}.")).expect("valid name");
        let mut message = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
        message
            .add_query(Query::query(name.clone(), RecordType::A))
            .add_answer(Record::from_rdata(
                name,
                ttl,
                RData::A(A::new(ip[0], ip[1], ip[2], ip[3])),
            ));
        message.to_vec().expect("encode")
    }

    #[test]
    fn mappings_from_a_response() {
        let pkt = build_a_response("api.openai.com", [52, 54, 28, 178], 120);
        assert_eq!(mappings_from_response(&pkt), vec![DnsMapping {
            ip: "52.54.28.178".to_string(),
            hostname: "api.openai.com".to_string(),
            ttl: 120,
        }]);
    }

    #[test]
    fn mappings_from_response_keeps_every_address_for_question() {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut message = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
        message
            .add_query(Query::query(name.clone(), RecordType::A))
            .add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::A(A::new(172, 66, 147, 243)),
            ))
            .add_answer(Record::from_rdata(
                name,
                300,
                RData::A(A::new(104, 20, 23, 154)),
            ));
        let pkt = message.to_vec().expect("encode");

        assert_eq!(mappings_from_response(&pkt), vec![
            DnsMapping {
                ip: "172.66.147.243".to_string(),
                hostname: "example.com".to_string(),
                ttl: 300,
            },
            DnsMapping {
                ip: "104.20.23.154".to_string(),
                hostname: "example.com".to_string(),
                ttl: 300,
            },
        ]);
    }

    #[test]
    fn mappings_follow_cname_but_keep_query_name() {
        let qname = Name::from_ascii("api.cursor.example.").expect("valid name");
        let cname_target = Name::from_ascii("edge.cursor-cdn.example.").expect("valid name");
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message
            .add_query(Query::query(qname.clone(), RecordType::A))
            .add_answer(Record::from_rdata(
                qname,
                300,
                RData::CNAME(CNAME(cname_target.clone())),
            ))
            .add_answer(Record::from_rdata(
                cname_target,
                300,
                RData::A(A::new(1, 2, 3, 4)),
            ));
        let pkt = message.to_vec().expect("encode");

        assert_eq!(mappings_from_response(&pkt), vec![DnsMapping {
            ip: "1.2.3.4".to_string(),
            hostname: "api.cursor.example".to_string(),
            ttl: 300,
        }]);
    }

    #[test]
    fn mappings_ignore_unrelated_answer_addresses() {
        let qname = Name::from_ascii("api.cursor.example.").expect("valid name");
        let unrelated = Name::from_ascii("unrelated.example.").expect("valid name");
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message
            .add_query(Query::query(qname, RecordType::A))
            .add_answer(Record::from_rdata(
                unrelated,
                300,
                RData::A(A::new(9, 9, 9, 9)),
            ));
        let pkt = message.to_vec().expect("encode");

        assert!(mappings_from_response(&pkt).is_empty());
    }

    #[test]
    fn mappings_extract_https_ip_hints() {
        let qname = Name::from_ascii("api.cursor.example.").expect("valid name");
        let svcb = SVCB::new(1, Name::root(), vec![
            (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A::new(1, 2, 3, 4)])),
            ),
            (
                SvcParamKey::Ipv6Hint,
                SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(Ipv6Addr::new(
                    0x2606, 0x4700, 0x7, 0, 0, 0, 0xA29F, 0x874F,
                ))])),
            ),
        ]);
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message
            .add_query(Query::query(qname.clone(), RecordType::HTTPS))
            .add_answer(Record::from_rdata(qname, 120, RData::HTTPS(HTTPS(svcb))));
        let pkt = message.to_vec().expect("encode");

        assert_eq!(mappings_from_response(&pkt), vec![
            DnsMapping {
                ip: "1.2.3.4".to_string(),
                hostname: "api.cursor.example".to_string(),
                ttl: 120,
            },
            DnsMapping {
                ip: "2606:4700:7::a29f:874f".to_string(),
                hostname: "api.cursor.example".to_string(),
                ttl: 120,
            },
        ]);
    }

    #[test]
    fn non_response_returns_empty() {
        let mut message = Message::new(0, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("test.").expect("valid name"),
            RecordType::A,
        ));
        let pkt = message.to_vec().expect("encode");
        assert!(mappings_from_response(&pkt).is_empty());
    }
}
