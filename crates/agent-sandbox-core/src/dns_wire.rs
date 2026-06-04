//! Extract A/AAAA answers from DNS response packets (`hickory-proto`).

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::RData;

fn query_name(message: &Message) -> Option<String> {
    let query = message.queries().first()?;
    let name = query.name().to_ascii();
    Some(name.trim_end_matches('.').to_lowercase())
}

fn ip_from_rdata(rdata: &RData) -> Option<String> {
    match rdata {
        RData::A(addr) => Some(addr.0.to_string()),
        RData::AAAA(addr) => Some(addr.0.to_string()),
        _ => None,
    }
}

/// Return `(ip, hostname, ttl)` tuples from a DNS response.
#[must_use]
pub fn mappings_from_response(data: &[u8]) -> Vec<(String, String, u32)> {
    let Ok(message) = Message::from_vec(data) else {
        return Vec::new();
    };
    if message.header().message_type() != MessageType::Response {
        return Vec::new();
    }
    let Some(qname) = query_name(&message) else {
        return Vec::new();
    };
    message
        .answers()
        .iter()
        .filter_map(|record| {
            let rdata = record.data()?;
            let ip = ip_from_rdata(rdata)?;
            Some((ip, qname.clone(), record.ttl()))
        })
        .collect()
}

/// First question name in a packet (lowercase, no trailing dot).
#[must_use]
pub fn question_name(data: &[u8]) -> Option<String> {
    let message = Message::from_vec(data).ok()?;
    query_name(&message)
}

#[cfg(test)]
mod tests {
    use super::{mappings_from_response, question_name};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    fn build_a_response(qname: &str, ip: (u8, u8, u8, u8), ttl: u32) -> Vec<u8> {
        let name = Name::from_ascii(format!("{qname}.")).expect("valid name");
        let mut message = Message::new();
        message
            .set_id(0xBEEF)
            .set_message_type(hickory_proto::op::MessageType::Response)
            .add_query(Query::query(name.clone(), RecordType::A))
            .add_answer(Record::from_rdata(
                name,
                ttl,
                RData::A(A::new(ip.0, ip.1, ip.2, ip.3)),
            ));
        message.to_vec().expect("encode")
    }

    #[test]
    fn mappings_from_a_response() {
        let pkt = build_a_response("api.openai.com", (52, 54, 28, 178), 120);
        assert_eq!(
            mappings_from_response(&pkt),
            vec![(
                "52.54.28.178".to_string(),
                "api.openai.com".to_string(),
                120
            )]
        );
    }

    #[test]
    fn question_name_normalizes_case() {
        let pkt = build_a_response("Example.COM", (1, 2, 3, 4), 300);
        assert_eq!(question_name(&pkt), Some("example.com".to_string()));
    }

    #[test]
    fn non_response_returns_empty() {
        let mut message = Message::new();
        message.add_query(Query::query(
            Name::from_ascii("test.").unwrap(),
            RecordType::A,
        ));
        let pkt = message.to_vec().unwrap();
        assert!(mappings_from_response(&pkt).is_empty());
    }
}
