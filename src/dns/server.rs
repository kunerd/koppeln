use crate::{
    Storage,
    dns::{self, DomainName, ResourceRecord, Response},
};

pub fn handle_standard_query(
    soa: &dns::StartOfAuthority,
    storage: &Storage,
    query: dns::StandardQuery,
) -> Response {
    let mut header = dns::Header {
        authoritative_answer: true,
        truncated: false,
        recursion_available: false,
        an_count: 0,
        response_code: dns::ResponseCode::NoError,
        ..query.header
    };

    if !matches!(
        query.question.query_type,
        dns::QueryType::A | dns::QueryType::AAAA | dns::QueryType::SOA
    ) {
        return Response {
            header,
            question: query.question,
            answer: vec![],
        };
    }

    let domain_name = DomainName::from(query.question.name.clone());
    let record = storage.get(&domain_name);
    let answer = match query.question.query_type {
        dns::QueryType::A => record.and_then(|r| r.ipv4).map(|ip| {
            vec![ResourceRecord::A {
                // TODO: use compression, e.g. `Name::Pointer`
                name: dns::Name::Labels(query.question.labels.clone()),
                ttl: 15,
                addr: ip,
            }]
        }),
        dns::QueryType::AAAA => record.and_then(|r| r.ipv6).map(|ip| {
            vec![ResourceRecord::AAAA {
                // TODO: use compression, e.g. `Name::Pointer`
                name: dns::Name::Labels(query.question.labels.clone()),
                ttl: 15,
                addr: ip,
            }]
        }),
        dns::QueryType::SOA => {
            if soa.mname == domain_name {
                Some(vec![ResourceRecord::SOA(soa.clone())])
            } else {
                None
            }
        }
        _ => None,
    };

    if answer.is_none() {
        header.response_code = dns::ResponseCode::NameError;
    }

    let answer = answer.unwrap_or_default();

    header.an_count = answer.len() as u16;
    Response {
        header,
        question: query.question,
        answer,
    }
}
