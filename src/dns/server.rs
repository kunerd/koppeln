use crate::{
    Storage,
    dns::{self, DomainName, ResourceRecord, request, response},
};

pub fn handle_standard_query(
    soa: &dns::StartOfAuthority,
    storage: &Storage,
    query: request::StandardQuery,
) -> response::StandardQuery {
    let mut header = response::Header {
        id: query.header.id,
        truncated: query.header.truncated,
        authoritative_answer: true,
        recursion_desired: query.header.recursion_desired,
        recursion_available: false,
        response_code: response::Rcode::NoError,
        qd_count: query.header.qd_count,
    };

    if !matches!(
        query.question.query_type,
        dns::QueryType::A | dns::QueryType::AAAA | dns::QueryType::SOA
    ) {
        return response::StandardQuery {
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
        header.response_code = response::Rcode::NameError;
    }

    let answer = answer.unwrap_or_default();

    response::StandardQuery {
        header,
        question: query.question,
        answer,
    }
}
