use std::collections::HashMap;

use koppeln::{
    Storage,
    dns::{self, DomainName},
};

#[test]
fn it_handles_soa_request() {
    let mname = DomainName::from("dyn.example.com");
    let sub_domains = HashMap::new();

    let soa = dns::StartOfAuthority {
        mname: mname.clone(),
        rname: DomainName::from("postmaster.example.com"),
        serial: 123,
        refresh: 100,
        retry: 200,
        expire: 300,
        minimum: 400,
    };
    let storage = Storage::new(mname, sub_domains);
    let query = dns::StandardQuery {
        header: dns::Header {
            id: 1234,
            opcode: dns::OpCode::StandardQuery,
            truncated: false,
            authoritative_answer: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: dns::ResponseCode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        },
        question: dns::Question {
            labels: ["dyn", "example", "com"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            name: "dyn.example.com".to_string(),
            query_type: dns::QueryType::SOA,
            query_class: dns::QueryClass::IN,
        },
    };

    let msg = dns::server::handle_standard_query(&soa, &storage, query);

    assert!(msg.header.authoritative_answer);
    assert_eq!(msg.header.response_code, dns::ResponseCode::NoError);
    assert_eq!(msg.header.an_count, 1, "to contain one answer record");
}
