use std::net::{IpAddr, SocketAddr};

use futures::{SinkExt, StreamExt};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

use crate::{
    SharedStorage,
    dns::{self, DomainName, ResourceRecord, request, response},
};

pub struct Server {
    pub soa: dns::StartOfAuthority,
    pub storage: SharedStorage,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
}

impl Server {
    pub async fn run(self) {
        let addr = SocketAddr::from((self.listen_addr, self.listen_port));
        let udp_socket = UdpSocket::bind(&addr).await.unwrap();
        // TODO: drop privileges

        let mut dns_stream = UdpFramed::new(udp_socket, dns::Codec);

        log::info!(
            "DNS server now listening on: {ip}:{port}",
            ip = self.listen_addr,
            port = self.listen_port
        );

        while let Some(res) = dns_stream.next().await {
            let (request, addr) = match res {
                Ok((query, addr)) => (query, addr),
                Err(err) => {
                    // TODO we probably should stop the server at this point
                    log::error!("{err}");
                    continue;
                }
            };

            // TODO: spawn a task for responding
            log::debug!("DNS message received: {:?}", request);
            let response = self.creat_response(request);

            log::debug!("Sending DNS response: {:?}", response);
            dns_stream.send((response, addr)).await.unwrap();
        }
    }

    fn creat_response(&self, request: dns::Request) -> dns::Response {
        match request {
            dns::Request::StandardQuery(query) => {
                let response = self.standard_query(query);
                dns::Response::StandardQuery(response)
            }
            dns::Request::Unsupported(header) => unsupported_response(header),
        }
    }

    pub fn standard_query(&self, query: request::StandardQuery) -> response::StandardQuery {
        let storage = match self.storage.lock() {
            Ok(storage) => storage,
            Err(err) => {
                // TODO return internal server error
                log::error!("failed to lock storage: {err}");
                panic!();
            }
        };
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
                if self.soa.mname == domain_name {
                    Some(vec![ResourceRecord::SOA(self.soa.clone())])
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
}

fn unsupported_response(header: dns::RawHeader) -> dns::Response {
    let header = dns::RawHeader {
        authoritative_answer: true,
        truncated: false,
        recursion_available: false,
        an_count: 0,
        response_code: response::Rcode::NotImplemented,
        ..header
    };

    dns::Response::NotImplemented(response::NotImplemented { header })
}

#[cfg(test)]
mod test {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use crate::{
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

        let storage = Arc::new(Mutex::new(Storage::new(mname, sub_domains)));
        let server = dns::Server {
            soa,
            storage,
            listen_addr: std::net::IpAddr::from([10, 0, 0, 1]),
            listen_port: 54,
        };
        let query = dns::request::StandardQuery {
            header: dns::request::Header {
                id: 1234,
                truncated: false,
                recursion_desired: false,
                qd_count: 1,
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

        let msg = server.standard_query(query);

        assert!(msg.header.authoritative_answer);
        assert_eq!(msg.header.response_code, dns::response::Rcode::NoError);
    }
}
