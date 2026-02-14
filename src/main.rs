use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use env_logger::Env;
use futures::SinkExt;
use futures::stream::StreamExt;
use koppeln::dns::{NotImplementedResponse, ResourceRecord, ResponseMessage, codec};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::udp::UdpFramed;

use koppeln::settings::{AddressConfig, Settings};
use koppeln::{dns, web};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let settings = Settings::load().expect("Could not load settings.");
    log::debug!("Settings:\n{:?}", settings);

    let storage = Arc::new(Mutex::new(settings.addresses));

    let web_server_address = SocketAddr::from((settings.web_address, settings.web_port));
    let update_server = tokio::spawn(web::create_update_server(
        web_server_address,
        storage.clone(),
    ));
    log::info!(
        "HTTP server now listening on: {ip}:{port}",
        ip = settings.web_address,
        port = settings.web_port
    );

    let addr = SocketAddr::from((settings.dns_address, settings.dns_port));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();
    let mut dns_stream = UdpFramed::new(udp_socket, dns::Codec::default());

    log::info!(
        "DNS server now listening on: {ip}:{port}",
        ip = settings.dns_address,
        port = settings.dns_port
    );

    let udp_server = tokio::spawn(async move {
        log::debug!("Waiting for DNS queries...");
        while let Some(res) = dns_stream.next().await {
            let (query, addr) = match res {
                Ok((query, addr)) => (query, addr),
                Err(err) => {
                    log::error!("{err}");
                    continue;
                }
            };
            log::debug!("DNS message received: {:?}", query);

            let response = match query {
                codec::Message::Query(query) => {
                    let records = storage.lock().await;
                    handle_standard_query(&records, query)
                }
                codec::Message::Unsupported(header, payload) => {
                    heandle_unsupported(header, payload)
                }
            };

            log::debug!("DNS response: {:?}", response);
            dns_stream.send((response, addr)).await.unwrap();
        }
    });

    futures::future::try_join(update_server, udp_server)
        .await
        .unwrap();
}

fn heandle_unsupported(header: dns::Header, payload: Vec<u8>) -> codec::Response {
    let header = dns::Header {
        authoritative_answer: true,
        truncated: false,
        recursion_available: false,
        an_count: 0,
        response_code: dns::ResponseCode::NotImplemented,
        ..header
    };
    codec::Response::NotImplemented(NotImplementedResponse { header, payload })
}

fn handle_standard_query(
    records: &HashMap<String, AddressConfig>,
    query: dns::StandardQuery,
) -> codec::Response {
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
        dns::QueryType::A | dns::QueryType::AAAA
    ) {
        return codec::Response::StandardQuery(ResponseMessage {
            header,
            question: query.question,
            answer: vec![],
        });
    }

    let answer = records.get(&query.question.name).and_then(|record| {
        match query.question.query_type {
            dns::QueryType::A => record.ipv4.map(|ip| {
                vec![ResourceRecord::A {
                    // TODO: use compression, e.g. `Name::Pointer`
                    name: dns::Name::Labels(query.question.labels.clone()),
                    ttl: 15,
                    addr: ip,
                }]
            }),
            dns::QueryType::AAAA => record.ipv6.map(|ip| {
                vec![ResourceRecord::AAAA {
                    // TODO: use compression, e.g. `Name::Pointer`
                    name: dns::Name::Labels(query.question.labels.clone()),
                    ttl: 15,
                    addr: ip,
                }]
            }),
            _ => None,
        }
    });

    if answer.is_none() {
        header.response_code = dns::ResponseCode::NameError;
    }

    let answer = answer.unwrap_or_default();

    header.an_count = answer.len() as u16;
    return codec::Response::StandardQuery(ResponseMessage {
        header,
        question: query.question,
        answer,
    });
}
