use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use env_logger::Env;
use futures::stream::StreamExt;
use futures::SinkExt;
use koppeln::dns::{codec, NotImplementedResponse, ResponseMessage};
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
        authoritative_anser: true,
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
    let record = records.get(&query.question.name);

    let mut header = dns::Header {
        //qr: DnsQr::Respons,
        authoritative_anser: true,
        truncated: false,
        recursion_available: false,
        an_count: 0,
        response_code: dns::ResponseCode::NoError,
        ..query.header
    };

    if query.question.query_type != dns::QueryType::A {
        return codec::Response::StandardQuery(ResponseMessage {
            header,
            question: query.question,
            answer: vec![],
        });
    }

    if let Some(address) = record {
        if let Some(ip) = address.ipv4 {
            header.an_count = 1;
            return codec::Response::StandardQuery(ResponseMessage {
                header,
                question: query.question,
                answer: vec![dns::ResourceRecord {
                    name: dns::Name::with_pointer(11),
                    data_type: dns::QueryType::A,
                    data_class: dns::QueryClass::IN,
                    ttl: 15,
                    resource_data_length: 4,
                    resource_data: ip,
                }],
            });
        }
    }

    header.response_code = dns::ResponseCode::NameError;
    codec::Response::StandardQuery(ResponseMessage {
        header,
        question: query.question,
        answer: vec![],
    })
}
