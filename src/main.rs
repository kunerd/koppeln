#[macro_use]
extern crate log;
extern crate koppeln;
extern crate tokio;
extern crate tokio_util;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use env_logger::Env;
use futures::stream::StreamExt;
use futures::{FutureExt, SinkExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::udp::UdpFramed;

use koppeln::settings::{AddressConfig, Settings};
use koppeln::web;
use koppeln::DnsMessageCodec;
use koppeln::DnsStandardQuery;
use koppeln::ResponseMessage;
use koppeln::{
    DnsClass, DnsHeader, DnsResourceRecord, DnsResponseCode, DnsType, Name, QueryMessage,
};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let settings = Settings::load().expect("Could not load settings.");
    debug!("Settings:\n{:?}", settings);

    let storage = Arc::new(Mutex::new(settings.addresses));

    let web_server_address = SocketAddr::from((settings.web_address, settings.web_port));
    let update_server = tokio::spawn(web::create_update_server(
        web_server_address,
        storage.clone(),
    ));
    info!(
        "HTTP server now listening on: {ip}:{port}",
        ip = settings.web_address,
        port = settings.web_port
    );

    let addr = SocketAddr::from((settings.dns_address, settings.dns_port));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();
    let mut dns_stream = UdpFramed::new(udp_socket, DnsMessageCodec::new());

    info!(
        "DNS server now listening on: {ip}:{port}",
        ip = settings.dns_address,
        port = settings.dns_port
    );

    let udp_server = tokio::spawn(async move {
        loop {
            debug!("Waiting for DNS queries...");
            let (query, addr) = dns_stream.next().map(|e| e.unwrap()).await.unwrap();

            debug!("DNS query received: {:?}", query);
            let response = match query {
                QueryMessage::StandardQuery(query) => {
                    let records = storage.lock().await;
                    handle_standard_query(&records, query)
                }
                // FIXME response with not implemented error
                _ => panic!("Not Implemented"), // TODO: not implemented response
            };

            debug!("DNS response: {:?}", response);
            dns_stream.send((response, addr)).await.unwrap();
        }
    });

    futures::future::try_join(update_server, udp_server)
        .await
        .unwrap();
}

fn handle_standard_query(
    records: &HashMap<String, AddressConfig>,
    query: DnsStandardQuery,
) -> ResponseMessage {
    let mut header = DnsHeader {
        //qr: DnsQr::Respons,
        authoritative_anser: true,
        truncated: false,
        recursion_available: false,
        an_count: 0,
        response_code: DnsResponseCode::NoError,
        ..query.header
    };

    let record = records.get(&query.question.name);
    if let Some(address) = record {
        if let Some(ip) = address.ipv4 {
            header.an_count = 1;
            return ResponseMessage {
                header,
                question: query.question,
                answer: vec![DnsResourceRecord {
                    name: Name::with_pointer(11),
                    data_type: DnsType::A,
                    data_class: DnsClass::IN,
                    ttl: 15,
                    resource_data_length: 4,
                    resource_data: ip,
                }],
            };
        }
    }

    header.response_code = DnsResponseCode::NameError;
    ResponseMessage {
        header,
        question: query.question,
        answer: vec![],
    }
}
