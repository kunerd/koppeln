#[macro_use]
extern crate log;
extern crate koppeln;
extern crate tokio;
extern crate tokio_util;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use futures::{StreamExt, SinkExt};

use env_logger::Env;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio_util::udp::UdpFramed;

use koppeln::settings::{AddressConfig, Settings};
use koppeln::web;
use koppeln::DnsMessageCodec;
use koppeln::DnsStandardQuery;
use koppeln::ResponseMessage;
use koppeln::{
    AddressStorage, DnsClass, DnsHeader, DnsResourceRecord, DnsResponseCode, DnsType, Name,
    QueryMessage,
};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let settings = Settings::load().expect("Could not load settings.");
    debug!("Settings:\n{:?}", settings);

    let storage = Arc::new(RwLock::new(settings.addresses));

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

    let ip = settings.dns_address;
    let port = settings.dns_port;
    let udp_server = tokio::spawn(async move {
        create_udp_server(ip, port, &storage).await;
    });

    futures::future::try_join(update_server, udp_server)
        .await
        .unwrap();
}

async fn create_udp_server(ip: IpAddr, port: u16, storage: &AddressStorage) {
    let addr = SocketAddr::from((ip, port));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();
    let (dns_sink, dns_stream) = UdpFramed::new(udp_socket, DnsMessageCodec::new()).split();

    info!(
        "DNS server now listening on: {ip}:{port}",
        ip = ip,
        port = port
    );

    let sink = &Arc::new(Mutex::new(dns_sink));
    dns_stream
        .for_each_concurrent(100, |result| async move {
            let (query, addr) = result.unwrap();

            //handle_dns_query(query, addr, storage_clone.clone(), sink) .await;
            debug!("DNS query received: {:?}", query);
            let response = match query {
                QueryMessage::StandardQuery(query) => {
                    //let records = storage.lock().await;
                    let records = storage.read().await;
                    handle_standard_query(&records, query)
                }
                // FIXME response with not implemented error
                _ => panic!("Not Implemented"), // TODO: not implemented response
            };

            debug!("DNS response: {:?}", response);
            let mut sink = sink.lock().await;
            sink.send((response, addr)).await.unwrap();
        })
        .await;
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
