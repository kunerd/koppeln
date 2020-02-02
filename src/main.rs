#[macro_use]
extern crate log;
extern crate dns;
extern crate tokio;
extern crate tokio_util;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::Mutex;
use env_logger::Env;
use tokio::net::UdpSocket;
use tokio::stream::StreamExt;
use tokio_util::udp::UdpFramed;
use futures::{FutureExt, SinkExt};

use dns::settings::{Address, Settings};
use dns::web;
use dns::DnsMessageCodec;
use dns::DnsStandardQuery;
use dns::ResponseMessage;
use dns::{DnsClass, DnsHeader, DnsResourceRecord, DnsResponseCode, DnsType, Name, QueryMessage};

#[tokio::main]
async fn main() {
    env_logger::from_env(Env::default().default_filter_or("info")).init();

    let mut settings = Settings::load().expect("Could not load settings.");
    settings.addresses.get_mut("vpn.dyn.example.com").unwrap().ipv4 = Some(Ipv4Addr::from([127, 10, 1, 0]));
    let storage = Arc::new(Mutex::new(settings.addresses));
    
    let update_server = tokio::spawn(web::create_update_server(storage.clone()));
    info!(
        "HTTP/S server now listening on port: {}",
        settings.general.web_port
    );
    
    let addr = SocketAddr::from(([0, 0, 0, 0], settings.general.dns_port));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();
    let mut dns_stream = UdpFramed::new(udp_socket, DnsMessageCodec::new());
    info!(
        "DNS server now listening on UDP port: {}",
        settings.general.dns_port
    );

    let udp_server = tokio::spawn(async move {
        loop {
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

    futures::try_join!(update_server, udp_server).unwrap();
}

fn handle_standard_query(
    records: &HashMap<String, Address>,
    query: DnsStandardQuery,
) -> ResponseMessage {
    let record = records.get(&query.question.name);

    let mut header = DnsHeader {
        //qr: DnsQr::Respons,
        authoritative_anser: true,
        truncated: false,
        recursion_available: false,
        an_count: 0,
        response_code: DnsResponseCode::NoError,
        ..query.header
    };

    if let Some(address) = record {
        if let Some(ip) = address.ipv4 {
            header.an_count = 1;
            ResponseMessage {
                header: header,
                question: query.question,
                answer: vec![DnsResourceRecord {
                    name: Name::with_pointer(11),
                    data_type: DnsType::A,
                    data_class: DnsClass::IN,
                    ttl: 15,
                    resource_data_length: 4,
                    resource_data: ip,
                }],
            }
        } else {
            header.response_code = DnsResponseCode::NameError;
            ResponseMessage {
                header: header,
                question: query.question,
                answer: vec![],
            }
        }
    } else {
        header.response_code = DnsResponseCode::NameError;
        ResponseMessage {
            header: header,
            question: query.question,
            answer: vec![],
        }
    }
}
