#[macro_use]
extern crate log;
extern crate dns;
extern crate tokio;
extern crate tokio_util;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::Ipv4Addr;

use env_logger::Env;
use tokio::io;
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
    
    let update_server = tokio::spawn(web::create_update_server());
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
            let response = match query {
                QueryMessage::StandardQuery(query) => {
                    handle_standard_query(&settings.addresses, query)
                }
                // FIXME response with not implemented error
                _ => panic!("Not Implemented"), // TODO: not implemented response
            };
            
            dns_stream.send((response, addr)).await.unwrap();
        }
    });

//    let udp_server = tokio::task::spawn_blocking(|| {
//        let sock = UdpSocket::bind(addr).expect("Could not bind socket.");
//        info!(
//            "DNS server now listening on UDP port: {}",
//            settings.general.dns_port
//        );
//        // sock.set_nonblocking(true)
//        //     .expect("Failed to enter non-blocking mode");
//
//        // we only need 512 bytes because that's the max size a DNS udp packet will have
//        let mut buf = [0u8; 512];
//
//        loop {
//            let result = sock.recv_from(&mut buf);
//            match result {
//                Ok((num_bytes, src)) => {
//                    // if packet is shorter than the header the packet is invalid
//                    // move this check into parser
//                    if num_bytes < 12 {
//                        continue;
//                    }
//                    let query = QueryMessage::from_u8(&buf);
//                    let response = match query {
//                        QueryMessage::StandardQuery(query) => {
//                            handle_standard_query(&settings.addresses, query)
//                        }
//                        // FIXME response with not implemented error
//                        _ => panic!("Not Implemented"), // TODO: not implemented response
//                    };
//                    print!("{:?}", response);
//                    let answer = response.as_u8();
//                    sock.send_to(answer.as_ref(), src).unwrap();
//                }
//                // If we get an error other than "would block", print the error.
//                Err(ref err) if err.kind() != ErrorKind::WouldBlock => {
//                    println!("Something went wrong: {}", err)
//                }
//                // Do nothing otherwise.
//                Err(_) => {}
//            }
//        }
//    });

    futures::try_join!(update_server, udp_server);
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
