#[macro_use]
extern crate log;
extern crate dns;

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use dns::settings::Settings;
use dns::DnsStandardQuery;
use dns::ResponseMessage;
use dns::{DnsClass, DnsHeader, DnsResourceRecord, DnsResponseCode, DnsType, Name, QueryMessage};

use env_logger::Env;

fn main() {
    env_logger::from_env(Env::default().default_filter_or("info")).init();

    let mut records = HashMap::new();
    // TODO load this from config file or set via REST interface
    records.insert("example.com".to_string(), Ipv4Addr::new(127, 0, 0, 2));

    let settings = Settings::load().expect("Could not load settings.");
    let addr = SocketAddr::from(([0, 0, 0, 0], settings.general.dns_port));
    let sock = UdpSocket::bind(addr).expect("Could not bind socket.");

    info!(
        "DNS server now listening on UDP port: {}",
        settings.general.dns_port
    );
    // sock.set_nonblocking(true)
    //     .expect("Failed to enter non-blocking mode");

    // we only need 512 bytes because that's the max size a DNS udp packet will have
    let mut buf = [0u8; 512];

    loop {
        let result = sock.recv_from(&mut buf);
        match result {
            Ok((num_bytes, src)) => {
                // if packet is shorter than the header the packet is invalid
                // move this check into parser
                if num_bytes < 12 {
                    continue;
                }
                let query = QueryMessage::from_u8(&buf);
                let response = match query {
                    QueryMessage::StandardQuery(query) => handle_standard_query(&records, query),
                    // FIXME response with not implemented error
                    _ => panic!("Not Implemented"), // TODO: not implemented response
                };
                print!("{:?}", response);
                let answer = response.as_u8();
                sock.send_to(answer.as_ref(), src).unwrap();
            }
            // If we get an error other than "would block", print the error.
            Err(ref err) if err.kind() != ErrorKind::WouldBlock => {
                println!("Something went wrong: {}", err)
            }
            // Do nothing otherwise.
            Err(_) => {}
        }
    }
}

fn handle_standard_query(
    records: &HashMap<String, Ipv4Addr>,
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

    if let Some(ip) = record {
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
                resource_data: *ip,
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
}
