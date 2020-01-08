extern crate dns;

use dns::DnsStandardQuery;
use dns::ResponseMessage;
use std::str::FromStr;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, UdpSocket};

use std::convert::From;

use dns::{DnsClass, Name, DnsResourceRecord, DnsHeader, DnsResponseCode, QueryMessage, DnsType};

fn main() {
    let sock = UdpSocket::bind("0.0.0.0:5546").expect("Failed to bind socket");
    // sock.set_nonblocking(true)
    //     .expect("Failed to enter non-blocking mode");

    // we only need 512 bytes because that's the max size a DNS udp packet will have
    let mut buf = [0u8; 512];

    loop {
        let result = sock.recv_from(&mut buf);
        match result {
            Ok((num_bytes, src)) => {
                // if packet is shorter than the header the packet is invalid
                if num_bytes < 12 {
                    continue;
                }
                let answer = handle_dns_request(&buf);
                let answer = bytes::BytesMut::from(answer);
                sock.send_to(answer.as_ref(), src).unwrap();
            }
            // If we get an error other than "would block", print the error.
            Err(ref err) if err.kind() != ErrorKind::WouldBlock => {
                println!("Something went wrong: {}", err)
            }
            // Do nothing otherwise.
            _ => {}
        }

        // thread::sleep(Duration::from_millis(5));
    }
}

fn handle_standard_query(query: DnsStandardQuery) -> ResponseMessage {
    // TODO: load from Zone file
    let domain_name: Vec<String> = vec!["test", "dyn", "example", "com"]
        .iter()
        .map(|ref s| s.to_string())
        .collect::<Vec<String>>();

    // TODO lookup resource records from internal database

    let mut header = DnsHeader {
        //qr: DnsQr::Respons,
        authoritative_anser: true,
        truncated: false,
        recursion_available: false,
        an_count: 0,
        response_code: DnsResponseCode::NoError,
        ..query.header
    };

    if query.question.labels == domain_name {
        let ip = Ipv4Addr::from_str("192.1.2.3").unwrap();
        header.an_count = 1;
        ResponseMessage {
            header: header,
            question: query.question,
            answer: vec![
                DnsResourceRecord {
                    name: Name::with_pointer(11),
                    data_type: DnsType::A,
                    data_class: DnsClass::IN,
                    ttl: 15,
                    resource_data_length: 4,
                    resource_data: ip,
                }]
        }

    } else {
        header.response_code = DnsResponseCode::NameError;
        ResponseMessage {
            header: header,
            question: query.question,
            answer: vec![]
        }
    }
}

fn handle_dns_request(packet: &[u8]) -> Vec<u8> {
    let query = QueryMessage::from_u8(packet);

    let response = match query {
        QueryMessage::StandardQuery(query) => handle_standard_query(query),
        // FIXME response with not implemented error
        _ => panic!("Not Implemented") // TODO: not implemented response
    };

    response.as_u8()
}
