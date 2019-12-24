extern crate dns;

use std::io::ErrorKind;
use std::net::{Ipv4Addr, UdpSocket};
use std::str::FromStr;

use std::convert::From;

use byteorder::{BigEndian, WriteBytesExt};

use dns::{DnsClass, DnsHeader, DnsResponseCode, DnsStandardQuery, DnsType};

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

struct DnsResourceRecord {
    //name: Vec<String>,
    data_type: DnsType,
    data_class: DnsClass,
    ttl: u32,
    resource_data_length: u16,
    // TODO: this depends on type and class, maybe it can be implemented as an enum
    resource_data: Ipv4Addr,
}

impl From<DnsResourceRecord> for Vec<u8> {
    fn from(rr: DnsResourceRecord) -> Self {
        let mut raw_rr = Vec::new();

        raw_rr
            .write_u16::<BigEndian>(0b1100000000000000 | 12)
            .unwrap();
        raw_rr.write_u16::<BigEndian>(rr.data_type.into()).unwrap();
        raw_rr.write_u16::<BigEndian>(rr.data_class.into()).unwrap();
        raw_rr.write_u32::<BigEndian>(rr.ttl).unwrap();
        raw_rr
            .write_u16::<BigEndian>(rr.resource_data_length)
            .unwrap();
        // answer_packet.write_u16::<BigEndian>(1).unwrap();
        raw_rr
            .write_u32::<BigEndian>(rr.resource_data.into())
            .unwrap();

        raw_rr
    }
}

fn handle_dns_request(packet: &[u8]) -> Vec<u8> {
    let query = DnsStandardQuery::from_packet(packet);

    let domain_name: Vec<String> = vec!["test", "dyn", "example", "com"]
        .iter()
        .map(|ref s| s.to_string())
        .collect::<Vec<String>>();

    let rr = if query.question.labels == domain_name {
        let ip = Ipv4Addr::from_str("192.1.2.3").unwrap();
        DnsResourceRecord {
            data_type: DnsType::A,
            data_class: DnsClass::IN,
            ttl: 15,
            resource_data_length: 4,
            resource_data: ip,
        }
    } else {
        // This should return an error: not found
        DnsResourceRecord {
            data_type: DnsType::A,
            data_class: DnsClass::IN,
            ttl: 15,
            resource_data_length: 4,
            resource_data: Ipv4Addr::from_str("127.0.0.1").unwrap(),
        }
    };

    let answer_header = DnsHeader {
        //qr: DnsQr::Respons,
        authoritative_anser: true,
        truncated: false,
        recursion_available: false,
        an_count: 1, // FIXME needs to be genric, e.g. the number of resource records
        response_code: DnsResponseCode::NoError,
        ..query.header
    };

    let mut raw_message: Vec<u8> = answer_header.into();
    let mut raw_question: Vec<u8> = query.question.into();
    let mut raw_resource_record: Vec<u8> = rr.into();

    raw_message.append(&mut raw_question);
    raw_message.append(&mut raw_resource_record);

    raw_message
}
