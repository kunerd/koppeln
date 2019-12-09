use std::net::{Ipv4Addr, UdpSocket};
use std::str::FromStr;
// use std::time::Duration;
use std::io::ErrorKind;
// use std::thread;
use bytes::Bytes;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

const HOSTNAME: &str = "dyn.example.com";

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
                if num_bytes < 12 { continue; }
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

#[derive(Debug)]
enum DnsQr {
    Query,
    Respons
}

impl From<u16> for DnsQr {
    fn from(value: u16) -> Self {
        if value == 1 {
            DnsQr::Respons
        } else {
            DnsQr::Query
        }
    }
}

impl From<DnsQr> for u16 {
    fn from(value: DnsQr) -> Self {
        match value {
            DnsQr::Respons => 1,
            _ => 0
        }
    }
}

#[derive(Debug)]
enum DnsOpCode {
    StandardQuery,
    InversQuery,
    ServerStatusRequest,
    Reserved(u16)
}

impl From<u16> for DnsOpCode {
    fn from(value: u16) -> Self {
        match value {
            0 => DnsOpCode::StandardQuery,
            1 => DnsOpCode::InversQuery,
            2 => DnsOpCode::ServerStatusRequest,
            value => DnsOpCode::Reserved(value)
        }
    }
}

impl From<DnsOpCode> for u16 {
    fn from(value: DnsOpCode) -> Self {
        match value {
            DnsOpCode::StandardQuery => 0,
            DnsOpCode::InversQuery => 1,
            DnsOpCode::ServerStatusRequest => 2,
            DnsOpCode::Reserved(value) => value
        }
    }
}

#[derive(Debug)]
enum DnsResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused
}

impl From<u16> for DnsResponseCode {
    fn from(value: u16) -> Self {
        match value {
            0 => DnsResponseCode::NoError,
            1 => DnsResponseCode::FormatError,
            2 => DnsResponseCode::ServerFailure,
            3 => DnsResponseCode::NameError,
            4 => DnsResponseCode::NotImplemented,
            _ => DnsResponseCode::Refused
        }
    }
}

impl From<DnsResponseCode> for u16 {
    fn from(value: DnsResponseCode) -> Self {
        match value {
            DnsResponseCode::NoError => 0,
            DnsResponseCode::FormatError => 1,
            DnsResponseCode::ServerFailure => 2,
            DnsResponseCode::NameError => 3,
            DnsResponseCode::NotImplemented => 4,
            DnsResponseCode::Refused => 5
        }
    }
}

#[derive(Debug)]
struct DnsHeader {
    id: u16,
    qr: DnsQr,
    op_code: DnsOpCode,
    truncated: bool,
    authoritative_anser: bool,
    recursion_desired: bool,
    recursion_available: bool,
    response_code: DnsResponseCode,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16
}

impl DnsHeader {
    fn from_packet(mut packet: &[u8]) -> Self {
        let id = packet.read_u16::<BigEndian>().unwrap();

        let flags = packet.read_u16::<BigEndian>().unwrap();
        let qr = DnsQr::from((flags & 0b1000000000000000) >> 15);
        let op_code = DnsOpCode::from((flags & 0b0111100000000000) >> 11);
    	let authoritative_anser = (flags & 0b0000010000000000) >> 10 == 1;
    	let truncated = (flags & 0b0000001000000000) >> 9 == 1;
    	let recursion_desired = (flags & 0b0000000100000000) >> 8 == 1;
    	let recursion_available = (flags & 0b0000000010000000) >> 7 == 1;
        let response_code = DnsResponseCode::from(flags & 0b0000000000001111);

        let qd_count = packet.read_u16::<BigEndian>().unwrap();
        let an_count = packet.read_u16::<BigEndian>().unwrap();
        let ns_count = packet.read_u16::<BigEndian>().unwrap();
        let ar_count = packet.read_u16::<BigEndian>().unwrap();

        DnsHeader {
            id,
            qr,
            op_code,
            authoritative_anser,
            truncated,
            recursion_desired,
            recursion_available,
            response_code,
            qd_count,
            an_count,
            ns_count,
            ar_count
        }
    }
}

#[derive(Debug)]
struct DnsQuestion {
    domain_name: String,
    query_type: DnsType,
    query_class: DnsClass
}

impl DnsQuestion {
    fn from_packet(mut packet: &[u8]) -> Self {
        let mut labels = Vec::with_capacity(10);

        let mut length: usize =  packet.read_u8().unwrap() as usize;
        while length > 0  {
            labels.push(std::str::from_utf8(&packet[..length]).unwrap().to_string());
            packet = &packet[length..];
            length = packet.read_u8().unwrap() as usize;
        }
        let domain_name = labels.join(".");

        let query_type = DnsType::from(packet.read_u16::<BigEndian>().unwrap());
        let query_class = DnsClass::from(packet.read_u16::<BigEndian>().unwrap());
        DnsQuestion {
            domain_name,
            query_type,
            query_class
        }
    }
}

#[derive(Debug)]
enum DnsType {
    A,
    NS,
    MX,
    SOA,
    AAAA
}

impl From<u16> for DnsType {
    fn from(value: u16) -> Self {
        match value {
            1 => DnsType::A,
            2 => DnsType::NS,
            3 => DnsType::MX,
            4 => DnsType::MX,
            6 => DnsType::SOA,
            15 => DnsType::MX,
            28 => DnsType::AAAA,
            _ => panic!("This should not occur :(")
        }
    }
}

impl From<DnsType> for u16 {
    fn from(value: DnsType) -> u16 {
        match value {
            DnsType::A => 1,
             DnsType::NS => 2,
             DnsType::MX => 3,
             DnsType::MX => 4,
             DnsType::SOA => 6,
             DnsType::MX => 15,
             DnsType::AAAA => 28,
            _ => panic!("This should not occur :(")
        }
    }
}

#[derive(Debug)]
enum DnsClass {
    IN,
    CS,
    CH,
    HS
}

impl From<u16> for DnsClass {
    fn from(value: u16) -> Self {
        match value {
            1 => DnsClass::IN,
            2 => DnsClass::CS,
            3 => DnsClass::CH,
            4 => DnsClass::HS,
            _ => panic!("This should be an error :)")
        }
    }
}

impl From<DnsClass> for u16 {
    fn from(value: DnsClass) -> Self {
        match value {
            DnsClass::IN => 1,
            DnsClass::CS => 2,
            DnsClass::CH => 3,
            DnsClass::HS => 4,
            _ => panic!("This should be an error :)")
        }
    }
}

struct DnsResourceRecord {
    name: String,
    data_type: DnsType,
    data_class: DnsClass,
    ttl: u32,
    resource_data_length: u16,
    // TODO: this depends on type and class, maybe it can be implemented as an enum
    resource_data: Ipv4Addr
}

fn handle_dns_request(packet: &[u8]) -> Vec<u8>{
    let header = DnsHeader::from_packet(packet);
    let question = DnsQuestion::from_packet(&packet[12..]);
    println!("{:?}", header);
    println!("{:?}", question);

    let rr = if question.domain_name == "test.dyn.example.com" {
        let ip = Ipv4Addr::from_str("192.1.2.3").unwrap();
        DnsResourceRecord {
            name: question.domain_name.to_owned(),
            data_type: DnsType::A,
            data_class: DnsClass::IN,
            ttl: 15,
            resource_data_length: 4,
            resource_data: ip
        }
    } else {
        // This should return an error: not found
        DnsResourceRecord {
            name: question.domain_name.to_owned(),
            data_type: DnsType::A,
            data_class: DnsClass::IN,
            ttl: 15,
            resource_data_length: 4,
            resource_data: Ipv4Addr::from_str("127.0.0.1").unwrap()
        }
    };

    let answer_header = DnsHeader {
        qr: DnsQr::Respons,
        authoritative_anser: true,
        truncated: false,
        recursion_available: false,
        an_count: 1, // FIXME needs to be genric, e.g. the number of resource records
        response_code: DnsResponseCode::NoError,
        ..header
    };

    let mut answer_packet = Vec::new();
    // FIXME super dirty code
    // pack header
    answer_packet.write_u16::<BigEndian>(answer_header.id).unwrap();
    let mut flags: u16 = 0;
    flags |= (u16::from(answer_header.qr as u16) << 15) & 0b1000000000000000;
	flags |= (u16::from(answer_header.op_code) << 11) & 0b0111100000000000;
	flags |= ((answer_header.authoritative_anser as u16) << 10) & 0b0000010000000000;
	flags |= ((answer_header.truncated as u16) <<  9) & 0b0000001000000000;
	flags |= ((answer_header.recursion_desired as u16) <<  8) & 0b0000000100000000;
	flags |= ((answer_header.recursion_available as u16) <<  7) & 0b0000000010000000;
    flags |= (u16::from(answer_header.response_code) << 0) & 0b0000000000001111;
    answer_packet.write_u16::<BigEndian>(flags).unwrap();
    answer_packet.write_u16::<BigEndian>(answer_header.qd_count).unwrap();
    answer_packet.write_u16::<BigEndian>(answer_header.an_count).unwrap();
    answer_packet.write_u16::<BigEndian>(answer_header.ns_count).unwrap();
    answer_packet.write_u16::<BigEndian>(answer_header.ar_count).unwrap();

    println!("domain_name: {}", question.domain_name);
    let mut raw_question: Vec<u8> = question.domain_name.split(".")
            .flat_map(|x| {
                let mut r = Bytes::from(vec![x.len() as u8]);
                r.extend_from_slice(x.as_bytes());
                r
            })
            .collect();
    raw_question.push(0);

    println!("raw_question: {:?}", raw_question);

    answer_packet.append(&mut raw_question);
    answer_packet.write_u16::<BigEndian>(question.query_type.into()).unwrap();
    answer_packet.write_u16::<BigEndian>(question.query_class.into()).unwrap();


    // let mut raw_name: Vec<u8> = question.domain_name.split(".")
    //         .flat_map(|x| {
    //             let mut r = Bytes::from(vec![x.len() as u8]);
    //             r.extend_from_slice(x.as_bytes());
    //             r
    //         })
    //         .collect();
    // raw_name.push(0);
    // answer_packet.append(&mut raw_name);
    answer_packet.write_u16::<BigEndian>(0b1100000000000000 | 12).unwrap();
    answer_packet.write_u16::<BigEndian>(rr.data_type.into()).unwrap();
    answer_packet.write_u16::<BigEndian>(rr.data_class.into()).unwrap();
    answer_packet.write_u32::<BigEndian>(rr.ttl).unwrap();
    answer_packet.write_u16::<BigEndian>(rr.resource_data_length).unwrap();
    // answer_packet.write_u16::<BigEndian>(1).unwrap();
    answer_packet.write_u32::<BigEndian>(rr.resource_data.into()).unwrap();

    answer_packet
}
