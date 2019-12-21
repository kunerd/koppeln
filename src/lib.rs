extern crate nom;
use std::collections::VecDeque;

use nom::{
    number::complete::{be_u8, be_u16},
    IResult,
    bits::{
        bits,
        complete::take
    },
    sequence::tuple,
    multi::{length_value, many_till},
    bytes::complete::{tag,take_while1},
    character::is_alphanumeric,
    character::complete::alphanumeric1
};

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

#[derive(Debug, PartialEq)]
enum DnsOpCode {
    StandardQuery,
    InversQuery,
    ServerStatusRequest,
    Reserved(u8)
}

impl From<u8> for DnsOpCode {
    fn from(value: u8) -> Self {
        match value {
            0 => DnsOpCode::StandardQuery,
            1 => DnsOpCode::InversQuery,
            2 => DnsOpCode::ServerStatusRequest,
            value => DnsOpCode::Reserved(value)
        }
    }
}

impl From<DnsOpCode> for u8 {
    fn from(value: DnsOpCode) -> Self {
        match value {
            DnsOpCode::StandardQuery => 0,
            DnsOpCode::InversQuery => 1,
            DnsOpCode::ServerStatusRequest => 2,
            DnsOpCode::Reserved(value) => value
        }
    }
}

#[derive(Debug, PartialEq)]
enum DnsResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused
}

impl From<u8> for DnsResponseCode {
    fn from(value: u8) -> Self {
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

impl From<DnsResponseCode> for u8 {
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
    // qr: DnsQr,
    opcode: DnsOpCode,
    truncated: bool,
    authoritative_anser: bool,
    recursion_desired: bool,
    recursion_available: bool,
    response_code: DnsResponseCode,
    qd_count: u16,
    // an_count: u16,
    // ns_count: u16,
    // ar_count: u16
}

#[derive(Debug)]
struct DnsQuestion {
    labels: Vec<String>,
    query_type: DnsType,
    query_class: DnsClass
}

#[derive(Debug, PartialEq)]
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
             DnsType::SOA => 6,
             DnsType::MX => 15,
             DnsType::AAAA => 28,
            _ => panic!("This should not occur :(")
        }
    }
}

#[derive(Debug, PartialEq)]
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

impl DnsQuestion {
    // fn from_packet(mut packet: &[u8]) -> Self {
    //     let mut labels = Vec::with_capacity(10);

    //     let mut length: usize =  packet.read_u8().unwrap() as usize;
    //     while length > 0  {
    //         labels.push(std::str::from_utf8(&packet[..length]).unwrap().to_string());
    //         packet = &packet[length..];
    //         length = packet.read_u8().unwrap() as usize;
    //     }
    //     let domain_name = labels.join(".");

    //     let query_type = DnsType::from(packet.read_u16::<BigEndian>().unwrap());
    //     let query_class = DnsClass::from(packet.read_u16::<BigEndian>().unwrap());
    //     DnsQuestion {
    //         domain_name,
    //         query_type,
    //         query_class
    //     }
    // }
}

fn take_one_bit((input, offset): (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    let take_one = take::<_, u8, _, (_, _)>(1usize);

    take_one((input, offset)) 
}

fn take_four_bits((input, offset): (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    let take_one = take::<_, u8, _, (_, _)>(4usize);

    take_one((input, offset)) 
}

fn dns_header(input: &[u8]) -> IResult<&[u8], DnsHeader> {
    let take_three_bits = take::<_, u8, _, (_, _)>(3usize);

    let parser = tuple((
        be_u16,
        bits(tuple((
            take_one_bit,
            take_four_bits,
            take_one_bit,
            take_one_bit,
            take_one_bit,
            take_one_bit,
            take_three_bits,
            take_four_bits
        ))),
        be_u16
    ));

    let (
        input, (
            id,
            (qr, opcode, _, tc, rd, ra, _, rcode),
            qd_count
        )
    ) = parser(input)?;

    println!("{:?}", qr);

    Ok((input, DnsHeader {
        id,
        opcode: opcode.into(),
        authoritative_anser: false,
        truncated: tc != 0,
        recursion_desired: rd != 0,
        recursion_available: ra != 0,
        response_code: rcode.into(),
        qd_count
    }))
}

use nom::combinator::map;
use nom::combinator::map_res;
use nom::character::complete::alpha1;
use nom::branch::alt;
use nom::sequence::pair;
use nom::character::complete;
use nom::combinator::recognize;
use nom::multi::separated_list;
use nom::combinator::all_consuming;
use nom::combinator::peek;
use nom::character::complete::digit0;
use nom::character::complete::alphanumeric0;
use std::str;

/// Implemented as described in [RFC 1035](https://tools.ietf.org/html/rfc1035#section-2.3.1)
fn dns_label(input: &[u8]) -> IResult<&[u8], String> {
    // TODO: add support for message compression as desribed in https://tools.ietf.org/html/rfc1035#section-4.1.4
    let (rem, label) = map(
        map_res(
            length_value(
                be_u8,
                all_consuming(
                    recognize(
                        pair(
                            peek(alpha1), // a label must start with an ASCII letter
                            separated_list(complete::char('-'),
                            alphanumeric1)
                        )
                    )
                )
            ),
            str::from_utf8),
        |s| { s.to_owned() }
    )(input)?;

    Ok((rem, label))
}

fn dns_labels(input: &[u8]) -> IResult<&[u8], Vec<String>> {
    let (rem, (labels, _)) = many_till(dns_label, tag("\0"))(input)?;

    Ok((rem, labels))
}

fn dns_question(input: &[u8]) -> IResult<&[u8], DnsQuestion> {
    let parser = tuple((dns_labels, be_u16, be_u16));
    
    let (rem, (labels, qtype, qclass)) = parser(input)?;

    Ok((rem, DnsQuestion {
        labels,
        query_type: qtype.into(),
        query_class: qclass.into()
    }))
}


#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_parse_id() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\00\x00";

        let (_, header) = dns_header(raw_header).unwrap();
        
        println!("{:?}", header);

        assert_eq!(header.id, 26355);
        assert_eq!(header.opcode, DnsOpCode::StandardQuery);
    }

    #[test]
    fn test_parse_opcode() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\00\x00";

        let (_, header) = dns_header(raw_header).unwrap();
        
        assert_eq!(header.opcode, DnsOpCode::StandardQuery);
    }

    #[test]
    fn test_parse_tc() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\00\x00";

        let (_, header) = dns_header(raw_header).unwrap();
        
        assert_eq!(header.truncated, false);
    }

    #[test]
    fn test_parse_rd() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\00\x00";

        let (_, header) = dns_header(raw_header).unwrap();
        
        assert_eq!(header.recursion_desired, true);
    }


    #[test]
    fn test_parse_ra() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\00\x00";

        let (_, header) = dns_header(raw_header).unwrap();
        
        assert_eq!(header.recursion_available, false);
    }

    #[test]
    fn test_parse_rcode() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\00\x00";

        let (_, header) = dns_header(raw_header).unwrap();
        
        assert_eq!(header.response_code, DnsResponseCode::NoError);
    }

    #[test]
    fn test_parse_qd_count() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\00\x00";

        let (_, header) = dns_header(raw_header).unwrap();
        
        assert_eq!(header.qd_count, 1);
    }


    #[test]
    fn test_parse_hyphen_label() {
        let raw_header = b"\x0Btest-hyphen";

        let (_, label) = dns_label(raw_header).unwrap();

        assert_eq!(label, String::from("test-hyphen"));
    }

    // #[test]
    // fn test_parse_leading_digit_label() {
    //     let raw_header = b"\x050test";

    //     let (_, label) = dns_label(raw_header).unwrap();

    //     assert_eq!(label, String::from("0test"));
    // }

    // #[test]
    // fn test_parse_leading_hyphen_label() {
    //     let raw_header = b"\x05-test";

    //     let (_, label) = dns_label(raw_header).unwrap();

    //     assert_eq!(label, String::from(""));
    // }

    // #[test]
    // fn test_parse_tailing_hyphen_label() {
    //     let raw_header = b"\x05test-";

    //     let (_, label) = dns_label(raw_header).unwrap();

    //     assert_eq!(label, String::from(""));
    // }

    #[test]
    fn test_parse_alphabetic_label() {
        let raw_header = b"\x04test";

        let (_, label) = dns_label(raw_header).unwrap();

        assert_eq!(label, String::from("test"));
    }

    #[test]
    fn test_parse_labels() {
        let raw_labels = b"\x04\x74\x65\x73\x74\x03\x64\x79\x6e\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00";

        let (_, labels) = dns_labels(raw_labels).unwrap();

        assert_eq!(labels[0], String::from("test"));
        assert_eq!(labels[1], String::from("dyn"));
    }

    #[test]
    fn test_parse_question() {
        let raw_question = b"\x04\x74\x65\x73\x74\x03\x64\x79\x6e\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

        let(_, question) = dns_question(raw_question).unwrap();
        println!("{:?}", question);
        
        assert_eq!(question.labels[0], String::from("test"));
        assert_eq!(question.query_type, DnsType::A);
        assert_eq!(question.query_class, DnsClass::IN);
    }
}