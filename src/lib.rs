extern crate nom;
use std::collections::VecDeque;

use nom::{
    number::complete::be_u16,
    IResult,
    bits::{
        bits,
        complete::take
    },
    sequence::tuple
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

impl DnsHeader {
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
}