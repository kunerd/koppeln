use crate::QueryMessage;
use crate::DnsOpCode;
use crate::DnsStandardQuery;
use std::str;

use nom::{
    bits::{bits, complete::take},
    bytes::complete::tag,
    character::complete::{alpha1, alphanumeric1, char},
    combinator::{all_consuming, map, map_res, peek, recognize},
    multi::{length_value, many_till, separated_list},
    number::complete::{be_u16, be_u8},
    sequence::{pair, tuple},
    IResult,
};

use super::{DnsHeader, DnsQuestion};

fn take_one_bit((input, offset): (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    let take_one = take::<_, u8, _, (_, _)>(1usize);

    take_one((input, offset))
}

fn take_four_bits((input, offset): (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    let take_four = take::<_, u8, _, (_, _)>(4usize);

    take_four((input, offset))
}

pub fn dns_header(input: &[u8]) -> IResult<&[u8], DnsHeader> {
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
            take_four_bits,
        ))),
        be_u16,
        be_u16,
        be_u16,
        be_u16,
    ));

    let (input, (id, (_, opcode, _, tc, rd, ra, _, rcode), qd_count, _, _, _)) = parser(input)?;

    Ok((
        input,
        DnsHeader {
            id,
            opcode: opcode.into(),
            authoritative_anser: false,
            truncated: tc != 0,
            recursion_desired: rd != 0,
            recursion_available: ra != 0,
            response_code: rcode.into(),
            qd_count,
            an_count: 0,
            ar_count: 0,
            ns_count: 0,
        },
    ))
}

/// Implemented as described in [RFC 1035](https://tools.ietf.org/html/rfc1035#section-2.3.1)
fn dns_label(input: &[u8]) -> IResult<&[u8], String> {
    // TODO: add support for message compression as desribed in https://tools.ietf.org/html/rfc1035#section-4.1.4
    let (rem, label) = map(
        map_res(
            length_value(
                be_u8,
                all_consuming(recognize(pair(
                    peek(alpha1), // a label must start with an ASCII letter
                    separated_list(char('-'), alphanumeric1),
                ))),
            ),
            str::from_utf8,
        ),
        |s| s.to_owned(),
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
    let name = labels.join(".");

    Ok((
        rem,
        DnsQuestion {
            labels,
            name,
            query_type: qtype.into(),
            query_class: qclass.into(),
        },
    ))
}


pub fn dns_query(input: &[u8]) -> IResult<&[u8], QueryMessage> {
    let (input, header) = dns_header(input)?;

    let (input, query) = match header.opcode {
        DnsOpCode::StandardQuery => {
            let (input, question) = dns_question(input)?;
            (input, QueryMessage::StandardQuery( DnsStandardQuery{ header, question } ))
        },
        // TODO parse these formats too
        DnsOpCode::InversQuery => (input, QueryMessage::InverseQuery),
        DnsOpCode::ServerStatusRequest => (input, QueryMessage::Status),
        DnsOpCode::Reserved(value) => (input, QueryMessage::Reserved(value))
    };

    Ok((input, query))
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::{DnsClass, DnsOpCode, DnsResponseCode, DnsType};

    #[test]
    fn test_parse_id() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\00\x00";

        let (_, header) = dns_header(raw_header).unwrap();

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

        let (_, question) = dns_question(raw_question).unwrap();
        assert_eq!(question.labels[0], String::from("test"));
        assert_eq!(question.query_type, DnsType::A);
        assert_eq!(question.query_class, DnsClass::IN);
    }

    #[test]
    fn test_parse_standard_query() {
        let raw_data = b"\xf4\x4c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04\x74\x65\x73\x74\x03\x64\x79\x6e\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

        let (input, _) = dns_header(raw_data).unwrap();
        let (_, _) = dns_question(input).unwrap();
    }
}
