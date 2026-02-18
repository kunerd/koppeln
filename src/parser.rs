use crate::dns;

use nom::Parser;
use nom::{
    IResult,
    bits::{bits, complete::take},
    bytes::complete::tag,
    character::complete::{alpha1, alphanumeric1, char},
    combinator::{all_consuming, map, map_res, peek, recognize},
    multi::{length_value, many_till, separated_list0},
    number::complete::{be_u8, be_u16},
    sequence::pair,
};

use std::str;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not enough data")]
    Incomplete,
    #[error("failed to parse payload")]
    Parser,
}

impl<F> From<nom::Err<F>> for Error {
    fn from(err: nom::Err<F>) -> Self {
        match err {
            nom::Err::Incomplete(_) => Error::Incomplete,
            _ => Error::Parser,
        }
    }
}

pub fn dns_query(input: &[u8]) -> Result<dns::Request, Error> {
    let (rem, header) = dns_header(input)?;

    let request = match header.opcode {
        dns::OpCode::StandardQuery => {
            // TODO: treat query with qdcount > 1 as format error (code 1) according to:
            // https://www.rfc-editor.org/rfc/rfc9619#name-updates-to-rfc-1035

            let (_rem, question) = dns_question(rem)?;
            // TODO: we should check rem for remainding data, which would also
            // indicate a format error

            let query = dns::StandardQuery { header, question };
            dns::Request::StandardQuery(query)
        }
        dns::OpCode::InversQuery | dns::OpCode::ServerStatusRequest | dns::OpCode::Reserved(_) => {
            dns::Request::Unsupported(header)
        }
    };

    Ok(request)
}

pub fn dns_header(input: &[u8]) -> IResult<&[u8], dns::Header> {
    let mut parser = (
        be_u16,
        bits((
            take_one_bit,
            take_four_bits,
            take_one_bit,
            take_one_bit,
            take_one_bit,
            take_one_bit,
            take_three_bits,
            take_four_bits,
        )),
        be_u16,
        be_u16,
        be_u16,
        be_u16,
    );

    let (input, (id, (_, opcode, _, tc, rd, ra, _, rcode), qd_count, _, _, _)) =
        parser.parse(input)?;

    Ok((
        input,
        dns::Header {
            id,
            opcode: opcode.into(),
            authoritative_answer: false,
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
pub fn dns_question(input: &[u8]) -> IResult<&[u8], dns::Question> {
    let mut parser = (dns_labels, be_u16, be_u16);

    let (rem, (labels, qtype, qclass)) = parser.parse(input)?;
    let name = labels.join(".");

    Ok((
        rem,
        dns::Question {
            labels,
            name,
            query_type: qtype.into(),
            query_class: qclass.into(),
        },
    ))
}

fn dns_labels(input: &[u8]) -> IResult<&[u8], Vec<String>> {
    let mut parser = many_till(dns_label, tag("\0"));

    let (rem, (labels, _)) = parser.parse(input)?;

    Ok((rem, labels))
}

/// Implemented as described in [RFC 1035](https://tools.ietf.org/html/rfc1035#section-2.3.1)
fn dns_label(input: &[u8]) -> IResult<&[u8], String> {
    // TODO: add support for message compression as desribed in https://tools.ietf.org/html/rfc1035#section-4.1.4
    let mut parser = map(
        map_res(
            length_value(
                be_u8,
                all_consuming(recognize(pair(
                    peek(alpha1), // a label must start with an ASCII letter
                    separated_list0(char('-'), alphanumeric1),
                ))),
            ),
            str::from_utf8,
        ),
        |s| s.to_owned(),
    );

    let (rem, label) = parser.parse(input)?;

    Ok((rem, label))
}

fn take_one_bit((input, offset): (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    let take_one = take(1usize);

    take_one((input, offset))
}

fn take_three_bits((input, offset): (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    let take_three = take(3usize);

    take_three((input, offset))
}

fn take_four_bits((input, offset): (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    let take_four = take(4usize);

    take_four((input, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_id() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";

        let (_, header) = dns_header(raw_header).unwrap();

        assert_eq!(header.id, 26355);
    }

    #[test]
    fn test_parse_opcode() {
        let raw_header = b"\x66\xf3\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        let (_, header) = dns_header(raw_header).unwrap();
        assert_eq!(header.opcode, dns::OpCode::StandardQuery);

        let raw_header = b"\x66\xf3\x0a\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        let (_, header) = dns_header(raw_header).unwrap();
        assert_eq!(header.opcode, dns::OpCode::InversQuery);

        let raw_header = b"\x66\xf3\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        let (_, header) = dns_header(raw_header).unwrap();
        assert_eq!(header.opcode, dns::OpCode::ServerStatusRequest);

        let raw_header = b"\x66\xf3\x28\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        let (_, header) = dns_header(raw_header).unwrap();
        assert_eq!(header.opcode, dns::OpCode::Reserved(5));
    }

    #[test]
    fn test_parse_tc() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";

        let (_, header) = dns_header(raw_header).unwrap();
        assert!(!header.truncated);
    }

    #[test]
    fn test_parse_rd() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";

        let (_, header) = dns_header(raw_header).unwrap();
        assert!(header.recursion_desired);
    }

    #[test]
    fn test_parse_ra() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";

        let (_, header) = dns_header(raw_header).unwrap();
        assert!(!header.recursion_available);
    }

    #[test]
    fn test_parse_rcode() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";

        let (_, header) = dns_header(raw_header).unwrap();
        assert_eq!(header.response_code, dns::ResponseCode::NoError);
    }

    #[test]
    fn test_parse_qd_count() {
        let raw_header = b"\x66\xf3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";

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
        assert_eq!(question.query_type, dns::QueryType::A);
        assert_eq!(question.query_class, dns::QueryClass::IN);
    }

    #[test]
    fn test_parse_standard_query() {
        let raw_data = b"\xf4\x4c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04\x74\x65\x73\x74\x03\x64\x79\x6e\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

        let (input, _) = dns_header(raw_data).unwrap();
        let (_, _) = dns_question(input).unwrap();
    }
}
