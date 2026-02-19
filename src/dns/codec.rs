use crate::{
    dns::{self},
    parser,
};

use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use std::io;

#[derive(Default)]
pub struct Codec;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("failed to decode DNS message")]
    Decoding,
}

impl Decoder for Codec {
    type Item = dns::Request;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        log::debug!("Unpacking DNS query.");

        if buf.is_empty() {
            return Ok(None);
        }

        const DNS_HEADER_LEN: usize = 12;
        if buf.len() < DNS_HEADER_LEN {
            // not a enough data for a valid header
            return Ok(None);
        }
        // TODO DNS messages are restricted to 512 bytes, if this limit is
        // exceeded the messages should be truncated and the TC bit must be
        // set in the header

        let msg = match parser::dns_query(buf) {
            Ok(query) => {
                // there might still be payload data of unknown opcodes left
                // in the buf, so we have to clear it
                buf.clear();

                query
            }
            Err(err) => match err {
                parser::Error::Incomplete => return Ok(None),
                parser::Error::Parser => {
                    buf.clear();
                    return Err(Error::Decoding);
                }
            },
        };

        Ok(Some(msg))
    }
}

impl Encoder<dns::Response> for Codec {
    type Error = io::Error;

    fn encode(&mut self, response: dns::Response, buf: &mut BytesMut) -> Result<(), io::Error> {
        // TODO: remove double allocation
        let data = response.as_u8();
        buf.reserve(data.len());
        buf.put(data.as_ref());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_sender() {
        let mut codec = Codec;
        let mut buf = BytesMut::new();

        let header = dns::RawHeader {
            id: 1234,
            opcode: dns::OpCode::StandardQuery,
            truncated: false,
            authoritative_answer: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: dns::response::Rcode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };

        let header_raw: Vec<u8> = header.into();
        buf.put(&header_raw[0..11]);

        let result = codec.decode(&mut buf);
        assert_eq!(None, result.unwrap());
    }

    #[test]
    fn slow_sender_sends_rest_of_data() {
        let mut codec = Codec;
        let mut buf = BytesMut::new();

        let header = dns::RawHeader {
            id: 1234,
            opcode: dns::OpCode::StandardQuery,
            truncated: false,
            authoritative_answer: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: dns::response::Rcode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };

        let question = dns::Question {
            labels: ["example", "test", "com"]
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>(),
            name: "example.test.com".to_string(),
            query_type: dns::QueryType::A,
            query_class: dns::QueryClass::IN,
        };

        let mut raw_query: Vec<u8> = header.into();
        let raw_qustion: Vec<u8> = question.into();
        raw_query.extend(raw_qustion);

        buf.put(&raw_query[0..11]);
        let result = codec.decode(&mut buf);
        assert_eq!(None, result.unwrap());

        buf.put(&raw_query[11..]);
        let result = codec.decode(&mut buf).unwrap();
        assert!(matches!(result, Some(dns::Request::StandardQuery(_))));
    }

    #[test]
    fn slow_sender_sends_rest_of_data_incomlete() {
        let mut codec = Codec;
        let mut buf = BytesMut::new();

        let header = dns::RawHeader {
            id: 1234,
            opcode: dns::OpCode::StandardQuery,
            truncated: false,
            authoritative_answer: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: dns::response::Rcode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };

        let question = dns::Question {
            labels: ["example", "test", "com"]
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>(),
            name: "example.test.com".to_string(),
            query_type: dns::QueryType::A,
            query_class: dns::QueryClass::IN,
        };

        let mut raw_query: Vec<u8> = header.into();
        let raw_qustion: Vec<u8> = question.into();
        raw_query.extend(raw_qustion);

        buf.put(&raw_query[0..11]);
        let result = codec.decode(&mut buf);
        assert_eq!(None, result.unwrap());

        buf.put(&raw_query[11..21]);
        let result = codec.decode(&mut buf);
        assert_eq!(None, result.unwrap());

        buf.put(&raw_query[21..]);
        let result = codec.decode(&mut buf).unwrap();
        assert!(matches!(result, Some(dns::Request::StandardQuery(_))));
    }
}
