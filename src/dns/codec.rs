use crate::{
    dns::{self},
    parser,
};

use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use std::io;

#[derive(Default)]
pub struct Codec;

#[derive(Debug)]
pub enum Response {
    StandardQuery(dns::Response),
    NotImplemented(dns::NotImplementedResponse),
}

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

impl Encoder<Response> for Codec {
    type Error = io::Error;

    fn encode(&mut self, response: Response, buf: &mut BytesMut) -> Result<(), io::Error> {
        let data = match response {
            Response::StandardQuery(response) => response.as_u8(),
            Response::NotImplemented(response) => response.as_u8(),
        };
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

        let header = dns::Header {
            id: 1234,
            opcode: dns::OpCode::StandardQuery,
            truncated: false,
            authoritative_answer: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: dns::ResponseCode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };

        let header_raw: Vec<u8> = (&header).into();
        buf.put(&header_raw[0..11]);

        let result = codec.decode(&mut buf);
        assert_eq!(None, result.unwrap());
    }

    #[test]
    fn slow_sender_sends_rest_of_data() {
        let mut codec = Codec;
        let mut buf = BytesMut::new();

        let header = dns::Header {
            id: 1234,
            opcode: dns::OpCode::StandardQuery,
            truncated: false,
            authoritative_answer: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: dns::ResponseCode::NoError,
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

        let query = dns::StandardQuery { header, question };

        let header_raw: Vec<u8> = (&query).into();

        buf.put(&header_raw[0..11]);
        let result = codec.decode(&mut buf);
        assert_eq!(None, result.unwrap());

        buf.put(&header_raw[11..]);
        let result = codec.decode(&mut buf);
        assert_eq!(Some(dns::Request::StandardQuery(query)), result.unwrap());
    }

    #[test]
    fn slow_sender_sends_rest_of_data_incomlete() {
        let mut codec = Codec;
        let mut buf = BytesMut::new();

        let header = dns::Header {
            id: 1234,
            opcode: dns::OpCode::StandardQuery,
            truncated: false,
            authoritative_answer: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: dns::ResponseCode::NoError,
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

        let query = dns::StandardQuery { header, question };

        let mut header_raw: Vec<u8> = (&query).into();
        header_raw.append(&mut header_raw[0..11].to_vec());

        buf.put(&header_raw[0..11]);
        let result = codec.decode(&mut buf);
        assert_eq!(None, result.unwrap());

        buf.put(&header_raw[11..21]);
        let result = codec.decode(&mut buf);
        assert_eq!(None, result.unwrap());

        buf.put(&header_raw[21..]);
        let result = codec.decode(&mut buf);
        assert_eq!(Some(dns::Request::StandardQuery(query)), result.unwrap());
    }
}
