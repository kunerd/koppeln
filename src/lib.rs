mod parser;
pub mod settings;
pub mod web;

use bytes::Buf;
use bytes::{BufMut, BytesMut};
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

pub type AddressStorage = Arc<Mutex<HashMap<String, settings::AddressConfig>>>;

#[derive(Debug)]
pub enum DnsQr {
    Query,
    Response,
}

impl From<u16> for DnsQr {
    fn from(value: u16) -> Self {
        if value == 1 {
            DnsQr::Response
        } else {
            DnsQr::Query
        }
    }
}

impl From<DnsQr> for u16 {
    fn from(value: DnsQr) -> Self {
        match value {
            DnsQr::Response => 1,
            _ => 0,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DnsOpCode {
    StandardQuery,
    InversQuery,
    ServerStatusRequest,
    Reserved(u8),
}

impl From<u8> for DnsOpCode {
    fn from(value: u8) -> Self {
        match value {
            0 => DnsOpCode::StandardQuery,
            1 => DnsOpCode::InversQuery,
            2 => DnsOpCode::ServerStatusRequest,
            value => DnsOpCode::Reserved(value),
        }
    }
}

impl From<DnsOpCode> for u8 {
    fn from(value: DnsOpCode) -> Self {
        match value {
            DnsOpCode::StandardQuery => 0,
            DnsOpCode::InversQuery => 1,
            DnsOpCode::ServerStatusRequest => 2,
            DnsOpCode::Reserved(value) => value,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DnsResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

impl From<u8> for DnsResponseCode {
    fn from(value: u8) -> Self {
        match value {
            0 => DnsResponseCode::NoError,
            1 => DnsResponseCode::FormatError,
            2 => DnsResponseCode::ServerFailure,
            3 => DnsResponseCode::NameError,
            4 => DnsResponseCode::NotImplemented,
            _ => DnsResponseCode::Refused,
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
            DnsResponseCode::Refused => 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsHeader {
    pub id: u16,
    // qr: DnsQr,
    pub opcode: DnsOpCode,
    pub truncated: bool,
    pub authoritative_anser: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: DnsResponseCode,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl From<&DnsHeader> for Vec<u8> {
    fn from(header: &DnsHeader) -> Self {
        let mut raw_header = vec![];

        raw_header.put_u16(header.id);

        let mut flags: u16 = 0;
        flags |= (u16::from(DnsQr::Response) << 15) & 0b1000000000000000;
        flags |= (u16::from(u8::from(header.opcode)) << 11) & 0b0111100000000000;
        flags |= ((header.authoritative_anser as u16) << 10) & 0b0000010000000000;
        flags |= ((header.truncated as u16) << 9) & 0b0000001000000000;
        flags |= ((header.recursion_desired as u16) << 8) & 0b0000000100000000;
        flags |= ((header.recursion_available as u16) << 7) & 0b0000000010000000;
        flags |= u16::from(u8::from(header.response_code)) & 0b0000000000001111;
        raw_header.put_u16(flags);
        raw_header.put_u16(header.qd_count);
        raw_header.put_u16(header.an_count);
        raw_header.put_u16(header.ns_count);
        raw_header.put_u16(header.ar_count);

        raw_header
    }
}

impl From<&DnsQuestion> for Vec<u8> {
    fn from(question: &DnsQuestion) -> Self {
        let mut raw: Vec<u8> = question
            .labels
            .iter()
            .flat_map(|x| {
                let mut r = vec![x.len() as u8];
                r.put(x.as_bytes());
                r
            })
            .collect();

        raw.put_u8(0);

        raw.put_u16(question.query_type.into());
        raw.put_u16(question.query_class.into());

        raw
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsQuestion {
    pub labels: Vec<String>,
    pub name: String,
    query_type: DnsType,
    query_class: DnsClass,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DnsType {
    A,
    NS,
    MX,
    SOA,
    AAAA,
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
            _ => panic!("This should not occur :("),
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
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DnsClass {
    IN,
    CS,
    CH,
    HS,
}

impl From<u16> for DnsClass {
    fn from(value: u16) -> Self {
        match value {
            1 => DnsClass::IN,
            2 => DnsClass::CS,
            3 => DnsClass::CH,
            4 => DnsClass::HS,
            _ => panic!("This should be an error :)"),
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
        }
    }
}

#[derive(Debug)]
struct LabelPointer {
    offset: u16,
}

#[derive(Debug)]
pub struct Name {
    labels: Option<Vec<String>>,
    pointer: Option<LabelPointer>,
}

impl Name {
    pub fn with_pointer(offset: u16) -> Self {
        Name {
            labels: None,
            pointer: Some(LabelPointer { offset }),
        }
    }
}

impl From<Name> for Vec<u8> {
    fn from(name: Name) -> Self {
        let mut raw_name: Vec<u8> = Vec::new();

        // FIXME get rid of case where both, labels and pointer, are None
        if let Some(labels) = name.labels {
            let mut raw_labels: Vec<u8> = labels
                .iter()
                .flat_map(|x| {
                    let mut r = vec![x.len() as u8];
                    r.put(x.as_bytes());
                    r
                })
                .collect();
            raw_name.append(&mut raw_labels);
        }

        if let Some(pointer) = name.pointer {
            raw_name.put_u16(0b1100000000000000 | pointer.offset);
        }

        raw_name
    }
}

#[derive(Debug)]
pub struct DnsResourceRecord {
    pub name: Name,
    pub data_type: DnsType,
    pub data_class: DnsClass,
    pub ttl: u32,
    pub resource_data_length: u16,
    // TODO: this depends on type and class, maybe it can be implemented as an enum
    pub resource_data: Ipv4Addr,
}

impl From<DnsResourceRecord> for Vec<u8> {
    fn from(rr: DnsResourceRecord) -> Self {
        let mut raw_rr = Vec::new();
        raw_rr.append(&mut rr.name.into());
        raw_rr.put_u16(rr.data_type.into());
        raw_rr.put_u16(rr.data_class.into());
        raw_rr.put_u32(rr.ttl);
        raw_rr.put_u16(rr.resource_data_length);
        raw_rr.put_u32(rr.resource_data.into());

        raw_rr
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsStandardQuery {
    pub header: DnsHeader,
    pub question: DnsQuestion,
}

impl From<&DnsStandardQuery> for Vec<u8> {
    fn from(query: &DnsStandardQuery) -> Self {
        let mut raw_query: Vec<u8> = vec![];
        raw_query.append(&mut Into::<Vec<u8>>::into(&query.header));
        raw_query.append(&mut Into::<Vec<u8>>::into(&query.question));
        raw_query
    }
}

#[derive(Debug)]
pub struct ResponseMessage {
    pub header: DnsHeader,
    pub question: DnsQuestion,
    pub answer: Vec<DnsResourceRecord>,
    // authority: Vec<DnsResourceRecord>,
    // additional: Vec<DnsResourceRecord>
}

impl ResponseMessage {
    pub fn as_u8(self) -> Vec<u8> {
        let mut raw_message: Vec<u8> = (&self.header).into();
        let mut raw_question: Vec<u8> = (&self.question).into();

        raw_message.append(&mut raw_question);

        for rr in self.answer {
            let mut raw_resource_record: Vec<u8> = rr.into();

            raw_message.append(&mut raw_resource_record);
        }

        raw_message
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Query(DnsStandardQuery),
    Unsupported(DnsHeader, DnsQuestion),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("failed to decode DNS message")]
    Decoding,
}

#[derive(Default)]
pub struct DnsMessageCodec;

impl Decoder for DnsMessageCodec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        log::debug!("Unpacking DNS query.");
        if buf.is_empty() {
            return Ok(None);
        }

        let len = buf.len();
        if len < 12 {
            // not a enough data for a valid header
            return Ok(None);
        }

        let msg = match parser::dns_query(buf) {
            Ok((consumed, query)) => {
                buf.advance(consumed);

                Message::Query(query)
            }
            Err(err) => match err {
                parser::Error::NoStdQuery(header, question) => {
                    Message::Unsupported(header, question)
                }
                parser::Error::Incomplete => return Ok(None),
                parser::Error::Parser => return Err(Error::Decoding),
            },
        };

        Ok(Some(msg))
    }
}

impl Encoder<ResponseMessage> for DnsMessageCodec {
    type Error = io::Error;

    fn encode(&mut self, data: ResponseMessage, buf: &mut BytesMut) -> Result<(), io::Error> {
        let raw_data = data.as_u8();
        buf.reserve(raw_data.len());
        buf.put(raw_data.as_ref());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_sender() {
        let mut codec = DnsMessageCodec::default();
        let mut buf = BytesMut::new();

        let header = DnsHeader {
            id: 1234,
            opcode: DnsOpCode::StandardQuery,
            truncated: false,
            authoritative_anser: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: DnsResponseCode::NoError,
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
        let mut codec = DnsMessageCodec::default();
        let mut buf = BytesMut::new();

        let header = DnsHeader {
            id: 1234,
            opcode: DnsOpCode::StandardQuery,
            truncated: false,
            authoritative_anser: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: DnsResponseCode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };

        let question = DnsQuestion {
            labels: ["example", "test", "com"]
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>(),
            name: "example.test.com".to_string(),
            query_type: DnsType::A,
            query_class: DnsClass::IN,
        };

        let query = DnsStandardQuery { header, question };

        let header_raw: Vec<u8> = (&query).into();

        buf.put(&header_raw[0..11]);
        let result = codec.decode(&mut buf);
        assert_eq!(None, result.unwrap());

        buf.put(&header_raw[11..]);
        let result = codec.decode(&mut buf);
        assert_eq!(Some(Message::Query(query)), result.unwrap());
    }

    #[test]
    fn slow_sender_sends_rest_of_data_incomlete() {
        let mut codec = DnsMessageCodec::default();
        let mut buf = BytesMut::new();

        let header = DnsHeader {
            id: 1234,
            opcode: DnsOpCode::StandardQuery,
            truncated: false,
            authoritative_anser: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: DnsResponseCode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };

        let question = DnsQuestion {
            labels: ["example", "test", "com"]
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>(),
            name: "example.test.com".to_string(),
            query_type: DnsType::A,
            query_class: DnsClass::IN,
        };

        let query = DnsStandardQuery { header, question };

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
        assert_eq!(Some(Message::Query(query)), result.unwrap());
    }
}
