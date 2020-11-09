extern crate config;
extern crate nom;
extern crate serde;
extern crate tokio;
extern crate tokio_util;
extern crate toml;
#[macro_use]
extern crate log;

mod parser;
pub mod settings;
pub mod web;

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

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
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

#[derive(Debug)]
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

impl From<DnsHeader> for Vec<u8> {
    fn from(header: DnsHeader) -> Self {
        let mut raw_header = vec![];

        raw_header.put_u16(header.id);

        let mut flags: u16 = 0;
        flags |= (u16::from(DnsQr::Response as u16) << 15) & 0b1000000000000000;
        flags |= (u16::from(u8::from(header.opcode)) << 11) & 0b0111100000000000;
        flags |= ((header.authoritative_anser as u16) << 10) & 0b0000010000000000;
        flags |= ((header.truncated as u16) << 9) & 0b0000001000000000;
        flags |= ((header.recursion_desired as u16) << 8) & 0b0000000100000000;
        flags |= ((header.recursion_available as u16) << 7) & 0b0000000010000000;
        flags |= (u16::from(u8::from(header.response_code)) << 0) & 0b0000000000001111;
        raw_header.put_u16(flags);
        raw_header.put_u16(header.qd_count);
        raw_header.put_u16(header.an_count);
        raw_header.put_u16(header.ns_count);
        raw_header.put_u16(header.ar_count);

        raw_header
    }
}

impl From<DnsQuestion> for Vec<u8> {
    fn from(question: DnsQuestion) -> Self {
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

#[derive(Debug)]
pub struct DnsQuestion {
    pub labels: Vec<String>,
    pub name: String,
    query_type: DnsType,
    query_class: DnsClass,
}

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
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

#[derive(Debug)]
pub struct DnsStandardQuery {
    pub header: DnsHeader,
    pub question: DnsQuestion,
}

#[derive(Debug)]
pub enum QueryMessage {
    StandardQuery(DnsStandardQuery),
    InverseQuery,
    Status,
    Reserved(u8),
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
        let mut raw_message: Vec<u8> = self.header.into();
        let mut raw_question: Vec<u8> = self.question.into();

        raw_message.append(&mut raw_question);

        for rr in self.answer {
            let mut raw_resource_record: Vec<u8> = rr.into();

            raw_message.append(&mut raw_resource_record);
        }

        raw_message
    }
}

impl QueryMessage {
    pub fn from_u8(input: &[u8]) -> Self {
        // FIXME remove unwrap
        let (_, query) = parser::dns_query(input).unwrap();

        query
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct DnsMessageCodec(());

impl DnsMessageCodec {
    pub fn new() -> Self {
        DnsMessageCodec(())
    }
}

impl Decoder for DnsMessageCodec {
    type Item = QueryMessage;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, io::Error> {
        debug!("Unpacking DNS query.");
        if !buf.is_empty() {
            let len = buf.len();
            // if packet is shorter than the header the packet is invalid
            // move this check into parser
            if len < 12 {
                return Err(io::Error::from(io::ErrorKind::Other));
            }

            let query = QueryMessage::from_u8(&buf);
            Ok(Some(query))
        } else {
            Ok(None)
        }
    }
}

impl Encoder for DnsMessageCodec {
    type Item = ResponseMessage;
    type Error = io::Error;

    fn encode(&mut self, data: ResponseMessage, buf: &mut BytesMut) -> Result<(), io::Error> {
        let raw_data = data.as_u8();
        buf.reserve(raw_data.len());
        buf.put(raw_data.as_ref());
        Ok(())
    }
}
