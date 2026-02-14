pub mod codec;

pub use codec::Codec;

use bytes::BufMut;

use std::{
    mem,
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Debug, Clone, PartialEq)]
pub struct StandardQuery {
    pub header: Header,
    pub question: Question,
}

#[derive(Debug)]
pub struct ResponseMessage {
    pub header: Header,
    pub question: Question,
    pub answer: Vec<ResourceRecord>,
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

#[derive(Debug)]
pub struct NotImplementedResponse {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl NotImplementedResponse {
    pub fn as_u8(mut self) -> Vec<u8> {
        let mut raw_message: Vec<u8> = (&self.header).into();

        let mut payload = mem::take(&mut self.payload);
        raw_message.append(&mut payload);

        raw_message
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub id: u16,
    // qr: DnsQr,
    pub opcode: OpCode,
    pub truncated: bool,
    pub authoritative_anser: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: ResponseCode,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Question {
    pub labels: Vec<String>,
    pub name: String,
    pub query_type: QueryType,
    pub query_class: QueryClass,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum QueryType {
    A,
    NS,
    MX,
    SOA,
    AAAA,
    CNAME,
    NotImplmented(u16),
    ALL,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum QueryClass {
    IN,
    CS,
    CH,
    HS,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OpCode {
    StandardQuery,
    InversQuery,
    ServerStatusRequest,
    Reserved(u8),
}

#[derive(Debug)]
pub enum ResourceRecord {
    A {
        name: Name,
        ttl: u32,
        addr: Ipv4Addr,
    },
    AAAA {
        name: Name,
        ttl: u32,
        addr: Ipv6Addr,
    },
}

#[derive(Debug)]
pub enum Name {
    Labels(Vec<String>),
    Pointer(LabelPointer),
}

#[derive(Debug)]
pub struct LabelPointer(u16);

impl LabelPointer {
    pub fn new(offset: u16) -> Self {
        Self(offset)
    }
}

#[derive(Debug)]
pub enum Qr {
    Query,
    Response,
}

impl From<ResourceRecord> for Vec<u8> {
    fn from(rr: ResourceRecord) -> Self {
        let mut raw_rr = Vec::new();
        match rr {
            ResourceRecord::A { name, ttl, addr } => {
                raw_rr.append(&mut name.into());
                raw_rr.put_u16(QueryType::A.into());
                raw_rr.put_u16(QueryClass::IN.into());
                raw_rr.put_u32(ttl);

                // IPv4 addr consists of 4 byte octets
                raw_rr.put_u16(4);
                raw_rr.put_u32(addr.into());
            }
            ResourceRecord::AAAA { name, ttl, addr } => {
                raw_rr.append(&mut name.into());
                raw_rr.put_u16(QueryType::AAAA.into());
                raw_rr.put_u16(QueryClass::IN.into());
                raw_rr.put_u32(ttl);

                // IPv6 addr consists of 16 byte octets
                raw_rr.put_u16(16);
                for s in addr.segments() {
                    raw_rr.put_u16(s);
                }
            }
        }
        raw_rr
    }
}

impl From<&StandardQuery> for Vec<u8> {
    fn from(query: &StandardQuery) -> Self {
        let mut raw_query: Vec<u8> = vec![];
        raw_query.append(&mut Into::<Vec<u8>>::into(&query.header));
        raw_query.append(&mut Into::<Vec<u8>>::into(&query.question));
        raw_query
    }
}

impl From<&Header> for Vec<u8> {
    fn from(header: &Header) -> Self {
        let mut raw_header = vec![];

        raw_header.put_u16(header.id);

        let mut flags: u16 = 0;
        flags |= (u16::from(Qr::Response) << 15) & 0b1000000000000000;
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

impl From<&Question> for Vec<u8> {
    fn from(question: &Question) -> Self {
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

impl From<u8> for OpCode {
    fn from(code: u8) -> Self {
        match code {
            0 => OpCode::StandardQuery,
            1 => OpCode::InversQuery,
            2 => OpCode::ServerStatusRequest,
            v => OpCode::Reserved(v),
        }
    }
}

impl From<OpCode> for u8 {
    fn from(code: OpCode) -> Self {
        match code {
            OpCode::StandardQuery => 0,
            OpCode::InversQuery => 1,
            OpCode::ServerStatusRequest => 2,
            OpCode::Reserved(code) => code,
        }
    }
}

impl From<u8> for ResponseCode {
    fn from(code: u8) -> Self {
        match code {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            _ => ResponseCode::Refused,
        }
    }
}

impl From<ResponseCode> for u8 {
    fn from(value: ResponseCode) -> Self {
        match value {
            ResponseCode::NoError => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
        }
    }
}
impl From<u16> for QueryType {
    fn from(value: u16) -> Self {
        match value {
            1 => QueryType::A,
            2 => QueryType::NS,
            //NOTE: 3 and 4 Obsolete
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            // NOTE: [7, 8, 9, 10] experiemental
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            255 => QueryType::ALL,
            t => QueryType::NotImplmented(t),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(value: QueryType) -> u16 {
        match value {
            QueryType::A => 1,
            QueryType::NS => 2,
            //NOTE: 3 and 4 Obsolete
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            // NOTE: [7, 8, 9, 10] experiemental
            QueryType::MX => 15,
            QueryType::AAAA => 28,
            QueryType::ALL => 255,
            QueryType::NotImplmented(t) => t,
        }
    }
}

impl From<u16> for QueryClass {
    fn from(value: u16) -> Self {
        match value {
            1 => QueryClass::IN,
            2 => QueryClass::CS,
            3 => QueryClass::CH,
            4 => QueryClass::HS,
            _ => panic!("This should be an error :)"),
        }
    }
}

impl From<QueryClass> for u16 {
    fn from(value: QueryClass) -> Self {
        match value {
            QueryClass::IN => 1,
            QueryClass::CS => 2,
            QueryClass::CH => 3,
            QueryClass::HS => 4,
        }
    }
}

impl From<Name> for Vec<u8> {
    fn from(name: Name) -> Self {
        let mut raw_name: Vec<u8> = Vec::new();

        match name {
            Name::Labels(labels) => {
                labels.iter().for_each(|l| {
                    raw_name.put_u8(l.len() as u8);
                    raw_name.put(l.as_bytes());
                });
                // null termination
                raw_name.put_u8(0);
            }
            Name::Pointer(pointer) => {
                raw_name.put_u16(0b1100000000000000 | pointer.0);
            }
        }

        raw_name
    }
}

impl From<u16> for Qr {
    fn from(value: u16) -> Self {
        if value == 1 {
            Qr::Response
        } else {
            Qr::Query
        }
    }
}

impl From<Qr> for u16 {
    fn from(value: Qr) -> Self {
        match value {
            Qr::Response => 1,
            _ => 0,
        }
    }
}
