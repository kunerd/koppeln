use crate::dns::{OpCode, Question, RawHeader, ResourceRecord};

#[derive(Debug)]
pub enum Response {
    StandardQuery(StandardQuery),
    NotImplemented(NotImplemented),
}

impl Response {
    pub fn as_u8(self) -> Vec<u8> {
        match self {
            Response::StandardQuery(r) => r.as_u8(),
            Response::NotImplemented(r) => r.as_u8(),
        }
    }
}

#[derive(Debug)]
pub struct StandardQuery {
    // TODO make private
    pub header: Header,
    pub question: Question,
    pub answer: Vec<ResourceRecord>,
    // authority: Vec<DnsResourceRecord>,
    // additional: Vec<DnsResourceRecord>
}

impl StandardQuery {
    pub fn as_u8(self) -> Vec<u8> {
        let raw_header = RawHeader {
            id: self.header.id,
            opcode: OpCode::StandardQuery,
            truncated: self.header.truncated,
            // we only act as authoritative server
            authoritative_answer: true,
            recursion_desired: self.header.recursion_desired,
            // we don't support recursion
            recursion_available: false,
            response_code: Rcode::NoError,
            qd_count: self.header.qd_count,
            an_count: self.answer.len() as u16,
            ns_count: 0,
            ar_count: 0,
        };
        let mut raw_message: Vec<u8> = raw_header.into();
        let mut raw_question: Vec<u8> = self.question.into();

        raw_message.append(&mut raw_question);

        for rr in self.answer {
            let mut raw_resource_record: Vec<u8> = rr.into();

            raw_message.append(&mut raw_resource_record);
        }

        raw_message
    }
}

// impl From<&StandardQuery> for Vec<u8> {
//     fn from(query: &StandardQuery) -> Self {
//         let mut raw_query: Vec<u8> = vec![];
//         raw_query.append(&mut Into::<Vec<u8>>::into(&query.header));
//         raw_query.append(&mut Into::<Vec<u8>>::into(&query.question));
//         raw_query
//     }
// }

// NOTE: we can omit the other fields here, because we encode them via Rusts
// type system
#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub id: u16,
    pub truncated: bool,
    pub authoritative_answer: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: Rcode,
    pub qd_count: u16,
}

#[derive(Debug)]
pub struct NotImplemented {
    pub header: RawHeader,
}

impl NotImplemented {
    pub fn as_u8(self) -> Vec<u8> {
        self.header.into()
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

impl From<Rcode> for u8 {
    fn from(value: Rcode) -> Self {
        match value {
            Rcode::NoError => 0,
            Rcode::FormatError => 1,
            Rcode::ServerFailure => 2,
            Rcode::NameError => 3,
            Rcode::NotImplemented => 4,
            Rcode::Refused => 5,
        }
    }
}

impl From<u8> for Rcode {
    fn from(code: u8) -> Self {
        match code {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            _ => Rcode::Refused,
        }
    }
}
