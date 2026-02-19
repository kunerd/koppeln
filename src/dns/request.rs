use crate::dns::{Question, RawHeader};

#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    StandardQuery(StandardQuery),
    /// 3.1.4.  Unknown DNS Opcodes
    ///
    /// The use of previously undefined opcodes is to be expected.  Since the
    /// DNS was first defined, two new opcodes have been added, UPDATE and
    /// NOTIFY.
    ///
    /// NOTIMP is the expected rcode to an unknown or unimplemented opcode.
    ///
    /// NOTE: while new opcodes will most probably use the current
    /// layout structure for the rest of the message, there is no
    /// requirement that anything other than the DNS header match.
    Unsupported(RawHeader),
}

#[derive(Debug, Clone, PartialEq)]
pub struct StandardQuery {
    pub header: Header,
    pub question: Question,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub id: u16,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub qd_count: u16,
}
