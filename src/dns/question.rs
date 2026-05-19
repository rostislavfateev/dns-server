
use crate::dns::buffer::{BytePacketBuffer, BufferParseError};


//
/// DNS query type representation.
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}


//
/// DNS Question implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name: name, qtype: qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), BufferParseError> {
        /// @todo implement
        Ok(())
    }
}
