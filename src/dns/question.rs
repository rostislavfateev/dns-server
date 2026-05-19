
use crate::dns::buffer::{
    BytePacketBuffer,
    BufferParseError
};


//
/// DNS query type representation.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Hash, Copy)]
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
    pub fn new() -> DnsQuestion {
        DnsQuestion { name: String::new(), qtype: QueryType::UNKNOWN(0) }
    }

    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsQuestion, BufferParseError> {
        let mut name = String::new();
        buffer.read_qname(&mut name)?;

        let qtype = QueryType::from_num(buffer.read_u16()?);

        let _ = buffer.read_u16()?; // class

        Ok(DnsQuestion {
            name: name,
            qtype: qtype,
        })
    }
}
