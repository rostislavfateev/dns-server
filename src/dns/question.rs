
use crate::dns::buffer::{
    BytePacketBuffer,
    Result
};


//
/// DNS query type representation.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    ALIAS,
    NAMESERVER,
    CANONICALNAME,
    MAILEXCHANGE,
    AAAA, // IPv6 alias
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::ALIAS            => 1,
            QueryType::NAMESERVER       => 2,
            QueryType::CANONICALNAME    => 5,
            QueryType::MAILEXCHANGE     => 15,
            QueryType::AAAA             => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1  => QueryType::ALIAS,
            2  => QueryType::NAMESERVER,
            5  => QueryType::CANONICALNAME,
            15 => QueryType::MAILEXCHANGE,
            28 => QueryType::AAAA,
            _  => QueryType::UNKNOWN(num),
        }
    }
}


//
/// DNS Question implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name:   String,
    pub qtype:  QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name:   name,
            qtype:  qtype
        }
    }

    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsQuestion> {
        let mut name = String::new();
        buffer.read_qname(&mut name)?;

        let qtype = QueryType::from_num(buffer.read_u16()?);

        let _ = buffer.read_u16()?; // class

        Ok(DnsQuestion {
            name:   name,
            qtype:  qtype,
        })
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;
        buffer.write_u16(self.qtype.to_num())?;
        buffer.write_u16(1u16)?;

        Ok(())
    }
}
