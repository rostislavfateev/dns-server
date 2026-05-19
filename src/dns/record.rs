
use std::net::Ipv4Addr;
//
use crate::dns::buffer::{BytePacketBuffer, BufferParseError};


//
/// DNS Record implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    UNKNOWN {
        domain:     String,
        qtype:      u16,
        data_len:   u16,
        ttl:        u32,
    },
    A {
        domain:     String,
        addr:       Ipv4Addr,
        ttl:        u32,
    },
}

impl DnsRecord {
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), BufferParseError> {
        /// @todo implement
        Ok(())
    }
}