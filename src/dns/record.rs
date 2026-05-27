/// Implementation of generic DNS Record and supporting entities.

// includes
use std::net::{
    Ipv4Addr,
    Ipv6Addr
};
//
use crate::dns::{
    buffer::BytePacketBuffer,
    error::Result,
    question::QueryType
};


/// DNS Record implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    /// Generic unknown record type.
    UNKNOWN {
        domain:     String,
        qtype:      QueryType,
        data_len:   u16,
        ttl:        u32,
    },
    /// IPv4 <-> Name record type.
    ALIAS {
        domain:     String,
        addr:       Ipv4Addr,
        ttl:        u32,
    },
    /// DNS Server of a domain record type.
    NAMESERVER {
        domain:     String,
        host:       String,
        ttl:        u32,
    },
    /// Name <-> Name record type.
    CANONICALNAME {
        domain:     String,
        host:       String,
        ttl:        u32,
    },
    /// Domain mail host record type.
    MAILEXCHANGE {
        domain:     String,
        priority:   u16,
        host:       String,
        ttl:        u32,
    },
    /// IPv6 <-> Name record type.
    AAAA {
        domain:     String,
        addr:       Ipv6Addr,
        ttl:        u32,
    },
}

impl DnsRecord {
    /// Read DNS record from byte buffer.
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let domain = buffer.read_qname()?;
        
        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::ALIAS => {
                Ok(DnsRecord::ALIAS {
                    domain: domain,
                    addr:   Ipv4Addr::from(buffer.read_u32()?),
                    ttl:    ttl,
                })
            },
            QueryType::NAMESERVER => {
                Ok(DnsRecord::NAMESERVER {
                    domain: domain,
                    host:   buffer.read_qname()?,
                    ttl:    ttl })
            },
            QueryType::CANONICALNAME => {
                Ok(DnsRecord::CANONICALNAME {
                    domain: domain,
                    host:   buffer.read_qname()?,
                    ttl:    ttl
                })
            },
            QueryType::MAILEXCHANGE => {
                // @todo maybe there is an order for parameter initialization
                let priority = buffer.read_u16()?;

                Ok(DnsRecord::MAILEXCHANGE {
                    domain:     domain,
                    priority:   priority,
                    host:       buffer.read_qname()?,
                    ttl:        ttl
                })
            },
            QueryType::AAAA => {
                let mut raw_addr = [0u16; 8];
                for rw in raw_addr.iter_mut() {
                    *rw = buffer.read_u16()?;
                }

                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr:   Ipv6Addr::from(raw_addr),
                    ttl:    ttl
                })
            },
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain:     domain,
                    qtype:      qtype,
                    data_len:   data_len,
                    ttl:        ttl
                })
            }
        }
    }

    /// Write DNS record to byte buffer.
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::ALIAS {
                ref domain,
                ref addr,
                ttl } => {
                    buffer.write_qname(domain)?;
                    buffer.write_u16(QueryType::ALIAS.to_num())?;
                    buffer.write_u16(1u16)?;
                    buffer.write_u32(ttl)?;
                    buffer.write_u16(addr.octets().len() as u16)?;

                    for octet in addr.octets() {
                        buffer.write_u8(octet)?;
                    }
                },
            DnsRecord::NAMESERVER {
                ref domain,
                ref host,
                ttl } => {
                    buffer.write_qname(domain)?;
                    buffer.write_u16(QueryType::NAMESERVER.to_num())?;
                    buffer.write_u16(1u16)?;
                    buffer.write_u32(ttl)?;

                    Self::write_host(host, None, buffer)?;
                },
            DnsRecord::CANONICALNAME {
                ref domain,
                ref host,
                ttl } => {
                    buffer.write_qname(domain)?;
                    buffer.write_u16(QueryType::CANONICALNAME.to_num())?;
                    buffer.write_u16(1u16)?;
                    buffer.write_u32(ttl)?;

                    Self::write_host(host, None, buffer)?;
                },
            DnsRecord::MAILEXCHANGE {
                ref domain,
                priority,
                ref host,
                ttl } => {
                    buffer.write_qname(domain)?;
                    buffer.write_u16(QueryType::MAILEXCHANGE.to_num())?;
                    buffer.write_u16(1u16)?;
                    buffer.write_u32(ttl)?;

                    Self::write_host(host, Some(priority), buffer)?;
                },
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl } => {
                    buffer.write_qname(domain)?;
                    buffer.write_u16(QueryType::AAAA.to_num())?;
                    buffer.write_u16(1u16)?;
                    buffer.write_u32(ttl)?;
                    buffer.write_u16(addr.octets().len() as u16)?;

                    for octet in addr.octets() {
                        buffer.write_u8(octet)?;
                    }
                },
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }


        Ok(buffer.pos() - start_pos)
    }

    /// Helper function to eliminate duplicated code in host string writing.
    /// (priority is represented as i32 to allow safe conversion (with guard) from/to u16;
    /// negative priority - don't write it).
    fn write_host(host: &str, priority: Option<u16>, buffer: &mut BytePacketBuffer) -> Result<()> {
        let pos = buffer.pos();
        buffer.write_u16(0u16)?;

        if let Some(value) = priority {
            buffer.write_u16(value)?;
        }

        buffer.write_qname(host)?;

        let size = buffer.pos() - (pos + 2);
        buffer.set_u16(pos, size as u16)?;

        Ok(())
    }
}

