
use std::net::{
    Ipv4Addr,
    Ipv6Addr
};
//
use crate::dns::{
    buffer::{
        BytePacketBuffer,
        Result
    },
    question::QueryType
};


//
/// DNS Record implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    UNKNOWN {
        domain:     String,
        qtype:      QueryType,
        data_len:   u16,
        ttl:        u32,
    },
    ALIAS {
        domain:     String,
        addr:       Ipv4Addr,
        ttl:        u32,
    },
    NAMESERVER {
        domain:     String,
        host:       String,
        ttl:        u32,
    },
    CANONICALNAME {
        domain:     String,
        host:       String,
        ttl:        u32,
    },
    MAILEXCHANGE {
        domain:     String,
        priority:   u16,
        host:       String,
        ttl:        u32,
    },
    AAAA {
        domain:     String,
        addr:       Ipv6Addr,
        ttl:        u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;
        
        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::ALIAS => {
                let ip_u32 = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((ip_u32 >> 24) & 0xFF) as u8,
                    ((ip_u32 >> 16) & 0xFF) as u8,
                    ((ip_u32 >> 8)  & 0xFF) as u8,
                    (ip_u32         & 0xFF) as u8,
                );

                Ok(DnsRecord::ALIAS {
                    domain: domain,
                    addr:   addr,
                    ttl:    ttl,
                })
            },
            QueryType::NAMESERVER => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::NAMESERVER {
                    domain: domain,
                    host:   host,
                    ttl:    ttl })
            },
            QueryType::CANONICALNAME => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::CANONICALNAME {
                    domain: domain,
                    host:   host,
                    ttl:    ttl
                })
            },
            QueryType::MAILEXCHANGE => {
                let priority = buffer.read_u16()?;
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::MAILEXCHANGE {
                    domain:     domain,
                    priority:   priority,
                    host:       host,
                    ttl:        ttl
                })
            },
            QueryType::AAAA => {
                let mut raw_addr = [0u32; 4];
                for rw in raw_addr.iter_mut() {
                    *rw = buffer.read_u32()?;
                }

                let addr = Ipv6Addr::new(
                    ((raw_addr[0] >> 16) & 0xFFFF) as u16,
                    (raw_addr[0]         & 0xFFFF) as u16,
                    ((raw_addr[1] >> 16) & 0xFFFF) as u16,
                    (raw_addr[1]         & 0xFFFF) as u16,
                    ((raw_addr[2] >> 16) & 0xFFFF) as u16,
                    (raw_addr[2]         & 0xFFFF) as u16,
                    ((raw_addr[3] >> 16) & 0xFFFF) as u16,
                    (raw_addr[3]         & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr:   addr,
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

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::ALIAS {
                ref domain,
                ref addr,
                ttl } => {
                    buffer.write_qname(domain)?;
                    buffer.write_u16(QueryType::A.to_num())?;
                    buffer.write_u16(1u16)?;
                    buffer.write_u32(ttl)?;
                    buffer.write_u16(4u16)?;

                    let octets = addr.octets();
                    for i in 0..octets.len() {
                        buffer.write_u8(octets[i])?;
            }
        }
    }
}


        Ok(buffer.pos() - start_pos)
    }
}

