/// Implementation of generic DNS Record and supporting entities.

// includes
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

                    let octets = addr.octets();
                    for i in 0..octets.len() {
                        buffer.write_u8(octets[i])?;
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

                    Self::write_host(host, -1i32, buffer)?;
                },
            DnsRecord::CANONICALNAME {
                ref domain,
                ref host,
                ttl } => {
                    buffer.write_qname(domain)?;
                    buffer.write_u16(QueryType::CANONICALNAME.to_num())?;
                    buffer.write_u16(1u16)?;
                    buffer.write_u32(ttl)?;

                    Self::write_host(host, -1i32, buffer)?;
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

                    Self::write_host(host, priority as i32, buffer)?;
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

                    let octets = addr.octets();
                    for i in 0..octets.len() {
                        buffer.write_u8(octets[i])?;
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
    fn write_host(host: &String, priority: i32, buffer: &mut BytePacketBuffer) -> Result<()> {
        let pos = buffer.pos();
        buffer.write_u16(0u16)?;

        if priority > 0 {
            buffer.write_u16(priority as u16)?;

        }
        buffer.write_qname(host)?;

        let size = buffer.pos() - (pos + 2);
        buffer.set_u16(pos, size as u16)?;

        Ok(())
    }
}

