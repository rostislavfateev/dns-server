use std::net::Ipv4Addr;

/// Implementation of DNS Packet and support entities.

//
use crate::dns::{
    buffer::BytePacketBuffer,
    error::Result,
    header::DnsHeader,
    question::DnsQuestion,
    record::DnsRecord
};

/// DNS packet implementation.
#[derive(Clone, Debug)]
pub struct DnsPacket {
    /// DNS header.
    pub header:         DnsHeader,
    /// DNS question records container.
    pub questions:      Vec<DnsQuestion>,
    /// DNS answers records container.
    pub answers:        Vec<DnsRecord>,
    /// DNS authorities records container.
    pub authorities:    Vec<DnsRecord>,
    /// DNS additional records container.
    pub resources:      Vec<DnsRecord>,
}

impl DnsPacket {
    /// Default constructor.
    pub fn new() -> DnsPacket {
        DnsPacket {
            header:         DnsHeader::new(),
            questions:      Vec::new(),
            answers:        Vec::new(),
            authorities:    Vec::new(),
            resources:      Vec::new()
        }
    }

    /// Read DNS packet from byte buffer.
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();

        result.header.read(buffer)?;

        for _ in 0..result.header.question_count {
            let elem = DnsQuestion::read(buffer)?;
            result.questions.push(elem);
        }
        for _ in 0..result.header.answer_count {
            let elem = DnsRecord::read(buffer)?;
            result.answers.push(elem);
        }
        for _ in 0..result.header.authority_count {
            let elem = DnsRecord::read(buffer)?;
            result.authorities.push(elem);
        }
        for _ in 0..result.header.additional_count {
            let elem = DnsRecord::read(buffer)?;
            result.resources.push(elem);
        }

        Ok(result)
    }

    /// Write DNS packet to byte buffer.
    pub fn to_buffer(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.question_count      = self.questions.len()      as u16;
        self.header.answer_count        = self.answers.len()        as u16;
        self.header.authority_count     = self.authorities.len()    as u16;
        self.header.additional_count    = self.resources.len()      as u16;
        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for answer in &self.answers {
            answer.write(buffer)?;
        }
        for authority in &self.authorities {
            authority.write(buffer)?;
        }
        for resource in &self.resources {
            resource.write(buffer)?;
        }

        Ok(())
    }

    /// 
    pub fn get_random_alias(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                DnsRecord::ALIAS { addr, .. } => Some(*addr),
                _ => None,
            })
            .next()
    }

    fn get_nameserver<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            // trim records
            .filter_map(|record| match record {
                DnsRecord::NAMESERVER { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            // get only authoritative entries
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    pub fn get_resolved_nameserver(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_nameserver(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    // pick where domain matches NS record host currently in processing
                    .filter_map(move |record| match record {
                        DnsRecord::ALIAS { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            .next()
    }

    pub fn get_unresolved_nameserver<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_nameserver(qname)
            .map(|(_, host)| host)
            .next()
    }
}