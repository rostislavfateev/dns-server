
//
use crate::dns::{
    buffer::{
        BytePacketBuffer,
        Result
    },
    header::DnsHeader,
    question::DnsQuestion,
    record::DnsRecord
};


#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header:         DnsHeader,
    pub questions:      Vec<DnsQuestion>,
    pub answers:        Vec<DnsRecord>,
    pub authorities:    Vec<DnsRecord>,
    pub resources:      Vec<DnsRecord>,
}

impl DnsPacket {

    pub fn new() -> DnsPacket {
        DnsPacket {
            header:         DnsHeader::new(),
            questions:      Vec::new(),
            answers:        Vec::new(),
            authorities:    Vec::new(),
            resources:      Vec::new()
        }
    }

    ///
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

}