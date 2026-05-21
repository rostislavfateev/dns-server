
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
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new()
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

}