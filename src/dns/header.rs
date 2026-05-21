/// Implementation of DNS header struct and support entities.

// includes
use modular_bitfield::prelude::*;

use crate::dns::buffer::{
    BytePacketBuffer,
    Result
};


/// DNS Request Result Code.
#[derive(Specifier, Debug)]
#[bits = 4]
pub enum ResultCode {
    NoErr,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
}

impl ResultCode {
    /// Number to ResultCode converter.
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FormErr,
            2 => ResultCode::ServFail,
            3 => ResultCode::NxDomain,
            4 => ResultCode::NotImp,
            5 => ResultCode::Refused,
            0 | _ => ResultCode::NoErr,
        }
    }
}


/// DNS Header Control Flags Representation.
#[bitfield(bits = 16)]
#[derive(Clone, Debug)]
pub struct DnsControlFlags {
    // Byte 1
    /// Request recursion hint to server.
    pub recursion_desired:      B1,
    /// DNS packet length is larger than standard (512).
    pub truncated_message:      B1,
    /// Server ownership of requested domain.
    pub authoritative_answer:   B1,
    /// Operation code (typically 0).
    pub operation_code:         B4,
    /// Packet is a Query (0) or Response (1).
    pub query_response:         B1,
    // Byte 2
    /// Server status of the response.
    #[bits = 4]
    pub response_code:          ResultCode,
    /// ???
    pub check_disable:          B1,
    /// ???
    pub authoritative_data:     B1,
    #[skip]
    /// Reserved.
    pub z:                      B1,
    /// Server indicator if recursion is allowed.
    pub recursion_available:    B1,
}

impl DnsControlFlags {
    /// Read control flags out of DNS packet buffer.
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), BufferParseError> {
        let flag_byte1 = buffer.read_u8()?;
        let flag_byte2 = buffer.read_u8()?;

        // bit:       0                  1                     2                 3 4 5 6            7
        //   [recursion_desired | truncated_message | authoritative_answer | operation_code | query_response]
        self.set_recursion_desired(flag_byte1 & 1);
        self.set_truncated_message(flag_byte1 & (1 << 1));
        self.set_authoritative_answer(flag_byte1 & (1 << 2));
        self.set_operation_code((flag_byte1 >> 3) & 0x0F);
        self.set_query_response(flag_byte1 & (1 << 7));

        // bit:   0 1 2 3          4                  5            6           7
        //   [response_code | check_disable | authoritative_data | z | recursion_available]
        self.set_response_code(ResultCode::from_num(flag_byte2 & 0x0F));
        self.set_check_disable(flag_byte2 & (1 << 4));
        self.set_authoritative_data(flag_byte2 & (1 << 5));
        //self.set_z(flag_byte2 & (1 << 6));
        self.set_recursion_available(flag_byte2 & (1 << 7));

        Ok(())
    }
}


/// DNS Header implementation.
#[derive(Clone, Debug)]
pub struct DnsHeader {
    /// Unique random id of the request; should be reused in response.
    pub id:                 u16,
    /// Control flags structure.
    pub control_flags:      DnsControlFlags,
    /// Number of questions in a request.
    pub question_count:     u16,
    /// Number of answers in a response.
    pub answer_count:       u16,
    /// Number of authority entries in a response.
    pub authority_count:    u16,
    /// Number of additional records in a request/response.
    pub additional_count:   u16,
}

impl DnsHeader {
    /// Default constructor.
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0, // make it random
            control_flags: DnsControlFlags::new()
                .with_query_response(0)
                .with_operation_code(0)
                .with_authoritative_answer(0)
                .with_truncated_message(0)
                .with_recursion_desired(0)
                .with_recursion_available(0)
                .with_response_code(ResultCode::NoErr),
            question_count:     0,
            answer_count:       0,
            authority_count:    0,
            additional_count:   0,
        }
    }

    /// Read data from DNS packet buffer.
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), BufferParseError> {
        self.id = buffer.read_u16()?;
        self.control_flags.read(buffer)?;
        self.question_count     = buffer.read_u16()?;
        self.answer_count       = buffer.read_u16()?;
        self.authority_count    = buffer.read_u16()?;
        self.additional_count   = buffer.read_u16()?;

        Ok(())
    }
}
