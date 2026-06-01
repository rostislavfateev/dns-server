/// Implementation of DNS header struct and support entities.

// includes
use crate::dns::{
    buffer::BytePacketBuffer,
    error::Result
};


/// DNS Request Result Code.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    /// No error detected.
    NoErr = 0,
    /// Format error.
    FormErr,
    /// Server failure.
    ServFail,
    ///
    NxDomain,
    /// Not implemented error.
    NotImp,
    /// Request refused error.
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
#[derive(Clone, Debug)]
pub struct DnsControlFlags {
    // Byte 1
    /// Request recursion hint to server.
    pub recursion_desired:      bool,
    /// DNS packet length is larger than standard (512).
    pub truncated_message:      bool,
    /// Server ownership of requested domain.
    pub authoritative_answer:   bool,
    /// Operation code (typically 0).
    pub operation_code:         u8,
    /// Packet is a Query (0) or Response (1).
    pub query_response:         bool,

    // Byte 2
    /// Server status of the response.
    pub result_code:            ResultCode,
    /// ???
    pub check_disable:          bool,
    /// ???
    pub authoritative_data:     bool,
    /// Reserved.
    pub z:                      bool,
    /// Server indicator if recursion is allowed.
    pub recursion_available:    bool,
}

impl DnsControlFlags {
    /// Default constructor.
    pub fn new() -> DnsControlFlags {
        DnsControlFlags {
            recursion_desired:      false,
            truncated_message:      false,
            authoritative_answer:   false,
            operation_code:         0,
            query_response:         false,
            result_code:            ResultCode::NoErr,
            check_disable:          false,
            authoritative_data:     false,
            z:                      false,
            recursion_available:    false
        }
    }

    /// Read control flags out of DNS packet buffer.
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        let flag_byte1 = buffer.read_u8()?;
        let flag_byte2 = buffer.read_u8()?;

        // bit:       0                  1                     2                 3 4 5 6            7
        //   [recursion_desired | truncated_message | authoritative_answer | operation_code | query_response]
        self.recursion_desired      = (flag_byte1 & (1 << DnsControlFlags::FLAG_RD)) > 0;
        self.truncated_message      = (flag_byte1 & (1 << DnsControlFlags::FLAG_TM)) > 0;
        self.authoritative_answer   = (flag_byte1 & (1 << DnsControlFlags::FLAG_AA)) > 0;
        self.operation_code         = (flag_byte1 >> DnsControlFlags::FLAG_OPCODE) & 0x0F;
        self.query_response         = (flag_byte1 & (1 << DnsControlFlags::FLAG_QR)) > 0;

        // bit: 0 1 2 3          4                  5            6           7
        //   [result_code | check_disable | authoritative_data | z | recursion_available]
        self.result_code            = ResultCode::from_num(flag_byte2 & 0x0F);
        self.check_disable          = (flag_byte2 & (1 << DnsControlFlags::FLAG_CD)) > 0;
        self.authoritative_data     = (flag_byte2 & (1 << DnsControlFlags::FLAG_AD)) > 0;
        //self.z                    = (flag_byte2 & (1 << DnsControlFlags::FLAG_Z)) > 0;
        self.recursion_available    = (flag_byte2 & (1 << DnsControlFlags::FLAG_RA)) > 0;

        Ok(())
    }

    /// Write control flags to DNS packet buffer.
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u8(
            (self.recursion_desired as u8)
            | ((self.truncated_message      as u8) << 1)
            | ((self.authoritative_answer   as u8) << 2)
            | ((self.operation_code         as u8) << 3)
            | ((self.query_response         as u8) << 7)
        )?;
        buffer.write_u8(
            (self.result_code as u8)
            | ((self.check_disable          as u8) << 4)
            | ((self.authoritative_data     as u8) << 5)
            | ((0u8)                               << 6)
            | ((self.recursion_available    as u8) << 7)
        )?;


        Ok(())
    }

    /// Accessor of "recursion_desired" flag.
    pub const FLAG_RD: u8 = 0u8;
    /// Accessor of "truncated_message" flag.
    pub const FLAG_TM: u8 = 1u8;
    /// Accessor of "authoritative_answer" flag.
    pub const FLAG_AA: u8 = 2u8;
    /// Accessor of "operation_code" flag.
    pub const FLAG_OPCODE: u8 = 3u8;
    /// Accessor of "query_response" flag.
    pub const FLAG_QR: u8 = 7u8;
    /// Accessor of "check_disable" flag.
    pub const FLAG_CD: u8 = 4u8;
    /// Accessor of "authoritative_data" flag.
    pub const FLAG_AD: u8 = 5u8;
    //pub const FLAG_Z: u8 = 6u8;
    /// Accessor of "recursion_available" flag.
    pub const FLAG_RA: u8 = 7u8;
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
            id:                 0,
            control_flags:      DnsControlFlags::new(),
            question_count:     0,
            answer_count:       0,
            authority_count:    0,
            additional_count:   0,
        }
    }

    /// Read data from DNS packet buffer.
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;
        self.control_flags.read(buffer)?;
        self.question_count     = buffer.read_u16()?;
        self.answer_count       = buffer.read_u16()?;
        self.authority_count    = buffer.read_u16()?;
        self.additional_count   = buffer.read_u16()?;

        Ok(())
    }

    /// Write data to DNS packet buffer.
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;
        self.control_flags.write(buffer)?;
        buffer.write_u16(self.question_count)?;
        buffer.write_u16(self.answer_count)?;
        buffer.write_u16(self.authority_count)?;
        buffer.write_u16(self.additional_count)?;

        Ok(())
    }
}
