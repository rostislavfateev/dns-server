/// Implementation of DNS header struct and support entities.

// includes
use crate::dns::buffer::{
    BytePacketBuffer,
    Result
};


/// DNS Request Result Code.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NoErr = 0,
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
        self.recursion_desired      = (flag_byte1 & 1) > 0;
        self.truncated_message      = (flag_byte1 & (1 << 1)) > 0;
        self.authoritative_answer   = (flag_byte1 & (1 << 2)) > 0;
        self.operation_code         = (flag_byte1 >> 3) & 0x0F;
        self.query_response         = (flag_byte1 & (1 << 7)) > 0;

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
}
