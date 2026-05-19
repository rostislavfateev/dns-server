
use modular_bitfield::prelude::*;
//
use crate::dns::buffer::{BytePacketBuffer, BufferParseError};


//
/// DNS Request Result Code.
#[derive(Specifier)]
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


//
/// DNS Header Control Flags Representation.
#[bitfield(bits = 16)]
pub struct DnsControlFlags {
    // Byte 1
    pub rec_des:        B1,
    pub trunc_msg:      B1,
    pub auth_answ:      B1,
    pub op_code:        B4,
    pub query_resp:     B1,
    // Byte 2
    #[bits = 4]
    pub resp_code:      ResultCode,
    pub check_disable:  B1,
    pub auth_data:      B1,
    #[skip]
    pub z:              B1, // reserved
    pub rec_av:         B1,
}

impl DnsControlFlags {

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), BufferParseError> {
        let flag_byte1 = buffer.read_u8()?;
        let flag_byte2 = buffer.read_u8()?;

        // bit:   0          1           2       3 4 5 6       7
        //   [ rec_des | trunc_msg | auth_answ | op_code | query_resp ]
        self.set_rec_des(flag_byte1 & 1);
        self.set_trunc_msg(flag_byte1 & (1 << 1));
        self.set_auth_answ(flag_byte1 & (1 << 2));
        self.set_op_code((flag_byte1 >> 3) & 0x0F);
        self.set_query_resp(flag_byte1 & (1 << 7));

        // bit: 0 1 2 3          4             5       6      7
        //   [ resp_code | check_disable | auth_data | z | rec_av ]
        self.set_resp_code(ResultCode::from_num(flag_byte2 & 0x0F));
        self.set_check_disable(flag_byte2 & (1 << 4));
        self.set_auth_data(flag_byte2 & (1 << 5));
        //self.set_z(flag_byte2 & (1 << 6));
        self.set_rec_av(flag_byte2 & (1 << 7));

        Ok(())
    }
}


//
/// DNS Header implementation.
pub struct DnsHeader {
    pub id:                 u16,
    pub control_flags:      DnsControlFlags,
    pub question_count:     u16,
    pub answer_count:       u16,
    pub authority_count:    u16,
    pub additional_count:   u16,
}

impl DnsHeader {

    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0, // make it random
            control_flags: DnsControlFlags::new()
                .with_query_resp(0)
                .with_op_code(0)
                .with_auth_answ(0)
                .with_trunc_msg(0)
                .with_rec_des(0)
                .with_rec_av(0)
                .with_resp_code(ResultCode::NoErr),
            question_count:     0,
            answer_count:       0,
            authority_count:    0,
            additional_count:   0,
        }
    }

    /// Read data from packet buffer
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
