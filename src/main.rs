
pub mod data_structs {

    //
    // Includes
    //
    use std::fmt;
    use modular_bitfield::prelude::*;


    //
    // Constants
    //
    const DNS_PACKET_SIZE: usize = 512;


    //
    // Custom exception
    //
    #[derive(Debug, Clone)]
    pub struct BufferParseError;

    impl fmt::Display for BufferParseError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Buffer overflow detected!")
        }
    }


    //
    // Custom Result codes
    //
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
    // DNS Header Representation
    //
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

        // ...
    }

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

        // ...
    }


    //
    // DNS Packet implementation.
    //
    pub struct BytePacketBuffer {
        pub buff: [u8; DNS_PACKET_SIZE],
        pub pos:  usize,
    }

    impl BytePacketBuffer {
        /// Constructor
        pub fn new() -> BytePacketBuffer {
            BytePacketBuffer {
                buff: [0; DNS_PACKET_SIZE],
                pos:  0,
            }
        }

        /// Get current buffer position
        fn pos(&self) -> usize {
            self.pos
        }

        /// Change buffer position
        fn seek(&mut self, pos: usize) {
            self.pos = pos;
        }

        /// Step the buffer forward a particular number of Bytes
        fn step(&mut self, steps: usize) {
            self.pos += steps;
        }

        /// Get a single Byte, the buffer position is unchanged
        fn peek(&mut self, pos: usize) -> Result<u8, BufferParseError> {
            if pos >= DNS_PACKET_SIZE {
                return Err(BufferParseError {});
            }

            Ok(self.buff[pos])
        }

        /// Get a range of Bytes, the buffer position is unchanged
        fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], BufferParseError> {
            if start + len >= DNS_PACKET_SIZE {
                return Err(BufferParseError {});
            }

            Ok(&self.buff[start..start + len as usize])
        }

        /// Read single Byte and increment 
        fn read_u8(&mut self) -> Result<u8, BufferParseError> {
            if self.pos >= DNS_PACKET_SIZE {
                return Err(BufferParseError {});
            }

            let result = self.buff[self.pos];
            self.pos += 1;

            Ok(result)
        }

        /// Read two Bytes and increment 
        fn read_u16(&mut self) -> Result<u16, BufferParseError> {
            let result = ((self.read_u8()? as u16) << 8)
                | (self.read_u8()? as u16);

            Ok(result)
        }

        /// Read four Bytes and increment
        fn read_u32(&mut self) -> Result<u32, BufferParseError> {
            let result = ((self.read_u8()? as u32) << 24)
                | ((self.read_u8()? as u32) << 16)
                | ((self.read_u8()? as u32) << 8)
                | ((self.read_u8()? as u32) << 0);

            Ok(result)
        }

        // fn read_qname(&mut self, outstr: &mut String) -> Result<(), ParseIntError> { ... }
    }

}


fn main() {
    println!("Hello, world!");
}
