
use std::fmt;
//
use crate::dns::constants::DNS_PACKET_SIZE;


//
/// DNS Packet Buffer parsing error.
#[derive(Debug, Clone)]
pub struct BufferParseError;

impl fmt::Display for BufferParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Buffer overflow detected!")
    }
}


//
/// DNS Packet buffer implementation.
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
    pub fn read_u8(&mut self) -> Result<u8, BufferParseError> {
        if self.pos >= DNS_PACKET_SIZE {
            return Err(BufferParseError {});
        }

        let result = self.buff[self.pos];
        self.pos += 1;

        Ok(result)
    }

    /// Read two Bytes and increment 
    pub fn read_u16(&mut self) -> Result<u16, BufferParseError> {
        let result = ((self.read_u8()? as u16) << 8)
            | (self.read_u8()? as u16);

        Ok(result)
    }

    /// Read four Bytes and increment
    pub fn read_u32(&mut self) -> Result<u32, BufferParseError> {
        let result = ((self.read_u8()? as u32) << 24)
            | ((self.read_u8()? as u32) << 16)
            | ((self.read_u8()? as u32) << 8)
            | ((self.read_u8()? as u32) << 0);

        Ok(result)
    }

    // fn read_qname(&mut self, outstr: &mut String) -> Result<(), ParseIntError> { ... }
}