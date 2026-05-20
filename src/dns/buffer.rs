/// Implementation of DNS packet buffer structure and support entities.

// includes
use std::fmt;

use crate::dns::constants::DNS_PACKET_SIZE;


/// DNS Packet Buffer parsing error.
#[derive(Debug, Clone)]
pub struct BufferParseError;

impl fmt::Display for BufferParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Buffer overflow detected!")
    }
}


/// DNS Packet buffer implementation.
pub struct BytePacketBuffer {
    /// Container.
    pub buff: [u8; DNS_PACKET_SIZE],
    /// Current parsing position.
    pub pos:  usize,
}

impl BytePacketBuffer {
    /// Default constructor.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buff: [0; DNS_PACKET_SIZE],
            pos:  0,
        }
    }

    /// Gets buffer current parsing position.
    fn pos(&self) -> usize {
        self.pos
    }

    /// Change (with check) buffer current parsing position to provided value.
    fn seek(&mut self, pos: usize) -> Result<(), BufferParseError> {
        if pos >= DNS_PACKET_SIZE {
            return Err(BufferParseError {});
        }

        self.pos = pos;

        Ok(())
    }

    /// Step (with check) the buffer current parsing position forward a provided number of Bytes.
    pub fn step(&mut self, steps: usize) -> Result<(), BufferParseError> {
        if self.pos + steps  >= DNS_PACKET_SIZE {
            return Err(BufferParseError {});
        }

        self.pos += steps;
        Ok(())
    }

    /// Get a single Byte on a provided position (with check), the buffer current parsing position
    /// is unchanged.
    fn peek(&mut self, pos: usize) -> Result<u8, BufferParseError> {
        if pos >= DNS_PACKET_SIZE {
            return Err(BufferParseError {});
        }

        Ok(self.buff[pos])
    }

    /// Get a range of Bytes from a provided start position (with check), the buffer current
    /// parsing position is unchanged.
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], BufferParseError> {
        if start + len >= DNS_PACKET_SIZE {
            return Err(BufferParseError {});
        }

        Ok(&self.buff[start..start + len as usize])
    }

    /// Read a single Byte (with check) and increment current parsing position. 
    pub fn read_u8(&mut self) -> Result<u8, BufferParseError> {
        if self.pos >= DNS_PACKET_SIZE {
            return Err(BufferParseError {});
        }

        let result = self.buff[self.pos];
        self.pos += 1;

        Ok(result)
    }

    /// Read two Bytes (with check) and increment current parsing position. 
    pub fn read_u16(&mut self) -> Result<u16, BufferParseError> {
        let result = ((self.read_u8()? as u16) << 8)
            | (self.read_u8()? as u16);

        Ok(result)
    }

    /// Read four Bytes (with check) and increment current parsing position.
    pub fn read_u32(&mut self) -> Result<u32, BufferParseError> {
        let result = ((self.read_u8()? as u32) << 24)
            | ((self.read_u8()? as u32) << 16)
            | ((self.read_u8()? as u32) << 8)
            | ((self.read_u8()? as u32) << 0);

        Ok(result)
    }

    /// Read domain name and increment current parsing position.
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<(), BufferParseError> {
        let mut pos = self.pos();
        // Track jumps ("compression" for domain names)
        let mut jumped = false;
        let max_jumps = 5u8;
        let mut jump_count = 0u8;

        let mut delim = "";

        loop {
            if jump_count > max_jumps {
                return Err(BufferParseError {});
            }

            let len = self.peek(pos)?;
            // Two most-significant bits set indicate jump to some offset in the packet
            if (len & 0xC0) == 0xC0 {
                // Skip current label
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Calculate offset and jump
                let byte2 = self.peek(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | byte2;
                pos = offset as usize;

                jumped = true;
                jump_count += 1;

                continue;
            }
            else {
                pos += 1;

                // Empty label of length 0 terminates domain name
                if len == 0 {
                    break;
                }

                // Append ASCII bytes ".<DOMAIN_PART>"
                outstr.push_str(delim);
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}
