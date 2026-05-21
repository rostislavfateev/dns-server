/// Implementation of DNS packet buffer structure and support entities.

// includes
use crate::dns::constants::DNS_PACKET_SIZE;


/// "Custom exception" for DNS Packet Buffer parsing.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;


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
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Change (with check) buffer current parsing position to provided value.
    fn seek(&mut self, pos: usize) -> Result<()> {
        if pos >= DNS_PACKET_SIZE {
            return Err("Buffer overflow detected!".into());
        }

        self.pos = pos;

        Ok(())
    }

    /// Step (with check) the buffer current parsing position forward a provided number of Bytes.
    pub fn step(&mut self, steps: usize) -> Result<()> {
        if self.pos + steps  >= DNS_PACKET_SIZE {
            return Err("Buffer overflow detected!".into());
        }

        self.pos += steps;
        Ok(())
    }

    /// Get a single Byte on a provided position (with check), the buffer current parsing position
    /// is unchanged.
    fn peek(&mut self, pos: usize) -> Result<u8> {
        if pos >= DNS_PACKET_SIZE {
            return Err("Buffer overflow detected!".into());
        }

        Ok(self.buff[pos])
    }

    /// Get a range of Bytes from a provided start position (with check), the buffer current
    /// parsing position is unchanged.
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= DNS_PACKET_SIZE {
            return Err("Buffer overflow detected!".into());
        }

        Ok(&self.buff[start..start + len as usize])
    }

    /// Read a single Byte (with check) and increment current parsing position. 
    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= DNS_PACKET_SIZE {
            return Err("Buffer overflow detected!".into());
        }

        let result = self.buff[self.pos];
        self.pos += 1;

        Ok(result)
    }

    /// Read two Bytes (with check) and increment current parsing position. 
    pub fn read_u16(&mut self) -> Result<u16> {
        let result = ((self.read_u8()? as u16) << 8)
            | (self.read_u8()? as u16);

        Ok(result)
    }

    /// Read four Bytes (with check) and increment current parsing position.
    pub fn read_u32(&mut self) -> Result<u32> {
        let result = ((self.read_u8()? as u32) << 24)
            | ((self.read_u8()? as u32) << 16)
            | ((self.read_u8()? as u32) << 8)
            | ((self.read_u8()? as u32) << 0);

        Ok(result)
    }

    /// Read domain name and increment current parsing position.
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();
        // Track jumps ("compression" for domain names)
        let mut jumped = false;
        let max_jumps = 5u8;
        let mut jump_count = 0u8;

        let mut delim = "";

        loop {
            if jump_count > max_jumps {
                return Err("Maximum number of jumps exceeded!".into());
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


    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        if self.pos >= DNS_PACKET_SIZE {
            return Err("Buffer overflow detected!".into());
        }

        self.buff[self.pos] = val;
        self.pos += 1;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write_u8(((val >> 8) & 0xFF) as u8)?;
        self.write_u8((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write_u8(((val >> 24) & 0xFF) as u8)?;
        self.write_u8(((val >> 16) & 0xFF) as u8)?;
        self.write_u8(((val >> 8) & 0xFF) as u8)?;
        self.write_u8((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            if label.len() > 0x3F {
                // @todo different exception - label length exceeded.
                return Err("Maximum label length exceeded!".into()); 
            }

            self.write_u8(label.len() as u8)?;
            for byte in label.as_bytes() {
                self.write_u8(*byte)?;
            }
        }

        // Label ending.
        self.write_u8(0u8)?;

        Ok(())
    }
}

