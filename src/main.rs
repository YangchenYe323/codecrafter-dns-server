use std::{
    default,
    net::{Ipv4Addr, UdpSocket},
    result,
};

use bytes::{BufMut, Bytes};
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum DnsParseError {
    #[error("Max number of jumps exceeded (is there a cycle in the qnames?)")]
    MaxJumpsExceeded,
    #[error("Reading past the end of buffer")]
    EndOfBuffer,
    #[error("Unknown QTYPE {0}")]
    UnknownQueryType(u16),
    #[error("Unknown QCLASS {0}")]
    UnknownQueryClass(u16),
    #[error("Malformed IP V4 Address data field")]
    MalformedIpV4Addr,
}

#[derive(Debug, Clone, Error)]
pub enum DnsEncodeError {
    #[error("Qname label exceeds maximum length 63")]
    QnameLabelTooLong,
}

#[derive(Debug, Clone, Error)]
pub enum Error {
    #[error("Error parsing DNS packet: {0}")]
    Parse(DnsParseError),
}

pub type Result<T, E = Error> = result::Result<T, E>;

#[derive(Debug, Default)]
pub struct DnsPacketBuffer {
    buffer: Vec<u8>,
    pos: usize,
}

impl DnsPacketBuffer {
    pub fn new(buffer: Vec<u8>, pos: usize) -> DnsPacketBuffer {
        DnsPacketBuffer { buffer, pos: 0 }
    }

    pub fn read_u8(&mut self) -> result::Result<u8, DnsParseError> {
        self.read()
    }

    pub fn read_u16(&mut self) -> result::Result<u16, DnsParseError> {
        let high = self.read()?;
        let low = self.read()?;
        Ok((high as u16) << 8 | low as u16)
    }

    pub fn read_u32(&mut self) -> result::Result<u32, DnsParseError> {
        let b1 = self.read()?;
        let b2 = self.read()?;
        let b3 = self.read()?;
        let b4 = self.read()?;

        let num = (b1 as u32) << 24 | (b2 as u32) << 16 | (b3 as u32) << 8 | (b4 as u32);
        Ok(num)
    }

    pub fn read_slice(&mut self, len: usize) -> result::Result<&[u8], DnsParseError> {
        let start = self.pos();
        self.advance(len);
        self.get_range(start, len)
    }

    pub fn get_range(&mut self, start: usize, len: usize) -> result::Result<&[u8], DnsParseError> {
        if start + len >= self.buffer.len() {
            return Err(DnsParseError::EndOfBuffer);
        }
        Ok(&self.buffer[start..start + len])
    }

    pub fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn advance(&mut self, offset: usize) {
        self.pos += offset;
    }

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    pub fn read_qname(&mut self, out: &mut String) -> result::Result<(), DnsParseError> {
        const MAX_JUMP: i32 = 5;

        // Keep track of our position inside the buffer before the first jump and
        // return to the position after the reading is done. This is useful, for example, when reading
        // the question section, where after read_qname, buffer is in the correct position to continue
        // reading other fields.
        let mut pos_after_first_jump = 0;
        let mut jump_cnt = 0;
        let mut delim = "";

        loop {
            if jump_cnt == MAX_JUMP {
                return Err(DnsParseError::MaxJumpsExceeded);
            }

            let b1 = self.read_u8()?;
            // If the most significant two bits of the first length byte is set, then it is a jump label
            if b1 & 0xC0 == 0xC0 {
                let b2 = self.read_u8()?;
                // The position referenced by the jump label is the two bytes removing the leading two most significant bit
                let offset = ((b1 ^ 0xC0) as u16) << 8 | b2 as u16;

                if jump_cnt == 0 {
                    pos_after_first_jump = self.pos()
                }
                self.seek(offset as usize);
                jump_cnt += 1;
                continue;
            }

            // Otherwise this is a normal sequence.
            if b1 == 0 {
                // A 0-length label marks the end of the name
                break;
            }

            let len = {
                let sequence = self.get_range(self.pos(), b1 as usize)?;
                let sequence_str = String::from_utf8_lossy(sequence);

                out.push_str(delim);
                out.push_str(&sequence_str.to_lowercase());

                sequence.len()
            };

            if delim == "" {
                delim = ".";
            }

            self.advance(len);
        }

        if jump_cnt > 0 {
            self.seek(pos_after_first_jump);
        }

        Ok(())
    }

    #[inline(always)]
    fn read(&mut self) -> result::Result<u8, DnsParseError> {
        let val = self
            .buffer
            .get(self.pos)
            .copied()
            .ok_or(DnsParseError::EndOfBuffer)?;
        self.pos += 1;
        Ok(val)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    /// packet ID
    id: u16,
    /// QueryOrReply: true if this message is a reply, otherwise message is header
    qr: bool,
    /// OpCode: lower 4-bit opcode
    opcode: u8,
    /// Authoritative: true if the server is the authoritative name server of the queried domain
    aa: bool,
    /// Truncation: true if the reply is bigger than 512 bytes. Always 0 in UDP responses
    tc: bool,
    /// Recursion Desired: true if the sender desires the server to recursively resolve this query
    rd: bool,
    /// Recursion Available: true if the server could perform recursion for the query
    ra: bool,
    /// Reserved: Used by DNSSEC queries, last 3 bits
    z: u8,
    /// ResponseCode: lower 4-bit response code
    rcode: u8,
    /// QuestionCount: number of questions in the question section
    qdcount: u16,
    /// AnswerCount: number of records in the answer section
    ancount: u16,
    /// AuthorityCount: number of records in the authority section
    nscount: u16,
    /// AdditionalCount: number of records in the additional section
    arcount: u16,
}

impl DnsHeader {
    pub fn decode(buf: &mut DnsPacketBuffer) -> result::Result<DnsHeader, DnsParseError> {
        let id = buf.read_u16()?;
        let (qr, opcode, aa, tc, rd) = {
            let chunk = buf.read_u8()?;
            (
                (chunk >> 7 == 1),
                (chunk >> 3) & 0b1111,
                (chunk >> 2) & 0x1 == 1,
                (chunk >> 1 & 0x1 == 1),
                chunk & 0x1 == 1,
            )
        };
        let (ra, z, rcode) = {
            let chunk = buf.read_u8()?;
            (chunk >> 7 == 1, (chunk >> 4) & 0b111, chunk & 0b1111)
        };
        let qdcount = buf.read_u16()?;
        let ancount = buf.read_u16()?;
        let nscount = buf.read_u16()?;
        let arcount = buf.read_u16()?;

        Ok(DnsHeader {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = Vec::with_capacity(12);

        // First 2 bytes is the ID
        buf.put_u16(self.id);
        // Pack qr (1 bit), opcode (4 bit), aa (1 bit), tc (1 bit), rd (1 bit) into a single u8
        buf.put_u8(
            (self.qr as u8) << 7
                | (self.opcode & 0b1111) << 3
                | (self.aa as u8) << 2
                | (self.tc as u8) << 1
                | (self.rd as u8),
        );
        // Pack ra (1 bit), z (3 bit) and rcode (4 bit) into another u8
        buf.put_u8((self.ra as u8) << 7 | (self.z & 0b111) << 4 | (self.rcode & 0b1111));
        // Flush the rest fields
        buf.put_u16(self.qdcount);
        buf.put_u16(self.ancount);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);

        buf.into()
    }
}

/// `https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    A, // 1
}

impl QueryType {
    pub fn to_num(self) -> u16 {
        match self {
            QueryType::A => 1,
        }
    }

    pub fn from_num(x: u16) -> result::Result<QueryType, DnsParseError> {
        match x {
            1 => Ok(QueryType::A),
            x => Err(DnsParseError::UnknownQueryType(x)),
        }
    }
}

/// `https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryClass {
    In, // 1 Internet
}

impl QueryClass {
    pub fn to_num(self) -> u16 {
        match self {
            QueryClass::In => 1,
        }
    }

    pub fn from_num(x: u16) -> result::Result<QueryClass, DnsParseError> {
        match x {
            1 => Ok(QueryClass::In),
            x => Err(DnsParseError::UnknownQueryClass(x)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    qname: String,
    qtype: QueryType,
    qclass: QueryClass,
}

impl DnsQuestion {
    pub fn decode(buf: &mut DnsPacketBuffer) -> result::Result<DnsQuestion, DnsParseError> {
        let mut qname = String::new();
        buf.read_qname(&mut qname)?;
        let qtype = QueryType::from_num(buf.read_u16()?)?;
        let qclass = QueryClass::from_num(buf.read_u16()?)?;

        Ok(DnsQuestion {
            qname,
            qtype,
            qclass,
        })
    }

    pub fn encode(&self, out: &mut impl BufMut) -> result::Result<(), DnsEncodeError> {
        encode_qname_plain(&self.qname, out)?;
        out.put_u16(self.qtype.to_num());
        out.put_u16(self.qclass.to_num());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum DnsRecord {
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn decode(buffer: &mut DnsPacketBuffer) -> result::Result<DnsRecord, DnsParseError> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;
        let qtype = QueryType::from_num(buffer.read_u16()?)?;
        let qclass = QueryClass::from_num(buffer.read_u16()?)?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;
        let data = buffer.read_slice(data_len as usize)?;

        match (qtype, qclass) {
            (QueryType::A, QueryClass::In) => {
                let data: [u8; 4] = data
                    .try_into()
                    .map_err(|_| DnsParseError::MalformedIpV4Addr)?;
                let addr = Ipv4Addr::from(data);
                Ok(DnsRecord::A { domain, addr, ttl })
            }
        }
    }
}

fn encode_qname_plain(qname: &str, out: &mut impl BufMut) -> result::Result<(), DnsEncodeError> {
    let split = qname.split(".");
    for s in split {
        if s.len() > 63 {
            return Err(DnsEncodeError::QnameLabelTooLong);
        }
        out.put_u8(s.len() as u8);
        out.put_slice(s.as_bytes());
    }
    out.put_u8(0);
    Ok(())
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                let mut header = DnsHeader::default();
                header.id = 1234;
                header.qr = true;
                let response = header.encode();

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;

    use crate::{DnsHeader, DnsPacketBuffer, DnsParseError, DnsQuestion, QueryClass, QueryType};

    #[test]
    fn test_dns_header_serialize() {
        let mut header = DnsHeader::default();
        header.id = 1234;
        header.qr = true;

        let expected_bytes = b"\x04\xd2\x80\0\0\0\0\0\0\0\0\0";
        assert_eq!(expected_bytes, &*header.encode());
    }

    #[test]
    fn test_dns_header_serde() {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut header = DnsHeader::default();
        header.id = rng.r#gen();
        header.aa = rng.r#gen();
        header.opcode = rng.r#gen::<u8>() & 0b1111; // opcode is 4 bits
        header.z = rng.r#gen::<u8>() & 0b111; // reserved is 3 bits
        header.rd = rng.r#gen();
        header.qdcount = rng.r#gen();

        let b = header.encode();
        let mut buffer = DnsPacketBuffer {
            buffer: b.to_vec(),
            pos: 0,
        };
        let actual = DnsHeader::decode(&mut buffer).expect("Failed to decode header");

        assert_eq!(header, actual);
    }

    #[test]
    fn test_qname() {
        let expected = "www.google.com";

        let mut buffer = Vec::new();
        // Encode www.google.com as [3]www[6]google[3]com
        buffer.put_u8(3);
        buffer.put_slice(b"www");
        buffer.put_u8(6);
        buffer.put_slice(b"google");
        buffer.put_u8(3);
        buffer.put_slice(b"com");
        buffer.put_u8(0);

        let mut pbuffer = DnsPacketBuffer { buffer, pos: 0 };
        let mut actual = String::new();
        pbuffer
            .read_qname(&mut actual)
            .expect("Failed to read qname from buffer");

        assert_eq!(expected, actual);
        assert_eq!(pbuffer.buffer.len(), pbuffer.pos());
    }

    #[test]
    fn test_qname_jump_label() {
        let expected = "www.google.com";
        let mut buffer = Vec::new();
        // First sequence start at offset 0
        buffer.put_u8(3);
        buffer.put_slice(b"www");
        // Second sequence start at offset 1000
        buffer.put_u16(0xC000 | 1000);
        // Pad to 1000
        buffer.put_bytes(0, 1000 - buffer.len());
        buffer.put_u8(6);
        buffer.put_slice(b"google");
        // Third sequence start at offset 2000
        buffer.put_u16(0xC000 | 2000);
        // Pad to 2000
        buffer.put_bytes(0, 2000 - buffer.len());
        buffer.put_u8(3);
        buffer.put_slice(b"com");
        buffer.put_u8(0);
        // We read from offset 3000
        buffer.put_bytes(0, 3000 - buffer.len());
        // The first label points to offset 0
        buffer.put_u16(0xC000);

        let mut pbuffer = DnsPacketBuffer { buffer, pos: 3000 };
        let mut actual = String::new();
        pbuffer.read_qname(&mut actual).unwrap();

        assert_eq!(expected, actual);
        assert_eq!(pbuffer.buffer.len(), pbuffer.pos());
    }

    #[test]
    fn test_jump_cycle() {
        // construct a jump loop
        let mut buffer = Vec::new();
        buffer.put_u16(0xC000 | 1000);
        buffer.put_bytes(0, 1000 - buffer.len());
        buffer.put_u16(0xC000);

        let mut pbuffer = DnsPacketBuffer { buffer, pos: 0 };
        let mut actual = String::new();

        let res = pbuffer.read_qname(&mut actual);

        assert!(matches!(res, Err(DnsParseError::MaxJumpsExceeded)))
    }

    #[test]
    fn test_question_serde() {
        let question = DnsQuestion {
            qname: "www.google.com".to_string(),
            qtype: QueryType::A,
            qclass: QueryClass::In,
        };

        let mut buf = Vec::new();
        question.encode(&mut buf).unwrap();

        let mut buf = DnsPacketBuffer::new(buf, 0);

        let actual = DnsQuestion::decode(&mut buf).unwrap();

        assert_eq!(question, actual);
    }
}
