use std::net::UdpSocket;

use bytes::{Buf, BufMut, Bytes};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct DnsHeader {
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
  pub fn decode(mut buf: impl Buf) -> DnsHeader {
    let id = buf.get_u16();
    let (qr, opcode, aa, tc, rd) = {
      let chunk = buf.get_u8();
      ((chunk >> 7 == 1), (chunk >> 3) & 0b1111, (chunk >> 2) & 0x1 == 1, (chunk >> 1 & 0x1 == 1), chunk & 0x1 == 1)
    };
    let (ra, z, rcode)  = {
      let chunk = buf.get_u8();
      (chunk >> 7 == 1, (chunk >> 4) & 0b111, chunk & 0b1111)
    };
    let qdcount = buf.get_u16();
    let ancount = buf.get_u16();
    let nscount = buf.get_u16();
    let arcount = buf.get_u16();
    
    DnsHeader { id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount }
  }

  pub fn encode(&self) -> Bytes {
    let mut buf = Vec::with_capacity(12);

    // First 2 bytes is the ID
    buf.put_u16(self.id);
    // Pack qr (1 bit), opcode (4 bit), aa (1 bit), tc (1 bit), rd (1 bit) into a single u8
    buf.put_u8((self.qr as u8) << 7 | (self.opcode & 0b1111) << 3 | (self.aa as u8) << 2 | (self.tc as u8) << 1 | (self.rd as u8));
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
    use crate::DnsHeader;

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
    let actual = DnsHeader::decode(&*b);

    assert_eq!(header, actual);
  }
}