use std::net::UdpSocket;

use crate::dns::{
    buffer::{
        BytePacketBuffer,
        Result
    },
    packet::DnsPacket, 
    question::{
        DnsQuestion,
        QueryType
}};


pub mod dns;


fn main() -> Result<()> {
    let qname = "google.com";
    let qtype = QueryType::A;
    let server = ("8.8.8.8", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;
    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.question_count = 1;
    packet.header.control_flags.recursion_desired = true;
    packet.questions.push(DnsQuestion {
        name:   qname.to_string(),
        qtype:  qtype
    });

    let mut req_buff = BytePacketBuffer::new();
    packet.to_buffer(&mut req_buff)?;

    socket.send_to(&req_buff.buff[0..req_buff.pos], server)?;

    let mut res_buff = BytePacketBuffer::new();
    socket.recv_from(&mut res_buff.buff)?;

    let res_packet = DnsPacket::from_buffer(&mut res_buff)?;
    println!("{:#?}", res_packet.header);

    for q in res_packet.questions {
        println!("{:#?}", q);
    }
    for a in res_packet.answers {
        println!("{:#?}", a);
    }
    for a in res_packet.authorities {
        println!("{:#?}", a);
    }
    for r in res_packet.resources {
        println!("{:#?}", r);
    }

    Ok(())
}
