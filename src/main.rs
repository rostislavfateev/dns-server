use std::net::{Ipv4Addr, UdpSocket};
use rand;

use crate::dns::{
    buffer::BytePacketBuffer,
    error::Result,
    header::ResultCode,
    packet::DnsPacket, 
    question::{
        DnsQuestion,
        QueryType
}};


pub mod dns;


//
// Server
fn handle_query(socket: &UdpSocket) -> Result<()> {
    let mut req_buffer = BytePacketBuffer::new();
    let (_, src) = socket.recv_from(&mut req_buffer.buff)?;
    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut response = DnsPacket::new();
    response.header.id = request.header.id;
    response.header.control_flags.recursion_desired = true;
    response.header.control_flags.recursion_available = true;
    response.header.control_flags.query_response = true;

    // Normal case: single question present
    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        // Proceed with server lookup
        if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
            response.questions.push(question);
            response.header.control_flags.result_code = result.header.control_flags.result_code;

            for a in result.answers {
                println!("{:#?}", a);
                response.answers.push(a);
            }
            for a in result.authorities {
                println!("{:#?}", a);
                response.authorities.push(a);
            }
            for r in result.resources {
                println!("{:#?}", r);
                response.resources.push(r);
            }
        } else {
            response.header.control_flags.result_code = ResultCode::ServFail;
        }
    }
    // Potentially unreliable input data from the requester
    else {
        response.header.control_flags.result_code = ResultCode::FormErr;
    }

    let mut res_buffer = BytePacketBuffer::new();
    response.to_buffer(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}


fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;
    let mut packet = DnsPacket::new();

    packet.header.id = rand::random::<u16>();
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

    DnsPacket::from_buffer(&mut res_buff)
}


fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    loop {
        println!("Attempting lookup of {:?} {} with name server {}", qtype, qname, ns);

        let ns_copy = ns;
        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        // Success
        if !response.answers.is_empty() && response.header.control_flags.result_code == ResultCode::NoErr {
            return Ok(response);
        }

        // Name doesn't exist on a server
        if response.header.control_flags.result_code == ResultCode::NxDomain {
            return Ok(response);
        }

        // Retrying lookup on a more suitable nameserver
        if let Some(new_ns) = response.get_resolved_nameserver(qname) {
            ns = new_ns;
            continue;
        }

        // Resolve IP of NS record
        let new_ns_name = match response.get_unresolved_nameserver(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        let rec_response = recursive_lookup(&new_ns_name, QueryType::ALIAS)?;

        if let Some(new_ns) = rec_response.get_random_alias() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}


fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        match handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprintln!("Error detected: {}", e),
        }
    }
}
