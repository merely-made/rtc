use super::*;
use crate::message::parser::Parser;

pub(super) struct AddressRecord {
    pub name: Name,
    pub address: Ipv4Addr,
    pub ttl: u32,
    pub answer: bool,
    pub authority: bool,
}

pub(super) struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub records: Vec<AddressRecord>,
}

pub(super) fn parse(bytes: &[u8], config: ResponderConfig) -> Option<Packet> {
    if bytes.len() < 12 || bytes.len() > config.max_packet_bytes {
        return None;
    }
    // Bound allocations before invoking the existing incremental codec. Skip
    // unrelated RDATA instead of constructing its potentially nested objects.
    let count = |offset| u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    let counts = [count(4), count(6), count(8), count(10)];
    if counts[0] > config.max_questions || counts[1..].iter().sum::<usize>() > config.max_records {
        return None;
    }
    let mut parser = Parser::default();
    let header = parser.start(bytes).ok()?;
    if header.op_code != 0 || header.rcode as u16 != 0 || header.truncated {
        return None;
    }
    let mut questions = Vec::with_capacity(counts[0]);
    for _ in 0..counts[0] {
        questions.push(parser.question().ok()?);
    }
    parser.skip_all_questions().ok()?;
    let mut records = Vec::new();
    for (section, count) in counts[1..].iter().enumerate() {
        for _ in 0..*count {
            let h = match section {
                0 => parser.answer_header(),
                1 => parser.authority_header(),
                _ => parser.additional_header(),
            }
            .ok()?;
            if h.typ == DnsType::A {
                if h.length != 4 {
                    return None;
                }
                let data = bytes.get(parser.off..parser.off.checked_add(4)?)?;
                if h.class.0 & !CLASS_FLAG == 1 {
                    records.push(AddressRecord {
                        name: h.name,
                        address: Ipv4Addr::new(data[0], data[1], data[2], data[3]),
                        ttl: h.ttl,
                        answer: section == 0,
                        authority: section == 1,
                    });
                }
            }
            match section {
                0 => parser.skip_answer(),
                1 => parser.skip_authority(),
                _ => parser.skip_additional(),
            }
            .ok()?;
        }
        match section {
            0 => parser.skip_all_answers(),
            1 => parser.skip_all_authorities(),
            _ => parser.skip_all_additionals(),
        }
        .ok()?;
    }
    (parser.off == bytes.len()).then_some(Packet {
        header,
        questions,
        records,
    })
}
