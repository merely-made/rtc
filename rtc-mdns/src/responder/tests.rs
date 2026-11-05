use super::*;
use crate::message::resource::aaaa::AaaaResource;

const NAME: &str = "53caef04-4218-4fb0-815d-f91a511bb8d2.local.";
const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);
const JITTER: Duration = Duration::from_millis(75);

#[test]
fn shared_port_qu_responses_multicast_with_pacing_but_legacy_stays_unicast() {
    let now = Instant::now();
    let mut r = Responder::new(
        now,
        NAME,
        ADDRESS,
        ResponderConfig {
            multicast_qu: true,
            ..Default::default()
        },
    )
    .unwrap();
    r.poll_transmit(now).unwrap();
    r.poll_transmit(now + MULTICAST_INTERVAL).unwrap();
    receive(
        &mut r,
        now + MULTICAST_INTERVAL,
        5353,
        &mut query(0, 0x8001),
    );
    assert!(r.poll_transmit(now + MULTICAST_INTERVAL).is_none());
    assert_eq!(
        r.poll_transmit(now + Duration::from_secs(2))
            .unwrap()
            .destination,
        multicast()
    );
    receive(
        &mut r,
        now + Duration::from_secs(2),
        40001,
        &mut query(10, 1),
    );
    let tx = r.poll_transmit(now + Duration::from_secs(2)).unwrap();
    assert_eq!(tx.destination.port(), 40001);
    assert_eq!(unpack(&tx).header.id, 10);
}

fn responder(now: Instant) -> Responder {
    Responder::new(now, NAME, ADDRESS, ResponderConfig::default()).unwrap()
}

fn started(now: Instant) -> Responder {
    let mut r = responder(now);
    r.poll_transmit(now).unwrap();
    r.poll_transmit(now + MULTICAST_INTERVAL).unwrap();
    r
}

fn question(typ: DnsType, class: u16) -> Question {
    Question {
        name: Name::new(NAME).unwrap(),
        typ,
        class: DnsClass(class),
    }
}

fn query(id: u16, class: u16) -> Message {
    Message {
        header: Header {
            id,
            ..Default::default()
        },
        questions: vec![question(DnsType::A, class)],
        ..Default::default()
    }
}

fn record(address: Ipv4Addr, ttl: u32) -> Resource {
    Resource {
        header: ResourceHeader {
            name: Name::new(NAME).unwrap(),
            typ: DnsType::A,
            class: DnsClass(1),
            ttl,
            ..Default::default()
        },
        body: Some(Box::new(AResource {
            a: address.octets(),
        })),
    }
}

fn receive(r: &mut Responder, now: Instant, port: u16, message: &mut Message) {
    r.handle_packet(
        now,
        SocketAddrV4::new(OTHER, port),
        MDNS_MULTICAST_IPV4,
        &message.pack().unwrap(),
        JITTER,
    );
}

fn unpack(transmit: &ResponderTransmit) -> Message {
    let mut result = Message::default();
    result.unpack(&transmit.payload).unwrap();
    result
}

#[test]
fn two_announcements_are_unique_and_do_not_burst_when_late() {
    let now = Instant::now();
    let mut r = responder(now);
    assert_eq!(r.next_deadline(), Some(now));
    let first = r.poll_transmit(now).unwrap();
    assert_eq!(first.destination, multicast());
    let m = unpack(&first);
    assert!(m.header.response && m.header.authoritative);
    assert_eq!(m.header.id, 0);
    assert!(m.questions.is_empty());
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].header.class.0, 0x8001);
    assert_eq!(m.answers[0].header.ttl, 120);
    assert!(r.poll_transmit(now + Duration::from_millis(999)).is_none());
    assert!(r.poll_transmit(now + Duration::from_secs(20)).is_some());
    assert!(r.poll_transmit(now + Duration::from_secs(20)).is_none());
    assert_eq!(r.next_deadline(), None);
}

#[test]
fn invalid_names_including_unicode_cannot_panic_or_register() {
    let now = Instant::now();
    // Exactly 42 bytes, with byte 36 inside a UTF-8 character.
    let boundary = format!("{}élocal", &NAME[..35]);
    assert_eq!(boundary.len(), 42);
    for name in [
        "host.local",
        "53caef04-4218-1fb0-815d-f91a511bb8d2.local",
        "53caef04-4218-4fb0-715d-f91a511bb8d2.local",
        "53caef04-4218-4fb0-815d-f91a511bb8d2.local..",
        boundary.as_str(),
    ] {
        assert!(matches!(
            Responder::new(now, name, ADDRESS, ResponderConfig::default()),
            Err(RegistrationError::InvalidName)
        ));
    }
    assert!(
        Responder::new(
            now,
            &NAME.to_uppercase(),
            ADDRESS,
            ResponderConfig::default()
        )
        .is_ok()
    );
    assert!(
        Responder::new(
            now,
            NAME.trim_end_matches('.'),
            ADDRESS,
            ResponderConfig::default()
        )
        .is_ok()
    );
}

#[test]
fn invalid_addresses_and_configuration_are_rejected() {
    let now = Instant::now();
    for address in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        MDNS_MULTICAST_IPV4,
    ] {
        assert!(matches!(
            Responder::new(now, NAME, address, ResponderConfig::default()),
            Err(RegistrationError::InvalidAddress)
        ));
    }
    let default = ResponderConfig::default();
    for config in [
        ResponderConfig {
            ttl_seconds: 0,
            ..default
        },
        ResponderConfig {
            ttl_seconds: 121,
            ..default
        },
        ResponderConfig {
            max_packet_bytes: 511,
            ..default
        },
        ResponderConfig {
            max_packet_bytes: 9001,
            ..default
        },
        ResponderConfig {
            max_questions: 0,
            ..default
        },
        ResponderConfig {
            max_questions: 17,
            ..default
        },
        ResponderConfig {
            max_records: 0,
            ..default
        },
        ResponderConfig {
            max_records: 65,
            ..default
        },
        ResponderConfig {
            unicast_interval: Duration::ZERO,
            ..default
        },
        ResponderConfig {
            unicast_interval: Duration::from_secs(2),
            ..default
        },
    ] {
        assert!(matches!(
            Responder::new(now, NAME, ADDRESS, config),
            Err(RegistrationError::InvalidConfig)
        ));
    }
}

#[test]
fn multicast_a_and_any_match_case_insensitively_without_question_echo() {
    let now = Instant::now();
    for (typ, class) in [(DnsType::A, 1), (DnsType::All, 255)] {
        let mut r = started(now);
        let mut q = query(34, class);
        q.questions[0].typ = typ;
        q.questions[0].name = Name::new(&NAME.to_uppercase()).unwrap();
        let at = now + Duration::from_secs(2);
        receive(&mut r, at, 5353, &mut q);
        let tx = r.poll_transmit(at).unwrap();
        assert_eq!(tx.destination, multicast());
        let m = unpack(&tx);
        assert_eq!(m.header.id, 0);
        assert!(m.questions.is_empty());
        assert_eq!(m.answers[0].header.class.0, 0x8001);
    }
}

#[test]
fn legacy_unicast_echoes_id_questions_with_short_ttl_and_no_flush() {
    let now = Instant::now();
    let mut r = started(now);
    let mut q = query(0x1234, 1);
    q.questions.push(question(DnsType::Aaaa, 1));
    receive(&mut r, now, 40001, &mut q);
    let tx = r.poll_transmit(now).unwrap();
    assert_eq!(tx.destination, SocketAddrV4::new(OTHER, 40001));
    let m = unpack(&tx);
    assert_eq!(m.header.id, 0x1234);
    assert_eq!(m.questions, q.questions);
    assert_eq!(m.answers[0].header.ttl, 10);
    assert_eq!(m.answers[0].header.class.0, 1);
}

#[test]
fn qu_uses_unicast_when_recent_then_refreshes_multicast_caches() {
    let now = Instant::now();
    let mut r = started(now);
    let mut q = query(51, 0x8001);
    let at = now + Duration::from_secs(2);
    receive(&mut r, at, 5353, &mut q);
    let tx = r.poll_transmit(at).unwrap();
    assert_eq!(tx.destination, SocketAddrV4::new(OTHER, 5353));
    let m = unpack(&tx);
    assert_eq!(m.header.id, 0);
    assert!(m.questions.is_empty());
    assert_eq!(m.answers[0].header.class.0, 0x8001);
    let later = now + Duration::from_secs(31);
    receive(&mut r, later, 5353, &mut q);
    assert_eq!(r.poll_transmit(later).unwrap().destination, multicast());
}

#[test]
fn direct_unicast_is_treated_as_qu() {
    let now = Instant::now();
    let mut r = started(now);
    let q = query(2, 1).pack().unwrap();
    r.handle_packet(now, SocketAddrV4::new(OTHER, 5353), ADDRESS, &q, JITTER);
    assert_eq!(
        r.poll_transmit(now).unwrap().destination,
        SocketAddrV4::new(OTHER, 5353)
    );
}

#[test]
fn known_answer_half_ttl_suppresses_but_lower_ttl_refreshes() {
    let now = Instant::now();
    for ttl in [59, 60, 120] {
        let mut r = started(now);
        let mut q = query(0, 1);
        q.answers.push(record(ADDRESS, ttl));
        let at = now + Duration::from_secs(2);
        receive(&mut r, at, 5353, &mut q);
        assert_eq!(r.poll_transmit(at).is_some(), ttl < 60);
    }
}

#[test]
fn stale_or_different_known_answer_is_not_a_conflict() {
    let now = Instant::now();
    let mut r = started(now);
    let mut q = query(0, 1);
    q.answers.push(record(OTHER, 120));
    let at = now + Duration::from_secs(2);
    receive(&mut r, at, 5353, &mut q);
    assert_eq!(r.state(), RegistrationState::Active);
    assert!(r.poll_transmit(at).is_some());
}

#[test]
fn legacy_query_does_not_use_multicast_known_answer_suppression() {
    let now = Instant::now();
    let mut r = started(now);
    let mut q = query(4, 1);
    q.answers.push(record(ADDRESS, 120));
    receive(&mut r, now, 40001, &mut q);
    assert!(r.poll_transmit(now).is_some());
}

#[test]
fn multicast_replies_are_paced_and_cannot_accumulate_a_flood() {
    let now = Instant::now();
    let mut r = started(now);
    let at = now + Duration::from_secs(1);
    let mut q = query(0, 1);
    for _ in 0..1000 {
        receive(&mut r, at, 5353, &mut q);
    }
    assert_eq!(r.next_deadline(), Some(now + Duration::from_secs(2)));
    assert!(r.poll_transmit(at).is_none());
    assert!(r.poll_transmit(now + Duration::from_secs(2)).is_some());
    assert!(r.poll_transmit(now + Duration::from_secs(2)).is_none());
}

#[test]
fn unicast_reply_slot_and_interval_are_bounded_and_configurable() {
    let now = Instant::now();
    let mut r = started(now);
    let mut q = query(1, 1);
    receive(&mut r, now, 40001, &mut q);
    r.poll_transmit(now).unwrap();
    r.config.unicast_interval = Duration::from_millis(30);
    for port in 40002..41000 {
        receive(&mut r, now, port, &mut q);
    }
    assert_eq!(r.next_deadline(), Some(now + Duration::from_millis(30)));
    assert!(r.poll_transmit(now + Duration::from_millis(29)).is_none());
    assert_eq!(
        r.poll_transmit(now + Duration::from_millis(30))
            .unwrap()
            .destination
            .port(),
        40002
    );
    assert!(r.poll_transmit(now + Duration::from_secs(1)).is_none());
}

#[test]
fn multiquestion_reply_waits_for_caller_jitter_and_coalesces_duplicates() {
    let now = Instant::now();
    let mut r = started(now);
    let mut q = query(0, 1);
    q.questions.push(question(DnsType::All, 1));
    let at = now + Duration::from_secs(2);
    receive(&mut r, at, 5353, &mut q);
    assert_eq!(r.next_deadline(), Some(at + JITTER));
    assert!(r.poll_transmit(at).is_none());
    let m = unpack(&r.poll_transmit(at + JITTER).unwrap());
    assert_eq!(m.answers.len(), 1);
    assert!(r.poll_transmit(at + JITTER).is_none());
}

#[test]
fn live_conflict_cancels_queued_reply_and_announcements_without_goodbye() {
    let now = Instant::now();
    for section in 0..3 {
        let mut r = responder(now);
        r.poll_transmit(now).unwrap();
        receive(&mut r, now, 5353, &mut query(0, 1));
        let mut m = Message {
            header: Header {
                response: true,
                ..Default::default()
            },
            ..Default::default()
        };
        match section {
            0 => &mut m.answers,
            1 => &mut m.authorities,
            _ => &mut m.additionals,
        }
        .push(record(OTHER, 120));
        receive(&mut r, now, 5353, &mut m);
        assert_eq!(r.state(), RegistrationState::Conflict);
        assert_eq!(r.next_deadline(), None);
        assert!(r.poll_transmit(now + Duration::from_secs(100)).is_none());
        r.close();
        assert!(r.poll_transmit(now + Duration::from_secs(100)).is_none());
    }
}

#[test]
fn goodbye_different_class_or_wrong_response_port_cannot_force_conflict() {
    let now = Instant::now();
    for (ttl, class, port) in [(0, 1, 5353), (120, 3, 5353), (120, 1, 40001)] {
        let mut r = started(now);
        let mut rr = record(OTHER, ttl);
        rr.header.class = DnsClass(class);
        let mut m = Message {
            header: Header {
                response: true,
                ..Default::default()
            },
            answers: vec![rr],
            ..Default::default()
        };
        receive(&mut r, now, port, &mut m);
        assert_eq!(r.state(), RegistrationState::Active);
        assert!(r.poll_transmit(now + Duration::from_secs(10)).is_none());
    }
}

#[test]
fn own_record_low_ttl_is_rescued_instead_of_withdrawn() {
    let now = Instant::now();
    for ttl in [0, 59, 60] {
        let mut r = started(now);
        let mut m = Message {
            header: Header {
                response: true,
                ..Default::default()
            },
            answers: vec![record(ADDRESS, ttl)],
            ..Default::default()
        };
        let at = now + Duration::from_secs(2);
        receive(&mut r, at, 5353, &mut m);
        assert_eq!(r.state(), RegistrationState::Active);
        assert_eq!(r.poll_transmit(at).is_some(), ttl < 60);
    }
}

#[test]
fn probe_is_defended_at_250ms_instead_of_being_a_response_conflict() {
    let now = Instant::now();
    let mut r = started(now);
    let at = now + Duration::from_secs(1);
    // Even a queued ordinary query cannot delay defense.
    receive(&mut r, at, 5353, &mut query(0, 1));
    let mut probe = query(0, 1);
    probe.authorities.push(record(OTHER, 120));
    receive(&mut r, at, 5353, &mut probe);
    assert_eq!(r.state(), RegistrationState::Active);
    assert_eq!(r.next_deadline(), Some(at + PROBE_INTERVAL));
    assert!(r.poll_transmit(at + Duration::from_millis(249)).is_none());
    assert!(r.poll_transmit(at + PROBE_INTERVAL).is_some());
}

#[test]
fn close_discards_positive_pending_work_and_sends_one_ttl_zero_goodbye() {
    let now = Instant::now();
    let mut r = responder(now);
    r.poll_transmit(now).unwrap();
    receive(&mut r, now, 40001, &mut query(12, 1));
    r.close();
    r.close();
    assert_eq!(r.state(), RegistrationState::Closed);
    assert_eq!(r.next_deadline(), None);
    let tx = r.poll_transmit(now).unwrap();
    assert_eq!(tx.destination, multicast());
    let m = unpack(&tx);
    assert_eq!(m.answers[0].header.ttl, 0);
    assert_eq!(m.answers[0].header.class.0, 0x8001);
    receive(&mut r, now, 40001, &mut query(13, 1));
    assert!(r.poll_transmit(now + Duration::from_secs(100)).is_none());
}

#[test]
fn closing_before_first_transmit_sends_nothing() {
    let now = Instant::now();
    let mut r = responder(now);
    r.close();
    assert!(r.poll_transmit(now).is_none());
}

#[test]
fn irrelevant_questions_and_unrelated_aaaa_records_are_ignored() {
    let now = Instant::now();
    for (typ, class, name) in [
        (DnsType::Aaaa, 1, NAME),
        (DnsType::A, 3, NAME),
        (DnsType::A, 1, "other.local."),
    ] {
        let mut r = started(now);
        let mut q = query(0, class);
        q.questions[0].typ = typ;
        q.questions[0].name = Name::new(name).unwrap();
        receive(&mut r, now, 5353, &mut q);
        assert!(r.poll_transmit(now + Duration::from_secs(2)).is_none());
    }
    let mut r = started(now);
    let mut q = query(0, 1);
    q.additionals.push(Resource {
        header: ResourceHeader {
            name: Name::new("other.local.").unwrap(),
            typ: DnsType::Aaaa,
            class: DnsClass(1),
            ..Default::default()
        },
        body: Some(Box::new(AaaaResource { aaaa: [1; 16] })),
    });
    receive(&mut r, now + Duration::from_secs(2), 5353, &mut q);
    assert!(r.poll_transmit(now + Duration::from_secs(2)).is_some());
}

#[test]
fn wrong_actual_destination_and_invalid_sources_are_ignored() {
    let now = Instant::now();
    let q = query(0, 1).pack().unwrap();
    for (source, destination) in [
        (SocketAddrV4::new(OTHER, 5353), OTHER),
        (SocketAddrV4::new(OTHER, 0), MDNS_MULTICAST_IPV4),
        (
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5353),
            MDNS_MULTICAST_IPV4,
        ),
        (
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 5353),
            MDNS_MULTICAST_IPV4,
        ),
        (multicast(), MDNS_MULTICAST_IPV4),
    ] {
        let mut r = started(now);
        r.handle_packet(now, source, destination, &q, JITTER);
        assert!(r.poll_transmit(now + Duration::from_secs(2)).is_none());
    }
}

#[test]
fn malformed_truncated_over_budget_and_trailing_packets_have_no_effect() {
    let now = Instant::now();
    let good = query(0, 1).pack().unwrap();
    let mut bad = vec![vec![], vec![0; 11], vec![0; 1501]];
    for offset in [4, 6, 8, 10] {
        let mut p = good.clone();
        p[offset] = 0xff;
        p[offset + 1] = 0xff;
        bad.push(p);
    }
    let mut trailing = good.clone();
    trailing.push(0);
    bad.push(trailing);
    let mut truncated = good.clone();
    truncated[2] |= 2;
    bad.push(truncated);
    let mut opcode = good.clone();
    opcode[2] |= 8;
    bad.push(opcode);
    let mut rcode = good.clone();
    rcode[3] |= 1;
    bad.push(rcode);
    let mut compression_loop = good.clone();
    compression_loop[12] = 0xc0;
    compression_loop[13] = 12;
    bad.push(compression_loop);
    for cut in 0..good.len() {
        bad.push(good[..cut].to_vec());
    }
    for p in bad {
        let mut r = started(now);
        r.handle_packet(
            now,
            SocketAddrV4::new(OTHER, 5353),
            MDNS_MULTICAST_IPV4,
            &p,
            JITTER,
        );
        assert!(r.poll_transmit(now + Duration::from_secs(2)).is_none());
        assert_eq!(r.state(), RegistrationState::Active);
    }
}

#[test]
fn a_rdata_length_must_be_exact_even_when_followed_by_more_bytes() {
    let now = Instant::now();
    let mut m = query(0, 1);
    m.answers.push(record(ADDRESS, 120));
    let good = m.pack().unwrap();
    for length in [0u16, 3, 5, 65535] {
        let mut r = started(now);
        let mut p = good.clone();
        let at = p.len() - 6;
        p[at..at + 2].copy_from_slice(&length.to_be_bytes());
        r.handle_packet(
            now,
            SocketAddrV4::new(OTHER, 5353),
            MDNS_MULTICAST_IPV4,
            &p,
            JITTER,
        );
        assert_eq!(r.next_deadline(), None);
        assert!(r.poll_transmit(now + Duration::from_secs(2)).is_none());
    }
}

#[test]
fn duplicate_answer_suppresses_a_queued_multicast_but_not_legacy_reply() {
    let now = Instant::now();
    for port in [5353, 40001] {
        let mut r = started(now);
        receive(&mut r, now, port, &mut query(1, 1));
        let mut m = Message {
            header: Header {
                response: true,
                ..Default::default()
            },
            answers: vec![record(ADDRESS, 120)],
            ..Default::default()
        };
        receive(&mut r, now, 5353, &mut m);
        assert_eq!(
            r.poll_transmit(now + Duration::from_secs(2)).is_some(),
            port != 5353
        );
    }
}

#[test]
fn odd_custom_ttl_uses_ceiling_half_for_known_answers() {
    let now = Instant::now();
    for ttl in [59, 60] {
        let mut r = Responder::new(
            now,
            NAME,
            ADDRESS,
            ResponderConfig {
                ttl_seconds: 119,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            unpack(&r.poll_transmit(now).unwrap()).answers[0].header.ttl,
            119
        );
        r.poll_transmit(now + MULTICAST_INTERVAL).unwrap();
        let mut q = query(0, 1);
        q.answers.push(record(ADDRESS, ttl));
        receive(&mut r, now + Duration::from_secs(2), 5353, &mut q);
        assert_eq!(
            r.poll_transmit(now + Duration::from_secs(2)).is_some(),
            ttl < 60
        );
    }
}

#[test]
fn multiquestion_jitter_is_clamped_to_protocol_range() {
    let now = Instant::now();
    let at = now + Duration::from_secs(2);
    for (jitter, expected) in [(Duration::ZERO, 20), (Duration::from_secs(1), 120)] {
        let mut r = started(now);
        let mut q = query(0, 1);
        q.questions.push(question(DnsType::All, 1));
        r.handle_packet(
            at,
            SocketAddrV4::new(OTHER, 5353),
            MDNS_MULTICAST_IPV4,
            &q.pack().unwrap(),
            jitter,
        );
        assert_eq!(
            r.next_deadline(),
            Some(at + Duration::from_millis(expected))
        );
    }
}
