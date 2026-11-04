use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;

fn host(address: &str, port: u16) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".into(),
            address: address.into(),
            port,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap()
}

#[test]
fn host_resolution_preserves_names_and_excludes_relay_pairs_in_both_orders() {
    for remote_first in [false, true] {
        let mut agent = Agent::new(
            Instant::now(),
            Arc::new(AgentConfig {
                multicast_dns_mode: MulticastDnsMode::Disabled,
                ..Default::default()
            }),
            crypto::default_provider().unwrap(),
        )
        .unwrap();
        let remote = host("12345678-1234-4234-8234-123456789abc.local", 50000);
        let id = remote.id().to_owned();
        let ip: IpAddr = "192.0.2.20".parse().unwrap();
        if remote_first {
            agent
                .add_resolved_remote_candidate(remote.clone(), ip)
                .unwrap();
        }
        agent.add_local_candidate(host("127.0.0.1", 40000)).unwrap();
        agent
            .add_local_candidate(
                CandidateRelayConfig {
                    base_config: CandidateConfig {
                        network: "udp".into(),
                        address: "203.0.113.1".into(),
                        port: 40001,
                        component: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                }
                .new_candidate_relay()
                .unwrap(),
            )
            .unwrap();
        if !remote_first {
            agent.add_resolved_remote_candidate(remote, ip).unwrap();
        }
        assert_eq!(agent.remote_candidates.len(), 1);
        assert_eq!(agent.remote_candidates[0].id(), id);
        assert!(agent.remote_candidates[0].address().ends_with(".local"));
        assert_eq!(
            agent.remote_candidates[0].addr(),
            SocketAddr::new(ip, 50000)
        );
        assert_eq!(agent.candidate_pairs.len(), 1, "only local host may pair");
        agent.add_pair(1, 0);
        assert_eq!(
            agent.candidate_pairs.len(),
            1,
            "triggered path cannot bypass the pairing rule"
        );
        let message = Message::new();
        agent.send_binding_success(Instant::now(), &message, 1, 0);
        agent.send_binding_request(Instant::now(), &message, 1, 0);
        assert!(
            agent.write_outs.is_empty(),
            "neither checks nor replies disclose an mDNS endpoint through TURN"
        );
        assert!(agent.mdns_queries.is_empty());
        assert!(agent.mdns.is_none());
    }
}

#[test]
fn resolved_insertion_is_not_a_generic_numeric_candidate_bypass() {
    let mut agent = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        crypto::default_provider().unwrap(),
    )
    .unwrap();
    assert!(
        agent
            .add_resolved_remote_candidate(host("127.0.0.1", 50000), "127.0.0.2".parse().unwrap())
            .is_err()
    );
    for ip in ["0.0.0.0", "224.0.0.251"] {
        assert!(
            agent
                .add_resolved_remote_candidate(host("test.local", 50000), ip.parse().unwrap())
                .is_err()
        );
    }
    assert!(agent.remote_candidates.is_empty());
}

#[test]
fn restart_rechecks_the_resolved_endpoint_without_reinterpreting_its_name() {
    let now = Instant::now();
    let mut agent = Agent::new(
        now,
        Arc::new(AgentConfig {
            multicast_dns_mode: MulticastDnsMode::Disabled,
            is_controlling: true,
            ..Default::default()
        }),
        crypto::default_provider().unwrap(),
    )
    .unwrap();
    agent.add_local_candidate(host("127.0.0.1", 40000)).unwrap();
    let remote = host("12345678-1234-4234-8234-123456789abc.local", 50000);
    let id = remote.id().to_owned();
    let ip: IpAddr = "192.0.2.20".parse().unwrap();
    agent.add_resolved_remote_candidate(remote, ip).unwrap();
    agent
        .set_remote_credentials("oldRemote".into(), "oldRemotePassword".into())
        .unwrap();
    agent.candidate_pairs[0].state = CandidatePairState::Succeeded;
    agent.set_selected_pair(Some(now), Some(0));
    agent
        .generate_restart_credentials(String::new(), String::new())
        .unwrap();
    agent.apply_restart(now, true).unwrap();
    assert!(agent.remote_candidates.is_empty());
    agent
        .set_remote_credentials("newRemote".into(), "newRemotePassword".into())
        .unwrap();
    assert_eq!(agent.remote_candidates.len(), 1);
    assert_eq!(agent.remote_candidates[0].id(), id);
    assert!(agent.remote_candidates[0].address().ends_with(".local"));
    assert_eq!(
        agent.remote_candidates[0].addr(),
        SocketAddr::new(ip, 50000)
    );
    assert_eq!(agent.candidate_pairs.len(), 1);
    assert_ne!(
        agent.candidate_pairs[0].state,
        CandidatePairState::Succeeded
    );
    assert!(!agent.candidate_pairs[0].nominated);
    assert!(agent.get_selected_pair().is_none());
    assert!(agent.mdns_queries.is_empty());
    agent
        .handle_timeout(now + Duration::from_millis(1))
        .unwrap();
    assert_eq!(
        agent.poll_write().unwrap().transport.peer_addr,
        SocketAddr::new(ip, 50000)
    );
}

#[test]
fn fresh_nomination_keeps_only_bounded_old_consent_until_mutual_credentials() {
    for acknowledge in [false, true] {
        let now = Instant::now();
        let provider = crypto::default_provider().unwrap();
        let mut agent =
            Agent::new(now, Arc::new(AgentConfig::default()), provider.clone()).unwrap();
        agent.add_local_candidate(host("127.0.0.1", 40000)).unwrap();
        agent
            .add_remote_candidate(host("127.0.0.1", 50000))
            .unwrap();
        agent
            .set_remote_credentials("oldRemote".into(), "oldRemotePassword".into())
            .unwrap();
        agent.candidate_pairs[0].state = CandidatePairState::Succeeded;
        agent.set_selected_pair(Some(now), Some(0));
        let old = agent.ufrag_pwd.local_credentials.clone();
        agent
            .generate_restart_credentials(String::new(), String::new())
            .unwrap();
        agent.apply_restart(now, true).unwrap();
        let deadline = agent.previous_pair_deadline.unwrap();
        agent
            .set_remote_credentials("newRemote".into(), "newRemotePassword".into())
            .unwrap();
        agent
            .add_remote_candidate(host("127.0.0.1", 50001))
            .unwrap();
        agent.candidate_pairs[1].state = CandidatePairState::Succeeded;
        agent.set_selected_pair(Some(now), Some(1));
        assert!(
            agent.previous_pair.is_none(),
            "the old data path is retired"
        );
        assert_eq!(
            agent.get_selected_candidate_pair().unwrap().1.addr().port(),
            50001
        );
        assert_eq!(agent.retired_consent.as_ref().unwrap().deadline, deadline);
        let request = |username: String, password: &str| {
            let mut message = Message::new();
            message
                .build(&[
                    Box::new(BINDING_REQUEST),
                    Box::new(TransactionId::new()),
                    Box::new(Username::new(ATTR_USERNAME, username)),
                    Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                        password.to_owned(),
                        provider.crypto(),
                    )),
                    Box::new(FINGERPRINT),
                ])
                .unwrap();
            message
        };
        let old_route = "127.0.0.1:50000".parse().unwrap();
        let old_username = format!("{}:oldRemote", old.ufrag);
        agent
            .handle_inbound(
                now,
                &mut request(old_username.clone(), &old.pwd),
                0,
                old_route,
            )
            .unwrap();
        assert_eq!(agent.poll_write().unwrap().transport.peer_addr, old_route);
        assert_eq!(agent.candidate_pairs.len(), 2);
        assert_eq!(
            agent.get_selected_candidate_pair().unwrap().1.addr().port(),
            50001
        );
        if acknowledge {
            let username = format!("{}:newRemote", agent.ufrag_pwd.local_credentials.ufrag);
            let password = agent.ufrag_pwd.local_credentials.pwd.clone();
            let fresh_route = "127.0.0.1:50001".parse().unwrap();
            assert!(
                agent
                    .handle_inbound(
                        now,
                        &mut request(username.clone(), "wrongPassword"),
                        0,
                        fresh_route
                    )
                    .is_err()
            );
            assert!(agent.retired_consent.is_some());
            agent
                .handle_inbound(now, &mut request(username, &password), 0, fresh_route)
                .unwrap();
            assert!(agent.retired_consent.is_none());
            while agent.poll_write().is_some() {}
            assert!(
                agent
                    .handle_inbound(now, &mut request(old_username, &old.pwd), 0, old_route)
                    .is_err()
            );
        } else {
            assert!(
                agent
                    .handle_inbound(deadline, &mut request(old_username, &old.pwd), 0, old_route)
                    .is_err()
            );
            agent.handle_timeout(deadline).unwrap();
            assert!(agent.retired_consent.is_none());
        }
    }
}

#[test]
fn restart_nomination_waits_for_full_peer_credentials_but_not_lite_peer_checks() {
    for lite in [false, true] {
        let now = Instant::now();
        let provider = crypto::default_provider().unwrap();
        let mut agent =
            Agent::new(now, Arc::new(AgentConfig::default()), provider.clone()).unwrap();
        agent.add_local_candidate(host("127.0.0.1", 40000)).unwrap();
        agent
            .add_remote_candidate(host("127.0.0.1", 50000))
            .unwrap();
        agent
            .set_remote_credentials("oldRemote".into(), "oldRemotePassword".into())
            .unwrap();
        agent.candidate_pairs[0].state = CandidatePairState::Succeeded;
        agent.set_selected_pair(Some(now), Some(0));
        agent
            .generate_restart_credentials(String::new(), String::new())
            .unwrap();
        agent.apply_restart(now, true).unwrap();
        agent.set_role(true);
        agent.set_remote_lite(lite);
        agent
            .set_remote_credentials("newRemote".into(), "newRemotePassword".into())
            .unwrap();
        agent
            .add_remote_candidate(host("127.0.0.1", 50001))
            .unwrap();
        agent.candidate_pairs[1].state = CandidatePairState::Succeeded;
        let check = now + Duration::from_secs(1);
        agent.contact_candidates(check);
        let mut nominations = 0;
        while let Some(packet) = agent.poll_write() {
            let mut message = Message::new();
            message.raw = packet.message.to_vec();
            message.decode().unwrap();
            nominations += usize::from(message.contains(ATTR_USE_CANDIDATE));
        }
        assert_eq!(nominations > 0, lite);
        assert_eq!(
            agent.get_selected_candidate_pair().unwrap().1.addr().port(),
            50000
        );
        if !lite {
            let password = agent.ufrag_pwd.local_credentials.pwd.clone();
            let username = format!("{}:newRemote", agent.ufrag_pwd.local_credentials.ufrag);
            let request = |password: String| {
                let mut message = Message::new();
                message
                    .build(&[
                        Box::new(BINDING_REQUEST),
                        Box::new(TransactionId::new()),
                        Box::new(Username::new(ATTR_USERNAME, username.clone())),
                        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                            password,
                            provider.crypto(),
                        )),
                        Box::new(FINGERPRINT),
                    ])
                    .unwrap();
                message
            };
            let fresh_route = "127.0.0.1:50001".parse().unwrap();
            assert!(
                agent
                    .handle_inbound(check, &mut request("wrongPassword".into()), 0, fresh_route)
                    .is_err()
            );
            agent.contact_candidates(check);
            assert!(agent.nominated_pair.is_none());
            while agent.poll_write().is_some() {}
            agent
                .handle_inbound(check, &mut request(password), 0, fresh_route)
                .unwrap();
            agent.contact_candidates(check);
            assert_eq!(agent.nominated_pair, Some(1));
            assert_eq!(agent.candidate_pairs[1].requests_received, 1);
        }
    }
}
