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
