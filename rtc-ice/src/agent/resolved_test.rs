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
