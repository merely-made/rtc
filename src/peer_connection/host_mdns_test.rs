use super::*;
use crate::peer_connection::transport::RTCIceCandidate;
use crate::statistics::{StatsSelector, report::RTCStatsReportEntry};

#[test]
fn host_resolved_mdns_preserves_identity_and_registers_only_the_resolved_insertion() {
    let now = Instant::now();
    let settings = || {
        crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::new()
            .with_multicast_dns_mode(ice::mdns::MulticastDnsMode::Disabled)
            .build()
    };
    let mut sender = RTCPeerConnectionBuilder::new()
        .with_setting_engine(settings())
        .build(now)
        .unwrap();
    sender.create_data_channel("mdns", None).unwrap();
    let offer = sender.create_offer(None).unwrap();
    let mut receiver = RTCPeerConnectionBuilder::new()
        .with_setting_engine(settings())
        .build(now)
        .unwrap();
    let raw =
        "candidate:mdns 1 udp 123456 12345678-1234-4234-8234-123456789abc.local 50000 typ host";
    let candidate = RTCIceCandidate::from(
        &unmarshal_candidate(raw.strip_prefix("candidate:").unwrap()).unwrap(),
    );
    let id = candidate.id.clone();
    assert!(
        receiver
            .add_resolved_remote_candidate(candidate.clone(), "127.0.0.1".parse().unwrap())
            .is_err()
    );
    receiver.set_remote_description(now, offer).unwrap();
    receiver
        .add_remote_candidate(RTCIceCandidateInit {
            candidate: raw.into(),
            ..Default::default()
        })
        .unwrap();
    assert!(
        !receiver
            .get_stats(now, StatsSelector::None)
            .iter()
            .any(|r| matches!(r, RTCStatsReportEntry::RemoteCandidate(_)))
    );
    receiver
        .add_resolved_remote_candidate(candidate, "127.0.0.1".parse().unwrap())
        .unwrap();
    let remote = receiver.ice_transport().get_remote_candidates();
    assert_eq!(remote.len(), 1);
    assert_eq!(remote[0].id, id);
    assert!(remote[0].address.ends_with(".local"));
    assert_eq!(
        receiver
            .get_stats(now, StatsSelector::None)
            .iter()
            .filter(|r| matches!(r, RTCStatsReportEntry::RemoteCandidate(_)))
            .count(),
        1
    );
}
