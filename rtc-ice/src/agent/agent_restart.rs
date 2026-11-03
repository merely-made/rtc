use super::*;

impl Agent {
    // A restart may have installed new credentials before its answer arrives.
    // Respond to consent on the old nominated route without inserting old
    // candidates, checks or role changes into the new ICE generation.
    pub(super) fn handle_retained_binding(
        &mut self,
        now: Instant,
        message: &mut Message,
        local_index: usize,
        remote_addr: SocketAddr,
    ) -> Result<bool> {
        let (Some((local, remote)), Some((credentials, remote_credentials))) =
            (&self.previous_pair, &self.previous_credentials)
        else {
            return Ok(false);
        };
        if message.typ != BINDING_REQUEST
            || !self
                .previous_pair_deadline
                .is_some_and(|deadline| now < deadline)
            || remote_addr != remote.addr()
            || self
                .local_candidates
                .get(local_index)
                .is_none_or(|candidate| {
                    candidate.base_addr() != local.base_addr()
                        || candidate.network_type() != local.network_type()
                })
            || assert_inbound_username(
                message,
                &format!("{}:{}", credentials.ufrag, remote_credentials.ufrag),
            )
            .is_err()
        {
            return Ok(false);
        }
        assert_inbound_message_integrity(
            message,
            credentials.pwd.as_bytes(),
            self.crypto_provider.crypto(),
        )?;
        let mut response = Message::new();
        response.build(&[
            Box::new(message.clone()),
            Box::new(BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: remote_addr.ip(),
                port: remote_addr.port(),
            }),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                credentials.pwd.clone(),
                self.crypto_provider.crypto(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        self.write_outs.push_back(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: local.base_addr(),
                peer_addr: remote_addr,
                ecn: None,
                transport_protocol: local.network_type().to_protocol(),
            },
            message: BytesMut::from(&response.raw[..]),
        });
        Ok(true)
    }
}
