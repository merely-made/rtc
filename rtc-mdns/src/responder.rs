//! Bounded, caller-driven IPv4 registration for UUID WebRTC candidate names.
//!
//! This is the unique-name profile of the work-in-progress
//! [mDNS ICE candidate draft](https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates-03#section-3.1.1), not a
//! general DNS-SD registry. The caller generates an unpredictable UUID-v4 name,
//! validates incoming interface/destination and on-link sources, and sends every
//! returned packet from UDP port 5353 on that interface (IP TTL 255). No socket
//! or background task is created here. Truncated multipacket queries are ignored.

mod decode;
#[cfg(test)]
mod tests;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use crate::message::header::Header;
use crate::message::name::Name;
use crate::message::question::Question;
use crate::message::resource::a::AResource;
use crate::message::resource::{Resource, ResourceHeader};
use crate::message::{DnsClass, DnsType, Message};
use crate::{MDNS_MULTICAST_IPV4, MDNS_PORT};

const MULTICAST_INTERVAL: Duration = Duration::from_secs(1);
const PROBE_INTERVAL: Duration = Duration::from_millis(250);
const CLASS_FLAG: u16 = 0x8000;

/// Configurable per-registration resource limits.
#[derive(Debug, Clone, Copy)]
pub struct ResponderConfig {
    /// Authoritative lifetime, in seconds, from 1 through 120 (default 120).
    pub ttl_seconds: u32,
    /// Maximum accepted input size, from 512 through 9000 (default 1500).
    pub max_packet_bytes: usize,
    /// Maximum questions per packet, from 1 through 16 (default 4).
    pub max_questions: usize,
    /// Maximum total resource records, from 1 through 64 (default 16).
    pub max_records: usize,
    /// Minimum interval between unicast replies, 10 ms through 1 s (default 100 ms).
    pub unicast_interval: Duration,
    /// Prefer multicast for QU questions when port 5353 is shared with other
    /// local responders. QU accepts multicast too; legacy replies stay unicast.
    /// Defaults to false. Multicast pacing still applies.
    pub multicast_qu: bool,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: 120,
            max_packet_bytes: 1500,
            max_questions: 4,
            max_records: 16,
            unicast_interval: Duration::from_millis(100),
            multicast_qu: false,
        }
    }
}

/// A rejected registration. Contains no address or hostname diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationError {
    /// The name is not exactly a UUID-v4 followed by `.local` (optional final dot).
    InvalidName,
    /// The address is unspecified, multicast, or limited broadcast.
    InvalidAddress,
    /// A configured limit is outside its supported range.
    InvalidConfig,
}

impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mDNS registration: {self:?}")
    }
}
impl std::error::Error for RegistrationError {}

/// Registration lifecycle, inspected without an unbounded event queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    /// Announcing and answering queries.
    Active,
    /// A different live A record claimed the same name. Generate a new name;
    /// never fall back to exposing the numeric address.
    Conflict,
    /// Closed; at most one previously scheduled goodbye remains.
    Closed,
}

/// A single bounded datagram to send from the registered interface's port 5353.
pub struct ResponderTransmit {
    /// Multicast or explicitly requested unicast destination.
    pub destination: SocketAddrV4,
    /// Encoded DNS response. May contain the private interface address.
    pub payload: Vec<u8>,
}

struct Reply {
    destination: SocketAddrV4,
    id: u16,
    questions: Vec<Question>,
    due: Instant,
    defensive: bool,
}

/// One UUID-to-IPv4 registration, with two startup announcements and one pending
/// reply slot. Dropping it cancels all work. Call [`Self::close`] and drain its
/// goodbye before releasing the host socket when graceful withdrawal is possible.
/// A handed-out datagram is owned by the caller and cannot be recalled on close.
pub struct Responder {
    config: ResponderConfig,
    name: Name,
    address: Ipv4Addr,
    state: RegistrationState,
    announcements: u8,
    announce_at: Instant,
    last_multicast: Option<Instant>,
    last_unicast: Option<Instant>,
    pending: Option<Reply>,
    goodbye: bool,
}

impl Responder {
    /// Register a caller-generated UUID-v4 name without probing, following the
    /// ICE candidate draft. The first announcement is ready immediately.
    pub fn new(
        now: Instant,
        name: &str,
        address: Ipv4Addr,
        config: ResponderConfig,
    ) -> Result<Self, RegistrationError> {
        let bare = name.strip_suffix('.').unwrap_or(name);
        if !valid_name(bare) {
            return Err(RegistrationError::InvalidName);
        }
        if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
            return Err(RegistrationError::InvalidAddress);
        }
        if !(1..=120).contains(&config.ttl_seconds)
            || !(512..=9000).contains(&config.max_packet_bytes)
            || !(1..=16).contains(&config.max_questions)
            || !(1..=64).contains(&config.max_records)
            || !(Duration::from_millis(10)..=MULTICAST_INTERVAL).contains(&config.unicast_interval)
        {
            return Err(RegistrationError::InvalidConfig);
        }
        Ok(Self {
            config,
            name: Name::new(&format!("{}.", bare.to_ascii_lowercase()))
                .map_err(|_| RegistrationError::InvalidName)?,
            address,
            state: RegistrationState::Active,
            announcements: 2,
            announce_at: now,
            last_multicast: None,
            last_unicast: None,
            pending: None,
            goodbye: false,
        })
    }

    /// Inspect the lifecycle; conflict and close are terminal.
    pub fn state(&self) -> RegistrationState {
        self.state
    }

    /// Process one already interface/source-validated packet. `destination` is
    /// the actual IP destination obtained from packet metadata, not the bind
    /// address. The host must reject off-link unicast sources before this call.
    /// For multiquestion replies supply fresh uniform jitter in 20..=120 ms;
    /// out-of-range jitter is clamped. Ordinary unique single-question replies
    /// do not wait for jitter. Malformed/oversized packets have no effect.
    pub fn handle_packet(
        &mut self,
        now: Instant,
        source: SocketAddrV4,
        destination: Ipv4Addr,
        packet: &[u8],
        jitter: Duration,
    ) {
        if self.state != RegistrationState::Active
            || source.port() == 0
            || source.ip().is_unspecified()
            || source.ip().is_multicast()
            || source.ip().is_broadcast()
            || (destination != MDNS_MULTICAST_IPV4 && destination != self.address)
        {
            return;
        }
        let Some(message) = decode::parse(packet, self.config) else {
            return;
        };
        if message.header.response {
            if source.port() != MDNS_PORT {
                return;
            }
            if message
                .records
                .iter()
                .any(|r| self.matches(&r.name) && r.address != self.address && r.ttl != 0)
            {
                self.state = RegistrationState::Conflict;
                self.pending = None;
                self.announcements = 0;
            } else if message.records.iter().any(|r| {
                self.matches(&r.name)
                    && r.address == self.address
                    && r.ttl < self.config.ttl_seconds.div_ceil(2)
            }) {
                // Correct premature expiration, including another host's goodbye.
                self.queue(now, multicast(), 0, Vec::new(), false);
            } else if message.records.iter().any(|r| {
                self.matches(&r.name)
                    && r.address == self.address
                    && r.ttl >= self.config.ttl_seconds.div_ceil(2)
            }) && self
                .pending
                .as_ref()
                .is_some_and(|p| p.destination == multicast())
            {
                // A cooperating responder already supplied the same answer.
                self.pending = None;
            }
            return;
        }
        let matches = |q: &&Question| {
            self.matches(&q.name)
                && matches!(q.typ, DnsType::A | DnsType::All)
                && matches!(q.class.0 & !CLASS_FLAG, 1 | 255)
        };
        let matching: Vec<_> = message.questions.iter().filter(matches).collect();
        if matching.is_empty() {
            return;
        }
        let legacy = source.port() != MDNS_PORT;
        if !legacy
            && message.records.iter().any(|r| {
                r.answer
                    && self.matches(&r.name)
                    && r.address == self.address
                    && r.ttl >= self.config.ttl_seconds.div_ceil(2)
            })
        {
            return;
        }
        let probe = !legacy
            && message
                .records
                .iter()
                .any(|r| r.authority && self.matches(&r.name));
        let qu = matching.iter().all(|q| q.class.0 & CLASS_FLAG != 0)
            || destination != MDNS_MULTICAST_IPV4;
        let recent = self.last_multicast.is_some_and(|last| {
            now.saturating_duration_since(last)
                < Duration::from_secs(self.config.ttl_seconds.into()) / 4
        });
        let target = if legacy || (!self.config.multicast_qu && qu && (probe || recent)) {
            source
        } else {
            multicast()
        };
        let delay = if message.questions.len() > 1 && !probe && !legacy {
            jitter.clamp(Duration::from_millis(20), Duration::from_millis(120))
        } else {
            Duration::ZERO
        };
        self.queue(
            now + delay,
            target,
            if legacy { message.header.id } else { 0 },
            if legacy {
                message.questions
            } else {
                Vec::new()
            },
            probe,
        );
    }

    /// Cancel pending positive responses and schedule one TTL-zero goodbye if
    /// a positive record has been handed to the caller. Repeated close is inert;
    /// conflict withdrawal sends no goodbye that could erase the competing owner.
    pub fn close(&mut self) {
        if self.state == RegistrationState::Closed {
            return;
        }
        self.goodbye = self.state == RegistrationState::Active
            && (self.last_multicast.is_some() || self.last_unicast.is_some());
        self.state = RegistrationState::Closed;
        self.announcements = 0;
        self.pending = None;
    }

    /// Earliest deadline. A pending goodbye is immediately ready; call
    /// `poll_transmit` directly after close. No timer is retained once inactive.
    pub fn next_deadline(&self) -> Option<Instant> {
        let announce =
            (self.announcements > 0).then(|| self.multicast_due(self.announce_at, false));
        let reply = self.pending.as_ref().map(|p| self.reply_due(p));
        announce.into_iter().chain(reply).min()
    }

    /// Return at most one datagram, advancing time only from the caller's clock.
    /// Polling late does not replay missed announcements in a burst. Hosts must
    /// send promptly or discard the result, rather than retaining another queue.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<ResponderTransmit> {
        if std::mem::take(&mut self.goodbye) {
            return self.encode(multicast(), 0, Vec::new(), 0);
        }
        if self.state != RegistrationState::Active {
            return None;
        }
        if self.announcements > 0 && self.multicast_due(self.announce_at, false) <= now {
            self.announcements -= 1;
            self.announce_at = now + MULTICAST_INTERVAL;
            self.last_multicast = Some(now);
            if self
                .pending
                .as_ref()
                .is_some_and(|p| p.destination == multicast())
            {
                self.pending = None;
            }
            return self.encode(multicast(), 0, Vec::new(), self.config.ttl_seconds);
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|p| self.reply_due(p) <= now)
        {
            let reply = self.pending.take()?;
            if reply.destination == multicast() {
                self.last_multicast = Some(now);
            } else {
                self.last_unicast = Some(now);
            }
            return self.encode(
                reply.destination,
                reply.id,
                reply.questions,
                self.config.ttl_seconds,
            );
        }
        None
    }

    fn matches(&self, name: &Name) -> bool {
        self.name.data.eq_ignore_ascii_case(&name.data)
    }

    fn queue(
        &mut self,
        due: Instant,
        destination: SocketAddrV4,
        id: u16,
        questions: Vec<Question>,
        defensive: bool,
    ) {
        // One slot for all requesters. Retransmission handles saturation. A
        // defensive multicast may replace a queued ordinary reply.
        if self.pending.is_none()
            || (defensive && !self.pending.as_ref().is_some_and(|p| p.defensive))
        {
            self.pending = Some(Reply {
                destination,
                id,
                questions,
                due,
                defensive,
            });
        }
    }

    fn multicast_due(&self, due: Instant, defensive: bool) -> Instant {
        self.last_multicast.map_or(due, |last| {
            due.max(
                last + if defensive {
                    PROBE_INTERVAL
                } else {
                    MULTICAST_INTERVAL
                },
            )
        })
    }

    fn reply_due(&self, reply: &Reply) -> Instant {
        if reply.destination == multicast() {
            self.multicast_due(reply.due, reply.defensive)
        } else {
            self.last_unicast.map_or(reply.due, |last| {
                reply.due.max(last + self.config.unicast_interval)
            })
        }
    }

    fn encode(
        &self,
        destination: SocketAddrV4,
        id: u16,
        questions: Vec<Question>,
        ttl: u32,
    ) -> Option<ResponderTransmit> {
        let legacy = destination.port() != MDNS_PORT;
        let mut message = Message {
            header: Header {
                id,
                response: true,
                authoritative: true,
                ..Default::default()
            },
            questions,
            answers: vec![Resource {
                header: ResourceHeader {
                    name: self.name.clone(),
                    typ: DnsType::A,
                    class: DnsClass(1 | if legacy { 0 } else { CLASS_FLAG }),
                    ttl: if legacy { ttl.min(10) } else { ttl },
                    ..Default::default()
                },
                body: Some(Box::new(AResource {
                    a: self.address.octets(),
                })),
            }],
            ..Default::default()
        };
        Some(ResponderTransmit {
            destination,
            payload: message.pack().ok()?,
        })
    }
}

fn multicast() -> SocketAddrV4 {
    SocketAddrV4::new(MDNS_MULTICAST_IPV4, MDNS_PORT)
}

fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 42
        && b[36..].eq_ignore_ascii_case(b".local")
        && b[..36].iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
        && b[14] == b'4'
        && matches!(b[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b')
}
