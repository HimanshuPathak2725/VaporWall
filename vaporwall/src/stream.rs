//! Stateful TCP stream reassembly (Phase 4, Step 4.1).
//!
//! Scope: in-order reassembly only. Out-of-order packets are logged and
//! skipped (TODO(security) below) — full reordering/overlap resolution is
//! a deliberately deferred follow-up, not this phase's job.
//!
//! Buffer sizing rationale: the eBPF side only ever hands us up to 128
//! bytes of payload PER PACKET (fixed-length bpf_xdp_load_bytes capture).
//! A reassembly buffer can never legitimately need more than a few
//! packets' worth of snippet data to catch a signature split across a
//! packet boundary — it is NOT reconstructing full session payloads.
//! README's max_payload_buffer_bytes=1MB default assumes full-payload
//! capture we do not have; using it here would let 65536 streams reserve
//! up to 64 GB combined. We cap much lower.

use std::collections::HashMap;
use std::time::Instant;

use log::{debug, warn};

const MAX_TRACKED_STREAMS: usize = 65_536;
const MAX_DIRECTION_BUFFER_BYTES: usize = 8192;
const STREAM_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    ip_lo: u32,
    port_lo: u16,
    ip_hi: u32,
    port_hi: u16,
    protocol: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Reverse,
}

impl ConnectionKey {
    pub fn from_packet(
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        protocol: u8,
    ) -> (Self, Direction) {
        let src_tuple = (src_ip, src_port);
        let dst_tuple = (dst_ip, dst_port);

        if src_tuple <= dst_tuple {
            (
                Self {
                    ip_lo: src_ip,
                    port_lo: src_port,
                    ip_hi: dst_ip,
                    port_hi: dst_port,
                    protocol,
                },
                Direction::Forward,
            )
        } else {
            (
                Self {
                    ip_lo: dst_ip,
                    port_lo: dst_port,
                    ip_hi: src_ip,
                    port_hi: src_port,
                    protocol,
                },
                Direction::Reverse,
            )
        }
    }
}

#[derive(Debug)]
struct DirectionState {
    expected_seq: Option<u32>,
    buffer: Vec<u8>,
}

impl DirectionState {
    fn new() -> Self {
        Self {
            expected_seq: None,
            buffer: Vec::new(),
        }
    }

    fn ingest(&mut self, seq: u32, snippet: &[u8]) -> bool {
        if snippet.is_empty() {
            // Pure control packet (SYN/ACK/FIN with no data) or a packet
            // whose payload capture returned nothing. Carries nothing to
            // reassemble, and critically must NOT be used to bootstrap
            // expected_seq: a SYN's sequence number is one less than the
            // first real data byte (SYN consumes one sequence number per
            // RFC 793), so bootstrapping off it misaligns expected_seq by
            // exactly the SYN's cost, silently marking every subsequent
            // real data packet as "out of order" and dropping the entire
            // payload. Bug found via live loopback test (multi-segment
            // EVIL_PAYLOAD split across two sends) — the SYN/ACK before
            // the data was bootstrapping expected_seq one byte early.
            return false;
        }

        let Some(expected) = self.expected_seq else {
            self.expected_seq = Some(seq.wrapping_add(snippet.len() as u32));
            self.buffer.extend_from_slice(snippet);
            self.trim();
            return true;
        };

        // Wrapping-aware comparison via signed delta — required because
        // seq wraps at u32::MAX and a naive `seq > expected` breaks the
        // moment a long-lived connection crosses that boundary.
        let delta = (seq.wrapping_sub(expected)) as i32;

        if delta == 0 {
            // TODO(security): out-of-order/overlap evasion is NOT handled.
            // An attacker can deliberately reorder/overlap segments to
            // straddle a signature across this naive in-order boundary.
            // Known, accepted MVP gap — not fixed here.
            self.expected_seq = Some(expected.wrapping_add(snippet.len() as u32));
            self.buffer.extend_from_slice(snippet);
            self.trim();
            true
        } else if delta < 0 {
            false // duplicate/retransmit — routine, no log spam
        } else {
            debug!(
                "out-of-order segment skipped: seq={} expected={} (delta={})",
                seq, expected, delta
            );
            false
        }
    }

    fn trim(&mut self) {
        if self.buffer.len() > MAX_DIRECTION_BUFFER_BYTES {
            let excess = self.buffer.len() - MAX_DIRECTION_BUFFER_BYTES;
            self.buffer.drain(0..excess);
        }
    }
}

struct ConnectionState {
    forward: DirectionState,
    reverse: DirectionState,
    last_activity: Instant,
}

impl ConnectionState {
    fn new() -> Self {
        Self {
            forward: DirectionState::new(),
            reverse: DirectionState::new(),
            last_activity: Instant::now(),
        }
    }
}

/// Bundles one packet's identifying/reassembly-relevant fields into a
/// single argument. Replaces a previous 8-parameter `ingest()` signature
/// that clippy correctly flagged (`too_many_arguments`) — grouping these
/// also means a future field (e.g. TCP flags for SYN/FIN-aware state
/// transitions) is a one-place change, not a signature change at every
/// call site.
pub struct PacketMeta<'a> {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub seq: u32,
    pub snippet: &'a [u8],
}

/// Single-owner, single-task — no locking. If the consumer ever moves to
/// multiple worker tasks, this needs Arc<Mutex<StreamTable>> (or sharding)
/// at that point, not before.
pub struct StreamTable {
    connections: HashMap<ConnectionKey, ConnectionState>,
}

pub enum IngestResult<'a> {
    Scan(&'a [u8]),
    Skipped,
    TableFull,
}

impl StreamTable {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    pub fn ingest<'a>(&'a mut self, pkt: PacketMeta<'_>) -> IngestResult<'a> {
        let (key, direction) = ConnectionKey::from_packet(
            pkt.src_ip,
            pkt.src_port,
            pkt.dst_ip,
            pkt.dst_port,
            pkt.protocol,
        );

        if !self.connections.contains_key(&key) {
            if self.connections.len() >= MAX_TRACKED_STREAMS {
                warn!(
                    "stream table at capacity ({} entries) — refusing new connection",
                    MAX_TRACKED_STREAMS
                );
                return IngestResult::TableFull;
            }
            self.connections.insert(key, ConnectionState::new());
        }

        let conn = self
            .connections
            .get_mut(&key)
            .expect("just inserted or existed");
        conn.last_activity = Instant::now();

        let dir_state = match direction {
            Direction::Forward => &mut conn.forward,
            Direction::Reverse => &mut conn.reverse,
        };

        if dir_state.ingest(pkt.seq, pkt.snippet) {
            IngestResult::Scan(&dir_state.buffer)
        } else {
            IngestResult::Skipped
        }
    }

    /// Call periodically from the SAME task that owns the table (a
    /// tokio::time::interval branch in the existing select!, not a
    /// separately spawned task) — keeps this lock-free.
    pub fn sweep_expired(&mut self) {
        let timeout = std::time::Duration::from_secs(STREAM_TIMEOUT_SECS);
        let before = self.connections.len();
        self.connections
            .retain(|_, conn| conn.last_activity.elapsed() < timeout);
        let evicted = before - self.connections.len();
        if evicted > 0 {
            debug!("stream sweep evicted {} idle connection(s)", evicted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the SYN-bootstrap off-by-one bug: a zero-payload
    /// packet (SYN/ACK) must never set expected_seq, or the very next real
    /// data packet gets misclassified as out-of-order and silently dropped.
    #[test]
    fn empty_snippet_does_not_bootstrap_expected_seq() {
        let mut dir = DirectionState::new();

        // SYN: seq=100, no payload.
        assert!(!dir.ingest(100, &[]));
        assert_eq!(dir.expected_seq, None);

        // Pure ACK: seq=101, no payload.
        assert!(!dir.ingest(101, &[]));
        assert_eq!(dir.expected_seq, None);

        // First real data: seq=101 (SYN consumed seq 100), payload "hi".
        assert!(dir.ingest(101, b"hi"));
        assert_eq!(dir.expected_seq, Some(103));
        assert_eq!(dir.buffer, b"hi");
    }

    #[test]
    fn split_payload_reassembles_across_two_packets() {
        let mut dir = DirectionState::new();
        assert!(dir.ingest(1000, b"EVIL_PA"));
        assert!(dir.ingest(1007, b"YLOAD"));
        assert_eq!(dir.buffer, b"EVIL_PAYLOAD");
    }

    #[test]
    fn out_of_order_packet_is_skipped_not_buffered() {
        let mut dir = DirectionState::new();
        assert!(dir.ingest(1000, b"AAAA"));
        // Future packet (gap) — MVP scope: log and skip.
        assert!(!dir.ingest(1010, b"BBBB"));
        assert_eq!(dir.buffer, b"AAAA");
    }

    #[test]
    fn duplicate_retransmit_is_skipped() {
        let mut dir = DirectionState::new();
        assert!(dir.ingest(1000, b"AAAA"));
        assert!(!dir.ingest(1000, b"AAAA"));
        assert_eq!(dir.buffer, b"AAAA");
    }
}
