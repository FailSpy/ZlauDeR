//! Monitor state: ring buffer, broadcast channel, approval waiters, and the
//! conversation/turn index. Holds all state-mutating methods.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{broadcast, oneshot};
use zlauder_engine::UnmaskManifest;

use super::delta::{compute_delta, compute_delta_from_hashes};
use super::model::{
    ApprovalDecision, ConversationMeta, MonitorEvent, MonitorMode, MonitorSnapshot,
    RequestDecision, RequestRecord, Surface, TurnDelta,
};
use super::spans::{now_ms, preview, spans_from_manifest, spans_from_values, token_previews};
use super::surfaces::{surfaces_from_body, surfaces_from_response_body};

const MAX_RECORDS: usize = 500;
const APPROVAL_TIMEOUT_SECS: u64 = 300;
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(APPROVAL_TIMEOUT_SECS);
const DEFAULT_MAX_PENDING_APPROVALS: usize = 32;
/// Cap on the per-conversation cache of last-turn surface hashes. Keeps deltas
/// computable even after the prior turn's record is evicted from the global ring.
const MAX_TRACKED_CONVERSATIONS: usize = 1024;

/// Domain-level failure of a state mutation keyed by request id. The web layer
/// maps this to an HTTP status; the state layer stays framework-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecideError {
    /// No such request id (absent, or — for `decide` — not pending).
    Unknown,
}

/// Shared, cheaply-cloneable handle to the monitor.
#[derive(Clone)]
pub struct Monitor {
    inner: Arc<Mutex<Inner>>,
    events: broadcast::Sender<MonitorEvent>,
}

struct Inner {
    mode: MonitorMode,
    max_pending_approvals: usize,
    next_seq: u64,
    /// Newest-first ring buffer of records.
    records: VecDeque<RequestRecord>,
    waiters: HashMap<String, oneshot::Sender<ApprovalDecision>>,
    /// Per-conversation turn counter (monotonic, 1-based).
    turn_counts: HashMap<String, u32>,
    /// Per-conversation cache of the most recent turn's `(turn_index, surface
    /// block_hashes)`. Lets the delta survive eviction of the prior turn's full
    /// record from the global ring, so a resent transcript is not mis-flagged as
    /// "first contact / all new". Bounded by [`MAX_TRACKED_CONVERSATIONS`].
    last_turn_hashes: HashMap<String, (u32, Vec<String>)>,
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Monitor {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                mode: MonitorMode::Off,
                max_pending_approvals: DEFAULT_MAX_PENDING_APPROVALS,
                next_seq: 1,
                records: VecDeque::new(),
                waiters: HashMap::new(),
                turn_counts: HashMap::new(),
                last_turn_hashes: HashMap::new(),
            })),
            events,
        }
    }

    pub fn snapshot(&self) -> MonitorSnapshot {
        let inner = self.inner.lock().expect("monitor mutex poisoned");
        MonitorSnapshot {
            mode: inner.mode,
            pending_count: inner.waiters.len(),
            max_pending_approvals: inner.max_pending_approvals,
            records: inner.records.iter().cloned().collect(),
            conversations: conversations_from_records(&inner.records),
            approval_timeout_secs: APPROVAL_TIMEOUT_SECS,
        }
    }

    pub fn set_mode(
        &self,
        mode: MonitorMode,
        max_pending_approvals: Option<usize>,
    ) -> MonitorSnapshot {
        {
            let mut inner = self.inner.lock().expect("monitor mutex poisoned");
            inner.mode = mode;
            if let Some(max) = max_pending_approvals {
                inner.max_pending_approvals = max;
            }
        }
        let snap = self.snapshot();
        self.emit(MonitorEvent::Snapshot(Box::new(snap.clone())));
        snap
    }

    pub fn record_llm_request(
        &self,
        endpoint: &'static str,
        method: &str,
        conversation_id: Option<String>,
        masked_body: &[u8],
        manifest: &UnmaskManifest,
    ) -> ReviewTicket {
        // Compute everything that does NOT depend on shared state BEFORE taking the
        // lock. The masked body can be 100KB+ and `surfaces_from_body` parses it as
        // JSON and blake3-hashes every surface; doing that under the global mutex
        // would serialize the realtime hot path (every request blocks on every
        // other request's parse). Only the seq/turn/delta bookkeeping needs `inner`.
        let now = now_ms();
        let request_preview = preview(masked_body);
        let tokens = token_previews(manifest);
        let request_spans = spans_from_manifest(manifest, &request_preview);
        let request_surfaces = surfaces_from_body(masked_body, &tokens);
        let this_turn_hashes: Vec<String> = request_surfaces
            .iter()
            .map(|s| s.block_hash.clone())
            .collect();
        let conversation_id = conversation_id.unwrap_or_else(|| "unknown".to_string());

        let mut inner = self.inner.lock().expect("monitor mutex poisoned");
        let id = format!("req-{}", inner.next_seq);
        inner.next_seq += 1;
        let should_hold = match inner.mode {
            MonitorMode::Off => false,
            MonitorMode::ManualAllLlm => true,
            MonitorMode::ManualOnDetection => !manifest.is_empty(),
        };

        // Assign this request's 1-based turn index within its conversation.
        let turn_index = {
            let c = inner
                .turn_counts
                .entry(conversation_id.clone())
                .or_insert(0);
            *c += 1;
            *c
        };

        // Delta vs the most recent prior turn of this conversation.
        //
        // Prefer the prior turn's live record (full surface compare). If that
        // record has been evicted from the global ring, fall back to the cached
        // last-turn hashes so a resent transcript is not mislabeled. Only the
        // genuine first turn (turn_index == 1) is `is_first`; a non-first turn
        // with no prior data is `prev_unavailable`, not "all new".
        let delta = if let Some((pt, surfaces)) =
            previous_turn_surfaces(&inner.records, &conversation_id, turn_index)
        {
            compute_delta(&request_surfaces, Some((pt, &surfaces)))
        } else if let Some((pt, hashes)) = inner
            .last_turn_hashes
            .get(&conversation_id)
            .filter(|(pt, _)| *pt < turn_index)
        {
            compute_delta_from_hashes(&request_surfaces, *pt, hashes)
        } else if turn_index == 1 {
            TurnDelta::first()
        } else {
            TurnDelta::prev_unavailable(turn_index - 1)
        };

        // Cache this turn's surface hashes (computed before the lock) for future
        // delta computation after the full record is evicted from the ring.
        {
            // Reborrow through the guard so the two field accesses are seen as
            // disjoint by the borrow checker.
            let inner = &mut *inner;
            inner
                .last_turn_hashes
                .insert(conversation_id.clone(), (turn_index, this_turn_hashes));
            if inner.last_turn_hashes.len() > MAX_TRACKED_CONVERSATIONS {
                evict_stale_conversation_hashes(&mut inner.last_turn_hashes, &inner.turn_counts);
            }
        }

        let pending_full = should_hold && inner.waiters.len() >= inner.max_pending_approvals;
        let (status, rx, immediate_reject) = if pending_full {
            (
                RequestDecision::BackpressureRejected,
                None,
                Some(format!(
                    "pending approval limit reached ({})",
                    inner.max_pending_approvals
                )),
            )
        } else if should_hold {
            let (tx, rx) = oneshot::channel();
            inner.waiters.insert(id.clone(), tx);
            (RequestDecision::Pending, Some(rx), None)
        } else {
            (RequestDecision::AutoAccepted, None, None)
        };
        let record = RequestRecord {
            id: id.clone(),
            conversation_id,
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            started_ms: now,
            updated_ms: now,
            decision: status,
            request_preview,
            request_spans,
            response_preview: None,
            response_spans: Vec::new(),
            response_status: None,
            tokens,
            tags: Vec::new(),
            rejection_reason: immediate_reject.clone(),
            turn_index,
            request_surfaces,
            response_surfaces: Vec::new(),
            delta,
        };
        push_record(&mut inner.records, record.clone());
        drop(inner);
        self.emit(MonitorEvent::Record(Box::new(record.clone())));
        ReviewTicket {
            id,
            rx,
            immediate_reject,
        }
    }

    pub fn record_response(&self, id: &str, status: u16, body: Option<&[u8]>) {
        self.update_record(id, |r| {
            r.response_status = Some(status);
            r.response_preview = body.map(preview);
            r.response_spans = r
                .response_preview
                .as_deref()
                .map(|p| spans_from_values(&r.tokens, p))
                .unwrap_or_default();
            // The response body is UNMASKED here (walk::unmask_response has
            // already replaced every [ENTITY_xxxx] handle with its plaintext),
            // so segment by the canonical VALUE, not the handle.
            r.response_surfaces = body
                .map(|b| surfaces_from_response_body(b, &r.tokens))
                .unwrap_or_default();
            if !matches!(
                r.decision,
                RequestDecision::Rejected
                    | RequestDecision::TimedOut
                    | RequestDecision::BackpressureRejected
            ) {
                r.decision = RequestDecision::Completed;
            }
        });
    }

    pub fn record_upstream_error(&self, id: &str, msg: &str) {
        self.update_record(id, |r| {
            r.decision = RequestDecision::UpstreamError;
            r.rejection_reason = Some(msg.to_string());
        });
    }

    pub(crate) async fn wait_for_approval(&self, ticket: ReviewTicket) -> ApprovalDecision {
        let Some(rx) = ticket.rx else {
            if let Some(reason) = ticket.immediate_reject {
                return ApprovalDecision::Reject { reason };
            }
            return ApprovalDecision::Approve;
        };
        match tokio::time::timeout(APPROVAL_TIMEOUT, rx).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(_)) => ApprovalDecision::Reject {
                reason: "approval channel closed".to_string(),
            },
            Err(_) => {
                let mut inner = self.inner.lock().expect("monitor mutex poisoned");
                inner.waiters.remove(&ticket.id);
                drop(inner);
                self.update_record(&ticket.id, |r| {
                    r.decision = RequestDecision::TimedOut;
                    r.rejection_reason = Some("approval timed out".to_string());
                });
                ApprovalDecision::Reject {
                    reason: "approval timed out".to_string(),
                }
            }
        }
    }

    pub(crate) fn decide(
        &self,
        id: &str,
        decision: ApprovalDecision,
    ) -> Result<RequestRecord, DecideError> {
        let waiter = {
            let mut inner = self.inner.lock().expect("monitor mutex poisoned");
            inner.waiters.remove(id)
        };
        let Some(waiter) = waiter else {
            return Err(DecideError::Unknown);
        };
        let _ = waiter.send(decision.clone());
        let mut out = None;
        self.update_record(id, |r| {
            match &decision {
                ApprovalDecision::Approve => r.decision = RequestDecision::Approved,
                ApprovalDecision::Reject { reason } => {
                    r.decision = RequestDecision::Rejected;
                    r.rejection_reason = Some(reason.clone());
                }
            }
            out = Some(r.clone());
        });
        out.ok_or(DecideError::Unknown)
    }

    pub(crate) fn update_tags(
        &self,
        id: &str,
        tags: Vec<String>,
    ) -> Result<RequestRecord, DecideError> {
        let mut out = None;
        self.update_record(id, |r| {
            r.tags = tags.clone();
            out = Some(r.clone());
        });
        out.ok_or(DecideError::Unknown)
    }

    fn update_record(&self, id: &str, f: impl FnOnce(&mut RequestRecord)) {
        let mut changed = None;
        {
            let mut inner = self.inner.lock().expect("monitor mutex poisoned");
            if let Some(r) = inner.records.iter_mut().find(|r| r.id == id) {
                f(r);
                r.updated_ms = now_ms();
                changed = Some(r.clone());
            }
        }
        if let Some(record) = changed {
            self.emit(MonitorEvent::Record(Box::new(record)));
        }
    }

    fn emit(&self, event: MonitorEvent) {
        let _ = self.events.send(event);
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<MonitorEvent> {
        self.events.subscribe()
    }
}

/// Approval handle returned by [`Monitor::record_llm_request`].
pub struct ReviewTicket {
    id: String,
    rx: Option<oneshot::Receiver<ApprovalDecision>>,
    immediate_reject: Option<String>,
}

impl ReviewTicket {
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Find the most recent record in the same conversation with a smaller turn
/// index, returning its turn index and a clone of its request surfaces.
///
/// `records` is newest-first, so the first match older than `turn_index` is the
/// immediately-previous turn.
fn previous_turn_surfaces(
    records: &VecDeque<RequestRecord>,
    conversation_id: &str,
    turn_index: u32,
) -> Option<(u32, Vec<Surface>)> {
    records
        .iter()
        .filter(|r| r.conversation_id == conversation_id && r.turn_index < turn_index)
        .max_by_key(|r| r.turn_index)
        .map(|r| (r.turn_index, r.request_surfaces.clone()))
}

/// Bound the per-conversation last-turn hash cache. Drops the entries with the
/// lowest current turn count (least active conversations) until back under cap.
fn evict_stale_conversation_hashes(
    cache: &mut HashMap<String, (u32, Vec<String>)>,
    turn_counts: &HashMap<String, u32>,
) {
    while cache.len() > MAX_TRACKED_CONVERSATIONS {
        let Some(victim) = cache
            .keys()
            .min_by_key(|k| turn_counts.get(*k).copied().unwrap_or(0))
            .cloned()
        else {
            break;
        };
        cache.remove(&victim);
    }
}

fn push_record(records: &mut VecDeque<RequestRecord>, record: RequestRecord) {
    records.push_front(record);
    while records.len() > MAX_RECORDS {
        records.pop_back();
    }
}

/// Derive a friendlier channel label than the raw conversation id.
///
/// Real conversation ids are opaque UUIDs/hashes; the triage rail reads better
/// as the endpoint's terminal segment plus a short id tail (e.g.
/// `messages · a1b2c3`). Falls back to the bare id when it is already short.
fn conversation_label(endpoint: &str, conversation_id: &str) -> String {
    let leaf = endpoint
        .rsplit(['/', ':'])
        .find(|s| !s.is_empty())
        .unwrap_or(endpoint);
    let id = conversation_id.trim();
    if id == "unknown" || id.is_empty() {
        return format!("{leaf} · unknown");
    }
    // Last six chars give a stable, human-scannable tail without leaking the
    // full id into the rail (the full id stays available via the row title).
    let tail: String = {
        let chars: Vec<char> = id.chars().collect();
        let n = chars.len();
        chars[n.saturating_sub(6)..].iter().collect()
    };
    if tail == id {
        id.to_string()
    } else {
        format!("{leaf} · {tail}")
    }
}

/// Build the conversation timeline from the current record set.
fn conversations_from_records(records: &VecDeque<RequestRecord>) -> Vec<ConversationMeta> {
    let mut metas: HashMap<String, ConversationMeta> = HashMap::new();
    for r in records {
        let pending = matches!(r.decision, RequestDecision::Pending);
        let m = metas
            .entry(r.conversation_id.clone())
            .or_insert_with(|| ConversationMeta {
                id: r.conversation_id.clone(),
                label: conversation_label(&r.endpoint, &r.conversation_id),
                turn_count: 0,
                last_updated_ms: 0,
                pending_count: 0,
            });
        m.turn_count = m.turn_count.max(r.turn_index);
        m.last_updated_ms = m.last_updated_ms.max(r.updated_ms);
        if pending {
            m.pending_count += 1;
        }
    }
    let mut out: Vec<ConversationMeta> = metas.into_values().collect();
    // Most recently active first.
    out.sort_by(|a, b| b.last_updated_ms.cmp(&a.last_updated_ms));
    out
}
