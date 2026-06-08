/* ============================================================
   ZLAUDER INTERCEPT STATION  -  frontend controller
   Binds to the exact serde contract emitted by monitor/model.rs:
     MonitorSnapshot { mode, pending_count, max_pending_approvals,
                       records[], conversations[] }
     RequestRecord   { id, conversation_id, endpoint, method, started_ms,
                       updated_ms, decision, request_preview, request_spans,
                       response_preview, response_spans, response_status,
                       tokens[], tags[], rejection_reason, turn_index,
                       request_surfaces[], response_surfaces[], delta }
     Surface         { label, role?, kind, runs[], block_hash }
     Run             { text, token? }      // token ABSENT => plain run
     TokenRef        { token, value, entity_kind, surface }
     TurnDelta       { prev_turn?, is_first, added_surface_hashes[] }
     ConversationMeta{ id, label, turn_count, last_updated_ms, pending_count }
   Surfaces are rendered run-by-run with ZERO client offset arithmetic.
   ============================================================ */

/* ---------- key handling (x-zlauder-key + EventSource ?key=) ---------- */
let key = new URLSearchParams(location.search).get('key')
       || localStorage.getItem('zlauderKey') || '';
if (key) { localStorage.setItem('zlauderKey', key); history.replaceState(null, '', location.pathname); }
if (!key) { key = (prompt('x-zlauder-key') || '').trim(); if (key) localStorage.setItem('zlauderKey', key); }

const hdr = { 'x-zlauder-key': key, 'content-type': 'application/json' };
function api(path, opts = {}) { opts.headers = { ...(opts.headers || {}), ...hdr }; return fetch(path, opts); }

/* ---------- state ---------- */
let records = [];
let conversations = [];
let selectedId = null;
let channelFilter = null;
let channelQuery = '';
let firstPaint = true;

const $ = id => document.getElementById(id);

/* ---------- utils ---------- */
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}
function attr(s) { return esc(s).replace(/\n/g, '&#10;'); }
function ago(ms) {
  if (!ms) return '';
  const d = Date.now() - Number(ms);
  if (d < 1500) return 'now';
  const s = Math.floor(d / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm';
  const h = Math.floor(m / 60);
  if (h < 24) return h + 'h';
  return Math.floor(h / 24) + 'd';
}
function statusClass(decision) { return 'st-' + decision; }
function toast(msg, kind) {
  const tpl = $('tpl-toast').content.cloneNode(true);
  const el = tpl.querySelector('.toast');
  if (kind) el.classList.add(kind);
  el.querySelector('.toast-msg').textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 320); }, 2600);
}

/* ============================================================
   SURFACE / RUN RENDERING  (zero offset arithmetic)
   A run with a `token` is a masked occurrence -> chip that reveals
   the hidden canonical value. A run without `token` is plain text.
   Concatenated run.text reproduces the surface byte-for-byte.
   ============================================================ */
function renderRuns(runs) {
  return (runs || []).map(run => {
    if (run.token) {
      const t = run.token;
      const reveal = `${t.entity_kind}\n${t.value}` + (t.surface ? `\n(${t.surface})` : '');
      return `<span class="mark" tabindex="0" data-reveal="${attr(reveal)}">${esc(run.text)}</span>`;
    }
    return esc(run.text);
  }).join('');
}

function renderSurface(s, addedSet) {
  const isNew = addedSet && addedSet.has(s.block_hash);
  const kindClass = 'kind-' + s.kind;
  const role = s.role ? ` &middot; ${esc(s.role)}` : '';
  return `<div class="surface ${isNew ? 'is-new' : ''}">`
    + `<div class="surface-head">`
    +   `<span class="kind-tag ${kindClass}">${esc(s.kind)}</span>`
    +   `<span class="surface-label">${esc(s.label)}${role}</span>`
    +   (isNew ? `<span class="new-flag">NEW</span>` : '')
    +   `<span class="surface-hash">${esc(s.block_hash)}</span>`
    + `</div>`
    + `<pre class="payload">${renderRuns(s.runs)}</pre>`
  + `</div>`;
}

/* ============================================================
   DELTA SPOTLIGHT  (the heart of the review)
   Surfaces whose block_hash is in delta.added_surface_hashes are
   what THIS turn newly exposes. Default view shows only those.
   ============================================================ */
function renderSpotlight(r) {
  const delta = r.delta || {};
  const addedSet = new Set(delta.added_surface_hashes || []);
  const surfaces = r.request_surfaces || [];
  const newSurfaces = surfaces.filter(s => addedSet.has(s.block_hash));

  if (delta.is_first) {
    const allNew = new Set(surfaces.map(s => s.block_hash));
    return `<div class="spotlight">`
      + `<div class="spotlight-head">`
      +   `<span class="spotlight-icon">&#9650;</span>`
      +   `<span class="spotlight-title">FIRST CONTACT</span>`
      +   `<span class="spotlight-sub">entire channel is new &mdash; all ${surfaces.length} surface(s)</span>`
      + `</div>`
      + `<div class="spotlight-body">`
      +   (surfaces.length ? surfaces.map(s => renderSurface(s, allNew)).join('')
                            : `<div class="empty-note">No recognized text surfaces in this request.</div>`)
      + `</div></div>`;
  }

  if (delta.prev_unavailable) {
    return `<div class="spotlight warn">`
      + `<div class="spotlight-head">`
      +   `<span class="spotlight-icon">&#9888;</span>`
      +   `<span class="spotlight-title">PREVIOUS TURN EVICTED</span>`
      +   `<span class="spotlight-sub">cannot compute delta vs turn ${delta.prev_turn ?? '-'} &mdash; audit full request</span>`
      + `</div>`
      + `<div class="spotlight-body">`
      +   (surfaces.length ? surfaces.map(s => renderSurface(s, null)).join('')
                            : `<div class="empty-note">No recognized text surfaces in this request.</div>`)
      + `</div></div>`;
  }

  if (!newSurfaces.length) {
    return `<div class="spotlight calm">`
      + `<div class="spotlight-head">`
      +   `<span class="spotlight-icon">&#9679;</span>`
      +   `<span class="spotlight-title">NO NEW EXPOSURE</span>`
      +   `<span class="spotlight-sub">turn ${r.turn_index} resends prior context (prev turn ${delta.prev_turn ?? '-'})</span>`
      + `</div>`
      + `<div class="spotlight-body"><div class="empty-note">`
      +   `Nothing new is exposed this turn. Expand the full request below to audit resent context.`
      + `</div></div></div>`;
  }

  return `<div class="spotlight">`
    + `<div class="spotlight-head">`
    +   `<span class="spotlight-icon">&#9650;</span>`
    +   `<span class="spotlight-title">DELTA &middot; ${newSurfaces.length} NEW SURFACE${newSurfaces.length === 1 ? '' : 'S'}</span>`
    +   `<span class="spotlight-sub">new this turn vs turn ${delta.prev_turn ?? '-'}</span>`
    + `</div>`
    + `<div class="spotlight-body">`
    +   newSurfaces.map(s => renderSurface(s, addedSet)).join('')
    + `</div></div>`;
}

/* ============================================================
   FULL MASKED REQUEST / RESPONSE  (legacy preview + spans)
   Uses request_preview/request_spans byte offsets -> we render via
   the same span data the backend supplies. Collapsed by default.
   ============================================================ */
function renderSpanned(preview, spans) {
  if (preview == null) return '';
  const text = String(preview);
  spans = (spans || []).slice().sort((a, b) => a.start - b.start);
  // Build by byte offsets using a TextEncoder/Decoder to stay byte-correct,
  // matching the backend's byte-offset PreviewSpan semantics.
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const bytes = enc.encode(text);
  let out = '', cursor = 0;
  for (const sp of spans) {
    if (sp.start < cursor || sp.start > bytes.length) continue;
    out += esc(dec.decode(bytes.subarray(cursor, sp.start)));
    const handle = dec.decode(bytes.subarray(sp.start, Math.min(sp.end, bytes.length)));
    const reveal = `${esc(sp.entity_kind)}` + (sp.surface ? `\n(${esc(sp.surface)})` : '');
    out += `<span class="mark" tabindex="0" data-reveal="${attr(reveal)}">${esc(handle)}</span>`;
    cursor = sp.end;
  }
  out += esc(dec.decode(bytes.subarray(cursor)));
  return out;
}

/* ============================================================
   REVIEW PANE
   ============================================================ */
function renderReview() {
  const r = records.find(x => x.id === selectedId);
  const d = $('detail');
  if (!r) {
    d.innerHTML = `<div class="placeholder">`
      + `<span class="placeholder-glyph">&#9678;</span>`
      + `<p>SELECT AN INTERCEPT</p>`
      + `<small>Review what plaintext leaves this machine before it ships.</small>`
      + `</div>`;
    return;
  }

  const tokens = r.tokens || [];
  const tags = r.tags || [];
  const pending = r.decision === 'pending';

  const head = `<div class="review-head">`
    + `<div><div class="rh-id">TURN ${r.turn_index}`
    +   `<small>${esc(r.method)} ${esc(r.endpoint)} &middot; ${esc(r.id)}</small></div></div>`
    + `<div class="rh-spacer"></div>`
    + `<div class="rh-tags">${tags.map(t => `<span class="rh-tag">${esc(t)}</span>`).join('')}</div>`
  + `</div>`;

  const verdict = `<div class="verdict-bar">`
    + `<span class="verdict ${statusClass(r.decision)}">${esc(r.decision)}</span>`
    + (r.response_status ? `<span class="surface-label">HTTP ${r.response_status}</span>` : '')
    + (r.rejection_reason ? `<span class="surface-label">${esc(r.rejection_reason)}</span>` : '')
    + (pending
        ? `<div class="action-group">`
          + `<input class="reject-reason" id="rejectReason" placeholder="reject reason&hellip;" autocomplete="off">`
          + `<button class="btn danger" data-act="reject" data-id="${esc(r.id)}">REJECT</button>`
          + `<button class="btn primary" data-act="approve" data-id="${esc(r.id)}">APPROVE</button>`
          + `</div>`
        : '')
  + `</div>`;

  const spotlight = renderSpotlight(r);

  const tokenLedger = `<details class="panel">`
    + `<summary><span class="panel-title">TOKEN LEDGER</span><span class="panel-count">${tokens.length}</span></summary>`
    + `<div class="panel-body"><div class="token-grid">`
    +   (tokens.length ? tokens.map(t =>
          `<div class="token-row">`
          + `<span class="token-handle">${esc(t.token)}</span>`
          + `<span class="token-value"><span class="token-arrow">&rarr;</span> ${esc(t.value)}</span>`
          + `<span class="token-kind">${esc(t.entity_kind)}</span>`
          + `</div>`).join('')
        : `<div class="empty-note">No tokens masked in this request.</div>`)
    + `</div></div></details>`;

  const reqSurfaces = r.request_surfaces || [];
  const fullRequest = `<details class="panel">`
    + `<summary><span class="panel-title">FULL MASKED REQUEST</span><span class="panel-count">${reqSurfaces.length} surface(s)</span></summary>`
    + `<div class="panel-body">`
    +   (reqSurfaces.length
          ? reqSurfaces.map(s => renderSurface(s, new Set(r.delta && r.delta.added_surface_hashes))).join('')
          : `<div class="empty-note">No structured surfaces. Raw preview:</div><pre class="payload">${renderSpanned(r.request_preview, r.request_spans)}</pre>`)
    + `</div></details>`;

  const respSurfaces = r.response_surfaces || [];
  // Only prefer surfaces when at least one carries a token run; a tokenless
  // surface set means segmentation found no exposed plaintext, so fall back to
  // the span-based preview rather than hiding which spans are exposed.
  const respHasTokenRun = respSurfaces.some(s => (s.runs || []).some(run => run.token));
  const hasResp = r.response_preview != null || respSurfaces.length;
  const fullResponse = hasResp ? `<details class="panel">`
    + `<summary><span class="panel-title">RESPONSE</span><span class="panel-count">${r.response_status ? 'HTTP ' + r.response_status : ''}</span></summary>`
    + `<div class="panel-body">`
    +   (respHasTokenRun
          ? respSurfaces.map(s => renderSurface(s, null)).join('')
          : `<pre class="payload">${renderSpanned(r.response_preview, r.response_spans)}</pre>`)
    + `</div></details>`
    : '';

  const tagComposer = `<details class="panel">`
    + `<summary><span class="panel-title">ANNOTATE</span></summary>`
    + `<div class="panel-body"><div class="tag-composer">`
    +   `<input id="tagInput" placeholder="add tag to this intercept&hellip;" autocomplete="off">`
    +   `<button class="btn ghost" data-act="tag" data-id="${esc(r.id)}">TAG</button>`
    + `</div></div></details>`;

  d.innerHTML = head + verdict + spotlight + tokenLedger + fullRequest + fullResponse + tagComposer;
}

/* ============================================================
   CHANNELS (conversations) + TRAFFIC (records)
   ============================================================ */
function renderChannels() {
  const q = channelQuery.toLowerCase();
  const list = conversations.filter(c =>
    !q || (c.label || '').toLowerCase().includes(q) || (c.id || '').toLowerCase().includes(q));
  $('convoCount').textContent = conversations.length;
  $('sessions').innerHTML = list.length ? list.map(c =>
    `<div class="convo ${channelFilter === c.id ? 'active' : ''}" data-channel="${esc(c.id)}">`
    + `<div class="convo-top"><span class="convo-label" title="${esc(c.id)}">${esc(c.label)}</span></div>`
    + `<div class="convo-meta">`
    +   `<span class="turn-pip">${c.turn_count} turn${c.turn_count === 1 ? '' : 's'}</span>`
    +   (c.pending_count ? `<span class="pending-badge">${c.pending_count} HOLD</span>` : '')
    +   `<span class="ago">${ago(c.last_updated_ms)}</span>`
    + `</div></div>`
  ).join('') : `<div class="empty-note" style="padding:14px">No channels${channelQuery ? ' match.' : ' yet.'}</div>`;
}

function renderTraffic(flashId) {
  const visible = records.filter(r => !channelFilter || r.conversation_id === channelFilter)
                         .slice().sort((a, b) => Number(b.started_ms) - Number(a.started_ms));
  const title = channelFilter
    ? (conversations.find(c => c.id === channelFilter)?.label || 'CHANNEL')
    : 'TRAFFIC';
  $('recordsTitle').textContent = title.toUpperCase();
  $('clearFilter').hidden = !channelFilter;

  $('records').innerHTML = visible.length ? visible.map(r => {
    const tc = (r.tokens || []).length;
    const newCount = (r.delta && !r.delta.is_first) ? (r.delta.added_surface_hashes || []).length : -1;
    return `<div class="rec ${r.decision === 'pending' ? 'pending' : ''} ${selectedId === r.id ? 'active' : ''} ${flashId === r.id ? 'flash' : ''}" data-rec="${esc(r.id)}">`
      + `<div class="rec-top">`
      +   `<span class="rec-turn">T${r.turn_index}</span>`
      +   `<span class="rec-endpoint">${esc(r.endpoint)}</span>`
      +   (r.delta && r.delta.is_first ? `<span class="new-flag">FIRST</span>`
            : (r.delta && r.delta.prev_unavailable ? `<span class="new-flag warn-flag">?</span>`
            : (newCount > 0 ? `<span class="new-flag">+${newCount}</span>` : '')))
      + `</div>`
      + `<div class="rec-meta">`
      +   `<span class="status-tag ${statusClass(r.decision)}">${esc(r.decision)}</span>`
      +   `<span class="tok-count ${tc ? '' : 'zero'}">${tc} tok</span>`
      +   `<span class="ago">${ago(r.started_ms)}</span>`
      + `</div></div>`;
  }).join('') : `<div class="empty-note" style="padding:14px">No traffic${channelFilter ? ' on this channel.' : ' yet.'}</div>`;
}

/* ---------- header ---------- */
function renderHeader(snap) {
  if (snap) {
    $('mode').value = snap.mode;
    const max = snap.max_pending_approvals || 0;
    const pend = snap.pending_count || 0;
    $('queue').textContent = `${pend} / ${max}`;
    const pct = max ? Math.min(100, (pend / max) * 100) : (pend ? 100 : 0);
    $('queueFill').style.width = pct + '%';
    $('queueMeter').classList.toggle('hot', max > 0 && pend >= max);
  }
}

function render(flashId) {
  renderChannels();
  renderTraffic(flashId);
  renderReview();
}

/* ============================================================
   ACTIONS
   ============================================================ */
function approve(id) {
  api(`/zlauder/monitor/requests/${id}/approve`, { method: 'POST' })
    .then(r => r.ok ? toast('APPROVED &mdash; released upstream', 'good') : toast('approve failed', 'bad'))
    .then(load);
}
function reject(id) {
  const reason = ($('rejectReason')?.value || '').trim() || 'rejected in monitor';
  api(`/zlauder/monitor/requests/${id}/reject`, { method: 'POST', body: JSON.stringify({ reason }) })
    .then(r => r.ok ? toast('REJECTED &mdash; blocked', 'bad') : toast('reject failed', 'bad'))
    .then(load);
}
function tagReq(id) {
  const v = ($('tagInput')?.value || '').trim();
  if (!v) return;
  const existing = records.find(x => x.id === id)?.tags || [];
  api(`/zlauder/monitor/requests/${id}/tags`, { method: 'POST', body: JSON.stringify({ tags: [...existing, v] }) })
    .then(() => toast('tag added', 'good')).then(load);
}

/* event delegation for all dynamic buttons */
document.addEventListener('click', e => {
  const act = e.target.closest('[data-act]');
  if (act) {
    const id = act.getAttribute('data-id');
    if (act.dataset.act === 'approve') approve(id);
    else if (act.dataset.act === 'reject') reject(id);
    else if (act.dataset.act === 'tag') tagReq(id);
    return;
  }
  const rec = e.target.closest('[data-rec]');
  if (rec) { selectedId = rec.getAttribute('data-rec'); render(); return; }
  const ch = e.target.closest('[data-channel]');
  if (ch) {
    const id = ch.getAttribute('data-channel');
    channelFilter = channelFilter === id ? null : id;
    render(); return;
  }
});

$('clearFilter').addEventListener('click', e => { e.stopPropagation(); channelFilter = null; render(); });
$('convoFilterInput').addEventListener('input', e => { channelQuery = e.target.value; renderChannels(); });

$('saveMode').addEventListener('click', () => {
  api('/zlauder/monitor/mode', { method: 'POST', body: JSON.stringify({ mode: $('mode').value }) })
    .then(r => r.ok ? toast('posture set: ' + $('mode').value, 'good') : toast('mode change failed', 'bad'))
    .then(load);
});

/* ---------- selection -> custom mask affordance ---------- */
const maskHint = document.createElement('div');
maskHint.className = 'mask-hint';
maskHint.textContent = 'mask selection';
document.body.appendChild(maskHint);
let pendingMask = '';
document.addEventListener('mouseup', () => {
  const sel = (getSelection().toString() || '').trim();
  if (sel && sel.length > 1) {
    const rng = getSelection().getRangeAt(0).getBoundingClientRect();
    pendingMask = sel;
    maskHint.style.display = 'block';
    maskHint.style.left = Math.min(rng.left, window.innerWidth - 130) + 'px';
    maskHint.style.top = (rng.bottom + 6) + 'px';
  } else {
    maskHint.style.display = 'none';
  }
});
maskHint.addEventListener('click', () => {
  if (!pendingMask) return;
  api('/zlauder/monitor/custom-mask', { method: 'POST', body: JSON.stringify({ pattern: pendingMask }) })
    .then(r => r.ok ? toast('custom mask added', 'good') : toast('mask rejected', 'bad'));
  maskHint.style.display = 'none';
  getSelection().removeAllRanges();
});

/* ============================================================
   DATA: snapshot + SSE live stream
   ============================================================ */
let lastSnap = null;
function applySnapshot(s) {
  lastSnap = s;
  records = s.records || [];
  conversations = s.conversations || [];
  renderHeader(s);
}
function load() {
  return api('/zlauder/monitor/snapshot')
    .then(r => r.json())
    .then(s => { applySnapshot(s); render(); })
    .catch(() => toast('snapshot fetch failed', 'bad'));
}

function setLink(on) {
  $('carrier').classList.toggle('live', on);
  $('liveLabel').textContent = on ? 'LIVE' : 'LINK';
}

load();

const es = new EventSource(`/zlauder/monitor/events?key=${encodeURIComponent(key)}`);
es.onopen = () => setLink(true);
es.onerror = () => setLink(false);
es.onmessage = e => {
  let ev;
  try { ev = JSON.parse(e.data); } catch { return; }
  if (ev.event === 'snapshot') {
    applySnapshot(ev.data);
    render();
  } else if (ev.event === 'record') {
    const rec = ev.data;
    const isNew = !records.some(r => r.id === rec.id);
    records = [rec, ...records.filter(r => r.id !== rec.id)];
    // recompute lightweight header counts from records when no fresh snapshot
    if (lastSnap) {
      const pending = records.filter(r => r.decision === 'pending').length;
      renderHeader({ ...lastSnap, pending_count: pending });
    }
    render(isNew ? rec.id : null);
    if (isNew && rec.decision === 'pending') toast(`HOLD &mdash; turn ${rec.turn_index} awaiting review`, 'bad');
  }
};
