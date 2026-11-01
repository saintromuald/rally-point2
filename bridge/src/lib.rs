//! `rally-point-bridge` — the C ABI seam between a non-Rust game engine
//! (Hyperion) and ShieldBattery's rally-point2 netcode client.
//!
//! # Shape of the seam
//!
//! The embedding game calls everything from its own game thread, polled and
//! never blocking (except [`rp_start`], which dials the relay and returns
//! within a bounded timeout — call it during a loading screen):
//!
//! - **OUT** (a local turn was produced): [`rp_submit_turn`].
//! - **IN** (peers' turns, buffer directives, synced leaves): [`rp_poll`],
//!   called once per network step with the current game frame.
//! - **PIPE** (latency-buffer pacing): seed with [`rp_initial_buffer`], then
//!   apply the buffer events [`rp_poll`] reports.
//! - **Life**: [`rp_status`] for the driver's health, [`rp_end`] to tear down.
//!
//! One dedicated OS thread runs a Tokio runtime that dials the relay, drives
//! `LinkDriver::run_reconnecting` (reconnect + resync live inside the crate),
//! and owns every channel. The game-side half is guarded by a `Mutex`, and
//! every handoff is a `try_send`/`try_recv` so the game thread can never block
//! on the network.
//!
//! # Conventions
//!
//! - Return codes: `0` is success; negative values are errors (see the
//!   `RP_*` constants). A negative `rp_status` is a `DriverError` code.
//! - Pointers are valid only for the duration of the call; every turn is
//!   copied (turns are ≤ 16 KB, so the copy cost is noise).
//! - All multi-byte integers in poll events are little-endian, matching the
//!   game's own byte order.

#![allow(non_snake_case)]

mod setup;

use std::ffi::{c_char, CStr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use rally_point_client::proto::ids::SlotId;
use rally_point_client::proto::messages::Payload;
use rally_point_client::{
    ClientEndpoint, DirectiveTracker, DriverError, LeaveTracker, LinkDriver, Reconnect,
    TurnChannels,
};
use tokio::sync::mpsc as tmpsc;

use setup::Setup;

// ---------------------------------------------------------------------------
// Error and status codes
// ---------------------------------------------------------------------------

pub const RP_OK: i32 = 0;
pub const RP_ERR_PANIC: i32 = -100;
pub const RP_ERR_SETUP: i32 = -200;
pub const RP_ERR_DIAL: i32 = -201;
pub const RP_ERR_START_TIMEOUT: i32 = -202;
pub const RP_ERR_TURN_ENDED: i32 = -1;
pub const RP_ERR_TURN_FULL: i32 = -2;

/// `rp_status` values: 0 starting, 1 running, 2 ended cleanly, else the
/// negated `DriverError` code (see [`driver_error_code`]).
pub const RP_STAT_STARTING: i32 = 0;
pub const RP_STAT_RUNNING: i32 = 1;
pub const RP_STAT_ENDED: i32 = 2;

/// Maps a [`DriverError`] onto the stable negative codes the game switches on.
fn driver_error_code(e: &DriverError) -> i32 {
    match e {
        DriverError::Link(_) => -1,
        DriverError::ControlStream(_) => -2,
        DriverError::ControlStreamLost => -3,
        DriverError::GameStalled => -4,
        DriverError::UnackedWindowExhausted { .. } => -5,
        DriverError::OutageBufferExhausted { .. } => -6,
        DriverError::SlotDeparted => -7,
        DriverError::EvidenceRejected => -8,
        DriverError::Evicted { .. } => -9,
        DriverError::TokenExpired => -10,
    }
}

// ---------------------------------------------------------------------------
// Event framing (little-endian, written into the caller's poll buffer)
// ---------------------------------------------------------------------------

pub const EV_TURN: u8 = 1; //  u8, u32 slot, u64 seq, u32 len, len bytes
pub const EV_BUFFER: u8 = 2; // u8, u32 buffer_turns
pub const EV_LEAVE: u8 = 3; //  u8, u32 slot, u32 reason
pub const EV_LOBBY: u8 = 4; //  u8, u32 slot, u32 len, len bytes
pub const EV_CHAT: u8 = 5; //  u8, u32 slot, u32 len, len bytes

struct EvWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
    overflow: bool,
}

impl<'a> EvWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            overflow: false,
        }
    }

    fn need(&mut self, n: usize) -> bool {
        if self.pos + n > self.buf.len() {
            self.overflow = true;
            false
        } else {
            true
        }
    }

    fn u8(&mut self, v: u8) {
        if self.need(1) {
            self.buf[self.pos] = v;
            self.pos += 1;
        }
    }

    fn u32(&mut self, v: u32) {
        if self.need(4) {
            self.buf[self.pos..self.pos + 4].copy_from_slice(&v.to_le_bytes());
            self.pos += 4;
        }
    }

    fn u64(&mut self, v: u64) {
        if self.need(8) {
            self.buf[self.pos..self.pos + 8].copy_from_slice(&v.to_le_bytes());
            self.pos += 8;
        }
    }

    fn bytes(&mut self, v: &[u8]) {
        if self.need(v.len()) {
            self.buf[self.pos..self.pos + v.len()].copy_from_slice(v);
            self.pos += v.len();
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// The game-thread-facing half of the seam. Everything the game touches is
/// behind one mutex and uses only `try_*` channel operations.
struct GameState {
    channels: Option<TurnChannels>,
    directive: DirectiveTracker,
    leave: LeaveTracker,
    local_slot: u32,
    initial_buffer: u32,
}

/// A started session: the shared game state, the driver's health, the shutdown
/// flag, and the Tokio thread that owns the link.
pub struct RpSession {
    state: Arc<Mutex<GameState>>,
    status: Arc<AtomicI32>,
    shutdown: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Starts a session from the launch JSON (`Setup` shape), dialing the home
/// relay on a dedicated Tokio thread. Blocks the caller until the relay is
/// dialed and the driver is running, or until the start fails / 40 s elapse.
///
/// On success writes an opaque `RpSession*` to `*out`; returns 0.
///
/// # Safety
/// `setup_json` must be a valid NUL-terminated UTF-8 C string; `out` must be a
/// writable `RpSession**`. Both are used only for the call's duration.
#[no_mangle]
pub unsafe extern "C" fn rp_start(setup_json: *const c_char, out: *mut *mut RpSession) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if setup_json.is_null() || out.is_null() {
            return RP_ERR_SETUP;
        }
        let json = match CStr::from_ptr(setup_json).to_str() {
            Ok(s) => s,
            Err(_) => return RP_ERR_SETUP,
        };
        let creds = match serde_json::from_str::<Setup>(json) {
            Ok(s) => match s.resolve() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("rp_start: setup: {e}");
                    return RP_ERR_SETUP;
                }
            },
            Err(e) => {
                eprintln!("rp_start: setup json: {e}");
                return RP_ERR_SETUP;
            }
        };

        let state = Arc::new(Mutex::new(GameState {
            channels: None,
            directive: DirectiveTracker::default(),
            leave: LeaveTracker::new(),
            local_slot: creds.local_slot,
            initial_buffer: creds.initial_buffer,
        }));
        let status = Arc::new(AtomicI32::new(RP_STAT_STARTING));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (started_tx, started_rx) = mpsc::channel::<Result<(), i32>>();

        let t_state = Arc::clone(&state);
        let t_status = Arc::clone(&status);
        let t_shutdown = Arc::clone(&shutdown);
        let thread = std::thread::Builder::new()
            .name("rallypoint".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => {
                        let _ = started_tx.send(Err(RP_ERR_DIAL));
                        return;
                    }
                };

                let channels: Result<TurnChannels, i32> = rt.block_on(async {
                    let endpoint = match ClientEndpoint::bind(creds.roots) {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("rp_start: endpoint bind failed: {e:?}");
                            return Err(RP_ERR_DIAL);
                        }
                    };

                    // Dial the relay, trying its candidates in preference
                    // order. A stagger favouring earlier entries is the
                    // production behaviour; the simple sequential form is
                    // right for the first integration.
                    let mut link = None;
                    let mut relay_addr = None;
                    for addr in &creds.addrs {
                        match endpoint.connect(*addr, &creds.server_name, &creds.identity).await {
                            Ok(l) => {
                                link = Some(l);
                                relay_addr = Some(*addr);
                                break;
                            }
                            Err(e) => {
                                eprintln!("rp_start: dial {addr} failed: {e:?}");
                            }
                        }
                    }
                    let (link, relay_addr) = match (link, relay_addr) {
                        (Some(l), Some(a)) => (l, a),
                        _ => return Err(RP_ERR_DIAL),
                    };

                    let (driver, channels) = LinkDriver::new(link);

                    let reconnect = Reconnect {
                        endpoint: ClientEndpoint::from_endpoint(endpoint.endpoint().clone()),
                        relay_addr,
                        fallback_addrs: creds
                            .addrs
                            .iter()
                            .copied()
                            .filter(|a| *a != relay_addr)
                            .collect(),
                        server_name: creds.server_name,
                        relay_id: creds.relay_id,
                        identity: creds.identity,
                        rehome: None, // v1: same-relay reconnect only, no re-home
                        escalate_after: None,
                        escalate_retry: None,
                        fresh_port_redials: true,
                    };

                    let d_status = Arc::clone(&t_status);
                    tokio::spawn(async move {
                        let result = driver.run_reconnecting(reconnect).await;
                        d_status.store(
                            match result {
                                Ok(()) => RP_STAT_ENDED,
                                Err(e) => driver_error_code(&e),
                            },
                            Ordering::SeqCst,
                        );
                    });

                    Ok(channels)
                });

                match channels {
                    Ok(channels) => {
                        if let Ok(mut guard) = t_state.lock() {
                            guard.channels = Some(channels);
                        }
                        t_status.store(RP_STAT_RUNNING, Ordering::SeqCst);
                        let _ = started_tx.send(Ok(()));
                    }
                    Err(code) => {
                        let _ = started_tx.send(Err(code));
                        return;
                    }
                }

                // Keep the runtime (and the driver) alive until the game ends
                // the session.
                rt.block_on(async {
                    while !t_shutdown.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                });
                // Dropping the channels stops the driver cleanly (its
                // outbound/inbound ends); the runtime drop then reaps it.
                if let Ok(mut guard) = t_state.lock() {
                    guard.channels = None;
                }
            })
            .expect("spawning the rallypoint thread");

        let started = match started_rx.recv_timeout(Duration::from_secs(40)) {
            Ok(Ok(())) => true,
            Ok(Err(code)) => {
                let _ = thread.join();
                return code;
            }
            Err(_) => {
                shutdown.store(true, Ordering::SeqCst);
                let _ = thread.join();
                return RP_ERR_START_TIMEOUT;
            }
        };
        debug_assert!(started);

        let session = Box::new(RpSession {
            state,
            status,
            shutdown,
            thread: Some(thread),
        });
        *out = Box::into_raw(session);
        RP_OK
    }))
    .unwrap_or(RP_ERR_PANIC)
}

/// The driver's health: 0 starting, 1 running, 2 ended cleanly, or the negated
/// `DriverError` code.
#[no_mangle]
pub extern "C" fn rp_status(session: *mut RpSession) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        match unsafe { session.as_ref() } {
            Some(s) => s.status.load(Ordering::SeqCst),
            None => RP_ERR_SETUP,
        }
    }))
    .unwrap_or(RP_ERR_PANIC)
}

/// The turn-pipe depth to seed at start (the session's initial latency
/// buffer). The game applies buffer events from [`rp_poll`] on top of this.
#[no_mangle]
pub extern "C" fn rp_initial_buffer(session: *mut RpSession) -> u32 {
    catch_unwind(AssertUnwindSafe(|| {
        match unsafe { session.as_ref() } {
            Some(s) => match s.state.lock() {
                Ok(guard) => guard.initial_buffer,
                Err(_) => 0,
            },
            None => 0,
        }
    }))
    .unwrap_or(0)
}

/// This client's slot in the session, from the signed token.
#[no_mangle]
pub extern "C" fn rp_local_slot(session: *mut RpSession) -> u32 {
    catch_unwind(AssertUnwindSafe(|| {
        match unsafe { session.as_ref() } {
            Some(s) => match s.state.lock() {
                Ok(guard) => guard.local_slot,
                Err(_) => u32::MAX,
            },
            None => u32::MAX,
        }
    }))
    .unwrap_or(u32::MAX)
}

/// OUT: hands the game's fully-assembled local turn to the driver. The driver
/// assigns the transport seq; the relay binds the slot. `frame` is the game's
/// current frame (0 for lobby turns, which carry no consensus coordinate).
///
/// Returns 0 when queued, [`RP_ERR_TURN_FULL`] when the driver's queue is full
/// (the game stalls and retries, as Storm's backpressure would), and
/// [`RP_ERR_TURN_ENDED`] when the session has ended.
///
/// # Safety
/// `data` must be readable for `len` bytes; both are used only for the call's
/// duration (the turn is copied).
#[no_mangle]
pub unsafe extern "C" fn rp_submit_turn(
    session: *mut RpSession,
    frame: u32,
    data: *const u8,
    len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(s) = (unsafe { session.as_ref() }) else {
            return RP_ERR_TURN_ENDED;
        };
        if data.is_null() || len > 1024 * 1024 {
            return RP_ERR_SETUP;
        }
        let commands = std::slice::from_raw_parts(data, len).to_vec();
        let payload = Payload {
            seq: 0, // the driver assigns it
            slot: 0, // the relay rebinds it
            commands: commands.into(),
            game_frame_count: (frame > 0).then_some(frame),
            ..Default::default()
        };
        let Ok(guard) = s.state.lock() else {
            return RP_ERR_TURN_ENDED;
        };
        match &guard.channels {
            None => RP_ERR_TURN_ENDED,
            Some(ch) => match ch.outbound.try_send(payload) {
                Ok(()) => RP_OK,
                Err(tmpsc::error::TrySendError::Full(_)) => RP_ERR_TURN_FULL,
                Err(tmpsc::error::TrySendError::Closed(_)) => RP_ERR_TURN_ENDED,
            },
        }
    }))
    .unwrap_or(RP_ERR_PANIC)
}

/// IN: drains the driver's channels and writes poll events into `buf`
/// (see the `EV_*` constants for the framing). Called once per network step
/// with the current game frame; buffer directives and leaves are observed from
/// received turns here and surfaced due exactly at `frame`.
///
/// Returns the number of **bytes** written into `buf` (walk it event by
/// event), or a negative error. Non-turn traffic (chat, skins, connectivity)
/// is consumed and dropped — v1 has no side channel.
///
/// # Safety
/// `buf` must be writable for `cap` bytes; used only for the call's duration.
#[no_mangle]
pub unsafe extern "C" fn rp_poll(
    session: *mut RpSession,
    frame: u32,
    buf: *mut u8,
    cap: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(s) = (unsafe { session.as_ref() }) else {
            return RP_ERR_TURN_ENDED;
        };
        if buf.is_null() && cap > 0 {
            return RP_ERR_SETUP;
        }
        let out = std::slice::from_raw_parts_mut(buf, cap);
        let mut w = EvWriter::new(out);

        let mut guard = match s.state.lock() {
            Ok(g) => g,
            Err(_) => return RP_ERR_TURN_ENDED,
        };
        if guard.channels.is_none() {
            return RP_ERR_TURN_ENDED;
        }

        // Turns first: a directive observed off a turn applies to the step
        // that drains it, so events of this poll precede the game's dispatch.
        loop {
            let received = guard
                .channels
                .as_mut()
                .expect("checked above")
                .inbound
                .try_recv();
            match received {
                Ok(payload) => {
                    if let Some(d) = &payload.buffer_directive {
                        guard.directive.observe(d, frame);
                    }
                    w.u8(EV_TURN);
                    w.u32(payload.slot);
                    w.u64(payload.seq);
                    w.u32(payload.commands.len() as u32);
                    w.bytes(&payload.commands);
                }
                Err(tmpsc::error::TryRecvError::Empty) => break,
                Err(tmpsc::error::TryRecvError::Disconnected) => {
                    if s.status.load(Ordering::SeqCst) == RP_STAT_RUNNING {
                        s.status.store(RP_STAT_ENDED, Ordering::SeqCst);
                    }
                    break;
                }
            }
        }

        // Synced leaves: observe everything available, surface the due ones.
        loop {
            let received = guard
                .channels
                .as_mut()
                .expect("checked above")
                .leaves
                .try_recv();
            match received {
                Ok(d) => guard.leave.observe(&d),
                Err(tmpsc::error::TryRecvError::Empty) => break,
                Err(tmpsc::error::TryRecvError::Disconnected) => break,
            }
        }
        for (slot, reason) in guard.leave.take_due(frame, |_| 0) {
            w.u8(EV_LEAVE);
            w.u32(u32::from(slot.0));
            w.u32(reason);
        }

        // The authority's session-start depth overrides the seeded one (a
        // computed initial buffer is more current than the launch minimum).
        loop {
            let received = guard
                .channels
                .as_mut()
                .expect("checked above")
                .session_start
                .try_recv();
            match received {
                Ok(Some(depth)) => guard.initial_buffer = depth,
                Ok(None) => {}
                Err(_) => break,
            }
        }

        // Buffer directive due at this frame (at most one per step).
        if let Some(d) = guard.directive.take_due(frame) {
            w.u8(EV_BUFFER);
            w.u32(d.buffer_turns);
        }

        // Consume the side channels so their queues never fill; lobby
        // commands are surfaced, everything else is dropped (v1).
        loop {
            let received = guard
                .channels
                .as_mut()
                .expect("checked above")
                .lobby_in
                .try_recv();
            match received {
                Ok((slot, bytes)) => {
                    w.u8(EV_LOBBY);
                    w.u32(u32::from(slot.0));
                    w.u32(bytes.len() as u32);
                    w.bytes(&bytes);
                }
                Err(_) => break,
            }
        }
        if let Some(channels) = guard.channels.as_mut() {
            loop {
                match channels.chat_in.try_recv() {
                    Ok((slot, chat)) => {
                        w.u8(EV_CHAT);
                        w.u32(u32::from(slot.0));
                        w.u32(chat.text.len() as u32);
                        w.bytes(chat.text.as_bytes());
                    }
                    Err(_) => break,
                }
            }
            let _ = channels.skin_in.try_recv();
            let _ = channels.connectivity.try_recv();
            let _ = channels.region_labels.try_recv();
        }

        drop(guard);
        if w.overflow {
            RP_ERR_SETUP
        } else {
            w.pos as i32
        }
    }))
    .unwrap_or(RP_ERR_PANIC)
}

// ---------------------------------------------------------------------------
// Fire-and-forget signals (never block, never fail the session)
// ---------------------------------------------------------------------------

/// The game will produce a result report before leaving; the driver holds a
/// pending leave intent until the result is sent.
#[no_mangle]
pub extern "C" fn rp_result_expected(session: *mut RpSession) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(s) = unsafe { session.as_ref() } {
            if let Ok(guard) = s.state.lock() {
                if let Some(ch) = &guard.channels {
                    ch.result_expected.store(true, Ordering::SeqCst);
                }
            }
        }
    }));
}

/// The end-of-game result report, as opaque serialized bytes. At most one is
/// sent; a second is dropped by the driver.
///
/// # Safety
/// `data` must be readable for `len` bytes for the call's duration.
#[no_mangle]
pub unsafe extern "C" fn rp_send_result(session: *mut RpSession, data: *const u8, len: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(s) = (unsafe { session.as_ref() }) else {
            return;
        };
        if data.is_null() || len > 1024 * 1024 {
            return;
        }
        let bytes = std::slice::from_raw_parts(data, len).to_vec();
        if let Ok(guard) = s.state.lock() {
            if let Some(ch) = &guard.channels {
                let _ = ch.result.try_send(bytes);
            }
        }
    }));
}

/// The game is departing intentionally (quit, game over); the driver drains
/// the outbound queue and unacked window, then announces the clean leave.
#[no_mangle]
pub extern "C" fn rp_leave_intent(session: *mut RpSession) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(s) = unsafe { session.as_ref() } {
            if let Ok(guard) = s.state.lock() {
                if let Some(ch) = &guard.channels {
                    let _ = ch.leave_intent.try_send(());
                }
            }
        }
    }));
}

/// The game's loop has begun stepping; reported once per session to the relay.
#[no_mangle]
pub extern "C" fn rp_game_started(session: *mut RpSession) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(s) = unsafe { session.as_ref() } {
            if let Ok(guard) = s.state.lock() {
                if let Some(ch) = &guard.channels {
                    let _ = ch.game_started.try_send(());
                }
            }
        }
    }));
}

/// In-game chat (best-effort, never correctness-critical): the relay stamps
/// the authoring slot and fans it out; other members' lines arrive as
/// `EV_CHAT` events from [`rp_poll`].
///
/// # Safety
/// `data` must be readable for `len` bytes for the call's duration.
#[no_mangle]
pub unsafe extern "C" fn rp_chat_send(session: *mut RpSession, data: *const u8, len: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(s) = (unsafe { session.as_ref() }) else {
            return;
        };
        if data.is_null() || len > 1024 * 1024 {
            return;
        }
        let text = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(data, len) }) {
            Ok(t) => t.to_string(),
            Err(_) => return, // chat is UTF-8; non-UTF-8 lines are dropped
        };
        if let Ok(guard) = s.state.lock() {
            if let Some(ch) = &guard.channels {
                let _ = ch.chat_out.try_send(rally_point_client::ChatOut {
                    target_kind: 0, // 0 = all members
                    target_slot: 0,
                    text,
                });
            }
        }
    }));
}

/// A pre-game lobby command (the game's init data, slot/race setup, whatever
/// the lobby exchanges): carried on the reliable control stream, stamped with
/// the authoring slot by the relay, replayed to members that connect late, and
/// delivered to the others as `EV_LOBBY` events from [`rp_poll`]. Returns 0
/// when queued, [`RP_ERR_TURN_FULL`] when the driver's queue is full,
/// [`RP_ERR_TURN_ENDED`] when the session has ended. Bounded by the relay's
/// lobby caps (32-command burst, 256 KB logged per session).
///
/// # Safety
/// `data` must be readable for `len` bytes for the call's duration.
#[no_mangle]
pub unsafe extern "C" fn rp_lobby_send(session: *mut RpSession, data: *const u8, len: usize) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(s) = (unsafe { session.as_ref() }) else {
            return RP_ERR_TURN_ENDED;
        };
        if data.is_null() || len > 256 * 1024 {
            return RP_ERR_SETUP;
        }
        let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
        let Ok(guard) = s.state.lock() else {
            return RP_ERR_TURN_ENDED;
        };
        match &guard.channels {
            None => RP_ERR_TURN_ENDED,
            Some(ch) => match ch.lobby_out.try_send(bytes) {
                Ok(()) => RP_OK,
                Err(tmpsc::error::TrySendError::Full(_)) => RP_ERR_TURN_FULL,
                Err(tmpsc::error::TrySendError::Closed(_)) => RP_ERR_TURN_ENDED,
            },
        }
    }))
    .unwrap_or(RP_ERR_PANIC)
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

/// Ends the session: signals the Tokio thread to drop the channels (which
/// stops the driver cleanly) and joins it. Idempotent; safe to call twice.
#[no_mangle]
pub extern "C" fn rp_end(session: *mut RpSession) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if session.is_null() {
            return;
        }
        let boxed = unsafe { Box::from_raw(session) };
        boxed.shutdown.store(true, Ordering::SeqCst);
        if let Some(thread) = boxed.thread {
            let _ = thread.join();
        }
    }));
}

/// A manual drop request: the game asks the relay's authority to decide a
/// synced leave for a disconnected slot. The relay may refuse while the drop's
/// unlock floor has not passed; the confirmation is the `EV_LEAVE` event for
/// the slot. Returns 0 when queued, -1 when the session has ended.
#[no_mangle]
pub extern "C" fn rp_request_drop(session: *mut RpSession, slot: u32) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(s) = (unsafe { session.as_ref() }) else {
            return RP_ERR_TURN_ENDED;
        };
        if slot > u32::from(u8::MAX) {
            return RP_ERR_SETUP;
        }
        let Ok(guard) = s.state.lock() else {
            return RP_ERR_TURN_ENDED;
        };
        match &guard.channels {
            None => RP_ERR_TURN_ENDED,
            Some(ch) => match ch.request_drop.try_send(SlotId(slot as u8)) {
                Ok(()) => RP_OK,
                Err(tmpsc::error::TrySendError::Full(_)) => RP_ERR_TURN_FULL,
                Err(tmpsc::error::TrySendError::Closed(_)) => RP_ERR_TURN_ENDED,
            },
        }
    }))
    .unwrap_or(RP_ERR_PANIC)
}

/// The bridge's own version, for the game's log lines.
#[no_mangle]
pub extern "C" fn rp_bridge_version() -> u32 {
    1
}
