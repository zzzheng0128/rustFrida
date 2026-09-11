//! JS(QuickJS agent) ↔ kernel-trace 双向桥接。
//!
//! 通道复用现有 host↔agent 协议,agent 侧零改动:
//! - JS → host:agent 的 console.log 走 FRAME_KIND_LOG,前缀 "KT>" 的消息
//!   在此被截获解析为 TraceCommand(或 sub/unsub 订阅控制)。
//! - host → JS:trace 事件通过 HostToAgentMessage::Command 下发一段 JS eval,
//!   回调 JS 里定义的 globalThis.__kt_on_event(event)。
//!
//! JS 侧用法(在 -l 脚本里):
//! ```js
//! globalThis.__kt_on_event = function (e) {
//!     if (e.lib_hit) console.log("metasec svc nr=" + e.nr + " args=" + JSON.stringify(e.args));
//! };
//! globalThis.__kt_on_ack = function (m) { console.log("[kt-ack] " + m); };
//! console.log("KT>sub");                                  // 订阅事件推送
//! console.log("KT>brk /path/libmetasec_ml.so 0x135ff8");  // 动态断点
//! console.log("KT>nr 56");                                // 实时改过滤器
//! ```

#![cfg(all(target_os = "android", target_arch = "aarch64", feature = "kernel-trace"))]

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use crate::communication::HostToAgentMessage;
use crate::session::Session;
use kernel_trace::TraceCommand;

/// 当前 tracer 的命令通道(tracer 启动时注册)
static CMD_TX: OnceLock<mpsc::Sender<TraceCommand>> = OnceLock::new();
/// 当前 agent session(agent HELLO 时注册)
static SESSION: OnceLock<Arc<Session>> = OnceLock::new();
/// 事件流三态(由 JS 的 KT>sub / KT>unsub 控制):
/// 0 = 默认:host 打印事件到 stdout,不推送 JS
/// 1 = 已订阅:host 打印 + 推送 JS 回调
/// 2 = 已退订:完全静默(不打印、不推送)——JS 主动要安静
static MODE: AtomicU8 = AtomicU8::new(0);

/// Callback admission is independent of file/console output. These limits bound
/// enqueue attempts, not target CPU use or the existing transport queue depth.
const SVC_CALLBACKS_PER_SECOND: f64 = 200.0;
const UPROBE_CALLBACKS_PER_SECOND: f64 = 100.0;
// HWBP is a separate admission lane.  In particular, a write watchpoint on
// a method slot is a control event for the demo gate; it must not wait behind
// a burst of execute-breakpoint samples.
const HWBP_CALLBACKS_PER_SECOND: f64 = 200.0;
const CALLBACK_BURST: f64 = 20.0;
// The agent currently evaluates each host command on a detached raw worker.
// Admission must therefore be bounded by completed callbacks, rather than
// only by an arrival-rate token bucket; otherwise HWBP bursts create an
// unbounded queue of 2 MiB worker stacks on Android.
const MAX_CALLBACKS_IN_FLIGHT: usize = 1;
// A callback completion marker is emitted by the generated JS expression. If
// evaluation stalls before that marker, the bridge trips a circuit breaker
// instead of creating another raw worker every timeout interval.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CallbackStats {
    pub svc_sent: u64,
    pub svc_limited: u64,
    pub uprobe_sent: u64,
    pub uprobe_limited: u64,
    pub hwbp_sent: u64,
    pub hwbp_limited: u64,
    pub unavailable: u64,
    pub timed_out: u64,
}

struct CallbackBucket {
    rate: f64,
    tokens: f64,
    updated_at: Instant,
}

impl CallbackBucket {
    fn new(rate: f64, now: Instant) -> Self {
        Self {
            rate,
            tokens: CALLBACK_BURST,
            updated_at: now,
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        self.tokens = (self.tokens + now.saturating_duration_since(self.updated_at).as_secs_f64() * self.rate)
            .min(CALLBACK_BURST);
        self.updated_at = self.updated_at.max(now);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

struct CallbackState {
    svc: CallbackBucket,
    uprobe: CallbackBucket,
    hwbp: CallbackBucket,
    stats: CallbackStats,
    in_flight: Option<InFlightCallback>,
    stalled_id: Option<u64>,
    hwbp_in_flight: Option<InFlightCallback>,
    hwbp_stalled_id: Option<u64>,
    // A watchpoint is a control event for method-slot handoff.  It gets a
    // second reservation so an execute-hit sample cannot block it.
    hwbp_critical_in_flight: Option<InFlightCallback>,
    hwbp_critical_stalled_id: Option<u64>,
    hwbp_write_in_flight: [Option<InFlightCallback>; 4],
    hwbp_write_stalled_id: [Option<u64>; 4],
    // 每个写观察点地址最多占一个 reservation。否则高频对象写入会把
    // 4 个槽位全部占满，method_slot 的控制事件永远进不了 JS。
    hwbp_write_keys: [u64; 4],
    next_id: u64,
}

#[derive(Clone, Copy)]
struct InFlightCallback {
    id: u64,
    started_at: Instant,
}

impl CallbackState {
    fn new(now: Instant) -> Self {
        Self {
            svc: CallbackBucket::new(SVC_CALLBACKS_PER_SECOND, now),
            uprobe: CallbackBucket::new(UPROBE_CALLBACKS_PER_SECOND, now),
            hwbp: CallbackBucket::new(HWBP_CALLBACKS_PER_SECOND, now),
            stats: CallbackStats::default(),
            in_flight: None,
            stalled_id: None,
            hwbp_in_flight: None,
            hwbp_stalled_id: None,
            hwbp_critical_in_flight: None,
            hwbp_critical_stalled_id: None,
            hwbp_write_in_flight: [None; 4],
            hwbp_write_stalled_id: [None; 4],
            hwbp_write_keys: [0; 4],
            next_id: 1,
        }
    }

    fn admit(&mut self, syscall: bool, subscribed: bool, available: bool, now: Instant) -> Option<u64> {
        if !subscribed {
            return None;
        }
        if !available {
            self.stats.unavailable = self.stats.unavailable.saturating_add(1);
            return None;
        }
        if let Some(in_flight) = self.in_flight {
            if now.saturating_duration_since(in_flight.started_at) >= CALLBACK_TIMEOUT {
                self.in_flight = None;
                self.stalled_id = Some(in_flight.id);
                self.stats.timed_out = self.stats.timed_out.saturating_add(1);
            }
        }
        if self.stalled_id.is_some() {
            // A timed-out callback may still be executing on a raw worker.
            // Refuse further admissions until its id-matched marker arrives
            // or the user explicitly starts a fresh subscription. This keeps
            // repeated timeouts from accumulating worker stacks.
            if syscall {
                self.stats.svc_limited = self.stats.svc_limited.saturating_add(1);
            } else {
                self.stats.uprobe_limited = self.stats.uprobe_limited.saturating_add(1);
            }
            return None;
        }
        if MAX_CALLBACKS_IN_FLIGHT != 0 && self.in_flight.is_some() {
            // Do not spend a rate token while the agent is still processing
            // the previous callback.  This keeps the limit self-clocked by
            // the actual QuickJS worker throughput.
            if syscall {
                self.stats.svc_limited = self.stats.svc_limited.saturating_add(1);
            } else {
                self.stats.uprobe_limited = self.stats.uprobe_limited.saturating_add(1);
            }
            return None;
        }
        let bucket = if syscall { &mut self.svc } else { &mut self.uprobe };
        if bucket.take(now) {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            self.in_flight = Some(InFlightCallback { id, started_at: now });
            return Some(id);
        }
        let limited = if syscall {
            &mut self.stats.svc_limited
        } else {
            &mut self.stats.uprobe_limited
        };
        *limited = limited.saturating_add(1);
        None
    }

    fn finish(&mut self, syscall: bool, sent: bool, id: u64) {
        if self.in_flight.is_some_and(|in_flight| in_flight.id == id) {
            self.in_flight = None;
        }
        let count = if !sent {
            &mut self.stats.unavailable
        } else if syscall {
            &mut self.stats.svc_sent
        } else {
            &mut self.stats.uprobe_sent
        };
        *count = count.saturating_add(1);
    }

    /// Admit a HWBP callback on its own lane.  A read/write watchpoint is a
    /// control-plane event for method-slot handoff, so it bypasses the normal
    /// token bucket while still obeying the single in-flight limit for this
    /// lane.  Execute-breakpoint samples remain rate limited.
    fn admit_hwbp(
        &mut self,
        subscribed: bool,
        available: bool,
        now: Instant,
        critical: bool,
        write: bool,
        write_key: u64,
    ) -> Option<u64> {
        if !subscribed {
            return None;
        }
        if !available {
            self.stats.unavailable = self.stats.unavailable.saturating_add(1);
            return None;
        }
        if write {
            for slot in 0..self.hwbp_write_in_flight.len() {
                if let Some(in_flight) = self.hwbp_write_in_flight[slot] {
                    if now.saturating_duration_since(in_flight.started_at) >= CALLBACK_TIMEOUT {
                        self.hwbp_write_in_flight[slot] = None;
                        self.hwbp_write_stalled_id[slot] = Some(in_flight.id);
                        self.stats.timed_out = self.stats.timed_out.saturating_add(1);
                    }
                }
            }
            // Reuse the slot assigned to this address when present. A new
            // address gets a fresh slot; at most four distinct addresses are
            // admitted concurrently, preserving the old bounded behavior.
            let slot = if write_key != 0 {
                if let Some(existing) = self.hwbp_write_keys.iter().position(|key| *key == write_key) {
                    if self.hwbp_write_stalled_id[existing].is_some() || self.hwbp_write_in_flight[existing].is_some() {
                        return {
                            self.stats.hwbp_limited = self.stats.hwbp_limited.saturating_add(1);
                            None
                        };
                    }
                    Some(existing)
                } else {
                    (0..self.hwbp_write_in_flight.len()).find(|&slot| {
                        self.hwbp_write_keys[slot] == 0
                            && self.hwbp_write_stalled_id[slot].is_none()
                            && self.hwbp_write_in_flight[slot].is_none()
                    })
                }
            } else {
                (0..self.hwbp_write_in_flight.len()).find(|&slot| {
                    self.hwbp_write_stalled_id[slot].is_none() && self.hwbp_write_in_flight[slot].is_none()
                })
            };
            let Some(slot) = slot else {
                self.stats.hwbp_limited = self.stats.hwbp_limited.saturating_add(1);
                return None;
            };
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            if write_key != 0 {
                self.hwbp_write_keys[slot] = write_key;
            }
            self.hwbp_write_in_flight[slot] = Some(InFlightCallback { id, started_at: now });
            return Some(id);
        }
        let current = if critical {
            self.hwbp_critical_in_flight
        } else {
            self.hwbp_in_flight
        };
        if let Some(in_flight) = current {
            if now.saturating_duration_since(in_flight.started_at) >= CALLBACK_TIMEOUT {
                if critical {
                    self.hwbp_critical_in_flight = None;
                    self.hwbp_critical_stalled_id = Some(in_flight.id);
                } else {
                    self.hwbp_in_flight = None;
                    self.hwbp_stalled_id = Some(in_flight.id);
                }
                self.stats.timed_out = self.stats.timed_out.saturating_add(1);
            }
        }
        let stalled = if critical {
            self.hwbp_critical_stalled_id.is_some()
        } else {
            self.hwbp_stalled_id.is_some()
        };
        let occupied = if critical {
            self.hwbp_critical_in_flight.is_some()
        } else {
            self.hwbp_in_flight.is_some()
        };
        if stalled || occupied {
            self.stats.hwbp_limited = self.stats.hwbp_limited.saturating_add(1);
            return None;
        }
        if !critical && !self.hwbp.take(now) {
            self.stats.hwbp_limited = self.stats.hwbp_limited.saturating_add(1);
            return None;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let reservation = Some(InFlightCallback { id, started_at: now });
        if critical {
            self.hwbp_critical_in_flight = reservation;
        } else {
            self.hwbp_in_flight = reservation;
        }
        Some(id)
    }

    fn finish_hwbp(&mut self, sent: bool, id: u64, write: bool) {
        if write {
            for slot in 0..self.hwbp_write_in_flight.len() {
                if self.hwbp_write_in_flight[slot].is_some_and(|in_flight| in_flight.id == id) {
                    self.hwbp_write_in_flight[slot] = None;
                    self.hwbp_write_keys[slot] = 0;
                    break;
                }
            }
        } else if self.hwbp_critical_in_flight.is_some_and(|in_flight| in_flight.id == id) {
            self.hwbp_critical_in_flight = None;
        } else if self.hwbp_in_flight.is_some_and(|in_flight| in_flight.id == id) {
            self.hwbp_in_flight = None;
        }
        if sent {
            self.stats.hwbp_sent = self.stats.hwbp_sent.saturating_add(1);
        } else {
            self.stats.unavailable = self.stats.unavailable.saturating_add(1);
        }
    }

    /// Mark a successfully queued callback.  The in-flight slot remains held
    /// until the generated JS expression emits the completion marker.
    fn mark_sent(&mut self, syscall: bool) {
        let count = if syscall {
            &mut self.stats.svc_sent
        } else {
            &mut self.stats.uprobe_sent
        };
        *count = count.saturating_add(1);
    }

    fn mark_sent_hwbp(&mut self) {
        self.stats.hwbp_sent = self.stats.hwbp_sent.saturating_add(1);
    }

    fn complete(&mut self, id: u64) {
        if self.in_flight.is_some_and(|in_flight| in_flight.id == id) {
            self.in_flight = None;
        }
        if self.stalled_id == Some(id) {
            self.stalled_id = None;
        }
        if self.hwbp_in_flight.is_some_and(|in_flight| in_flight.id == id) {
            self.hwbp_in_flight = None;
        }
        if self.hwbp_stalled_id == Some(id) {
            self.hwbp_stalled_id = None;
        }
        if self.hwbp_critical_in_flight.is_some_and(|in_flight| in_flight.id == id) {
            self.hwbp_critical_in_flight = None;
        }
        if self.hwbp_critical_stalled_id == Some(id) {
            self.hwbp_critical_stalled_id = None;
        }
        for slot in 0..self.hwbp_write_in_flight.len() {
            if self.hwbp_write_in_flight[slot].is_some_and(|in_flight| in_flight.id == id) {
                self.hwbp_write_in_flight[slot] = None;
                self.hwbp_write_keys[slot] = 0;
            }
            if self.hwbp_write_stalled_id[slot] == Some(id) {
                self.hwbp_write_stalled_id[slot] = None;
                self.hwbp_write_keys[slot] = 0;
            }
        }
    }

    fn reset_subscription(&mut self, now: Instant) {
        // A new subscription starts a fresh admission window.  Clear any
        // reservation left by a previous agent session; its completion marker
        // carries the old id and therefore cannot release a later callback.
        self.in_flight = None;
        self.stalled_id = None;
        self.hwbp_in_flight = None;
        self.hwbp_stalled_id = None;
        self.hwbp_critical_in_flight = None;
        self.hwbp_critical_stalled_id = None;
        self.hwbp_write_in_flight = [None; 4];
        self.hwbp_write_stalled_id = [None; 4];
        self.hwbp_write_keys = [0; 4];
        self.svc = CallbackBucket::new(SVC_CALLBACKS_PER_SECOND, now);
        self.uprobe = CallbackBucket::new(UPROBE_CALLBACKS_PER_SECOND, now);
        self.hwbp = CallbackBucket::new(HWBP_CALLBACKS_PER_SECOND, now);
    }

    fn cancel_in_flight(&mut self) {
        // KT>unsub/print makes already queued callbacks best-effort.  Leaving
        // their reservation behind would delay a later KT>sub for up to the
        // watchdog timeout even though no callback is currently requested.
        self.in_flight = None;
        self.stalled_id = None;
        self.hwbp_in_flight = None;
        self.hwbp_stalled_id = None;
        self.hwbp_critical_in_flight = None;
        self.hwbp_critical_stalled_id = None;
        self.hwbp_write_in_flight = [None; 4];
        self.hwbp_write_stalled_id = [None; 4];
        self.hwbp_write_keys = [0; 4];
    }
}

static CALLBACK_STATE: OnceLock<Mutex<CallbackState>> = OnceLock::new();

fn callback_state() -> MutexGuard<'static, CallbackState> {
    CALLBACK_STATE
        .get_or_init(|| Mutex::new(CallbackState::new(Instant::now())))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

pub(crate) fn callback_stats() -> CallbackStats {
    callback_state().stats
}

/// host 侧是否应打印该事件
pub(crate) fn host_should_print() -> bool {
    MODE.load(Ordering::SeqCst) != 2
}

/// 是否应推送事件到 JS 回调
pub(crate) fn js_subscribed() -> bool {
    MODE.load(Ordering::SeqCst) == 1
}

pub(crate) fn register_tracer(tx: mpsc::Sender<TraceCommand>) {
    let _ = CMD_TX.set(tx);
}

pub(crate) fn register_session(session: &Arc<Session>) {
    let _ = SESSION.set(session.clone());
}

/// 处理一条 agent LOG 消息;若是 "KT>" 前缀的桥接消息则消费并返回 true。
/// agent 的 console.log 会自动加 "[JS] " 前缀,先剥掉再匹配。
pub(crate) fn handle_kt_message(msg: &str) -> bool {
    let m = msg.strip_prefix("[JS] ").unwrap_or(msg);
    let Some(rest) = m.strip_prefix("KT>") else {
        return false;
    };
    let rest = rest.trim();
    match rest {
        "sub" => {
            if MODE.load(Ordering::SeqCst) != 1 {
                callback_state().reset_subscription(Instant::now());
                // Publish the new mode only after the old reservation and
                // token window have been cleared.  A concurrent event can
                // therefore observe either the old unsubscribed mode or the
                // fully initialized subscription, never a half-reset state.
                MODE.store(1, Ordering::SeqCst);
            }
            ack("subscribed");
        }
        "unsub" => {
            MODE.store(2, Ordering::SeqCst);
            callback_state().cancel_in_flight();
            ack("unsubscribed (host silent)");
        }
        "print" => {
            // 恢复 host 打印但不推 JS
            MODE.store(0, Ordering::SeqCst);
            callback_state().cancel_in_flight();
            ack("host print only");
        }
        "__event_done__" => {
            // Ignore untagged legacy markers. Only an id-matched marker may
            // release a slot; otherwise a late callback from an older host
            // session could release a newer callback reservation.
        }
        _ if rest.starts_with("__event_done__:") => {
            if let Some(id) = rest.strip_prefix("__event_done__:").and_then(|id| id.parse().ok()) {
                callback_state().complete(id);
            }
        }
        _ => match TraceCommand::parse(rest) {
            Some(cmd) => {
                if let Some(tx) = CMD_TX.get() {
                    match tx.send(cmd) {
                        // Admission is asynchronous; attach failures are reported
                        // by the tracer after this acknowledgement.
                        Ok(_) => ack(&format!("cmd queued: {rest}")),
                        Err(_) => ack("cmd failed: tracer not running"),
                    }
                } else {
                    ack("cmd failed: tracer not running");
                }
            }
            None => ack(&format!("unknown kt cmd: {rest}")),
        },
    }
    true
}

/// trace 事件推送给 JS(仅当 JS 已 KT>sub)。
/// jsonl 是 TraceReport::to_jsonl() 的输出,本身即合法 JS 对象字面量。
pub(crate) fn push_event_jsonl(jsonl: &str, syscall: bool) {
    push_event_jsonl_inner(jsonl, syscall, false);
}

/// Push a HWBP event through the dedicated callback lane.  Watchpoint events
/// are marked critical so method-slot handoff is not starved by execute-hit
/// sampling.  The full event has already been written to trace-output.jsonl;
/// this only controls the optional live JS observer.
pub(crate) fn push_hwbp_event_jsonl(jsonl: &str) {
    push_event_jsonl_inner(jsonl, false, true);
}

/// Extract the write-watchpoint address from the compact callback JSON. The
/// callback serializer emits `bp.kind` before `bp.addr`; malformed/legacy
/// records simply use key=0 and retain the bounded first-free behavior.
fn hwbp_write_key(jsonl: &str) -> u64 {
    let Some(bp) = jsonl.split_once("\"bp\":").map(|(_, value)| value) else {
        return 0;
    };
    if !bp.starts_with("{\"kind\":\"w\"") {
        return 0;
    }
    let Some((_, tail)) = bp.split_once("\"addr\":\"0x") else {
        return 0;
    };
    let end = tail.find('"').unwrap_or(tail.len());
    u64::from_str_radix(&tail[..end], 16).unwrap_or(0)
}

fn push_event_jsonl_inner(jsonl: &str, syscall: bool, hwbp: bool) {
    let subscribed = js_subscribed();
    if !subscribed {
        return;
    }
    let sender = js_sender();
    let critical = hwbp && (jsonl.contains("\"bp\":{\"kind\":\"r\"") || jsonl.contains("\"bp\":{\"kind\":\"w\""));
    let write = hwbp && jsonl.contains("\"bp\":{\"kind\":\"w\"");
    let callback_id = {
        let mut state = callback_state();
        let write_key = if write { hwbp_write_key(jsonl) } else { 0 };
        if hwbp {
            state.admit_hwbp(subscribed, sender.is_some(), Instant::now(), critical, write, write_key)
        } else {
            state.admit(syscall, subscribed, sender.is_some(), Instant::now())
        }
    };
    let Some(callback_id) = callback_id else { return };
    // No rate-state lock is held while allocating the command or sending it.
    let sent = sender.is_some_and(|sender| {
        push_js_to(
            sender,
            &format!(
                "try{{globalThis.__kt_on_event&&__kt_on_event({})}}catch(e){{}};console.log(\"KT>__event_done__:{}\")",
                jsonl, callback_id
            ),
        )
    });
    if sent {
        if hwbp {
            callback_state().mark_sent_hwbp();
        } else {
            callback_state().mark_sent(syscall);
        }
    } else {
        if hwbp {
            callback_state().finish_hwbp(false, callback_id, write);
        } else {
            callback_state().finish(syscall, false, callback_id);
        }
    }
}

fn ack(s: &str) {
    push_js(&format!(
        "try{{globalThis.__kt_on_ack&&__kt_on_ack({:?})}}catch(e){{}}",
        s
    ));
}

fn js_sender() -> Option<&'static mpsc::Sender<HostToAgentMessage>> {
    let session = SESSION.get()?;
    if !session.is_connected() {
        return None;
    }
    session.get_sender()
}

fn push_js(code: &str) -> bool {
    js_sender().is_some_and(|sender| push_js_to(sender, code))
}

fn push_js_to(sender: &mpsc::Sender<HostToAgentMessage>, code: &str) -> bool {
    // agent 侧裸 JS 走 "jseval <expr>" 命令字(与 REPL eval 同路径,
    // 与 loadjs 脚本共享同一 QuickJS 上下文,能看到脚本定义的全局函数)
    sender
        .send(HostToAgentMessage::Command(format!("jseval {}", code)))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn callback_budgets_bound_bursts_and_sustained_admissions() {
        for (syscall, rate) in [(true, 200u64), (false, 100u64)] {
            let start = Instant::now();
            let mut state = CallbackState::new(start);
            let mut admitted = 0;
            for millis in 0..=10_000u64 {
                let now = start + Duration::from_millis(millis);
                // Multiple simultaneous arrivals exercise each burst limit.
                for _ in 0..25 {
                    if let Some(id) = state.admit(syscall, true, true, now) {
                        admitted += 1;
                        state.finish(syscall, true, id);
                    }
                }
                assert!(admitted <= CALLBACK_BURST as u64 + millis * rate / 1000);
                if millis == 0 {
                    assert_eq!(admitted, CALLBACK_BURST as u64);
                }
            }
            assert!(admitted >= rate * 10 * 95 / 100);
            assert_eq!(
                admitted,
                if syscall {
                    state.stats.svc_sent
                } else {
                    state.stats.uprobe_sent
                }
            );
        }
    }

    #[test]
    fn callbacks_have_independent_budgets_and_recover_after_idle() {
        let start = Instant::now();
        let mut state = CallbackState::new(start);
        for _ in 0..20 {
            let id = state.admit(true, true, true, start).unwrap();
            state.finish(true, true, id);
        }
        assert!(state.admit(true, true, true, start).is_none());
        assert_eq!(state.stats.svc_limited, 1);
        assert_eq!(state.stats.uprobe_limited, 0);
        for _ in 0..20 {
            let id = state.admit(false, true, true, start).unwrap();
            state.finish(false, true, id);
        }
        assert!(state.admit(false, true, true, start).is_none());
        let later = start + Duration::from_secs(60);
        for _ in 0..20 {
            let id = state.admit(true, true, true, later).unwrap();
            state.finish(true, true, id);
            let id = state.admit(false, true, true, later).unwrap();
            state.finish(false, true, id);
        }
        assert!(state.admit(true, true, true, later).is_none());
        assert!(state.admit(false, true, true, later).is_none());
    }

    #[test]
    fn unsubscribed_or_unavailable_callbacks_do_not_spend_tokens() {
        let start = Instant::now();
        let mut state = CallbackState::new(start);
        for _ in 0..100 {
            assert!(state.admit(true, false, false, start).is_none());
            assert!(state.admit(false, false, true, start).is_none());
        }
        assert_eq!(state.stats.unavailable, 0);
        assert_eq!(state.stats.svc_limited + state.stats.uprobe_limited, 0);
        for _ in 0..100 {
            assert!(state.admit(true, true, false, start).is_none());
        }
        assert_eq!(state.stats.unavailable, 100);
        assert_eq!(state.stats.svc_limited, 0);
        for _ in 0..20 {
            let id = state.admit(true, true, true, start).unwrap();
            state.finish(true, true, id);
            let id = state.admit(false, true, true, start).unwrap();
            state.finish(false, true, id);
        }
    }

    #[test]
    fn in_flight_limit_waits_for_event_completion() {
        let start = Instant::now();
        let mut state = CallbackState::new(start);
        let id = state.admit(false, true, true, start).unwrap();
        assert!(state.admit(false, true, true, start).is_none());
        assert_eq!(state.stats.uprobe_limited, 1);
        state.mark_sent(false);
        state.complete(id);
        let id = state.admit(false, true, true, start).unwrap();
        state.finish(false, false, id);
    }

    #[test]
    fn only_successful_sends_count_as_sent() {
        let start = Instant::now();
        let mut state = CallbackState::new(start);
        for (syscall, sent) in [(true, true), (true, false), (false, true), (false, false)] {
            let id = state.admit(syscall, true, true, start).unwrap();
            state.finish(syscall, sent, id);
        }
        assert_eq!(state.stats.svc_sent, 1);
        assert_eq!(state.stats.uprobe_sent, 1);
        assert_eq!(state.stats.unavailable, 2);
        assert_eq!(state.stats.svc_limited + state.stats.uprobe_limited, 0);
    }

    #[test]
    fn timed_out_callback_is_reclaimed_and_late_marker_is_ignored() {
        let start = Instant::now();
        let mut state = CallbackState::new(start);
        let old_id = state.admit(false, true, true, start).unwrap();
        assert!(state.admit(false, true, true, start + CALLBACK_TIMEOUT).is_none());
        assert_eq!(state.stats.timed_out, 1);
        assert_eq!(state.stalled_id, Some(old_id));
        // The late marker belongs to the timed-out worker and clears the
        // circuit breaker; no newer callback could have been admitted before
        // it, so it cannot release somebody else's reservation.
        state.complete(old_id);
        assert!(state.stalled_id.is_none());
        let new_id = state.admit(false, true, true, start + CALLBACK_TIMEOUT).unwrap();
        assert_ne!(old_id, new_id);
        state.complete(new_id);
        assert!(state.in_flight.is_none());
    }

    #[test]
    fn subscription_reset_drops_old_reservation_and_refills_buckets() {
        let start = Instant::now();
        let mut state = CallbackState::new(start);
        let old_id = state.admit(true, true, true, start).unwrap();
        state.reset_subscription(start + Duration::from_secs(1));
        assert!(state.in_flight.is_none());
        // The old marker cannot affect the fresh subscription.
        state.complete(old_id);
        for _ in 0..CALLBACK_BURST as usize {
            let id = state.admit(true, true, true, start + Duration::from_secs(1)).unwrap();
            state.finish(true, true, id);
        }
        assert!(state.admit(true, true, true, start + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn critical_watchpoint_has_a_reservation_independent_of_execute_hit() {
        let start = Instant::now();
        let mut state = CallbackState::new(start);
        let execute = state.admit_hwbp(true, true, start, false, false, 0).unwrap();
        let watch = state.admit_hwbp(true, true, start, true, false, 0).unwrap();
        assert_ne!(execute, watch);
        assert!(state.hwbp_in_flight.is_some());
        assert!(state.hwbp_critical_in_flight.is_some());
        state.complete(watch);
        state.complete(execute);
        assert!(state.hwbp_in_flight.is_none());
        assert!(state.hwbp_critical_in_flight.is_none());
    }

    #[test]
    fn write_watchpoints_have_bounded_parallel_reservations() {
        let start = Instant::now();
        let mut state = CallbackState::new(start);
        let ids: Vec<_> = (0..4)
            .map(|_| state.admit_hwbp(true, true, start, true, true, 0).unwrap())
            .collect();
        assert!(state.admit_hwbp(true, true, start, true, true, 0).is_none());
        for id in ids {
            state.complete(id);
        }
        assert!(state.admit_hwbp(true, true, start, true, true, 0).is_some());
    }

    #[test]
    fn write_watchpoints_are_fair_across_addresses() {
        let start = Instant::now();
        let mut state = CallbackState::new(start);
        let first = state.admit_hwbp(true, true, start, true, true, 0x1000).unwrap();
        // A second event for the same address cannot consume another slot.
        assert!(state.admit_hwbp(true, true, start, true, true, 0x1000).is_none());
        // Other watchpoint addresses still get their own reservations.
        let second = state.admit_hwbp(true, true, start, true, true, 0x2000).unwrap();
        let third = state.admit_hwbp(true, true, start, true, true, 0x3000).unwrap();
        assert_ne!(first, second);
        assert_ne!(second, third);
        state.complete(first);
        state.complete(second);
        state.complete(third);
    }
}
