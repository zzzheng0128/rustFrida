//! Agent log headers describe the thread/time supplied by the emitting agent.
//! Legacy frames have no emission TID/time; do not replace them with host values.

use crate::agent_log::AgentLogMeta;
use std::fmt::Write as _;

pub(crate) fn format_message(meta: Option<AgentLogMeta>, session_pid: i32, message: &str) -> String {
    let pid = match meta {
        Some(value) => (value.pid != 0).then_some(value.pid),
        None => (session_pid > 0).then_some(session_pid as u32),
    };
    let tid = meta.map(|value| value.tid).filter(|value| *value != 0);
    let timestamp = meta.map(|value| value.timestamp_ns).filter(|value| *value != 0);
    let mut result = String::with_capacity(message.len() + 80);
    result.push_str("pid=");
    number(&mut result, pid.map(u64::from));
    result.push_str(" tid=");
    number(&mut result, tid.map(u64::from));
    result.push_str(" ts=");
    number(&mut result, timestamp);
    result.push(' ');
    result.push_str(message);
    result
}

fn number(output: &mut String, value: Option<u64>) {
    match value {
        Some(value) => {
            let _ = write!(output, "{value}");
        }
        None => output.push('?'),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emission_metadata_is_preserved_instead_of_using_receiver_identity() {
        let meta = AgentLogMeta {
            pid: 101,
            tid: 202,
            timestamp_ns: 61787940239113,
        };
        assert_eq!(
            format_message(Some(meta), 999, "[JS] hook\nmore"),
            "pid=101 tid=202 ts=61787940239113 [JS] hook\nmore"
        );
    }

    #[test]
    fn legacy_or_failed_capture_marks_unknown_fields() {
        assert_eq!(format_message(None, 101, "legacy"), "pid=101 tid=? ts=? legacy");
        let meta = AgentLogMeta {
            pid: 0,
            tid: 0,
            timestamp_ns: 0,
        };
        assert_eq!(format_message(Some(meta), -1, "raw"), "pid=? tid=? ts=? raw");
    }

    #[test]
    fn new_frame_with_zero_pid_does_not_borrow_session_identity() {
        assert_eq!(
            format_message(Some(AgentLogMeta::default()), 101, "failed"),
            "pid=? tid=? ts=? failed"
        );
        let partial = AgentLogMeta {
            pid: 0,
            tid: 202,
            timestamp_ns: 61787940239113,
        };
        assert_eq!(
            format_message(Some(partial), 101, "partial"),
            "pid=? tid=202 ts=61787940239113 partial"
        );
    }
}
