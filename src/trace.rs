//! Optional raw-frame tracing hook (for logging / protocol analysis).

use std::fmt;
use std::sync::Arc;

/// Whether a traced frame was sent or received.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    Tx,
    Rx,
}

type TraceFn = dyn Fn(Direction, &[u8]) + Send + Sync;

/// A callback invoked with every complete frame (MBAP or RTU, including headers / CRC).
#[derive(Clone)]
pub struct FrameTrace(Arc<TraceFn>);

impl FrameTrace {
    pub fn new(f: impl Fn(Direction, &[u8]) + Send + Sync + 'static) -> Self {
        FrameTrace(Arc::new(f))
    }

    /// A tracer that prints frames as hex to stderr.
    pub fn stderr(prefix: &'static str) -> Self {
        FrameTrace::new(move |dir, bytes| eprintln!("{prefix} {dir:?} {}", hex(bytes)))
    }

    pub(crate) fn emit(&self, dir: Direction, bytes: &[u8]) {
        (self.0)(dir, bytes)
    }
}

pub(crate) fn emit(trace: &Option<FrameTrace>, dir: Direction, bytes: &[u8]) {
    if let Some(t) = trace {
        t.emit(dir, bytes);
    }
}

impl fmt::Debug for FrameTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FrameTrace(..)")
    }
}

/// Format bytes as space separated upper-case hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn hex_format() {
        assert_eq!(super::hex(&[0x01, 0xAB, 0x00]), "01 AB 00");
        assert_eq!(super::hex(&[]), "");
    }
}
