//! Transport framing: MBAP (Modbus TCP) and RTU (serial, CRC-16).

use crate::error::ProtocolError;
use crate::pdu::{limits::MAX_PDU_LEN, PduLen};
use tokio::io::{AsyncRead, AsyncReadExt};

/// How PDUs are wrapped on the wire.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Framing {
    /// MBAP header (transaction id, protocol id, length, unit id). Standard Modbus TCP.
    Tcp,
    /// Unit id + PDU + CRC-16. Used on serial lines, and for "RTU over TCP" gateways.
    Rtu,
}

// ---------------------------------------------------------------------------
// CRC-16 (polynomial 0xA001 reflected, init 0xFFFF)
// ---------------------------------------------------------------------------

const fn make_crc_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u16;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC_TABLE: [u16; 256] = make_crc_table();

/// Modbus RTU CRC-16. Transmitted low byte first.
pub fn crc16(data: &[u8]) -> u16 {
    data.iter().fold(0xFFFF, |crc, &b| {
        (crc >> 8) ^ CRC_TABLE[((crc ^ b as u16) & 0xFF) as usize]
    })
}

fn crc_ok(frame: &[u8]) -> bool {
    if frame.len() < 4 {
        return false;
    }
    let (body, tail) = frame.split_at(frame.len() - 2);
    crc16(body) == u16::from_le_bytes([tail[0], tail[1]])
}

/// Build a complete RTU frame.
pub fn encode_rtu(unit: u8, pdu: &[u8], out: &mut Vec<u8>) {
    let start = out.len();
    out.push(unit);
    out.extend_from_slice(pdu);
    let crc = crc16(&out[start..]);
    out.extend_from_slice(&crc.to_le_bytes());
}

// ---------------------------------------------------------------------------
// MBAP
// ---------------------------------------------------------------------------

pub(crate) const MBAP_HEADER_LEN: usize = 7;

/// Build a complete MBAP frame.
pub fn encode_mbap(transaction: u16, unit: u8, pdu: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&transaction.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
    out.push(unit);
    out.extend_from_slice(pdu);
}

/// A decoded MBAP frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MbapFrame {
    pub transaction: u16,
    pub unit: u8,
    pub pdu: Vec<u8>,
}

/// Outcome of reading an MBAP frame.
pub(crate) enum MbapRead {
    Frame(MbapFrame),
    /// The peer sent a header that cannot be resynchronised; the connection should be closed.
    Invalid(ProtocolError),
}

/// Read one MBAP frame from a stream.
pub(crate) async fn read_mbap<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
) -> std::io::Result<MbapRead> {
    let mut hdr = [0u8; MBAP_HEADER_LEN];
    stream.read_exact(&mut hdr).await?;
    let transaction = u16::from_be_bytes([hdr[0], hdr[1]]);
    let protocol = u16::from_be_bytes([hdr[2], hdr[3]]);
    let length = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
    let unit = hdr[6];
    if protocol != 0 || !(2..=MAX_PDU_LEN + 1).contains(&length) {
        return Ok(MbapRead::Invalid(ProtocolError::BadMbapHeader));
    }
    let mut pdu = vec![0u8; length - 1];
    stream.read_exact(&mut pdu).await?;
    Ok(MbapRead::Frame(MbapFrame {
        transaction,
        unit,
        pdu,
    }))
}

// ---------------------------------------------------------------------------
// RTU stream reassembly
// ---------------------------------------------------------------------------

/// Reassembles RTU frames from an arbitrary byte stream.
///
/// RTU has no length field, so the expected length is predicted from the function
/// code. Garbage (bad CRC, unknown function) is skipped one byte at a time until a
/// valid frame lines up again.
pub(crate) struct RtuBuffer {
    buf: Vec<u8>,
    /// True when `buf` starts at a frame boundary (start, after a frame, after silence).
    /// False while resynchronising after garbage.
    at_boundary: bool,
}

impl Default for RtuBuffer {
    fn default() -> Self {
        RtuBuffer {
            buf: Vec::new(),
            at_boundary: true,
        }
    }
}

/// One RTU frame: unit id and PDU (CRC already checked and removed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RtuFrame {
    pub unit: u8,
    pub pdu: Vec<u8>,
}

impl RtuBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.at_boundary = true;
    }

    fn skip_byte(&mut self) {
        self.buf.remove(0);
        self.at_boundary = false;
    }

    pub fn extend(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        // Never grow unbounded on a noisy line.
        const MAX_BUFFER: usize = 4 * (MAX_PDU_LEN + 3);
        if self.buf.len() > MAX_BUFFER {
            let excess = self.buf.len() - MAX_BUFFER;
            self.buf.drain(..excess);
            self.at_boundary = false;
        }
    }

    /// Extract the next complete frame, skipping garbage. `None` means more bytes are needed.
    ///
    /// With `skip_unknown`, a byte sequence whose function code cannot be sized is
    /// discarded immediately (client side: we know what we expect). Otherwise it is kept
    /// until line silence (server side: we may still want to answer "illegal function").
    pub fn next_frame(
        &mut self,
        predict: fn(&[u8]) -> PduLen,
        skip_unknown: bool,
    ) -> Option<RtuFrame> {
        loop {
            if self.buf.len() < 2 {
                return None;
            }
            match predict(&self.buf[1..]) {
                PduLen::NeedAtLeast(_) => return None,
                PduLen::Exact(n) => {
                    let total = 1 + n + 2;
                    if self.buf.len() < total {
                        return None;
                    }
                    if crc_ok(&self.buf[..total]) {
                        let frame = RtuFrame {
                            unit: self.buf[0],
                            pdu: self.buf[1..1 + n].to_vec(),
                        };
                        self.buf.drain(..total);
                        self.at_boundary = true;
                        return Some(frame);
                    }
                    self.skip_byte();
                }
                PduLen::Unknown => {
                    // At a frame boundary this may be a valid request with a function
                    // code we cannot size: wait for line silence (`take_on_silence`).
                    // While resynchronising it is just garbage: skip it.
                    if skip_unknown || !self.at_boundary || self.buf.len() >= MAX_PDU_LEN + 3 {
                        self.skip_byte();
                    } else {
                        return None;
                    }
                }
            }
        }
    }

    /// Called after the line has been silent: treat whatever is buffered as one frame if
    /// its CRC is valid (this is how unknown function codes are still answered), then clear.
    pub fn take_on_silence(&mut self) -> Option<RtuFrame> {
        let frame = if crc_ok(&self.buf) {
            Some(RtuFrame {
                unit: self.buf[0],
                pdu: self.buf[1..self.buf.len() - 2].to_vec(),
            })
        } else {
            None
        };
        self.clear();
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{request_len, response_len};

    #[test]
    fn crc_known_vector() {
        // 01 03 00 00 00 0A -> CRC bytes C5 CD
        let mut out = Vec::new();
        encode_rtu(0x01, &[0x03, 0x00, 0x00, 0x00, 0x0A], &mut out);
        assert_eq!(out, [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD]);
    }

    #[test]
    fn mbap_layout() {
        let mut out = Vec::new();
        encode_mbap(0x1234, 0x11, &[0x03, 0x00, 0x6B, 0x00, 0x03], &mut out);
        assert_eq!(
            out,
            [0x12, 0x34, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6B, 0x00, 0x03]
        );
    }

    #[test]
    fn rtu_reassembly_with_garbage_and_split_reads() {
        let mut f1 = Vec::new();
        encode_rtu(1, &[0x03, 0x00, 0x00, 0x00, 0x0A], &mut f1);
        let mut f2 = Vec::new();
        encode_rtu(
            2,
            &[0x10, 0x00, 0x01, 0x00, 0x01, 0x02, 0xAB, 0xCD],
            &mut f2,
        );

        let mut stream = vec![0x01, 0x03, 0x77]; // noise
        stream.extend(&f1);
        stream.extend(&f2);

        let mut rb = RtuBuffer::new();
        let mut frames = Vec::new();
        for b in stream {
            rb.extend(&[b]);
            while let Some(f) = rb.next_frame(request_len, false) {
                frames.push(f);
            }
        }
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].unit, 1);
        assert_eq!(frames[1].unit, 2);
        assert_eq!(frames[1].pdu[0], 0x10);
        assert!(rb.is_empty());
    }

    #[test]
    fn rtu_response_and_silence() {
        let mut f = Vec::new();
        encode_rtu(5, &[0x83, 0x02], &mut f);
        let mut rb = RtuBuffer::new();
        rb.extend(&f);
        assert_eq!(rb.next_frame(response_len, true).unwrap().pdu, [0x83, 0x02]);

        // unknown function code: only recoverable on silence
        let mut f = Vec::new();
        encode_rtu(5, &[0x2B, 0x0E, 0x01, 0x00], &mut f);
        rb.extend(&f);
        assert!(rb.next_frame(request_len, false).is_none());
        assert_eq!(rb.take_on_silence().unwrap().pdu, [0x2B, 0x0E, 0x01, 0x00]);
    }
}
