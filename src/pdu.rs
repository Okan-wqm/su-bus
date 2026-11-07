//! Protocol Data Unit encoding / decoding (transport independent).
//!
//! Implemented from the public "MODBUS Application Protocol Specification".

use crate::error::{Error, ProtocolError};
use crate::types::{AddressRange, ExceptionCode};

/// Function codes supported by this crate.
pub mod function {
    pub const READ_COILS: u8 = 0x01;
    pub const READ_DISCRETE_INPUTS: u8 = 0x02;
    pub const READ_HOLDING_REGISTERS: u8 = 0x03;
    pub const READ_INPUT_REGISTERS: u8 = 0x04;
    pub const WRITE_SINGLE_COIL: u8 = 0x05;
    pub const WRITE_SINGLE_REGISTER: u8 = 0x06;
    pub const WRITE_MULTIPLE_COILS: u8 = 0x0F;
    pub const WRITE_MULTIPLE_REGISTERS: u8 = 0x10;
    pub const MASK_WRITE_REGISTER: u8 = 0x16;
    pub const READ_WRITE_MULTIPLE_REGISTERS: u8 = 0x17;
    /// Bit set in the function code of an exception response.
    pub const EXCEPTION_FLAG: u8 = 0x80;
}

/// Quantity limits from the specification (they keep every PDU <= 253 bytes).
pub mod limits {
    pub const MAX_PDU_LEN: usize = 253;
    pub const MAX_READ_BITS: u16 = 2000;
    pub const MAX_READ_REGISTERS: u16 = 125;
    pub const MAX_WRITE_BITS: u16 = 1968;
    pub const MAX_WRITE_REGISTERS: u16 = 123;
    pub const MAX_RW_WRITE_REGISTERS: u16 = 121;
}

use function as fc;
use limits::*;

const COIL_ON: u16 = 0xFF00;
const COIL_OFF: u16 = 0x0000;

/// A Modbus request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    ReadCoils(AddressRange),
    ReadDiscreteInputs(AddressRange),
    ReadHoldingRegisters(AddressRange),
    ReadInputRegisters(AddressRange),
    WriteSingleCoil {
        address: u16,
        value: bool,
    },
    WriteSingleRegister {
        address: u16,
        value: u16,
    },
    WriteMultipleCoils {
        start: u16,
        values: Vec<bool>,
    },
    WriteMultipleRegisters {
        start: u16,
        values: Vec<u16>,
    },
    /// `result = (current & and_mask) | (or_mask & !and_mask)`
    MaskWriteRegister {
        address: u16,
        and_mask: u16,
        or_mask: u16,
    },
    /// The write is performed before the read.
    ReadWriteMultipleRegisters {
        read: AddressRange,
        write_start: u16,
        values: Vec<u16>,
    },
}

/// A (non-exception) Modbus response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    ReadCoils(Vec<bool>),
    ReadDiscreteInputs(Vec<bool>),
    ReadHoldingRegisters(Vec<u16>),
    ReadInputRegisters(Vec<u16>),
    WriteSingleCoil {
        address: u16,
        value: bool,
    },
    WriteSingleRegister {
        address: u16,
        value: u16,
    },
    WriteMultipleCoils {
        start: u16,
        count: u16,
    },
    WriteMultipleRegisters {
        start: u16,
        count: u16,
    },
    MaskWriteRegister {
        address: u16,
        and_mask: u16,
        or_mask: u16,
    },
    ReadWriteMultipleRegisters(Vec<u16>),
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.data.split_first()?;
        self.data = rest;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.data.len() < n {
            return None;
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Some(head)
    }
    fn remaining(&self) -> usize {
        self.data.len()
    }
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn bit_bytes(count: usize) -> usize {
    count.div_ceil(8)
}

fn pack_bits(bits: &[bool], out: &mut Vec<u8>) {
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            if b {
                byte |= 1 << i;
            }
        }
        out.push(byte);
    }
}

fn unpack_bits(bytes: &[u8], count: usize) -> Vec<bool> {
    (0..count)
        .map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1)
        .collect()
}

fn unpack_registers(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

fn write_range(start: u16, len: usize) -> AddressRange {
    AddressRange::new(start, len.min(u16::MAX as usize) as u16)
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

impl Request {
    pub fn function_code(&self) -> u8 {
        match self {
            Request::ReadCoils(_) => fc::READ_COILS,
            Request::ReadDiscreteInputs(_) => fc::READ_DISCRETE_INPUTS,
            Request::ReadHoldingRegisters(_) => fc::READ_HOLDING_REGISTERS,
            Request::ReadInputRegisters(_) => fc::READ_INPUT_REGISTERS,
            Request::WriteSingleCoil { .. } => fc::WRITE_SINGLE_COIL,
            Request::WriteSingleRegister { .. } => fc::WRITE_SINGLE_REGISTER,
            Request::WriteMultipleCoils { .. } => fc::WRITE_MULTIPLE_COILS,
            Request::WriteMultipleRegisters { .. } => fc::WRITE_MULTIPLE_REGISTERS,
            Request::MaskWriteRegister { .. } => fc::MASK_WRITE_REGISTER,
            Request::ReadWriteMultipleRegisters { .. } => fc::READ_WRITE_MULTIPLE_REGISTERS,
        }
    }

    /// True for requests that only write (allowed as serial broadcast).
    pub fn is_write_only(&self) -> bool {
        matches!(
            self,
            Request::WriteSingleCoil { .. }
                | Request::WriteSingleRegister { .. }
                | Request::WriteMultipleCoils { .. }
                | Request::WriteMultipleRegisters { .. }
                | Request::MaskWriteRegister { .. }
        )
    }

    /// Check quantity / address limits before sending.
    pub fn validate(&self) -> Result<(), Error> {
        let ok = match self {
            Request::ReadCoils(r) | Request::ReadDiscreteInputs(r) => r.is_valid(MAX_READ_BITS),
            Request::ReadHoldingRegisters(r) | Request::ReadInputRegisters(r) => {
                r.is_valid(MAX_READ_REGISTERS)
            }
            Request::WriteSingleCoil { .. }
            | Request::WriteSingleRegister { .. }
            | Request::MaskWriteRegister { .. } => true,
            Request::WriteMultipleCoils { start, values } => {
                write_range(*start, values.len()).is_valid(MAX_WRITE_BITS)
                    && values.len() <= MAX_WRITE_BITS as usize
            }
            Request::WriteMultipleRegisters { start, values } => {
                write_range(*start, values.len()).is_valid(MAX_WRITE_REGISTERS)
                    && values.len() <= MAX_WRITE_REGISTERS as usize
            }
            Request::ReadWriteMultipleRegisters {
                read,
                write_start,
                values,
            } => {
                read.is_valid(MAX_READ_REGISTERS)
                    && write_range(*write_start, values.len()).is_valid(MAX_RW_WRITE_REGISTERS)
                    && values.len() <= MAX_RW_WRITE_REGISTERS as usize
            }
        };
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidRequest(
                "quantity out of range or address range exceeds 0xFFFF",
            ))
        }
    }

    /// Append the encoded PDU (function code + data) to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.function_code());
        match self {
            Request::ReadCoils(r)
            | Request::ReadDiscreteInputs(r)
            | Request::ReadHoldingRegisters(r)
            | Request::ReadInputRegisters(r) => {
                put_u16(out, r.start);
                put_u16(out, r.count);
            }
            Request::WriteSingleCoil { address, value } => {
                put_u16(out, *address);
                put_u16(out, if *value { COIL_ON } else { COIL_OFF });
            }
            Request::WriteSingleRegister { address, value } => {
                put_u16(out, *address);
                put_u16(out, *value);
            }
            Request::WriteMultipleCoils { start, values } => {
                put_u16(out, *start);
                put_u16(out, values.len() as u16);
                out.push(bit_bytes(values.len()) as u8);
                pack_bits(values, out);
            }
            Request::WriteMultipleRegisters { start, values } => {
                put_u16(out, *start);
                put_u16(out, values.len() as u16);
                out.push((values.len() * 2) as u8);
                values.iter().for_each(|v| put_u16(out, *v));
            }
            Request::MaskWriteRegister {
                address,
                and_mask,
                or_mask,
            } => {
                put_u16(out, *address);
                put_u16(out, *and_mask);
                put_u16(out, *or_mask);
            }
            Request::ReadWriteMultipleRegisters {
                read,
                write_start,
                values,
            } => {
                put_u16(out, read.start);
                put_u16(out, read.count);
                put_u16(out, *write_start);
                put_u16(out, values.len() as u16);
                out.push((values.len() * 2) as u8);
                values.iter().for_each(|v| put_u16(out, *v));
            }
        }
    }

    /// Decode a request PDU (server side). Errors are the exception the server should return.
    pub fn decode(pdu: &[u8]) -> Result<Request, ExceptionCode> {
        use ExceptionCode::*;
        let mut r = Reader::new(pdu);
        let code = r.u8().ok_or(IllegalFunction)?;

        // Every malformed / truncated field maps to IllegalDataValue.
        macro_rules! field {
            ($e:expr) => {
                $e.ok_or(IllegalDataValue)?
            };
        }
        let check_range = |range: AddressRange, max: u16| -> Result<AddressRange, ExceptionCode> {
            if range.count == 0 || range.count > max {
                Err(IllegalDataValue)
            } else if range.overflows() {
                Err(IllegalDataAddress)
            } else {
                Ok(range)
            }
        };

        let req = match code {
            fc::READ_COILS
            | fc::READ_DISCRETE_INPUTS
            | fc::READ_HOLDING_REGISTERS
            | fc::READ_INPUT_REGISTERS => {
                let range = AddressRange::new(field!(r.u16()), field!(r.u16()));
                let max = if code <= fc::READ_DISCRETE_INPUTS {
                    MAX_READ_BITS
                } else {
                    MAX_READ_REGISTERS
                };
                let range = check_range(range, max)?;
                match code {
                    fc::READ_COILS => Request::ReadCoils(range),
                    fc::READ_DISCRETE_INPUTS => Request::ReadDiscreteInputs(range),
                    fc::READ_HOLDING_REGISTERS => Request::ReadHoldingRegisters(range),
                    _ => Request::ReadInputRegisters(range),
                }
            }
            fc::WRITE_SINGLE_COIL => {
                let address = field!(r.u16());
                let value = match field!(r.u16()) {
                    COIL_ON => true,
                    COIL_OFF => false,
                    _ => return Err(IllegalDataValue),
                };
                Request::WriteSingleCoil { address, value }
            }
            fc::WRITE_SINGLE_REGISTER => Request::WriteSingleRegister {
                address: field!(r.u16()),
                value: field!(r.u16()),
            },
            fc::WRITE_MULTIPLE_COILS => {
                let range = AddressRange::new(field!(r.u16()), field!(r.u16()));
                let byte_count = field!(r.u8()) as usize;
                let range = check_range(range, MAX_WRITE_BITS)?;
                if byte_count != bit_bytes(range.count as usize) {
                    return Err(IllegalDataValue);
                }
                let bytes = field!(r.take(byte_count));
                Request::WriteMultipleCoils {
                    start: range.start,
                    values: unpack_bits(bytes, range.count as usize),
                }
            }
            fc::WRITE_MULTIPLE_REGISTERS => {
                let range = AddressRange::new(field!(r.u16()), field!(r.u16()));
                let byte_count = field!(r.u8()) as usize;
                let range = check_range(range, MAX_WRITE_REGISTERS)?;
                if byte_count != range.count as usize * 2 {
                    return Err(IllegalDataValue);
                }
                let bytes = field!(r.take(byte_count));
                Request::WriteMultipleRegisters {
                    start: range.start,
                    values: unpack_registers(bytes),
                }
            }
            fc::MASK_WRITE_REGISTER => Request::MaskWriteRegister {
                address: field!(r.u16()),
                and_mask: field!(r.u16()),
                or_mask: field!(r.u16()),
            },
            fc::READ_WRITE_MULTIPLE_REGISTERS => {
                let read = AddressRange::new(field!(r.u16()), field!(r.u16()));
                let write = AddressRange::new(field!(r.u16()), field!(r.u16()));
                let byte_count = field!(r.u8()) as usize;
                let read = check_range(read, MAX_READ_REGISTERS)?;
                let write = check_range(write, MAX_RW_WRITE_REGISTERS)?;
                if byte_count != write.count as usize * 2 {
                    return Err(IllegalDataValue);
                }
                let bytes = field!(r.take(byte_count));
                Request::ReadWriteMultipleRegisters {
                    read,
                    write_start: write.start,
                    values: unpack_registers(bytes),
                }
            }
            _ => return Err(IllegalFunction),
        };

        if r.remaining() != 0 {
            return Err(IllegalDataValue);
        }
        Ok(req)
    }
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

impl Response {
    pub fn function_code(&self) -> u8 {
        match self {
            Response::ReadCoils(_) => fc::READ_COILS,
            Response::ReadDiscreteInputs(_) => fc::READ_DISCRETE_INPUTS,
            Response::ReadHoldingRegisters(_) => fc::READ_HOLDING_REGISTERS,
            Response::ReadInputRegisters(_) => fc::READ_INPUT_REGISTERS,
            Response::WriteSingleCoil { .. } => fc::WRITE_SINGLE_COIL,
            Response::WriteSingleRegister { .. } => fc::WRITE_SINGLE_REGISTER,
            Response::WriteMultipleCoils { .. } => fc::WRITE_MULTIPLE_COILS,
            Response::WriteMultipleRegisters { .. } => fc::WRITE_MULTIPLE_REGISTERS,
            Response::MaskWriteRegister { .. } => fc::MASK_WRITE_REGISTER,
            Response::ReadWriteMultipleRegisters(_) => fc::READ_WRITE_MULTIPLE_REGISTERS,
        }
    }

    /// Append the encoded PDU to `out` (server side).
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.function_code());
        match self {
            Response::ReadCoils(bits) | Response::ReadDiscreteInputs(bits) => {
                out.push(bit_bytes(bits.len()) as u8);
                pack_bits(bits, out);
            }
            Response::ReadHoldingRegisters(regs)
            | Response::ReadInputRegisters(regs)
            | Response::ReadWriteMultipleRegisters(regs) => {
                out.push((regs.len() * 2) as u8);
                regs.iter().for_each(|v| put_u16(out, *v));
            }
            Response::WriteSingleCoil { address, value } => {
                put_u16(out, *address);
                put_u16(out, if *value { COIL_ON } else { COIL_OFF });
            }
            Response::WriteSingleRegister { address, value } => {
                put_u16(out, *address);
                put_u16(out, *value);
            }
            Response::WriteMultipleCoils { start, count }
            | Response::WriteMultipleRegisters { start, count } => {
                put_u16(out, *start);
                put_u16(out, *count);
            }
            Response::MaskWriteRegister {
                address,
                and_mask,
                or_mask,
            } => {
                put_u16(out, *address);
                put_u16(out, *and_mask);
                put_u16(out, *or_mask);
            }
        }
    }

    /// Append an exception response PDU to `out`.
    pub fn encode_exception(function: u8, code: ExceptionCode, out: &mut Vec<u8>) {
        out.push(function | fc::EXCEPTION_FLAG);
        out.push(code.into());
    }

    /// Decode a response PDU (client side) and verify it matches `request`.
    pub fn decode(request: &Request, pdu: &[u8]) -> Result<Response, Error> {
        let expected = request.function_code();
        let mut r = Reader::new(pdu);
        let actual = r.u8().ok_or(ProtocolError::BadLength)?;

        if actual == expected | fc::EXCEPTION_FLAG {
            let code = r.u8().ok_or(ProtocolError::BadLength)?;
            if r.remaining() != 0 {
                return Err(ProtocolError::BadLength.into());
            }
            return Err(Error::Exception(code.into()));
        }
        if actual != expected {
            return Err(ProtocolError::UnexpectedFunction { expected, actual }.into());
        }

        let bad_len = || Error::Protocol(ProtocolError::BadLength);

        let read_bits = |r: &mut Reader, count: u16| -> Result<Vec<bool>, Error> {
            let n = r.u8().ok_or_else(bad_len)? as usize;
            if n != bit_bytes(count as usize) {
                return Err(ProtocolError::BadByteCount.into());
            }
            let bytes = r.take(n).ok_or_else(bad_len)?;
            Ok(unpack_bits(bytes, count as usize))
        };
        let read_regs = |r: &mut Reader, count: u16| -> Result<Vec<u16>, Error> {
            let n = r.u8().ok_or_else(bad_len)? as usize;
            if n != count as usize * 2 {
                return Err(ProtocolError::BadByteCount.into());
            }
            let bytes = r.take(n).ok_or_else(bad_len)?;
            Ok(unpack_registers(bytes))
        };
        let echo = |cond: bool| -> Result<(), Error> {
            if cond {
                Ok(())
            } else {
                Err(ProtocolError::EchoMismatch.into())
            }
        };

        let resp = match request {
            Request::ReadCoils(range) => Response::ReadCoils(read_bits(&mut r, range.count)?),
            Request::ReadDiscreteInputs(range) => {
                Response::ReadDiscreteInputs(read_bits(&mut r, range.count)?)
            }
            Request::ReadHoldingRegisters(range) => {
                Response::ReadHoldingRegisters(read_regs(&mut r, range.count)?)
            }
            Request::ReadInputRegisters(range) => {
                Response::ReadInputRegisters(read_regs(&mut r, range.count)?)
            }
            Request::ReadWriteMultipleRegisters { read, .. } => {
                Response::ReadWriteMultipleRegisters(read_regs(&mut r, read.count)?)
            }
            Request::WriteSingleCoil { address, value } => {
                let a = r.u16().ok_or_else(bad_len)?;
                let v = r.u16().ok_or_else(bad_len)?;
                echo(a == *address && v == if *value { COIL_ON } else { COIL_OFF })?;
                Response::WriteSingleCoil {
                    address: a,
                    value: *value,
                }
            }
            Request::WriteSingleRegister { address, value } => {
                let a = r.u16().ok_or_else(bad_len)?;
                let v = r.u16().ok_or_else(bad_len)?;
                echo(a == *address && v == *value)?;
                Response::WriteSingleRegister {
                    address: a,
                    value: v,
                }
            }
            Request::WriteMultipleCoils { start, values } => {
                let s = r.u16().ok_or_else(bad_len)?;
                let c = r.u16().ok_or_else(bad_len)?;
                echo(s == *start && c as usize == values.len())?;
                Response::WriteMultipleCoils { start: s, count: c }
            }
            Request::WriteMultipleRegisters { start, values } => {
                let s = r.u16().ok_or_else(bad_len)?;
                let c = r.u16().ok_or_else(bad_len)?;
                echo(s == *start && c as usize == values.len())?;
                Response::WriteMultipleRegisters { start: s, count: c }
            }
            Request::MaskWriteRegister {
                address,
                and_mask,
                or_mask,
            } => {
                let a = r.u16().ok_or_else(bad_len)?;
                let am = r.u16().ok_or_else(bad_len)?;
                let om = r.u16().ok_or_else(bad_len)?;
                echo(a == *address && am == *and_mask && om == *or_mask)?;
                Response::MaskWriteRegister {
                    address: a,
                    and_mask: am,
                    or_mask: om,
                }
            }
        };

        if r.remaining() != 0 {
            return Err(bad_len());
        }
        Ok(resp)
    }
}

/// Apply the mask-write formula from the specification.
pub fn apply_mask(current: u16, and_mask: u16, or_mask: u16) -> u16 {
    (current & and_mask) | (or_mask & !and_mask)
}

// ---------------------------------------------------------------------------
// length prediction (needed by the RTU framer, which has no length field)
// ---------------------------------------------------------------------------

/// Result of predicting a PDU's length from its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PduLen {
    /// At least this many PDU bytes are needed before the length can be known.
    NeedAtLeast(usize),
    /// The PDU is exactly this long.
    Exact(usize),
    /// Unknown function code, or impossible length.
    Unknown,
}

fn bounded(n: usize) -> PduLen {
    if n <= MAX_PDU_LEN {
        PduLen::Exact(n)
    } else {
        PduLen::Unknown
    }
}

/// Predict the length of a request PDU.
pub(crate) fn request_len(pdu: &[u8]) -> PduLen {
    let Some(&code) = pdu.first() else {
        return PduLen::NeedAtLeast(1);
    };
    match code {
        fc::READ_COILS..=fc::WRITE_SINGLE_REGISTER => PduLen::Exact(5),
        fc::WRITE_MULTIPLE_COILS | fc::WRITE_MULTIPLE_REGISTERS => match pdu.get(5) {
            Some(&n) => bounded(6 + n as usize),
            None => PduLen::NeedAtLeast(6),
        },
        fc::MASK_WRITE_REGISTER => PduLen::Exact(7),
        fc::READ_WRITE_MULTIPLE_REGISTERS => match pdu.get(9) {
            Some(&n) => bounded(10 + n as usize),
            None => PduLen::NeedAtLeast(10),
        },
        _ => PduLen::Unknown,
    }
}

/// Predict the length of a response PDU.
pub(crate) fn response_len(pdu: &[u8]) -> PduLen {
    let Some(&code) = pdu.first() else {
        return PduLen::NeedAtLeast(1);
    };
    if code & fc::EXCEPTION_FLAG != 0 {
        return PduLen::Exact(2);
    }
    match code {
        fc::READ_COILS..=fc::READ_INPUT_REGISTERS | fc::READ_WRITE_MULTIPLE_REGISTERS => {
            match pdu.get(1) {
                Some(&n) => bounded(2 + n as usize),
                None => PduLen::NeedAtLeast(2),
            }
        }
        fc::WRITE_SINGLE_COIL
        | fc::WRITE_SINGLE_REGISTER
        | fc::WRITE_MULTIPLE_COILS
        | fc::WRITE_MULTIPLE_REGISTERS => PduLen::Exact(5),
        fc::MASK_WRITE_REGISTER => PduLen::Exact(7),
        _ => PduLen::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_req(r: &Request) -> Vec<u8> {
        let mut v = Vec::new();
        r.encode(&mut v);
        v
    }

    #[test]
    fn read_holding_request_bytes() {
        let r = Request::ReadHoldingRegisters(AddressRange::new(0x006B, 3));
        assert_eq!(enc_req(&r), [0x03, 0x00, 0x6B, 0x00, 0x03]);
    }

    #[test]
    fn write_multiple_coils_request_bytes() {
        // 10 coils starting at 19: 1,0,1,1,0,0,1,1, 1,0
        let values = vec![
            true, false, true, true, false, false, true, true, true, false,
        ];
        let r = Request::WriteMultipleCoils {
            start: 0x0013,
            values,
        };
        assert_eq!(
            enc_req(&r),
            [0x0F, 0x00, 0x13, 0x00, 0x0A, 0x02, 0xCD, 0x01]
        );
    }

    #[test]
    fn every_request_roundtrips() {
        let reqs = vec![
            Request::ReadCoils(AddressRange::new(1, 2000)),
            Request::ReadDiscreteInputs(AddressRange::new(0, 9)),
            Request::ReadHoldingRegisters(AddressRange::new(10, 125)),
            Request::ReadInputRegisters(AddressRange::new(0xFFFF, 1)),
            Request::WriteSingleCoil {
                address: 7,
                value: true,
            },
            Request::WriteSingleRegister {
                address: 7,
                value: 0xBEEF,
            },
            Request::WriteMultipleCoils {
                start: 3,
                values: vec![true; 17],
            },
            Request::WriteMultipleRegisters {
                start: 3,
                values: vec![1, 2, 3],
            },
            Request::MaskWriteRegister {
                address: 4,
                and_mask: 0xF2,
                or_mask: 0x25,
            },
            Request::ReadWriteMultipleRegisters {
                read: AddressRange::new(3, 6),
                write_start: 14,
                values: vec![0xFF, 0xFF, 0xFF],
            },
        ];
        for req in reqs {
            req.validate().unwrap();
            let pdu = enc_req(&req);
            assert_eq!(request_len(&pdu), PduLen::Exact(pdu.len()), "{req:?}");
            assert_eq!(Request::decode(&pdu).unwrap(), req);
        }
    }

    #[test]
    fn request_validation() {
        assert!(Request::ReadCoils(AddressRange::new(0, 0))
            .validate()
            .is_err());
        assert!(Request::ReadCoils(AddressRange::new(0, 2001))
            .validate()
            .is_err());
        assert!(Request::ReadHoldingRegisters(AddressRange::new(0xFFFF, 2))
            .validate()
            .is_err());
        assert!(Request::WriteMultipleRegisters {
            start: 0,
            values: vec![]
        }
        .validate()
        .is_err());
        assert!(Request::WriteMultipleRegisters {
            start: 0,
            values: vec![0; 124]
        }
        .validate()
        .is_err());
    }

    #[test]
    fn request_decode_errors() {
        use ExceptionCode::*;
        assert_eq!(Request::decode(&[0x2B, 0x0E]), Err(IllegalFunction));
        assert_eq!(Request::decode(&[0x03, 0, 0, 0, 0]), Err(IllegalDataValue));
        assert_eq!(
            Request::decode(&[0x03, 0, 0, 0, 126]),
            Err(IllegalDataValue)
        );
        assert_eq!(
            Request::decode(&[0x03, 0xFF, 0xFF, 0, 2]),
            Err(IllegalDataAddress)
        );
        assert_eq!(Request::decode(&[0x03, 0, 0, 0]), Err(IllegalDataValue));
        assert_eq!(
            Request::decode(&[0x03, 0, 0, 0, 1, 9]),
            Err(IllegalDataValue)
        );
        assert_eq!(
            Request::decode(&[0x05, 0, 0, 0x12, 0x34]),
            Err(IllegalDataValue)
        );
        // byte count mismatch
        assert_eq!(
            Request::decode(&[0x10, 0, 0, 0, 1, 3, 0, 0, 0]),
            Err(IllegalDataValue)
        );
    }

    #[test]
    fn response_roundtrip_and_validation() {
        let req = Request::ReadCoils(AddressRange::new(0, 10));
        let resp = Response::ReadCoils(vec![
            true, false, true, false, false, false, false, false, true, true,
        ]);
        let mut pdu = Vec::new();
        resp.encode(&mut pdu);
        assert_eq!(pdu, [0x01, 0x02, 0x05, 0x03]);
        assert_eq!(response_len(&pdu), PduLen::Exact(pdu.len()));
        assert_eq!(Response::decode(&req, &pdu).unwrap(), resp);

        // byte count for a different quantity
        let other = Request::ReadCoils(AddressRange::new(0, 20));
        assert!(matches!(
            Response::decode(&other, &pdu),
            Err(Error::Protocol(ProtocolError::BadByteCount))
        ));

        // exception
        assert!(matches!(
            Response::decode(&req, &[0x81, 0x02]),
            Err(Error::Exception(ExceptionCode::IllegalDataAddress))
        ));

        // wrong function
        assert!(matches!(
            Response::decode(&req, &[0x03, 0x00]),
            Err(Error::Protocol(ProtocolError::UnexpectedFunction { .. }))
        ));

        // echo mismatch
        let w = Request::WriteSingleRegister {
            address: 1,
            value: 2,
        };
        assert!(matches!(
            Response::decode(&w, &[0x06, 0, 1, 0, 3]),
            Err(Error::Protocol(ProtocolError::EchoMismatch))
        ));
    }

    #[test]
    fn mask_formula() {
        // example values from the specification
        assert_eq!(apply_mask(0x12, 0xF2, 0x25), 0x17);
    }
}
