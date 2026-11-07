//! Protocol Data Unit encoding / decoding (transport independent).
//!
//! Implemented from the public "MODBUS Application Protocol Specification".

use crate::device_id::{DeviceIdCode, DeviceIdResponse};
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
    pub const READ_EXCEPTION_STATUS: u8 = 0x07;
    pub const DIAGNOSTICS: u8 = 0x08;
    pub const GET_COMM_EVENT_COUNTER: u8 = 0x0B;
    pub const WRITE_MULTIPLE_COILS: u8 = 0x0F;
    pub const WRITE_MULTIPLE_REGISTERS: u8 = 0x10;
    pub const MASK_WRITE_REGISTER: u8 = 0x16;
    pub const READ_WRITE_MULTIPLE_REGISTERS: u8 = 0x17;
    pub const REPORT_SERVER_ID: u8 = 0x11;
    pub const READ_FIFO_QUEUE: u8 = 0x18;
    pub const ENCAPSULATED_INTERFACE: u8 = 0x2B;
    /// MEI type for "Read Device Identification" inside function 0x2B.
    pub const MEI_READ_DEVICE_ID: u8 = 0x0E;
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
    pub const MAX_FIFO_COUNT: usize = 31;
    /// Diagnostics data words that fit after function + sub-function.
    pub const MAX_DIAGNOSTIC_WORDS: usize = (MAX_PDU_LEN - 3) / 2;
    /// Payload bytes of a user-defined function (everything after the function code).
    pub const MAX_CUSTOM_DATA: usize = MAX_PDU_LEN - 1;
    /// Bytes of a "report server id" payload (after function code and byte count).
    pub const MAX_SERVER_ID_LEN: usize = MAX_PDU_LEN - 2;
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
    /// FC 0x07 (serial devices): eight device-specific status bits.
    ReadExceptionStatus,
    /// FC 0x08 with a sub-function and its data words.
    Diagnostics {
        sub_function: u16,
        data: Vec<u16>,
    },
    /// FC 0x0B: status word and successful-message event counter.
    GetCommEventCounter,
    /// FC 0x11: device-specific identification bytes.
    ReportServerId,
    /// FC 0x18: read the queue at `address` (count register followed by up to 31 values).
    ReadFifoQueue {
        address: u16,
    },
    /// FC 0x2B / MEI 0x0E.
    ReadDeviceIdentification {
        code: DeviceIdCode,
        object_id: u8,
    },
    /// Any other function code (e.g. user-defined 65-72, 100-110), passed through raw.
    Custom {
        function: u8,
        data: Vec<u8>,
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
    ReadExceptionStatus(u8),
    Diagnostics {
        sub_function: u16,
        data: Vec<u16>,
    },
    GetCommEventCounter {
        status: u16,
        event_count: u16,
    },
    ReportServerId(Vec<u8>),
    ReadFifoQueue(Vec<u16>),
    ReadDeviceIdentification(DeviceIdResponse),
    Custom {
        function: u8,
        data: Vec<u8>,
    },
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
            Request::ReadExceptionStatus => fc::READ_EXCEPTION_STATUS,
            Request::Diagnostics { .. } => fc::DIAGNOSTICS,
            Request::GetCommEventCounter => fc::GET_COMM_EVENT_COUNTER,
            Request::ReportServerId => fc::REPORT_SERVER_ID,
            Request::ReadFifoQueue { .. } => fc::READ_FIFO_QUEUE,
            Request::ReadDeviceIdentification { .. } => fc::ENCAPSULATED_INTERFACE,
            Request::Custom { function, .. } => *function,
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
            Request::ReadExceptionStatus
            | Request::GetCommEventCounter
            | Request::ReportServerId
            | Request::ReadFifoQueue { .. }
            | Request::ReadDeviceIdentification { .. } => true,
            Request::Diagnostics { data, .. } => data.len() <= MAX_DIAGNOSTIC_WORDS,
            Request::Custom { function, data } => {
                if *function == 0 || *function & fc::EXCEPTION_FLAG != 0 {
                    return Err(Error::InvalidRequest(
                        "custom function code must be in 1..=127",
                    ));
                }
                data.len() <= MAX_CUSTOM_DATA
            }
        };
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidRequest(
                "quantity out of range, address range exceeds 0xFFFF or PDU too long",
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
            Request::ReadExceptionStatus
            | Request::GetCommEventCounter
            | Request::ReportServerId => {}
            Request::Diagnostics { sub_function, data } => {
                put_u16(out, *sub_function);
                data.iter().for_each(|v| put_u16(out, *v));
            }
            Request::ReadFifoQueue { address } => put_u16(out, *address),
            Request::ReadDeviceIdentification { code, object_id } => {
                out.push(fc::MEI_READ_DEVICE_ID);
                out.push(code.to_u8());
                out.push(*object_id);
            }
            Request::Custom { data, .. } => out.extend_from_slice(data),
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
            fc::READ_EXCEPTION_STATUS => Request::ReadExceptionStatus,
            fc::GET_COMM_EVENT_COUNTER => Request::GetCommEventCounter,
            fc::REPORT_SERVER_ID => Request::ReportServerId,
            fc::DIAGNOSTICS => {
                let sub_function = field!(r.u16());
                let rest = field!(r.take(r.remaining()));
                if rest.len() % 2 != 0 {
                    return Err(IllegalDataValue);
                }
                Request::Diagnostics {
                    sub_function,
                    data: unpack_registers(rest),
                }
            }
            fc::READ_FIFO_QUEUE => Request::ReadFifoQueue {
                address: field!(r.u16()),
            },
            fc::ENCAPSULATED_INTERFACE => {
                let mei = field!(r.u8());
                if mei != fc::MEI_READ_DEVICE_ID {
                    return Err(IllegalFunction);
                }
                let code = DeviceIdCode::from_u8(field!(r.u8())).ok_or(IllegalDataValue)?;
                Request::ReadDeviceIdentification {
                    code,
                    object_id: field!(r.u8()),
                }
            }
            function if function & fc::EXCEPTION_FLAG == 0 && function != 0 => Request::Custom {
                function,
                data: field!(r.take(r.remaining())).to_vec(),
            },
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
            Response::ReadExceptionStatus(_) => fc::READ_EXCEPTION_STATUS,
            Response::Diagnostics { .. } => fc::DIAGNOSTICS,
            Response::GetCommEventCounter { .. } => fc::GET_COMM_EVENT_COUNTER,
            Response::ReportServerId(_) => fc::REPORT_SERVER_ID,
            Response::ReadFifoQueue(_) => fc::READ_FIFO_QUEUE,
            Response::ReadDeviceIdentification(_) => fc::ENCAPSULATED_INTERFACE,
            Response::Custom { function, .. } => *function,
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
            Response::ReadExceptionStatus(status) => out.push(*status),
            Response::Diagnostics { sub_function, data } => {
                put_u16(out, *sub_function);
                data.iter().for_each(|v| put_u16(out, *v));
            }
            Response::GetCommEventCounter {
                status,
                event_count,
            } => {
                put_u16(out, *status);
                put_u16(out, *event_count);
            }
            Response::ReportServerId(bytes) => {
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            }
            Response::ReadFifoQueue(values) => {
                put_u16(out, (2 + values.len() * 2) as u16);
                put_u16(out, values.len() as u16);
                values.iter().for_each(|v| put_u16(out, *v));
            }
            Response::ReadDeviceIdentification(d) => {
                out.push(fc::MEI_READ_DEVICE_ID);
                out.push(d.code.to_u8());
                out.push(d.conformity_level);
                out.push(if d.more_follows { 0xFF } else { 0x00 });
                out.push(d.next_object_id);
                out.push(d.objects.len() as u8);
                for (id, value) in &d.objects {
                    out.push(*id);
                    out.push(value.len() as u8);
                    out.extend_from_slice(value);
                }
            }
            Response::Custom { data, .. } => out.extend_from_slice(data),
        }
    }

    /// Encoded length of this response PDU.
    pub fn encoded_len(&self) -> usize {
        let mut v = Vec::with_capacity(MAX_PDU_LEN);
        self.encode(&mut v);
        v.len()
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
            Request::ReadExceptionStatus => {
                Response::ReadExceptionStatus(r.u8().ok_or_else(bad_len)?)
            }
            Request::GetCommEventCounter => Response::GetCommEventCounter {
                status: r.u16().ok_or_else(bad_len)?,
                event_count: r.u16().ok_or_else(bad_len)?,
            },
            Request::Diagnostics { sub_function, data } => {
                let sub = r.u16().ok_or_else(bad_len)?;
                let rest = r.take(r.remaining()).ok_or_else(bad_len)?;
                if rest.len() % 2 != 0 {
                    return Err(bad_len());
                }
                let words = unpack_registers(rest);
                // "Return query data" must echo the request verbatim.
                echo(sub == *sub_function && (*sub_function != 0 || words == *data))?;
                Response::Diagnostics {
                    sub_function: sub,
                    data: words,
                }
            }
            Request::ReportServerId => {
                let n = r.u8().ok_or_else(bad_len)? as usize;
                if n != r.remaining() {
                    return Err(ProtocolError::BadByteCount.into());
                }
                Response::ReportServerId(r.take(n).ok_or_else(bad_len)?.to_vec())
            }
            Request::ReadFifoQueue { .. } => {
                let byte_count = r.u16().ok_or_else(bad_len)? as usize;
                let count = r.u16().ok_or_else(bad_len)? as usize;
                if count > MAX_FIFO_COUNT || byte_count != 2 + count * 2 {
                    return Err(ProtocolError::BadByteCount.into());
                }
                let bytes = r.take(count * 2).ok_or_else(bad_len)?;
                Response::ReadFifoQueue(unpack_registers(bytes))
            }
            Request::ReadDeviceIdentification { code, object_id } => {
                let mei = r.u8().ok_or_else(bad_len)?;
                let echoed = r.u8().ok_or_else(bad_len)?;
                echo(mei == fc::MEI_READ_DEVICE_ID && echoed == code.to_u8())?;
                let conformity_level = r.u8().ok_or_else(bad_len)?;
                let more_follows = match r.u8().ok_or_else(bad_len)? {
                    0x00 => false,
                    0xFF => true,
                    _ => return Err(ProtocolError::Malformed("more-follows flag").into()),
                };
                let next_object_id = r.u8().ok_or_else(bad_len)?;
                let n = r.u8().ok_or_else(bad_len)?;
                let mut objects = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let id = r.u8().ok_or_else(bad_len)?;
                    let len = r.u8().ok_or_else(bad_len)? as usize;
                    objects.push((id, r.take(len).ok_or_else(bad_len)?.to_vec()));
                }
                if *code == DeviceIdCode::Specific
                    && (more_follows || objects.len() != 1 || objects[0].0 != *object_id)
                {
                    return Err(ProtocolError::Malformed("individual device id access").into());
                }
                if more_follows && objects.last().is_some_and(|o| next_object_id <= o.0) {
                    return Err(ProtocolError::Malformed("next object id").into());
                }
                Response::ReadDeviceIdentification(DeviceIdResponse {
                    code: *code,
                    conformity_level,
                    more_follows,
                    next_object_id,
                    objects,
                })
            }
            Request::Custom { function, .. } => Response::Custom {
                function: *function,
                data: r.take(r.remaining()).ok_or_else(bad_len)?.to_vec(),
            },
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
        fc::READ_EXCEPTION_STATUS | fc::GET_COMM_EVENT_COUNTER | fc::REPORT_SERVER_ID => {
            PduLen::Exact(1)
        }
        fc::DIAGNOSTICS => match pdu.get(1..3) {
            // Standard sub-functions carry one data word. "Return query data" (0x0000) and
            // device-specific sub-functions carry arbitrary data: only line silence ends them.
            Some(b) if is_standard_diagnostic(u16::from_be_bytes([b[0], b[1]])) => PduLen::Exact(5),
            Some(_) => PduLen::Unknown,
            None => PduLen::NeedAtLeast(3),
        },
        fc::READ_FIFO_QUEUE => PduLen::Exact(3),
        fc::ENCAPSULATED_INTERFACE => match pdu.get(1) {
            Some(&fc::MEI_READ_DEVICE_ID) => PduLen::Exact(4),
            Some(_) => PduLen::Unknown,
            None => PduLen::NeedAtLeast(2),
        },
        _ => PduLen::Unknown,
    }
}

/// Sub-functions 0x01..=0x15 defined by the specification, each with a single data word.
fn is_standard_diagnostic(sub: u16) -> bool {
    (0x01..=0x15).contains(&sub)
}

/// True when the response length cannot be derived, so an RTU client must wait for silence.
pub(crate) fn response_needs_silence(request: &Request) -> bool {
    match request {
        Request::Custom { .. } => true,
        Request::Diagnostics { sub_function, .. } => {
            *sub_function != 0 && !is_standard_diagnostic(*sub_function)
        }
        _ => false,
    }
}

/// Predict the length of the response to `request` (client side). More precise than
/// [`response_len`] because the request is known (e.g. diagnostics echo their request).
pub(crate) fn response_len_for(request: &Request, pdu: &[u8]) -> PduLen {
    match pdu.first() {
        None => PduLen::NeedAtLeast(1),
        Some(&code) if code & fc::EXCEPTION_FLAG != 0 => PduLen::Exact(2),
        Some(_) => match request {
            _ if response_needs_silence(request) => PduLen::Unknown,
            // standard diagnostics echo the shape of their request
            Request::Diagnostics { data, .. } => bounded(3 + data.len() * 2),
            _ => response_len(pdu),
        },
    }
}

fn device_id_response_len(pdu: &[u8]) -> PduLen {
    const HEADER: usize = 7;
    if pdu.len() < HEADER {
        return PduLen::NeedAtLeast(HEADER);
    }
    if pdu[1] != fc::MEI_READ_DEVICE_ID {
        return PduLen::Unknown;
    }
    let mut pos = HEADER;
    for _ in 0..pdu[6] {
        let Some(&len) = pdu.get(pos + 1) else {
            return PduLen::NeedAtLeast(pos + 2);
        };
        pos += 2 + len as usize;
        if pos > MAX_PDU_LEN {
            return PduLen::Unknown;
        }
    }
    bounded(pos)
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
        fc::READ_EXCEPTION_STATUS => PduLen::Exact(2),
        fc::GET_COMM_EVENT_COUNTER => PduLen::Exact(5),
        fc::REPORT_SERVER_ID => match pdu.get(1) {
            Some(&n) => bounded(2 + n as usize),
            None => PduLen::NeedAtLeast(2),
        },
        fc::READ_FIFO_QUEUE => match pdu.get(1..3) {
            Some(b) => bounded(3 + u16::from_be_bytes([b[0], b[1]]) as usize),
            None => PduLen::NeedAtLeast(3),
        },
        fc::ENCAPSULATED_INTERFACE => device_id_response_len(pdu),
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
        assert_eq!(Request::decode(&[0x2B, 0x0E]), Err(IllegalDataValue));
        assert_eq!(Request::decode(&[0x2B, 0x0D, 1, 0]), Err(IllegalFunction));
        assert_eq!(Request::decode(&[0x2B, 0x0E, 5, 0]), Err(IllegalDataValue));
        assert_eq!(Request::decode(&[0x08, 0, 0, 1]), Err(IllegalDataValue));
        assert_eq!(Request::decode(&[0x07, 0]), Err(IllegalDataValue));
        assert_eq!(Request::decode(&[0x83, 0]), Err(IllegalFunction));
        assert_eq!(Request::decode(&[]), Err(IllegalFunction));
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

    fn enc_resp(r: &Response) -> Vec<u8> {
        let mut v = Vec::new();
        r.encode(&mut v);
        v
    }

    #[test]
    fn extended_requests_roundtrip() {
        let reqs = vec![
            Request::ReadExceptionStatus,
            Request::GetCommEventCounter,
            Request::ReportServerId,
            Request::Diagnostics {
                sub_function: 0x000B,
                data: vec![0],
            },
            Request::ReadFifoQueue { address: 0x04DE },
            Request::ReadDeviceIdentification {
                code: DeviceIdCode::Regular,
                object_id: 3,
            },
            Request::Custom {
                function: 0x41,
                data: vec![1, 2, 3],
            },
        ];
        for req in reqs {
            req.validate().unwrap();
            let pdu = enc_req(&req);
            let expected = if matches!(req, Request::Custom { .. }) {
                PduLen::Unknown // only line silence ends a custom frame
            } else {
                PduLen::Exact(pdu.len())
            };
            assert_eq!(request_len(&pdu), expected, "{req:?}");
            assert_eq!(Request::decode(&pdu).unwrap(), req);
        }
        // "return query data" has no predictable length
        let echo = Request::Diagnostics {
            sub_function: 0,
            data: vec![0xA537, 0x1234],
        };
        let pdu = enc_req(&echo);
        assert_eq!(pdu, [0x08, 0, 0, 0xA5, 0x37, 0x12, 0x34]);
        assert_eq!(request_len(&pdu), PduLen::Unknown);
        assert_eq!(Request::decode(&pdu).unwrap(), echo);
        assert_eq!(
            enc_req(&Request::ReadDeviceIdentification {
                code: DeviceIdCode::Basic,
                object_id: 0
            }),
            [0x2B, 0x0E, 0x01, 0x00]
        );
    }

    #[test]
    fn diagnostics_length_prediction() {
        // standard sub-function: one data word
        assert_eq!(request_len(&[0x08, 0x00, 0x0B, 0, 0]), PduLen::Exact(5));
        // return query data and device-specific sub-functions: unknown length
        assert_eq!(request_len(&[0x08, 0x00, 0x00, 1, 2]), PduLen::Unknown);
        assert_eq!(
            request_len(&[0x08, 0x01, 0x00, 1, 2, 3, 4]),
            PduLen::Unknown
        );
        let custom_sub = Request::Diagnostics {
            sub_function: 0x0100,
            data: vec![1, 2],
        };
        assert!(response_needs_silence(&custom_sub));
        assert_eq!(response_len_for(&custom_sub, &[0x08]), PduLen::Unknown);
        let echo = Request::Diagnostics {
            sub_function: 0,
            data: vec![1, 2],
        };
        assert!(!response_needs_silence(&echo));
        assert_eq!(response_len_for(&echo, &[0x08]), PduLen::Exact(7));
        assert_eq!(response_len_for(&echo, &[0x88]), PduLen::Exact(2));
    }

    #[test]
    fn extended_request_validation() {
        assert!(Request::Custom {
            function: 0x80,
            data: vec![]
        }
        .validate()
        .is_err());
        assert!(Request::Custom {
            function: 0,
            data: vec![]
        }
        .validate()
        .is_err());
        assert!(Request::Custom {
            function: 100,
            data: vec![0; MAX_CUSTOM_DATA + 1]
        }
        .validate()
        .is_err());
        assert!(Request::Diagnostics {
            sub_function: 0,
            data: vec![0; MAX_DIAGNOSTIC_WORDS + 1]
        }
        .validate()
        .is_err());
        assert!(!Request::ReportServerId.is_write_only());
    }

    #[test]
    fn extended_responses_roundtrip() {
        let cases: Vec<(Request, Response)> = vec![
            (
                Request::ReadExceptionStatus,
                Response::ReadExceptionStatus(0x6D),
            ),
            (
                Request::GetCommEventCounter,
                Response::GetCommEventCounter {
                    status: 0xFFFF,
                    event_count: 0x0108,
                },
            ),
            (
                Request::ReportServerId,
                Response::ReportServerId(vec![0x11, 0xFF, b'S', b'U']),
            ),
            (
                Request::Diagnostics {
                    sub_function: 0,
                    data: vec![0xA537],
                },
                Response::Diagnostics {
                    sub_function: 0,
                    data: vec![0xA537],
                },
            ),
            (
                Request::Diagnostics {
                    sub_function: 0x0E,
                    data: vec![0],
                },
                Response::Diagnostics {
                    sub_function: 0x0E,
                    data: vec![42],
                },
            ),
            (
                Request::ReadFifoQueue { address: 0x04DE },
                Response::ReadFifoQueue(vec![0x01B8, 0x1284]),
            ),
            (
                Request::ReadDeviceIdentification {
                    code: DeviceIdCode::Basic,
                    object_id: 0,
                },
                Response::ReadDeviceIdentification(DeviceIdResponse {
                    code: DeviceIdCode::Basic,
                    conformity_level: 0x81,
                    more_follows: false,
                    next_object_id: 0,
                    objects: vec![
                        (0, b"Company".to_vec()),
                        (1, b"PC-1".to_vec()),
                        (2, b"V2.11".to_vec()),
                    ],
                }),
            ),
            (
                Request::Custom {
                    function: 0x64,
                    data: vec![9],
                },
                Response::Custom {
                    function: 0x64,
                    data: vec![1, 2, 3, 4, 5],
                },
            ),
        ];
        for (req, resp) in cases {
            let pdu = enc_resp(&resp);
            assert_eq!(resp.encoded_len(), pdu.len());
            let predicted = response_len_for(&req, &pdu);
            if !matches!(req, Request::Custom { .. }) {
                assert_eq!(predicted, PduLen::Exact(pdu.len()), "{req:?}");
            }
            assert_eq!(Response::decode(&req, &pdu).unwrap(), resp, "{req:?}");
        }
    }

    #[test]
    fn fifo_wire_format() {
        let pdu = enc_resp(&Response::ReadFifoQueue(vec![0x01B8, 0x1284]));
        assert_eq!(pdu, [0x18, 0x00, 0x06, 0x00, 0x02, 0x01, 0xB8, 0x12, 0x84]);
        let req = Request::ReadFifoQueue { address: 0 };
        // byte count inconsistent with fifo count
        assert!(matches!(
            Response::decode(&req, &[0x18, 0x00, 0x04, 0x00, 0x02, 0, 1, 0, 2]),
            Err(Error::Protocol(ProtocolError::BadByteCount))
        ));
    }

    #[test]
    fn extended_response_errors() {
        // diagnostics echo must match
        let req = Request::Diagnostics {
            sub_function: 0,
            data: vec![1],
        };
        assert!(matches!(
            Response::decode(&req, &[0x08, 0, 0, 0, 2]),
            Err(Error::Protocol(ProtocolError::EchoMismatch))
        ));
        // device id: bad more-follows flag
        let req = Request::ReadDeviceIdentification {
            code: DeviceIdCode::Basic,
            object_id: 0,
        };
        assert!(matches!(
            Response::decode(&req, &[0x2B, 0x0E, 1, 0x81, 0x12, 0, 0]),
            Err(Error::Protocol(ProtocolError::Malformed(_)))
        ));
        // device id: wrong echoed code
        assert!(matches!(
            Response::decode(&req, &[0x2B, 0x0E, 2, 0x81, 0, 0, 0]),
            Err(Error::Protocol(ProtocolError::EchoMismatch))
        ));
        // device id: object count larger than data
        assert!(matches!(
            Response::decode(&req, &[0x2B, 0x0E, 1, 0x81, 0, 0, 2, 0, 1, b'x']),
            Err(Error::Protocol(ProtocolError::BadLength))
        ));
        // individual access must return the requested object
        let req = Request::ReadDeviceIdentification {
            code: DeviceIdCode::Specific,
            object_id: 4,
        };
        assert!(matches!(
            Response::decode(&req, &[0x2B, 0x0E, 4, 0x81, 0, 0, 1, 5, 1, b'x']),
            Err(Error::Protocol(ProtocolError::Malformed(_)))
        ));
        // report server id: byte count mismatch
        assert!(matches!(
            Response::decode(&Request::ReportServerId, &[0x11, 3, 1, 2]),
            Err(Error::Protocol(ProtocolError::BadByteCount))
        ));
        // custom exception
        let req = Request::Custom {
            function: 0x41,
            data: vec![],
        };
        assert!(matches!(
            Response::decode(&req, &[0xC1, 0x01]),
            Err(Error::Exception(ExceptionCode::IllegalFunction))
        ));
    }

    #[test]
    fn device_id_length_prediction_is_incremental() {
        let resp = Response::ReadDeviceIdentification(DeviceIdResponse {
            code: DeviceIdCode::Regular,
            conformity_level: 0x82,
            more_follows: true,
            next_object_id: 5,
            objects: vec![(3, vec![b'u'; 10]), (4, vec![b'p'; 20])],
        });
        let pdu = enc_resp(&resp);
        for cut in 0..pdu.len() {
            let p = response_len(&pdu[..cut]);
            assert!(
                matches!(p, PduLen::NeedAtLeast(n) if n > cut) || p == PduLen::Exact(pdu.len()),
                "cut {cut}: {p:?}"
            );
        }
        assert_eq!(response_len(&pdu), PduLen::Exact(pdu.len()));
    }

    /// Tiny deterministic PRNG so the robustness tests need no extra dependency.
    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, max: usize) -> Vec<u8> {
            let n = (self.next() % (max as u64 + 1)) as usize;
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    #[test]
    fn random_input_never_panics() {
        let mut rng = XorShift(0x5EED_1234_ABCD_0001);
        let probes = [
            Request::ReadCoils(AddressRange::new(0, 13)),
            Request::ReadHoldingRegisters(AddressRange::new(0, 3)),
            Request::WriteMultipleCoils {
                start: 0,
                values: vec![true; 3],
            },
            Request::ReadWriteMultipleRegisters {
                read: AddressRange::new(0, 2),
                write_start: 0,
                values: vec![1],
            },
            Request::Diagnostics {
                sub_function: 0,
                data: vec![1, 2],
            },
            Request::ReadFifoQueue { address: 1 },
            Request::ReadDeviceIdentification {
                code: DeviceIdCode::Extended,
                object_id: 0,
            },
            Request::ReportServerId,
            Request::Custom {
                function: 0x41,
                data: vec![],
            },
        ];
        for i in 0..50_000 {
            let mut data = rng.bytes(260);
            // bias towards meaningful function codes
            if let Some(first) = data.first_mut() {
                if i % 2 == 0 {
                    const CODES: [u8; 16] = [
                        1, 2, 3, 4, 5, 6, 7, 8, 0x0B, 0x0F, 0x10, 0x11, 0x16, 0x17, 0x18, 0x2B,
                    ];
                    *first = CODES[(rng.next() % 16) as usize];
                }
            }
            let _ = request_len(&data);
            let _ = response_len(&data);
            if let Ok(req) = Request::decode(&data) {
                // anything that decodes must re-encode to the same bytes
                assert_eq!(enc_req(&req), data, "{req:?}");
            }
            for p in &probes {
                let _ = response_len_for(p, &data);
                if let Ok(resp) = Response::decode(p, &data) {
                    assert_eq!(enc_resp(&resp).len(), data.len(), "{p:?}");
                }
            }
        }
    }
}
