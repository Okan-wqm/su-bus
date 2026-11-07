//! Basic protocol types shared by client and server.

use std::fmt;

/// Modbus unit identifier (a.k.a. slave id / station address).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnitId(pub u8);

impl UnitId {
    /// Broadcast address (serial lines only: writes are executed by every station, nobody answers).
    pub const BROADCAST: UnitId = UnitId(0);

    pub fn is_broadcast(self) -> bool {
        self.0 == 0
    }
}

impl From<u8> for UnitId {
    fn from(v: u8) -> Self {
        UnitId(v)
    }
}

impl fmt::Display for UnitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A contiguous block of addresses: `start .. start + count`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AddressRange {
    pub start: u16,
    pub count: u16,
}

impl AddressRange {
    pub const fn new(start: u16, count: u16) -> Self {
        AddressRange { start, count }
    }

    /// True when the range is non-empty, does not exceed `max` items and does not wrap past 0xFFFF.
    pub fn is_valid(&self, max: u16) -> bool {
        self.count >= 1 && self.count <= max && !self.overflows()
    }

    /// True when `start + count` would exceed the 16-bit address space.
    pub fn overflows(&self) -> bool {
        self.start as u32 + self.count as u32 > 0x1_0000
    }

    /// Iterate over every address in the range.
    pub fn iter(&self) -> impl Iterator<Item = u16> {
        let start = self.start as u32;
        (start..start + self.count as u32).map(|a| a as u16)
    }

    /// The range as `usize` indices, convenient for slicing.
    pub fn to_std(&self) -> std::ops::Range<usize> {
        let s = self.start as usize;
        s..s + self.count as usize
    }
}

/// Modbus exception codes (returned by a server instead of a normal response).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExceptionCode {
    IllegalFunction,
    IllegalDataAddress,
    IllegalDataValue,
    ServerDeviceFailure,
    Acknowledge,
    ServerDeviceBusy,
    MemoryParityError,
    GatewayPathUnavailable,
    GatewayTargetDeviceFailedToRespond,
    Unknown(u8),
}

impl From<u8> for ExceptionCode {
    fn from(v: u8) -> Self {
        match v {
            0x01 => Self::IllegalFunction,
            0x02 => Self::IllegalDataAddress,
            0x03 => Self::IllegalDataValue,
            0x04 => Self::ServerDeviceFailure,
            0x05 => Self::Acknowledge,
            0x06 => Self::ServerDeviceBusy,
            0x08 => Self::MemoryParityError,
            0x0A => Self::GatewayPathUnavailable,
            0x0B => Self::GatewayTargetDeviceFailedToRespond,
            other => Self::Unknown(other),
        }
    }
}

impl From<ExceptionCode> for u8 {
    fn from(c: ExceptionCode) -> u8 {
        match c {
            ExceptionCode::IllegalFunction => 0x01,
            ExceptionCode::IllegalDataAddress => 0x02,
            ExceptionCode::IllegalDataValue => 0x03,
            ExceptionCode::ServerDeviceFailure => 0x04,
            ExceptionCode::Acknowledge => 0x05,
            ExceptionCode::ServerDeviceBusy => 0x06,
            ExceptionCode::MemoryParityError => 0x08,
            ExceptionCode::GatewayPathUnavailable => 0x0A,
            ExceptionCode::GatewayTargetDeviceFailedToRespond => 0x0B,
            ExceptionCode::Unknown(v) => v,
        }
    }
}

impl fmt::Display for ExceptionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalFunction => f.write_str("illegal function"),
            Self::IllegalDataAddress => f.write_str("illegal data address"),
            Self::IllegalDataValue => f.write_str("illegal data value"),
            Self::ServerDeviceFailure => f.write_str("server device failure"),
            Self::Acknowledge => f.write_str("acknowledge"),
            Self::ServerDeviceBusy => f.write_str("server device busy"),
            Self::MemoryParityError => f.write_str("memory parity error"),
            Self::GatewayPathUnavailable => f.write_str("gateway path unavailable"),
            Self::GatewayTargetDeviceFailedToRespond => {
                f.write_str("gateway target device failed to respond")
            }
            Self::Unknown(v) => write!(f, "unknown exception 0x{v:02X}"),
        }
    }
}

impl std::error::Error for ExceptionCode {}
