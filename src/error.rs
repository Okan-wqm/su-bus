//! Error types.

use crate::types::ExceptionCode;
use std::fmt;

/// Everything that can go wrong with a client request.
#[derive(Debug)]
pub enum Error {
    /// Underlying I/O failure (connection closed, refused, ...).
    Io(std::io::Error),
    /// No (valid) response arrived within the configured timeout.
    Timeout,
    /// The client has no connection and cannot open one (e.g. a closed user-supplied stream).
    NoConnection,
    /// The server answered with a Modbus exception.
    Exception(ExceptionCode),
    /// The request was rejected locally before being sent.
    InvalidRequest(&'static str),
    /// The remote side violated the protocol.
    Protocol(ProtocolError),
}

/// Specific protocol violations detected while decoding a frame or response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// MBAP header has a non-zero protocol id or an impossible length field.
    BadMbapHeader,
    /// The response carries a different function code than the request.
    UnexpectedFunction { expected: u8, actual: u8 },
    /// The response comes from a different unit than the one addressed.
    UnexpectedUnit { expected: u8, actual: u8 },
    /// The PDU length is not what the function code requires.
    BadLength,
    /// The byte-count field does not match the requested quantity.
    BadByteCount,
    /// A write response does not echo the request.
    EchoMismatch,
    /// A field holds a value the specification does not allow.
    Malformed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Timeout => f.write_str("response timeout"),
            Error::NoConnection => f.write_str("no connection"),
            Error::Exception(c) => write!(f, "modbus exception: {c}"),
            Error::InvalidRequest(m) => write!(f, "invalid request: {m}"),
            Error::Protocol(p) => write!(f, "protocol error: {p}"),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMbapHeader => f.write_str("bad MBAP header"),
            Self::UnexpectedFunction { expected, actual } => write!(
                f,
                "unexpected function code 0x{actual:02X} (expected 0x{expected:02X})"
            ),
            Self::UnexpectedUnit { expected, actual } => {
                write!(f, "response from unit {actual} (expected {expected})")
            }
            Self::BadLength => f.write_str("bad PDU length"),
            Self::BadByteCount => f.write_str("byte count does not match quantity"),
            Self::EchoMismatch => f.write_str("write response does not echo the request"),
            Self::Malformed(what) => write!(f, "malformed field: {what}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Exception(c) => Some(c),
            _ => None,
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Error::Protocol(e)
    }
}

impl From<ExceptionCode> for Error {
    fn from(e: ExceptionCode) -> Self {
        Error::Exception(e)
    }
}
