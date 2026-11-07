//! Device identification objects (function 0x2B / MEI type 0x0E).

use std::collections::BTreeMap;

/// Well-known object ids.
pub mod object {
    pub const VENDOR_NAME: u8 = 0x00;
    pub const PRODUCT_CODE: u8 = 0x01;
    pub const MAJOR_MINOR_REVISION: u8 = 0x02;
    pub const VENDOR_URL: u8 = 0x03;
    pub const PRODUCT_NAME: u8 = 0x04;
    pub const MODEL_NAME: u8 = 0x05;
    pub const USER_APPLICATION_NAME: u8 = 0x06;
}

/// "Read device id code" of a request: which category to stream, or one specific object.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DeviceIdCode {
    /// Objects 0x00..=0x02 (stream access).
    Basic,
    /// Objects 0x00..=0x7F (stream access).
    Regular,
    /// Objects 0x00..=0xFF (stream access).
    Extended,
    /// One specific object (individual access).
    Specific,
}

impl DeviceIdCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Basic,
            2 => Self::Regular,
            3 => Self::Extended,
            4 => Self::Specific,
            _ => return None,
        })
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Basic => 1,
            Self::Regular => 2,
            Self::Extended => 3,
            Self::Specific => 4,
        }
    }

    /// Highest object id belonging to a stream category.
    pub fn max_object(self) -> u8 {
        match self {
            Self::Basic => 0x02,
            Self::Regular => 0x7F,
            Self::Extended | Self::Specific => 0xFF,
        }
    }
}

/// Longest value an object can have so that it always fits into one response PDU.
pub const MAX_OBJECT_LEN: usize = 244;

/// The identification objects a server exposes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceIdentification {
    objects: BTreeMap<u8, Vec<u8>>,
}

impl DeviceIdentification {
    /// Create with the three mandatory basic objects.
    pub fn new(vendor: &str, product_code: &str, revision: &str) -> Self {
        DeviceIdentification::default()
            .with(object::VENDOR_NAME, vendor)
            .with(object::PRODUCT_CODE, product_code)
            .with(object::MAJOR_MINOR_REVISION, revision)
    }

    /// Builder form of [`insert`](Self::insert).
    pub fn with(mut self, id: u8, value: impl AsRef<[u8]>) -> Self {
        self.insert(id, value);
        self
    }

    /// Set an object. Values longer than [`MAX_OBJECT_LEN`] are truncated.
    pub fn insert(&mut self, id: u8, value: impl AsRef<[u8]>) {
        let v = value.as_ref();
        self.objects
            .insert(id, v[..v.len().min(MAX_OBJECT_LEN)].to_vec());
    }

    pub fn get(&self, id: u8) -> Option<&[u8]> {
        self.objects.get(&id).map(Vec::as_slice)
    }

    /// Object value as text (lossy UTF-8).
    pub fn get_str(&self, id: u8) -> Option<String> {
        self.get(id)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    pub fn iter(&self) -> impl Iterator<Item = (u8, &[u8])> {
        self.objects.iter().map(|(k, v)| (*k, v.as_slice()))
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Conformity level advertised by a server holding these objects
    /// (individual access is always supported, hence bit 0x80).
    pub fn conformity_level(&self) -> u8 {
        let level = if self.objects.keys().any(|&k| k >= 0x80) {
            3
        } else if self.objects.keys().any(|&k| k >= 0x03) {
            2
        } else {
            1
        };
        0x80 | level
    }
}

/// One response to a device identification request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdResponse {
    pub code: DeviceIdCode,
    pub conformity_level: u8,
    pub more_follows: bool,
    pub next_object_id: u8,
    pub objects: Vec<(u8, Vec<u8>)>,
}

/// Everything collected by a client from (possibly several) device identification responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdReport {
    pub conformity_level: u8,
    pub identification: DeviceIdentification,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformity_and_truncation() {
        let mut d = DeviceIdentification::new("Su", "SB-1", "1.0");
        assert_eq!(d.conformity_level(), 0x81);
        d.insert(object::PRODUCT_NAME, "pump");
        assert_eq!(d.conformity_level(), 0x82);
        d.insert(0x80, vec![0u8; 1000]);
        assert_eq!(d.conformity_level(), 0x83);
        assert_eq!(d.get(0x80).unwrap().len(), MAX_OBJECT_LEN);
        assert_eq!(d.get_str(object::VENDOR_NAME).unwrap(), "Su");
        for c in 1..=4 {
            assert_eq!(DeviceIdCode::from_u8(c).unwrap().to_u8(), c);
        }
        assert!(DeviceIdCode::from_u8(0).is_none());
        assert!(DeviceIdCode::from_u8(5).is_none());
    }
}
