//! Conversions between 16-bit registers and wider values (u32, i32, f32, u64, i64, f64)
//! or text, for every byte / word order found in real devices.

/// How a multi-register value is laid out. Letters name the bytes of the value from most
/// to least significant; `ABCD` is the plain big-endian order of the specification.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct RegisterOrder {
    /// Least significant register first.
    pub word_swap: bool,
    /// Low byte first inside each register.
    pub byte_swap: bool,
}

impl RegisterOrder {
    /// Big endian (`AB CD`). The default.
    pub const ABCD: Self = Self::new(false, false);
    /// Word swapped (`CD AB`), very common in PLCs.
    pub const CDAB: Self = Self::new(true, false);
    /// Byte swapped (`BA DC`).
    pub const BADC: Self = Self::new(false, true);
    /// Little endian (`DC BA`).
    pub const DCBA: Self = Self::new(true, true);

    pub const fn new(word_swap: bool, byte_swap: bool) -> Self {
        RegisterOrder {
            word_swap,
            byte_swap,
        }
    }
}

impl Default for RegisterOrder {
    fn default() -> Self {
        Self::ABCD
    }
}

/// A value stored in one or more consecutive registers.
pub trait RegisterValue: Sized + Copy {
    /// Number of registers used.
    const WORDS: usize;
    /// Encode, appending `WORDS` registers to `out`.
    fn encode(self, order: RegisterOrder, out: &mut Vec<u16>);
    /// Decode from exactly `WORDS` registers (`regs.len()` is checked by the caller).
    fn decode(regs: &[u16], order: RegisterOrder) -> Self;
}

fn bytes_to_words(be: &[u8], order: RegisterOrder, out: &mut Vec<u16>) {
    let start = out.len();
    for pair in be.chunks_exact(2) {
        let w = u16::from_be_bytes([pair[0], pair[1]]);
        out.push(if order.byte_swap { w.swap_bytes() } else { w });
    }
    if order.word_swap {
        out[start..].reverse();
    }
}

fn words_to_bytes<const N: usize>(regs: &[u16], order: RegisterOrder) -> [u8; N] {
    let mut be = [0u8; N];
    let words = N / 2;
    for i in 0..words {
        let w = if order.word_swap {
            regs[words - 1 - i]
        } else {
            regs[i]
        };
        let w = if order.byte_swap { w.swap_bytes() } else { w };
        be[2 * i..2 * i + 2].copy_from_slice(&w.to_be_bytes());
    }
    be
}

macro_rules! register_value {
    ($($t:ty),*) => {$(
        impl RegisterValue for $t {
            const WORDS: usize = std::mem::size_of::<$t>() / 2;
            fn encode(self, order: RegisterOrder, out: &mut Vec<u16>) {
                bytes_to_words(&self.to_be_bytes(), order, out)
            }
            fn decode(regs: &[u16], order: RegisterOrder) -> Self {
                <$t>::from_be_bytes(words_to_bytes(regs, order))
            }
        }
    )*};
}

register_value!(u16, i16, u32, i32, f32, u64, i64, f64);

/// Encode one value into registers.
pub fn encode<T: RegisterValue>(value: T, order: RegisterOrder) -> Vec<u16> {
    let mut v = Vec::with_capacity(T::WORDS);
    value.encode(order, &mut v);
    v
}

/// Encode several values back to back.
pub fn encode_all<T: RegisterValue>(values: &[T], order: RegisterOrder) -> Vec<u16> {
    let mut v = Vec::with_capacity(values.len() * T::WORDS);
    values.iter().for_each(|x| x.encode(order, &mut v));
    v
}

/// Decode one value; `None` when `regs` has the wrong length.
pub fn decode<T: RegisterValue>(regs: &[u16], order: RegisterOrder) -> Option<T> {
    (regs.len() == T::WORDS).then(|| T::decode(regs, order))
}

/// Decode consecutive values; `None` when `regs.len()` is not a multiple of the value size.
pub fn decode_all<T: RegisterValue>(regs: &[u16], order: RegisterOrder) -> Option<Vec<T>> {
    if !regs.len().is_multiple_of(T::WORDS) {
        return None;
    }
    Some(
        regs.chunks_exact(T::WORDS)
            .map(|c| T::decode(c, order))
            .collect(),
    )
}

/// Pack text into `words` registers (two characters per register, padded with NUL).
/// Longer text is truncated. `byte_swap` puts the first character in the low byte.
pub fn encode_string(text: &str, words: usize, byte_swap: bool) -> Vec<u16> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.resize(words * 2, 0);
    bytes
        .chunks_exact(2)
        .map(|c| {
            let w = u16::from_be_bytes([c[0], c[1]]);
            if byte_swap {
                w.swap_bytes()
            } else {
                w
            }
        })
        .collect()
}

/// Unpack text from registers, stopping at the first NUL and trimming trailing spaces.
pub fn decode_string(regs: &[u16], byte_swap: bool) -> String {
    let bytes: Vec<u8> = regs
        .iter()
        .flat_map(|&w| {
            let w = if byte_swap { w.swap_bytes() } else { w };
            w.to_be_bytes()
        })
        .take_while(|&b| b != 0)
        .collect();
    String::from_utf8_lossy(&bytes).trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f32_all_orders() {
        // 1.0f32 = 0x3F80_0000 -> bytes A=3F B=80 C=00 D=00
        assert_eq!(encode(1.0f32, RegisterOrder::ABCD), [0x3F80, 0x0000]);
        assert_eq!(encode(1.0f32, RegisterOrder::CDAB), [0x0000, 0x3F80]);
        assert_eq!(encode(1.0f32, RegisterOrder::BADC), [0x803F, 0x0000]);
        assert_eq!(encode(1.0f32, RegisterOrder::DCBA), [0x0000, 0x803F]);
        for order in [
            RegisterOrder::ABCD,
            RegisterOrder::CDAB,
            RegisterOrder::BADC,
            RegisterOrder::DCBA,
        ] {
            let regs = encode(-123.456f32, order);
            assert_eq!(decode::<f32>(&regs, order), Some(-123.456));
        }
    }

    #[test]
    fn u32_and_64_bit() {
        assert_eq!(
            encode(0x1234_5678u32, RegisterOrder::ABCD),
            [0x1234, 0x5678]
        );
        assert_eq!(
            encode(0x1234_5678u32, RegisterOrder::CDAB),
            [0x5678, 0x1234]
        );
        assert_eq!(
            encode(0x0102_0304_0506_0708u64, RegisterOrder::CDAB),
            [0x0708, 0x0506, 0x0304, 0x0102]
        );
        assert_eq!(
            encode(0x0102_0304_0506_0708u64, RegisterOrder::DCBA),
            [0x0807, 0x0605, 0x0403, 0x0201]
        );
        let regs = encode(-2i64, RegisterOrder::BADC);
        assert_eq!(decode::<i64>(&regs, RegisterOrder::BADC), Some(-2));
        let regs = encode(std::f64::consts::PI, RegisterOrder::DCBA);
        assert_eq!(
            decode::<f64>(&regs, RegisterOrder::DCBA),
            Some(std::f64::consts::PI)
        );
        assert_eq!(decode::<u32>(&[1], RegisterOrder::ABCD), None);
        assert_eq!(encode(-1i16, RegisterOrder::ABCD), [0xFFFF]);
    }

    #[test]
    fn many_values() {
        let vals = [1.5f32, -2.25, 1e9];
        let regs = encode_all(&vals, RegisterOrder::CDAB);
        assert_eq!(regs.len(), 6);
        assert_eq!(decode_all::<f32>(&regs, RegisterOrder::CDAB).unwrap(), vals);
        assert!(decode_all::<f32>(&regs[..5], RegisterOrder::CDAB).is_none());
    }

    #[test]
    fn strings() {
        let regs = encode_string("SU-BUS1", 5, false);
        assert_eq!(regs, [0x5355, 0x2D42, 0x5553, 0x3100, 0x0000]);
        assert_eq!(decode_string(&regs, false), "SU-BUS1");
        let swapped = encode_string("AB", 1, true);
        assert_eq!(swapped, [0x4241]);
        assert_eq!(decode_string(&swapped, true), "AB");
        assert_eq!(
            decode_string(&encode_string("toolongtext", 2, false), false),
            "tool"
        );
        assert_eq!(
            decode_string(&encode_string("pad  ", 4, false), false),
            "pad"
        );
    }
}
