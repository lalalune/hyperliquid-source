#![no_std]
//! Logical value/error/cursor reconstruction of Node115's linked-VA
//! 0x298f160 root and 0x2a00700 scalar helper. This is not its native ABI.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeError {
    /// Observed native error discriminant; inactive native fields are omitted.
    pub code: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlagPair {
    pub flag: bool,
    /// Four little-endian limbs, least significant limb first.
    pub first: [u64; 4],
    pub second: [u64; 4],
}
pub struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }
    pub fn consumed(&self) -> usize {
        self.position
    }
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.position..]
    }
    fn fail<T>(code: u8) -> Result<T, DecodeError> {
        Err(DecodeError { code })
    }
    /// Header errors retain any prefix and length bytes already consumed.
    fn payload(&mut self) -> Result<&'a [u8], DecodeError> {
        let prefix = match self.remaining().first() {
            Some(byte) => *byte,
            None => return Self::fail(2),
        };
        self.position += 1;
        if prefix < 0x80 {
            return Ok(&self.input[self.position - 1..self.position]);
        }
        if prefix <= 0xb7 {
            let length = usize::from(prefix - 0x80);
            if length == 1 {
                let first = match self.remaining().first() {
                    Some(byte) => *byte,
                    None => return Self::fail(2),
                };
                if first < 0x80 {
                    return Self::fail(3);
                }
            }
            return self.take_payload(length);
        }
        if prefix <= 0xbf || prefix >= 0xf8 {
            let width = usize::from(if prefix < 0xc0 {
                prefix - 0xb7
            } else {
                prefix - 0xf7
            });
            if self.remaining().len() < width {
                return Self::fail(2);
            }
            let encoded = &self.input[self.position..self.position + width];
            self.position += width;
            if encoded[0] == 0 {
                return Self::fail(1);
            }
            let mut length = 0u64;
            for byte in encoded {
                length = (length << 8) | u64::from(*byte);
            }
            if length < 56 {
                return Self::fail(4);
            }
            if length > self.remaining().len() as u64 {
                return Self::fail(2);
            }
            if prefix >= 0xf8 {
                return Self::fail(7);
            }
            // A length that fits the remaining slice also fits usize.
            return self.take_payload(length as usize);
        }
        let length = usize::from(prefix - 0xc0);
        Self::fail(if self.remaining().len() < length {
            2
        } else {
            7
        })
    }
    fn take_payload(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining().len() < length {
            return Self::fail(2);
        }
        let start = self.position;
        self.position += length;
        Ok(&self.input[start..self.position])
    }
    pub fn read_word256(&mut self) -> Result<[u64; 4], DecodeError> {
        let bytes = self.payload()?;
        if bytes.first() == Some(&0) {
            return Self::fail(1);
        }
        if bytes.len() > 32 {
            return Self::fail(0);
        }
        let mut limbs = [0u64; 4];
        for (position, byte) in bytes.iter().rev().enumerate() {
            limbs[position / 8] |= u64::from(*byte) << ((position % 8) * 8);
        }
        Ok(limbs)
    }
    pub fn read_flag_pair(&mut self) -> Result<FlagPair, DecodeError> {
        let flag = match self.payload()? {
            [] => false,
            [0] => return Self::fail(1),
            [1] => true,
            [_] => return Self::fail(9),
            _ => return Self::fail(0),
        };
        let first = self.read_word256()?;
        let second = self.read_word256()?;
        Ok(FlagPair {
            flag,
            first,
            second,
        })
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_flag_and_limb_order() {
        let mut r = Reader::new(&[0x80, 1, 2, 0xaa]);
        assert_eq!(
            r.read_flag_pair(),
            Ok(FlagPair {
                flag: false,
                first: [1, 0, 0, 0],
                second: [2, 0, 0, 0]
            })
        );
        assert_eq!(r.remaining(), &[0xaa]);
        let mut input = std::vec![1, 0xa0];
        input.extend(1u8..=32);
        input.push(0x80);
        let mut r = Reader::new(&input);
        assert_eq!(
            r.read_flag_pair(),
            Ok(FlagPair {
                flag: true,
                first: [
                    0x191a1b1c1d1e1f20,
                    0x1112131415161718,
                    0x090a0b0c0d0e0f10,
                    0x0102030405060708
                ],
                second: [0; 4]
            })
        );
    }
    #[test]
    fn prefix_failures_preserve_cursor() {
        for (input, code, consumed) in [
            (&[][..], 2, 0),
            (&[0][..], 1, 1),
            (&[2][..], 9, 1),
            (&[0x81, 1][..], 3, 1),
            (&[0x81, 0x80][..], 9, 2),
            (&[0x82, 0, 1][..], 0, 3),
            (&[0xc0][..], 7, 1),
            (&[0xc2, 1][..], 2, 1),
            (&[0xb8, 1, 0][..], 4, 2),
            (&[0xb8, 0][..], 1, 2),
            (&[0xb9, 1][..], 2, 1),
        ] {
            let mut r = Reader::new(input);
            assert_eq!(r.read_flag_pair(), Err(DecodeError { code }), "{input:x?}");
            assert_eq!(r.consumed(), consumed, "{input:x?}");
        }
    }
    #[test]
    fn scalar_errors_and_pair_short_circuit() {
        for (input, code, consumed) in [
            (&[0x80][..], 2, 1),
            (&[1, 0x80][..], 2, 2),
            (&[0x80, 0][..], 1, 2),
            (&[0x80, 0x81, 0][..], 3, 2),
        ] {
            let mut r = Reader::new(input);
            assert_eq!(r.read_flag_pair(), Err(DecodeError { code }));
            assert_eq!(r.consumed(), consumed);
        }
        let mut input = std::vec![0x80, 0xa1];
        input.extend([0xff; 33]);
        input.push(0x80);
        let mut r = Reader::new(&input);
        assert_eq!(r.read_flag_pair(), Err(DecodeError { code: 0 }));
        assert_eq!(r.consumed(), 35);
    }
    #[test]
    fn long_header_and_list_do_not_consume_payload_on_rejection() {
        let mut input = std::vec![0xb8, 56];
        input.extend([1; 56]);
        let mut r = Reader::new(&input);
        assert_eq!(r.read_flag_pair(), Err(DecodeError { code: 0 }));
        assert_eq!(r.consumed(), 58);
        input[0] = 0xf8;
        let mut r = Reader::new(&input);
        assert_eq!(r.read_flag_pair(), Err(DecodeError { code: 7 }));
        assert_eq!(r.consumed(), 2);
        let mut r = Reader::new(&input[..10]);
        assert_eq!(r.read_flag_pair(), Err(DecodeError { code: 2 }));
        assert_eq!(r.consumed(), 2);
    }
}
