//! Wire codec configuration matching Hyperliquid node #115 `z_forks/bincode-fork`.

/// Byte order for multi-byte integer payloads and fixed-width encodings.
///
/// In node #115 binary slow-path varint readers (`0x5822490`, `0x58225c0`, `0x5822710`),
/// byte flag `0` selects little-endian (passed by all observed first-party callers)
/// and any nonzero value selects big-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// Integer wire encoding mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntEncoding {
    /// Bincode 2 variable-length integer encoding (`0..=250`, `251`+u16, `252`+u32,
    /// `253`+u64, `254`+u128; ZigZag for signed widths).
    Varint,
    /// Fixed-width integer encoding.
    Fixed,
}

/// Allocation / read budget mode observed at offset `+0x0` (mode) and `+0x8` (limit)
/// in node #115 decoder state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    /// Mode `0`: unlimited reads.
    NoLimit,
    /// Mode `1`: maximum cumulative claimed bytes.
    Bytes(u64),
}

/// Runtime codec configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Configuration {
    pub endian: Endian,
    pub int_encoding: IntEncoding,
    pub limit: Limit,
}

/// Standard node #115 wire configuration: little-endian, varint integers, unlimited.
pub const fn standard() -> Configuration {
    Configuration {
        endian: Endian::Little,
        int_encoding: IntEncoding::Varint,
        limit: Limit::NoLimit,
    }
}

/// Legacy fixed-width little-endian configuration.
pub const fn legacy() -> Configuration {
    Configuration {
        endian: Endian::Little,
        int_encoding: IntEncoding::Fixed,
        limit: Limit::NoLimit,
    }
}

impl Configuration {
    pub const fn with_little_endian(mut self) -> Self {
        self.endian = Endian::Little;
        self
    }

    pub const fn with_big_endian(mut self) -> Self {
        self.endian = Endian::Big;
        self
    }

    pub const fn with_variable_int_encoding(mut self) -> Self {
        self.int_encoding = IntEncoding::Varint;
        self
    }

    pub const fn with_fixed_int_encoding(mut self) -> Self {
        self.int_encoding = IntEncoding::Fixed;
        self
    }

    pub const fn with_no_limit(mut self) -> Self {
        self.limit = Limit::NoLimit;
        self
    }

    pub const fn with_limit_bytes(mut self, limit: u64) -> Self {
        self.limit = Limit::Bytes(limit);
        self
    }

    pub const fn limit_option(self) -> Option<u64> {
        match self.limit {
            Limit::NoLimit => None,
            Limit::Bytes(n) => Some(n),
        }
    }
}
