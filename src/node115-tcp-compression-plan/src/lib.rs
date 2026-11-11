//! Independent logical reconstruction of selected node115 TCP sender arms.
//! No allocator, codec, socket, unwinder, native ABI or context type is supplied.
#![no_std]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    MultiplyOverflow,
    CodecFailure,
    PrefixOverflow,
    WireLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    SmallTable,
    LargeTable,
}

/// Normal framing boundary, after all selected opaque helpers normally return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub selected_len: u64,
    pub header: [u8; 5],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionPlan {
    allocation_bytes: u64,
    sink_capacity: u64,
    codec: Codec,
    inner_prefix: [u8; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Raw(Frame),
    Compress(CompressionPlan),
}

fn frame(selected_len: u64, marker: u8) -> Result<Frame, Error> {
    let length = u32::try_from(selected_len).map_err(|_| Error::WireLength)?;
    let bytes = length.to_be_bytes();
    Ok(Frame {
        selected_len,
        header: [bytes[0], bytes[1], bytes[2], bytes[3], marker],
    })
}

/// `context_field` is the observed dword at context+0x90; its type is unknown.
/// This pure plan does not imply the requested allocations can succeed.
pub fn plan(input_len: u64, context_field: u32) -> Result<Plan, Error> {
    let low = context_field as u16;
    if input_len < 1025 || low == 3998 || low == 3999 {
        return frame(input_len, 0).map(Plan::Raw);
    }
    let product = input_len.checked_mul(110).ok_or(Error::MultiplyOverflow)?;
    let quotient = product / 100;
    // With a checked product, quotient <= u64::MAX/100: additions cannot overflow.
    Ok(Plan::Compress(CompressionPlan {
        allocation_bytes: quotient + 24,
        sink_capacity: quotient + 20,
        codec: if input_len < 65535 {
            Codec::SmallTable
        } else {
            Codec::LargeTable
        },
        // The captured DWORD store truncates, independently of the outer u32 guard.
        inner_prefix: (input_len as u32).to_le_bytes(),
    }))
}

impl CompressionPlan {
    pub const fn allocation_bytes(self) -> u64 {
        self.allocation_bytes
    }
    pub const fn sink_capacity(self) -> u64 {
        self.sink_capacity
    }
    pub const fn codec(self) -> Codec {
        self.codec
    }
    pub const fn scratch_bytes(self) -> u64 {
        match self.codec {
            Codec::SmallTable => 8192,
            Codec::LargeTable => 16384,
        }
    }
    pub const fn inner_prefix(self) -> [u8; 4] {
        self.inner_prefix
    }
    /// Conditional caller relation for the retained codec RAX/RDX.
    /// `tag == 1` maps the observed unwrap path to a logical error; it does not
    /// simulate panic/unwind. Other tags retain only this caller's comparison.
    /// Codec validity, output contents, allocation/resize and telemetry are opaque.
    pub fn finish(self, tag: u64, written: u64) -> Result<Frame, Error> {
        if tag == 1 {
            return Err(Error::CodecFailure);
        }
        let with_prefix = written.checked_add(4).ok_or(Error::PrefixOverflow)?;
        frame(with_prefix.min(self.allocation_bytes), 1)
    }
}
