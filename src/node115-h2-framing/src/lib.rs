#![forbid(unsafe_code)]
//! Value-level node115 length framing. Native storage, allocation and asynchronous
//! polling are outside this API. See the target-bound contract for its premises.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub maximum: u64,
    pub field_bytes: u64,
    pub offset: u64,
    pub adjustment: i64,
    pub skip: Option<u64>,
    pub big_endian: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Head, Data(u64) }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    NeedMore = 0,
    Frame = 1,
    TooLong = 2,
    AdjustmentOverflow = 3,
    HeadLengthOverflow = 4,
    FieldWidthBoundary = 5,
    AdjustmentNegationBoundary = 6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub status: Status,
    pub consumed: u64,
    pub state: State,
    /// Logical additional capacity demand; not the actual number of allocations.
    pub reserve_payload: u64,
    pub reserve_header: u64,
    pub frame_length: u64,
}

/// Builder's scalar cap projection, restricted to a field width of at most eight.
pub fn adjusted_cap(width: u8, adjustment: i64, maximum: u64) -> Option<u64> {
    if width > 8 { return None; }
    let representable = if width == 8 { u64::MAX } else { (1u64 << (8 * width)) - 1 };
    let adjusted = if adjustment >= 0 {
        representable.saturating_add(adjustment as u64)
    } else {
        representable.saturating_sub(adjustment.unsigned_abs())
    };
    Some(maximum.min(adjusted))
}

/// The actual H2 constructor's admitted payload limit and continuation allowance.
/// The selected wrapper supplies a 16 MiB header-list budget.
pub fn h2_limits(maximum: u64) -> Option<(Config, u64)> {
    if !(16_384..=16_777_215).contains(&maximum) { return None; }
    let quotient = (1u64 << 24) / maximum;
    let continuations = (quotient + quotient / 4).max(5);
    Some((Config { maximum, field_bytes: 3, offset: 0, adjustment: 9,
        skip: Some(0), big_endian: true }, continuations))
}

/// One decoder step on an immutable byte view. `consumed` identifies bytes to
/// remove only after observing the returned decision. A frame is the original
/// range `consumed-frame_length .. consumed`. Error/boundary variants represent
/// native decision boundaries, not original io::Error layouts or panic handling.
///
/// The result assumes native helper calls return normally, preserve the byte
/// sequence, and satisfy the documented split/reserve postconditions. Buffer
/// ownership, allocations, scheduling and unwinding are not performed here.
pub fn decode(config: Config, state: State, bytes: &[u8]) -> Decision {
    let mut out = Decision { status: Status::NeedMore, consumed: 0, state,
        reserve_payload: 0, reserve_header: 0, frame_length: 0 };
    let head_length = config.offset.checked_add(config.field_bytes);
    let mut remaining = bytes.len() as u64;
    let length = match state {
        State::Data(length) => length,
        State::Head => {
            let head = match head_length {
                Some(n) => n,
                None => { out.status=Status::HeadLengthOverflow; return out; }
            };
            let skip = config.skip.unwrap_or(head);
            let requirement = head.max(skip);
            if remaining < requirement { return out; }
            if config.field_bytes > 8 { out.status=Status::FieldWidthBoundary; return out; }
            let start=config.offset as usize;
            let mut value=0u64;
            if config.big_endian {
                for &byte in &bytes[start..start+config.field_bytes as usize] {
                    value=(value << 8) | byte as u64;
                }
            } else {
                for (index,&byte) in bytes[start..start+config.field_bytes as usize].iter().enumerate() {
                    value |= (byte as u64) << (index*8);
                }
            }
            if value > config.maximum { out.status=Status::TooLong; return out; }
            if config.adjustment == i64::MIN {
                out.status=Status::AdjustmentNegationBoundary; return out;
            }
            let adjusted = if config.adjustment < 0 {
                value.checked_sub((-config.adjustment) as u64)
            } else {
                value.checked_add(config.adjustment as u64)
            };
            let n = match adjusted {
                Some(n) => n,
                None => { out.status=Status::AdjustmentOverflow; return out; }
            };
            out.consumed=skip;
            remaining-=skip;
            out.reserve_payload=n.saturating_sub(remaining);
            out.state=State::Data(n);
            n
        }
    };
    if remaining < length { return out; }
    out.consumed+=length;
    remaining-=length;
    out.state=State::Head;
    out.frame_length=length;
    let head = match head_length {
        Some(n) => n,
        None => { out.status=Status::HeadLengthOverflow; return out; }
    };
    out.reserve_header=head.max(config.skip.unwrap_or(head)).saturating_sub(remaining);
    out.status=Status::Frame;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_h2_header_and_payload() {
        let (c,_)=h2_limits(16_384).unwrap();
        assert_eq!(decode(c,State::Head,&[0,0]).state,State::Head);
        let a=decode(c,State::Head,&[0,0,1]);
        assert_eq!((a.status,a.state,a.consumed),(Status::NeedMore,State::Data(10),0));
        let all=[0,0,1,0,0,0,0,0,0,42];
        let b=decode(c,a.state,&all);
        assert_eq!((b.status,b.frame_length,b.consumed),(Status::Frame,10,10));
    }
    #[test]
    fn announced_limit_precedes_adjustment() {
        let (mut c,_)=h2_limits(16_384).unwrap();c.adjustment=i64::MIN;
        assert_eq!(decode(c,State::Head,&[0,64,1]).status,Status::TooLong);
        assert_eq!(decode(c,State::Head,&[0,64,0]).status,Status::AdjustmentNegationBoundary);
    }
    #[test]
    fn empty_frame_is_a_frame() {
        let c=Config{maximum:255,field_bytes:1,offset:0,adjustment:0,skip:None,big_endian:true};
        let d=decode(c,State::Head,&[0]);
        assert_eq!((d.status,d.consumed,d.frame_length,d.state),(Status::Frame,1,0,State::Head));
    }
    #[test]
    fn data_state_defers_configuration_checks() {
        let c=Config{maximum:0,field_bytes:1,offset:u64::MAX,adjustment:i64::MIN,skip:None,big_endian:true};
        assert_eq!(decode(c,State::Data(2),&[0]).status,Status::NeedMore);
        let d=decode(c,State::Data(2),&[0,0]);
        assert_eq!((d.status,d.consumed,d.state),(Status::HeadLengthOverflow,2,State::Head));
    }
}
