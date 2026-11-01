#![forbid(unsafe_code)]
//! Owned values for the qualified Visor child-argument collection prefix.
//!
//! This is a chosen safe API, not a native descriptor/container/error layout.
//! Evidence: RE-013-visor-child-args-rust and credited #1029/#1040/#988.
//! Native correspondence assumes the explicit valid-span/frame/allocator/copy
//! premises and ends before the selected caller's opaque cleanup.

/// Safe API refusals; none is a recovered native error object or error ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectError {
    DescriptorCountOutsideDomain,
    InvalidUtf8 { argument_index: usize },
    AllocationFailure,
}

/// Return the native interval's 24-byte descriptor length within its proof bound.
///
/// This chosen admission helper is used by collection. It does not construct
/// native pointers, select an allocator or reproduce a native refusal code.
pub const fn native_descriptor_bytes(count: u64) -> Option<u64> {
    match count.checked_mul(24) {
        Some(bytes) if bytes <= i64::MAX as u64 => Some(bytes),
        _ => None,
    }
}

/// Copy canonical UTF-8 spans, in order, until the first `None`.
///
/// `None` maps only to the native null-empty span. A nonnull empty span is
/// `Some(&[])` and remains an empty String. Embedded NUL and every other
/// admitted byte are preserved; no trimming, quoting or pathname policy occurs.
/// Bytes after `None` are not inspected. Returned strings own their storage.
///
/// Invalid UTF-8 is a new safe refusal at the first visited invalid argument,
/// not the behavior of the opaque native error helper. Host allocation failure
/// may precede a later invalid argument. Host allocation order, cleanup and
/// container capacity are not native equivalence claims.
pub fn collect_child_args(items: &[Option<&[u8]>]) -> Result<Vec<String>, CollectError> {
    let count =
        u64::try_from(items.len()).map_err(|_| CollectError::DescriptorCountOutsideDomain)?;
    native_descriptor_bytes(count).ok_or(CollectError::DescriptorCountOutsideDomain)?;

    let mut output = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let Some(bytes) = item else {
            break;
        };
        let value = std::str::from_utf8(bytes).map_err(|_| CollectError::InvalidUtf8 {
            argument_index: index,
        })?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| CollectError::AllocationFailure)?;
        owned.push_str(value);
        output
            .try_reserve(1)
            .map_err(|_| CollectError::AllocationFailure)?;
        output.push(owned);
    }
    Ok(output)
}
