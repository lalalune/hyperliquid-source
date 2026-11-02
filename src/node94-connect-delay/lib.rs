//! Selected gossip connect delay over supplied snapshot lookup results.
//! Actual wall-clock addition, lookup, scheduling and duration conversion are unclosed.
#![no_std]
#![forbid(unsafe_code)]

pub fn k_value(map_value: Option<u64>, list_index: Option<u64>, list_len: u64) -> u64 {
    map_value.or(list_index).unwrap_or(list_len)
}

/// Normal binary64 round-to-nearest scalar domain of the recorded conversion,
/// two ordered multiplies and positive MINSD cap. No fast-math or reassociation.
pub fn delay(snapshot_some: bool, x: u64, k: u64) -> f64 {
    if !snapshot_some {
        return 0.0;
    }
    let product = (k as f64) * ((x as f64) * 0.001);
    if product < 0.07 {
        product
    } else {
        0.07
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supplied_map_zero_wins_and_missing_peer_uses_length() {
        assert_eq!(k_value(Some(0), Some(5), 10), 0);
        assert_eq!(k_value(None, None, 10), 10);
    }
    #[test]
    fn absent_snapshot_zero_delay_and_present_delay_caps() {
        assert_eq!(delay(false, u64::MAX, u64::MAX).to_bits(), 0.0f64.to_bits());
        assert_eq!(delay(true, 1, 1), 0.001);
        assert_eq!(delay(true, u64::MAX, u64::MAX), 0.07);
    }
}
