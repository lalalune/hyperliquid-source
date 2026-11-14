//! Bounded shared-bound and split-result selection for node #115 fee traversal.
//! The caller supplies valid mode 0/1, a live shared atomic, and completed
//! child results. This does not reconstruct scheduling or diagnostic ownership.
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    First,
    Last,
}

/// Adapter entry's range-pruning check. Equality must remain eligible.
pub fn prune_range(bound: u64, left: u64, right: u64, direction: Direction) -> bool {
    match direction {
        Direction::First => bound < left,
        Direction::Last => bound > right,
    }
}

/// The failure path updates the shared bound with unsigned min/max. Equality
/// follows the selected branch even though no successful exchange was needed.
pub fn publish(bound: &AtomicU64, candidate: u64, direction: Direction) -> bool {
    let mut observed = bound.load(Ordering::SeqCst);
    loop {
        let better = match direction {
            Direction::First => candidate < observed,
            Direction::Last => candidate > observed,
        };
        if !better {
            return candidate == observed;
        }
        match bound.compare_exchange_weak(observed, candidate, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(current) => observed = current,
        }
    }
}

/// Classify using the previously recovered kernel, then project the selected
/// failure continuation. Prior tag 2 or direction Last enables bound arbitration;
/// otherwise the prior value is preserved. Formatting must return normally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointResult {
    Pass,
    Failure {
        classification: node115_fee_point_classifier::Classification,
        selected: bool,
    },
}
pub fn classify_and_publish(
    point: node115_fee_point_classifier::Point,
    prior_tag: u64,
    bound: &AtomicU64,
    candidate: u64,
    direction: Direction,
) -> Result<PointResult, node115_fee_point_classifier::DomainError> {
    use node115_fee_point_classifier::{Classification, classify};
    let classification = classify(point)?;
    if classification == Classification::Pass {
        return Ok(PointResult::Pass);
    }
    let eligible = prior_tag == 2 || direction == Direction::Last;
    Ok(PointResult::Failure {
        classification,
        selected: eligible && publish(bound, candidate, direction),
    })
}

/// Integrates a previous result (None is native tag 2) with a newly formatted
/// candidate payload. Actual formatting and native allocation are premises.
pub fn accumulate<T>(
    point: node115_fee_point_classifier::Point,
    previous: Option<T>,
    candidate_payload: T,
    bound: &AtomicU64,
    candidate: u64,
    direction: Direction,
) -> Result<Option<T>, node115_fee_point_classifier::DomainError> {
    let tag = if previous.is_none() { 2 } else { 0 };
    match classify_and_publish(point, tag, bound, candidate, direction)? {
        PointResult::Failure { selected: true, .. } => Ok(Some(candidate_payload)),
        _ => Ok(previous),
    }
}

/// Native tag 2 is absent. The chosen side is returned without interpreting
/// its payload; equal-coordinate payload identity is not decided by the bound.
pub fn select<T>(left: Option<T>, right: Option<T>, direction: Direction) -> Option<T> {
    match direction {
        Direction::First => left.or(right),
        Direction::Last => right.or(left),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_and_equalities() {
        for &(d, initial, better, worse) in
            &[(Direction::First, 10, 3, 11), (Direction::Last, 10, 17, 9)]
        {
            let a = AtomicU64::new(initial);
            assert!(publish(&a, better, d));
            assert!(publish(&a, better, d));
            assert!(!publish(&a, worse, d));
            assert_eq!(a.load(Ordering::SeqCst), better);
        }
        assert!(!prune_range(10, 10, 20, Direction::First));
        assert!(!prune_range(20, 10, 20, Direction::Last));
        assert!(prune_range(9, 10, 20, Direction::First));
        assert!(prune_range(21, 10, 20, Direction::Last));
    }
    #[test]
    fn all_small_orders_and_extremes() {
        for d in [Direction::First, Direction::Last] {
            for x in 0..8 {
                for y in 0..8 {
                    for z in 0..8 {
                        let b = AtomicU64::new(x);
                        publish(&b, y, d);
                        publish(&b, z, d);
                        let expected = match d {
                            Direction::First => x.min(y).min(z),
                            Direction::Last => x.max(y).max(z),
                        };
                        assert_eq!(b.load(Ordering::SeqCst), expected);
                    }
                }
            }
            let b = AtomicU64::new(if d == Direction::First { u64::MAX } else { 0 });
            assert!(publish(
                &b,
                if d == Direction::First { 0 } else { u64::MAX },
                d
            ));
        }
    }
    #[test]
    fn result_choice_and_equal_payloads() {
        for (l, r, first, last) in [
            (None, None, None, None),
            (Some(1), None, Some(1), Some(1)),
            (None, Some(2), Some(2), Some(2)),
            (Some(1), Some(2), Some(1), Some(2)),
        ] {
            assert_eq!(select(l, r, Direction::First), first);
            assert_eq!(select(l, r, Direction::Last), last);
        }
        let b = AtomicU64::new(7);
        assert!(publish(&b, 7, Direction::First));
        assert!(publish(&b, 7, Direction::First));
        assert_eq!(
            select(Some("left"), Some("right"), Direction::First),
            Some("left")
        );
    }
    #[test]
    fn existing_point_to_bound_witness() {
        use node115_fee_point_classifier::{Classification, Point, SCALE_BITS};
        let mut p = Point {
            quantity: 10,
            scale_bits: SCALE_BITS[0],
            t_bits: 1f64.to_bits(),
            d_bits: 0f64.to_bits(),
            q_bits: (-1f64).to_bits(),
            m_bits: 0f64.to_bits(),
            h_bits: 0f64.to_bits(),
        };
        let b = AtomicU64::new(9);
        assert_eq!(
            classify_and_publish(p, 2, &b, 4, Direction::First),
            Ok(PointResult::Failure {
                classification: Classification::FirstProductNegative,
                selected: true
            })
        );
        assert_eq!(b.load(Ordering::SeqCst), 4);
        p.q_bits = 0f64.to_bits();
        assert_eq!(
            classify_and_publish(p, 2, &b, 1, Direction::First),
            Ok(PointResult::Pass)
        );
        assert_eq!(b.load(Ordering::SeqCst), 4);
    }
    #[test]
    fn guard_and_real_thread_contention() {
        use node115_fee_point_classifier::{Classification, Point, SCALE_BITS};
        let p = Point {
            quantity: 10,
            scale_bits: SCALE_BITS[0],
            t_bits: 1f64.to_bits(),
            d_bits: 0f64.to_bits(),
            q_bits: (-1f64).to_bits(),
            m_bits: 0f64.to_bits(),
            h_bits: 0f64.to_bits(),
        };
        let a = AtomicU64::new(10);
        let failure = |selected| {
            Ok(PointResult::Failure {
                classification: Classification::FirstProductNegative,
                selected,
            })
        };
        assert_eq!(
            classify_and_publish(p, 0, &a, 1, Direction::First),
            failure(false)
        );
        assert_eq!(a.load(Ordering::SeqCst), 10);
        assert_eq!(
            classify_and_publish(p, 0, &a, 20, Direction::Last),
            failure(true)
        );
        assert_eq!(
            classify_and_publish(p, 0, &a, 20, Direction::Last),
            failure(true)
        );
        assert_eq!(
            accumulate(p, Some("old"), "new", &a, 1, Direction::First),
            Ok(Some("old"))
        );
        assert_eq!(a.load(Ordering::SeqCst), 20);
        assert_eq!(
            accumulate(p, Some("old"), "new", &a, 20, Direction::Last),
            Ok(Some("new"))
        );
        std::thread::scope(|scope| {
            for value in 0..32 {
                let a = &a;
                scope.spawn(move || {
                    publish(a, value, Direction::First);
                });
            }
        });
        assert_eq!(a.load(Ordering::SeqCst), 0);
    }
}
