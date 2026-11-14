//! Selected normal cleanup of TWAP-produced tag-4 records on both routes.
//! Valid distinct native allocations and normal-return destructors are premises.
//! This logical model owns its allocations and does not invent native pointers.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Perpetual,
    Spot,
}

/// One already constructed tag-4 record. `first_allocation` projects the
/// descriptor at record+0x18/+0x20. The producer's second descriptor is the
/// sentinel 0x8000000000000001 and does not own an allocation on this path.
pub struct Record {
    first_allocation: Option<Box<[u8]>>,
}
impl Record {
    pub fn from_owned_bytes(bytes: Vec<u8>) -> Self {
        let bytes = bytes.into_boxed_slice();
        Self {
            first_allocation: if bytes.is_empty() { None } else { Some(bytes) },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Cleanup {
    pub route: Route,
    pub original_count: usize,
    /// Sizes in native record order for the selected first-descriptor frees.
    pub released_sizes: Vec<usize>,
    /// The selected producer always supplies the second-descriptor sentinel.
    pub second_descriptor_frees: usize,
}

/// Detach the input queue, then consume records in order. The source queue is
/// empty before the first selected cleanup, as in both native flush prologues.
/// Other record tags, effects of unchecked helpers and unwind are outside scope.
pub fn drain_tag4(queue: &mut Vec<Record>, route: Route) -> Cleanup {
    let detached = std::mem::take(queue);
    let original_count = detached.len();
    let mut released_sizes = Vec::new();
    for record in detached {
        if let Some(bytes) = record.first_allocation {
            released_sizes.push(bytes.len());
            drop(bytes);
        }
    }
    Cleanup {
        route,
        original_count,
        released_sizes,
        second_descriptor_frees: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_routes_detach_and_release_in_record_order() {
        for route in [Route::Perpetual, Route::Spot] {
            let mut q = vec![
                Record::from_owned_bytes(vec![1; 3]),
                Record::from_owned_bytes(vec![]),
                Record::from_owned_bytes(vec![2; 7]),
            ];
            let out = drain_tag4(&mut q, route);
            assert_eq!(
                out,
                Cleanup {
                    route,
                    original_count: 3,
                    released_sizes: vec![3, 7],
                    second_descriptor_frees: 0
                }
            );
            assert!(q.is_empty());
            assert_eq!(q.capacity(), 0);
            assert_eq!(drain_tag4(&mut q, route).original_count, 0);
        }
    }
    #[test]
    fn all_small_allocation_combinations() {
        for mask in 0..256u16 {
            let mut q: Vec<_> = (0..8)
                .map(|i| {
                    Record::from_owned_bytes(vec![
                        i as u8;
                        if mask & (1 << i) != 0 { i + 1 } else { 0 }
                    ])
                })
                .collect();
            let expected: Vec<_> = (0..8)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| i + 1)
                .collect();
            assert_eq!(
                drain_tag4(&mut q, Route::Perpetual).released_sizes,
                expected
            );
            assert!(q.is_empty());
        }
    }
}
