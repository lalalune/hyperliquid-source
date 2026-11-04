//! Quantity-change observations at entry and an independently fresh post-lookup
//! point. Opaque calls are boundaries, never assumed to return or fabricated.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Notification {
    pub word: u64,
    pub payload: [u8; 20],
}

/// Analysis labels, not recovered native error variants or an original ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Boundary {
    Returned,
    Lookup,
    Notify {
        word: u64,
        new_bits: u64,
        payload: [u8; 20],
    },
    SubtractDiagnostic {
        pending: i64,
    },
    AddDiagnostic {
        pending: i64,
    },
    AbsoluteDiagnostic,
}

/// A memory observation; `value` is not an asserted native RAX return value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub value: u64,
    pub writes: Vec<u64>,
    pub next: Boundary,
}

impl Observation {
    fn initial(value: u64) -> Self {
        Self {
            value,
            writes: Vec::new(),
            next: Boundary::Returned,
        }
    }

    fn store(&mut self, value: u64) {
        self.value = value;
        self.writes.push(value);
    }

    fn notification(&mut self, old: i64, new: i64, notification: Notification) {
        if notification.word != 0 && old != new {
            self.next = Boundary::Notify {
                word: notification.word,
                new_bits: new as u64,
                payload: notification.payload,
            };
        }
    }
}

/// Actual counter update followed by a lookup boundary, notification boundary,
/// or normal return. This never supplies the optional lookup's result.
pub fn entry(
    old: i64,
    new: i64,
    counter: u64,
    has_total: bool,
    notification: Notification,
) -> Observation {
    let mut out = Observation::initial(counter);
    if old == 0 && new != 0 {
        out.store(counter.saturating_add(1));
    } else if old != 0 && new == 0 && counter != 0 {
        out.store(counter - 1);
    }
    if has_total {
        out.next = Boundary::Lookup;
    } else {
        out.notification(old, new, notification);
    }
    out
}

/// Independently fresh point after lookup. `total` is a newly supplied cell,
/// not a claimed return from the opaque lookup above. Ordered stores matter:
/// the first total store can precede the new-value absolute diagnostic.
pub fn post_lookup(old: i64, new: i64, total: i64, notification: Notification) -> Observation {
    let mut out = Observation::initial(total as u64);
    let Some(old_abs) = old.checked_abs() else {
        out.next = Boundary::AbsoluteDiagnostic;
        return out;
    };
    let Some(subtracted) = total.checked_sub(old_abs) else {
        out.next = Boundary::SubtractDiagnostic { pending: i64::MIN };
        return out;
    };
    out.store(subtracted as u64);
    let Some(new_abs) = new.checked_abs() else {
        out.next = Boundary::AbsoluteDiagnostic;
        return out;
    };
    let Some(added) = subtracted.checked_add(new_abs) else {
        out.next = Boundary::AddDiagnostic { pending: i64::MAX };
        return out;
    };
    out.store(added as u64);
    out.notification(old, new, notification);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("../../research/work-items/RE-004-quantity-change-115/client_fixture.rs");

    #[test]
    fn sealed_original_stores_and_frontiers() {
        for line in
            include_str!("../../research/work-items/RE-004-quantity-change-115/target-smoke.tsv")
                .lines()
        {
            let fields: Vec<_> = line.split('\t').collect();
            let input: Vec<u64> = fields[..6].iter().map(|s| s.parse().unwrap()).collect();
            assert_eq!(evaluate_row(&input).unwrap(), fields[6]);
        }
    }

    #[test]
    fn no_assumed_diagnostic_return_or_atomic_store() {
        let notification = Notification {
            word: 0,
            payload: [0; 20],
        };
        let underflow = post_lookup(i64::MAX, i64::MAX, i64::MIN, notification);
        assert!(underflow.writes.is_empty());
        assert_eq!(
            underflow.next,
            Boundary::SubtractDiagnostic { pending: i64::MIN }
        );
        let invalid_new = post_lookup(1, i64::MIN, 5, notification);
        assert_eq!(invalid_new.value, 4);
        assert_eq!(invalid_new.writes, vec![4]);
        assert_eq!(invalid_new.next, Boundary::AbsoluteDiagnostic);
    }
}
