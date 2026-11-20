//! Selected precheck-passed TWAP finish, with real owned tracker mutation.
//! This logical tree represents valid unique live records; it is not the native
//! ring/tree ABI. Alternate precheck output, allocation failures, panics and
//! the status-builder implementations are outside this slice.
use std::collections::BTreeMap;
pub type User = [u8; 20];
pub type Body = [u8; 0x68];
/// A stored order body cannot use the native missing-order sentinel.
#[derive(Debug)]
pub struct StoredBody(Body);
impl StoredBody {
    pub fn new(body: Body) -> Option<Self> {
        (body[0x22] != 2).then_some(Self(body))
    }
}
#[derive(Default)]
pub struct Tracker {
    users: BTreeMap<User, BTreeMap<u64, StoredBody>>,
}
impl Tracker {
    /// Valid bodies only; returns a replaced body if the key already exists.
    pub fn insert(&mut self, user: User, id: u64, body: StoredBody) -> Option<StoredBody> {
        self.users.entry(user).or_default().insert(id, body)
    }
    pub fn contains(&self, user: &User, id: u64) -> bool {
        self.users
            .get(user)
            .is_some_and(|orders| orders.contains_key(&id))
    }
    pub fn contains_user(&self, user: &User) -> bool {
        self.users.contains_key(user)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Perpetual,
    Spot,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Builder {
    PerpetualTag1,
    SpotTag1,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Stop {
    /// Native take reports 0xd4; no order or user was removed.
    Missing,
    /// Stop before the native expect-failure path; this is not a native return.
    /// The order has already been removed when the market bound fails.
    MarketOutOfRange { index: u64 },
}
#[derive(Debug)]
pub struct Prepared {
    pub builder: Builder,
    pub market_index: Option<u64>,
    pub body: Body,
    pub id: u64,
    pub user: User,
    pub moment: [u8; 12],
    pub reason: Vec<u8>,
}
/// The caller must have observed the native precheck byte 2 and supplied a
/// valid tracker: byte +0x22 is not the native missing-order sentinel. The
/// normal take result tag is 1. On successful removal, the last order removes
/// the user before any market bound check. No event is produced on a stop.
pub fn prepare(
    tracker: &mut Tracker,
    user: User,
    id: u64,
    route: Route,
    market_count: u64,
    moment: [u8; 12],
    reason: Vec<u8>,
) -> Result<Prepared, Stop> {
    let Some(orders) = tracker.users.get_mut(&user) else {
        return Err(Stop::Missing);
    };
    let Some(StoredBody(body)) = orders.remove(&id) else {
        return Err(Stop::Missing);
    };
    if orders.is_empty() {
        tracker.users.remove(&user);
    }
    let market_index = match route {
        Route::Perpetual => {
            let asset = u64::from_le_bytes(body[..8].try_into().unwrap());
            let index = asset / 10_000;
            if index >= market_count {
                return Err(Stop::MarketOutOfRange { index });
            }
            Some(index)
        }
        Route::Spot => None,
    };
    let builder = match route {
        Route::Perpetual => Builder::PerpetualTag1,
        Route::Spot => Builder::SpotTag1,
    };
    Ok(Prepared {
        builder,
        market_index,
        body,
        id,
        user,
        moment,
        reason,
    })
}
/// Logical event fields corresponding to the native tag-4 defined prefix.
/// The native allocator/pointer ABI and inactive event tail are not modeled.
#[derive(Debug, PartialEq, Eq)]
pub struct Event {
    pub tag: u8,
    pub status: [u8; 0x78],
    pub reason: Vec<u8>,
    pub id: u64,
    pub moment: [u8; 12],
    pub user: User,
}
impl Prepared {
    /// Resume after the selected status builder returns normally.
    pub fn complete(self, status: [u8; 0x78]) -> Event {
        Event {
            tag: 4,
            status,
            reason: self.reason,
            id: self.id,
            moment: self.moment,
            user: self.user,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn body(asset: u64) -> Body {
        let mut b = [0u8; 0x68];
        b[..8].copy_from_slice(&asset.to_le_bytes());
        b
    }
    #[test]
    fn missing_user_and_other_users_remain_unchanged() {
        let mut t = Tracker::default();
        let kept = [1; 20];
        let removed = [2; 20];
        t.insert(kept, 8, StoredBody::new(body(0)).unwrap());
        t.insert(removed, 9, StoredBody::new(body(u64::MAX)).unwrap());
        assert_eq!(
            prepare(&mut t, [3; 20], 9, Route::Spot, 0, [0; 12], vec![]).unwrap_err(),
            Stop::Missing
        );
        let ready = prepare(&mut t, removed, 9, Route::Spot, 0, [0; 12], vec![]).unwrap();
        assert_eq!(ready.market_index, None);
        assert!(!t.contains_user(&removed));
        assert!(t.contains(&kept, 8));
    }
    #[test]
    fn sentinel_is_rejected_before_insertion() {
        let mut b = body(0);
        b[0x22] = 2;
        assert!(StoredBody::new(b).is_none());
    }
    #[test]
    fn missing_does_not_mutate_existing_user() {
        let u = [7; 20];
        let mut t = Tracker::default();
        t.insert(u, 1, StoredBody::new(body(0)).unwrap());
        assert_eq!(
            prepare(&mut t, u, 2, Route::Spot, 0, [0; 12], vec![]).unwrap_err(),
            Stop::Missing
        );
        assert!(t.contains(&u, 1));
    }
    #[test]
    fn remove_one_then_last_and_emit_fields() {
        let u = [9; 20];
        let mut t = Tracker::default();
        t.insert(u, 1, StoredBody::new(body(20_001)).unwrap());
        t.insert(u, 2, StoredBody::new(body(0)).unwrap());
        let p = prepare(&mut t, u, 1, Route::Perpetual, 3, [4; 12], vec![5]).unwrap();
        assert_eq!(p.market_index, Some(2));
        assert_eq!(p.builder, Builder::PerpetualTag1);
        assert!(t.contains(&u, 2));
        let e = p.complete([6; 0x78]);
        assert_eq!(
            (e.tag, e.status, e.reason, e.id, e.moment, e.user),
            (4, [6; 0x78], vec![5], 1, [4; 12], u)
        );
        let p = prepare(&mut t, u, 2, Route::Spot, 0, [0; 12], vec![]).unwrap();
        assert_eq!(p.builder, Builder::SpotTag1);
        assert!(!t.contains_user(&u));
    }
    #[test]
    fn market_failure_occurs_after_removal() {
        let u = [1; 20];
        let mut t = Tracker::default();
        t.insert(u, 1, StoredBody::new(body(30_000)).unwrap());
        assert_eq!(
            prepare(&mut t, u, 1, Route::Perpetual, 3, [0; 12], vec![]).unwrap_err(),
            Stop::MarketOutOfRange { index: 3 }
        );
        assert!(!t.contains_user(&u));
    }
}
