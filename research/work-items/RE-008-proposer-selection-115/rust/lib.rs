// SPDX-License-Identifier: MIT
// Independent conditional value projection; see ../PROOF.md for native premises.
use std::cmp::Ordering;

pub type Key = [u8; 20];
pub type Row = (Key, u64);
pub const MISSING: u8 = 0x28;
pub const EMPTY: u8 = 0x0f;
pub const SELECTED: u8 = 0x2e;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    InvalidSnapshot,
    Capacity,
}

#[derive(Clone, Debug)]
pub struct Prepared {
    pub total: u64,
    pub threshold: u64,
    pub adjusted: Vec<Row>,
    pub fallback: Vec<(u64, Key)>,
    pub members: Vec<Key>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub bits: u64,
    pub key: Option<Key>,
}

#[derive(Clone, Debug)]
pub struct Schedule {
    pub image: [u8; 72],
    pub events: Vec<Event>,
    pub keys: Vec<Key>,
}

fn strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|w| w[0] < w[1])
}

/// Query and predecessor index. The snapshot keys must be strictly increasing.
pub fn history(base: u64, rounds: &[u64], round: u64) -> Result<(u64, Option<usize>), Failure> {
    if !strictly_sorted(rounds) {
        return Err(Failure::InvalidSnapshot);
    }
    let query = if round < base.saturating_add(2000) {
        base
    } else {
        base.max(round.wrapping_sub(200))
    };
    let index = rounds.partition_point(|&r| r <= query).checked_sub(1);
    Ok((query, index))
}

/// Both sets and map keys are supplied as complete, ordered value snapshots.
pub fn prepare(blocked: &[Key], extra: &[Key], rows: &[Row]) -> Result<Prepared, Failure> {
    if !strictly_sorted(blocked)
        || !strictly_sorted(extra)
        || !rows.windows(2).all(|w| w[0].0 < w[1].0)
    {
        return Err(Failure::InvalidSnapshot);
    }
    let mut members = blocked.to_vec();
    members.extend_from_slice(extra);
    members.sort_unstable();
    members.dedup();
    let kept: Vec<Row> = rows
        .iter()
        .copied()
        .filter(|(key, _)| blocked.binary_search(key).is_err())
        .collect();
    let mut total = 0u64;
    for &(_, weight) in &kept {
        total = total.saturating_add(weight);
    }
    let threshold = if members.is_empty() {
        0
    } else {
        total.saturating_sub(1000) / members.len() as u64
    };
    let adjusted: Vec<Row> = kept
        .into_iter()
        .map(|(key, weight)| {
            let weight = if members.binary_search(&key).is_ok() {
                weight.saturating_sub(threshold)
            } else {
                weight.saturating_mul(3)
            };
            (key, weight)
        })
        .collect();
    let mut fallback: Vec<(u64, Key)> = adjusted
        .iter()
        .filter(|(key, _)| members.binary_search(key).is_ok())
        .map(|&(key, weight)| (weight.saturating_mul(3), key))
        .collect();
    fallback.sort_unstable_by(|a, b| b.cmp(a));
    Ok(Prepared {
        total,
        threshold,
        adjusted,
        fallback,
        members,
    })
}

/// Arithmetic-stage projection, including inputs that cannot be materialized as
/// native arrays. i<n, j<w, n,w>0 and i<=i64::MAX are explicit admission bounds.
pub fn event_bits(i: u64, n: u64, weight: u64, j: u64) -> Result<[u64; 3], Failure> {
    if n == 0 || weight == 0 || i >= n || i > i64::MAX as u64 || j >= weight {
        return Err(Failure::InvalidSnapshot);
    }
    let inverse = 1.0 / weight as f64;
    let product = i as i64 as f64 * inverse;
    let base = product / n as f64;
    let point = inverse.mul_add(j as f64, base);
    Ok([inverse.to_bits(), base.to_bits(), point.to_bits()])
}

pub fn event_order(a: &Event, b: &Event) -> Ordering {
    f64::from_bits(a.bits)
        .total_cmp(&f64::from_bits(b.bits))
        .then_with(|| a.key.cmp(&b.key))
}

/// Ordered events -> three-at-a-time ranked replacement. Equal None events are
/// interchangeable; inactive payload bytes are deliberately not observed.
pub fn expand(events: &[Event], fallback: &[(u64, Key)]) -> Result<Vec<Key>, Failure> {
    let count = events.iter().try_fold(0usize, |sum, event| {
        sum.checked_add(if event.key.is_some() { 1 } else { 3 })
            .ok_or(Failure::Capacity)
    })?;
    if count > isize::MAX as usize / 20 {
        return Err(Failure::Capacity);
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| Failure::Capacity)?;
    let mut pool = fallback.to_vec();
    for event in events {
        if let Some(key) = event.key {
            result.push(key);
        } else if !pool.is_empty() {
            // Preserve the target's batch: no reranking between these writes.
            for index in [0, usize::from(pool.len() != 1), 2 % pool.len()] {
                result.push(pool[index].1);
                pool[index].0 = pool[index].0.saturating_sub(1);
            }
            pool.sort_unstable_by(|a, b| b.cmp(a));
            while pool.last().is_some_and(|x| x.0 == 0) {
                pool.pop();
            }
        }
    }
    Ok(result)
}

/// Normal-return semantic projection under the memory, helper and floating-point
/// premises in PROOF.md. Allocation/panic/ABI behavior is not reproduced.
pub fn schedule(
    blocked: &[Key],
    extra: &[Key],
    rows: &[Row],
    round: u64,
    mut image: [u8; 72],
) -> Result<Schedule, Failure> {
    let p = prepare(blocked, extra, rows)?;
    let count = p.adjusted.iter().try_fold(0usize, |sum, &(_, weight)| {
        usize::try_from(weight)
            .ok()
            .and_then(|w| sum.checked_add(w))
            .ok_or(Failure::Capacity)
    })?;
    if count > (isize::MAX as usize - 7) / 32 {
        return Err(Failure::Capacity);
    }
    let mut events = Vec::new();
    events
        .try_reserve_exact(count)
        .map_err(|_| Failure::Capacity)?;
    for (index, &(key, weight)) in p.adjusted.iter().enumerate() {
        let payload = if p.members.binary_search(&key).is_ok() {
            None
        } else {
            Some(key)
        };
        for j in 0..weight {
            let bits = event_bits(index as u64, p.adjusted.len() as u64, weight, j)?[2];
            events.push(Event { bits, key: payload });
        }
    }
    events.sort_by(event_order);
    let keys = expand(&events, &p.fallback)?;
    if keys.is_empty() {
        image[0] = EMPTY;
    } else {
        let key = keys[(round % keys.len() as u64) as usize];
        image[1..21].copy_from_slice(&key);
        image[0] = SELECTED;
    }
    Ok(Schedule {
        image,
        events,
        keys,
    })
}

pub struct History<T> {
    pub base: u64,
    pub snapshots: Vec<(u64, T)>,
}

/// Sequential value observation of a diagnostic. The native lock-inc is atomic;
/// this value API does not model concurrent interleavings or logging side effects.
pub fn diagnostic(
    stake_base: u64,
    execution: u64,
    query_round: u64,
    counter: u64,
) -> (u64, u64, bool) {
    let limit = stake_base
        .saturating_add(2000)
        .max(execution.saturating_add(201));
    let warning = query_round >= limit;
    (limit, counter.wrapping_add(u64::from(warning)), warning)
}

/// Safe logical projection of the 32/64-byte ring-history upper-bound helpers.
/// Unused capacity words have no order requirement. Valid logical keys are unique.
pub fn ring_history(
    physical: &[u64],
    head: usize,
    len: usize,
    query: u64,
) -> Result<(usize, Option<usize>), Failure> {
    let cap = physical.len();
    if len > cap || (cap == 0 && (head != 0 || len != 0)) || (cap != 0 && head >= cap) {
        return Err(Failure::InvalidSnapshot);
    }
    if len == 0 {
        return Ok((0, None));
    }
    let at = |i: usize| {
        if i >= cap - head {
            i - (cap - head)
        } else {
            head + i
        }
    };
    if (1..len).any(|i| physical[at(i - 1)] >= physical[at(i)]) {
        return Err(Failure::InvalidSnapshot);
    }
    let (mut lo, mut hi) = (0usize, len);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if physical[at(mid)] <= query {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok((lo, lo.checked_sub(1).map(at)))
}

pub enum HistoryResult {
    Missing {
        first: (u64, Option<usize>),
        second: Option<(u64, Option<usize>)>,
        counter: u64,
        image: [u8; 72],
    },
    Selected {
        first: (u64, Option<usize>),
        second: (u64, Option<usize>),
        counter: u64,
        schedule: Schedule,
    },
}

/// Query round is native RCX; selected round is native RDX. Scratch is the
/// supplied initial 72-byte local result image, distinct from caller output.
/// Missing queries copy that full scratch image after the helper's two writes.
pub fn from_histories(
    first: &History<Vec<Key>>,
    second: &History<Vec<Row>>,
    extra: &[Key],
    selected_round: u64,
    query_round: u64,
    execution: u64,
    counter: u64,
    mut scratch: [u8; 72],
    image: [u8; 72],
) -> Result<HistoryResult, Failure> {
    let (_, counter, _) = diagnostic(second.base, execution, query_round, counter);
    let a = history(
        first.base,
        &first.snapshots.iter().map(|x| x.0).collect::<Vec<_>>(),
        query_round,
    )?;
    let mut observed_counter = counter;
    let b = if a.1.is_some() {
        observed_counter = diagnostic(second.base, execution, query_round, counter).1;
        Some(history(
            second.base,
            &second.snapshots.iter().map(|x| x.0).collect::<Vec<_>>(),
            query_round,
        )?)
    } else {
        None
    };
    if let (Some(ai), Some((_, Some(bi)))) = (a.1, b) {
        let value = schedule(
            &first.snapshots[ai].1,
            extra,
            &second.snapshots[bi].1,
            selected_round,
            image,
        )?;
        Ok(HistoryResult::Selected {
            first: a,
            second: b.unwrap(),
            counter: observed_counter,
            schedule: value,
        })
    } else {
        scratch[0] = MISSING;
        scratch[8..16].copy_from_slice(&query_round.to_le_bytes());
        Ok(HistoryResult::Missing {
            first: a,
            second: b,
            counter: observed_counter,
            image: scratch,
        })
    }
}
