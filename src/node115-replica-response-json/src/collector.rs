//! Ordered result observations consumed by the selected replica collector.

use crate::Response;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedBundle<T> {
    Row {
        ordinal: u64,
        reference: [u8; 32],
        entries: Vec<T>,
    },
    End,
}

/// A Full response prefix with the source ordinals kept outside the JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectedFull<T> {
    ordinals: Vec<u64>,
    rows: Vec<([u8; 32], Vec<T>)>,
    stop_position: Option<usize>,
}

impl<T> CollectedFull<T> {
    pub fn ordinals(&self) -> &[u64] {
        &self.ordinals
    }

    /// Zero-based position of an explicit end observation in the input.
    pub fn stop_position(&self) -> Option<usize> {
        self.stop_position
    }

    pub fn response(&self) -> Response<'_, T> {
        Response::Full(&self.rows)
    }
}

/// Collect rows in the supplied logical order, before the first explicit end.
///
/// This models the emitted prefix of an observed row iterator. An ordinary
/// row without entries remains in the Full response. The caller determines
/// the original ring or tree order and supplies any end observation.
pub fn collect_full<T>(observed: impl IntoIterator<Item = ObservedBundle<T>>) -> CollectedFull<T> {
    let mut ordinals = Vec::new();
    let mut rows = Vec::new();
    let mut stop_position = None;
    for (position, observation) in observed.into_iter().enumerate() {
        match observation {
            ObservedBundle::Row {
                ordinal,
                reference,
                entries,
            } => {
                ordinals.push(ordinal);
                rows.push((reference, entries));
            }
            ObservedBundle::End => {
                stop_position = Some(position);
                break;
            }
        }
    }
    CollectedFull {
        ordinals,
        rows,
        stop_position,
    }
}
