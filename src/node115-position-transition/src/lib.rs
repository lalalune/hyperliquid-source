//! Caller-bound projection for the node 115 position value update.
use std::num::NonZeroU64;

pub use node115_quantity_notification::prior;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedSide {
    pub account: [u8; 20],
    pub saved_size: i64,
    subtracts: bool,
}

/// Capture the side record at +0 or +0x120 as 0x4487910 does before the
/// account lookup. Only tag 1 enters the reconstructed path.
pub fn select_side(context: &[u8; 0x240], selector: u32) -> Option<SelectedSide> {
    let offset = if selector == 0 { 0 } else { 0x120 };
    let side = &context[offset..offset + 0x120];
    let tag = u32::from_le_bytes(side[..4].try_into().unwrap());
    (tag == 1).then(|| SelectedSide {
        account: side[0xf8..0x10c].try_into().unwrap(),
        saved_size: i64::from_le_bytes(side[8..16].try_into().unwrap()),
        subtracts: selector as u8 != 0,
    })
}

/// Loads at +0x248, +0x250 and +0x258 of the fill context at the update.
#[derive(Clone, Copy, Debug)]
pub struct Fill {
    pub unit_value: u64,
    pub quantity: u64,
    pub added_value: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Row {
    pub size: i64,
    pub value: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum Origin {
    Existing,
    Inserted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    QuantityOutOfSignedRange,
    ExistingValueOutOfSignedRange,
    CrossingProductOutOfRange,
}

impl SelectedSide {
    /// Update the resolved row's +0x30 value and enter the existing
    /// quantity-change model. The returned observation is its first boundary.
    /// `notification_context` identifies the caller's state+0xa8 object.
    pub fn update(
        &self,
        row: &mut Row,
        origin: Origin,
        fill: Fill,
        counter: u64,
        notification_context: NonZeroU64,
    ) -> Result<prior::Observation, Stop> {
        let quantity = i64::try_from(fill.quantity).map_err(|_| Stop::QuantityOutOfSignedRange)?;
        let delta = if self.subtracts { -quantity } else { quantity };
        let next_size = self.saved_size.saturating_add(delta);
        row.value = if next_size == 0 {
            0
        } else if self.saved_size.signum() != next_size.signum() {
            fill.unit_value
                .checked_mul(next_size.unsigned_abs())
                .filter(|&value| value < i64::MAX as u64)
                .ok_or(Stop::CrossingProductOutOfRange)?
        } else if (self.saved_size < 0) == self.subtracts {
            row.value.saturating_add(fill.added_value)
        } else {
            let value =
                i64::try_from(row.value).map_err(|_| Stop::ExistingValueOutOfSignedRange)?;
            let ratio = next_size as f64 / self.saved_size as f64;
            ((value as f64 * ratio) as i64).max(0) as u64
        };

        let before = match origin {
            Origin::Existing => row.size,
            Origin::Inserted => 0,
        };
        let notification = prior::Notification {
            payload: self.account,
            word: notification_context.get(),
        };
        Ok(prior::entry(before, row.size, counter, true, notification))
    }
}
