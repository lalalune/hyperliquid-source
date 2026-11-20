//! Three price-list retain passes and their open-interest cap inputs.
use node115_open_interest_cap::{Input, Outcome, project};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Price {
    pub asset: u64,
    pub multiplier: i64,
}

/// Logical contents of a valid unique-key native lookup map. Ring entries
/// must be sorted by unsigned asset key in logical front-to-back order.
pub enum Sizes<'a> {
    Ring(&'a VecDeque<(u64, i64)>),
    Tree(&'a BTreeMap<u64, i64>),
}

impl Sizes<'_> {
    fn for_asset(&self, key: u64) -> i64 {
        match self {
            Self::Ring(rows) => rows
                .binary_search_by_key(&key, |row| row.0)
                .ok()
                .map_or(0, |i| rows[i].1),
            Self::Tree(rows) => rows.get(&key).copied().unwrap_or(0),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Diagnostic {
    SumOverflow,
    Cap,
}

/// Ordered logical requests corresponding to the two appended native strings.
#[derive(Debug, PartialEq)]
pub enum Message {
    Cap {
        mapped_asset: u32,
        selector: u8,
        open_interest: f64,
    },
    MissingPrice {
        mapped_asset: u32,
        selector: u8,
        oracle: u8,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Stop {
    BookIndex(u64),
    NegativeBookTotal(i64),
}

pub struct CapContext<'a> {
    pub sizes: Sizes<'a>,
    /// Optional book vector. The selected qword is at book-row +0x118.
    pub book_totals: Option<&'a [i64]>,
    pub cap_word: i64,
}

impl CapContext<'_> {
    fn keep(
        &mut self,
        price: Price,
        selector: u8,
        oracle: u8,
        messages: &mut Vec<Message>,
        diagnostic: &mut impl FnMut(Diagnostic, &mut i64),
    ) -> Result<bool, Stop> {
        let stored = self.sizes.for_asset(price.asset);
        let book = match self.book_totals {
            Some(rows) => {
                let index = price.asset % 10_000;
                *rows.get(index as usize).ok_or(Stop::BookIndex(index))?
            }
            None => 0,
        };
        if book < 0 {
            return Err(Stop::NegativeBookTotal(book));
        }
        // The helper reloads context+0x378 after the overflow callback returns.
        if stored.checked_add(book).is_none() {
            diagnostic(Diagnostic::SumOverflow, &mut self.cap_word);
        }
        let projection = project(Input {
            sum_left: stored,
            sum_right: book,
            multiplier: price.multiplier,
            key: price.asset,
            selector,
            observed_cap_word: self.cap_word,
        })
        .map_err(|_| Stop::NegativeBookTotal(book))?;
        if projection.cap_request {
            diagnostic(Diagnostic::Cap, &mut self.cap_word);
        }
        match projection.outcome {
            Outcome::SentinelOnly => Ok(true),
            Outcome::Format {
                mapped_key,
                selector,
                open_interest,
            } => {
                messages.push(Message::Cap {
                    mapped_asset: mapped_key,
                    selector,
                    open_interest,
                });
                messages.push(Message::MissingPrice {
                    mapped_asset: mapped_key,
                    selector,
                    oracle,
                });
                Ok(false)
            }
        }
    }

    /// Stable retain in native Spot, Mark, External order. A typed stop marks
    /// the failing predicate and leaves the remaining suffix available.
    pub fn retain(
        &mut self,
        lists: &mut [Vec<Price>; 3],
        oracle: u8,
        messages: &mut Vec<Message>,
        mut diagnostic: impl FnMut(Diagnostic, &mut i64),
    ) -> Result<(), Stop> {
        for (selector, list) in lists.iter_mut().enumerate() {
            let mut stop = None;
            list.retain(|&price| {
                if stop.is_some() {
                    return true;
                }
                match self.keep(price, selector as u8, oracle, messages, &mut diagnostic) {
                    Ok(keep) => keep,
                    Err(error) => {
                        stop = Some(error);
                        true
                    }
                }
            });
            if let Some(error) = stop {
                return Err(error);
            }
        }
        Ok(())
    }
}
