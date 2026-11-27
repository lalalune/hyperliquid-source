//! Multi-asset orderbook collection (`l1/src/books.rs`).

use std::collections::BTreeMap;

use node115_assets::qtys::{OverflowSink, Px};
use node115_fees::UserAddress;

use crate::matching::{
    Book, BookRiskOracle, CancelError, InsertError, InsertOrderRequest, InsertOutcome,
    ModifyError, ModifyOrderRequest,
};
use crate::slab::OrderRecord;

/// Collection of per-asset `Book` instances keyed by asset ID (`PerpAsset` or `SpotAsset`).
#[derive(Clone, Debug, Default)]
pub struct Books<A: Ord> {
    books: BTreeMap<A, Book>,
}

impl<A: Ord> Books<A> {
    pub fn new() -> Self {
        Self {
            books: BTreeMap::new(),
        }
    }

    pub fn get(&self, asset: &A) -> Option<&Book> {
        self.books.get(asset)
    }

    pub fn get_mut(&mut self, asset: &A) -> Option<&mut Book> {
        self.books.get_mut(asset)
    }

    pub fn entry_or_default(&mut self, asset: A) -> &mut Book {
        self.books.entry(asset).or_default()
    }

    pub fn len(&self) -> usize {
        self.books.len()
    }

    pub fn is_empty(&self) -> bool {
        self.books.is_empty()
    }

    pub fn bbo(&self, asset: &A) -> (Option<Px>, Option<Px>) {
        self.books
            .get(asset)
            .map(Book::bbo)
            .unwrap_or((None, None))
    }

    pub fn insert_order(
        &mut self,
        asset: A,
        req: InsertOrderRequest,
        risk: &mut impl BookRiskOracle,
        sink: &mut impl OverflowSink,
    ) -> Result<InsertOutcome, InsertError> {
        self.entry_or_default(asset).insert_order(req, risk, sink)
    }

    pub fn cancel_order(
        &mut self,
        asset: &A,
        user: &UserAddress,
        oid: u64,
        sink: &mut impl OverflowSink,
    ) -> Result<OrderRecord, CancelError> {
        self.books
            .get_mut(asset)
            .ok_or(CancelError::NotFound)?
            .cancel_order(user, oid, sink)
    }

    pub fn modify_order(
        &mut self,
        asset: &A,
        req: ModifyOrderRequest,
        risk: &mut impl BookRiskOracle,
        sink: &mut impl OverflowSink,
    ) -> Result<(OrderRecord, InsertOutcome), ModifyError> {
        self.books
            .get_mut(asset)
            .ok_or(ModifyError::Cancel(CancelError::NotFound))?
            .modify_order(req, risk, sink)
    }
}
