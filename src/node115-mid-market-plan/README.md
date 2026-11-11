# Node 115 midpoint-market plan

This `no_std` crate computes the bounded typed plan documented in
[`RE-006-node115-mid-market-plan`](../../research/work-items/RE-006-node115-mid-market-plan/README.md).
Inputs include an already obtained best pair, checked metadata and time. It does
not access a book, submit an order, or reproduce a native memory layout.
