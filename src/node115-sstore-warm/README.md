# Node 115 warm-resident SSTORE

Owned Rust source for the selected stack/gas/storage/journal/reserve/refund
transition. Accounts and slots reached by the operation must already be resident
and warm in the current transaction. This API retains native prefix effects:
later gas or refund failure does not undo earlier host writes.

See [the evidence packet](../../research/work-items/RE-011-node115-sstore-warm-source/README.md)
for addresses, input premises, previous research, exclusions and reproducible
checks. This is a scoped contribution to #3918, not a complete EVM or provider.
