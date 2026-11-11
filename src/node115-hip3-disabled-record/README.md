# node115-hip3-disabled-record

An independently authored, allocation-free encoding of the selected successful
five-field node115 per-DEX record. It composes existing date/time display with
the native `T` separator and MessagePack framing, integer widths, disabled-state
labels, and boolean `m` field. It does not implement the enclosing Main/Hip3
variant, request handling, mutation, or native allocation failures.

See `research/work-items/RE-007-node115-hip3-record-source/README.md` for the
target identity, dependency credit, scope, evidence and reproduction commands.
