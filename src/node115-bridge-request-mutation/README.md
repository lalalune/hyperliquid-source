# Owned bridge request mutation

See [the evidence and boundaries](../../research/work-items/RE-005-node115-bridge-request-mutation/README.md).
This source owns its logical ordered map and aggregate. It exposes state before
native panic/unwrap and after the aggregate store. It does not reproduce physical
allocation, native pointer values, outer rollback, or the full wrapper lifecycle.
