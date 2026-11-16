# node115-owned-frame-send

Owned selected TCP frame and chunked write continuation; reuses the existing
write-progress relation. The host `Write` adapter does not claim the native
socket/future ABI. See [the evidence packet](../../research/work-items/RE-012-node115-owned-frame-send/README.md)
for exact target-bound dataflow, tests and limits.
