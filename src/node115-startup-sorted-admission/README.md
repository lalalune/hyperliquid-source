# Node115 startup sorted admission

This opt-in adapter calls the existing `node115-startup-admission` API and
stably orders its accepted strings by their UTF-8 bytes. It retains that API's
supplied already-joined-byte premise and duplicate rows. Native path
construction, scratch allocation, tree construction and subsequent checkpoint
selection are outside this logical source adapter. The earlier admission crate
and its encounter-order behavior remain unchanged.

The target-bound static evidence and the conditional long-sort argument are in
`research/work-items/RE-012-node115-startup-path-long-sort`.
