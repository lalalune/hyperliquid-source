# Node 115 scheduled-cancel state

Owned request admission, due-key collection and counter reset with actual logical
volume/schedule maps. Due keys are a handoff projection, not completed order
cancellation. Collection and reset remain separate because the native driver
performs cancellation between them.

See [the evidence packet](../../research/work-items/RE-010-node115-schedule-cancel-source/README.md)
for native coordinates, prior work, validation and the precise calendar/container
boundary. This is a scoped contribution to #3912; the issue stays open.
