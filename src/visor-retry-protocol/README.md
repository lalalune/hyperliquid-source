# Visor retry protocol values

This real two-package Cargo graph adds a pure supplied-callback retry operation and its owned command/optional-cleanup specialization. Its only dependency is the unchanged sibling `visor-duration-value` component. It extends the same PR1599; it creates no root workspace or network dependency.

`retry` preserves initial-attempt laziness, exact raw schedules, error replacement order and terminal identity. `retry_owned` fixes the observed description, option0 and raw[1,3,10] schedule, then disposes the command and handles optional cleanup without changing the retry result. `SleepRequest` has private canonical fields and exposes raw clock1/flags0 to a supplied adapter. This crate performs no command, filesystem, network, clock or sleep operation.

`InvalidRemainder` and `UnexpectedSleepCode` are explicit new safe policies. Native correspondence covers ordinary callbacks and destructors, valid preserved borrows and unique owned resources; it does not include invalid native memory, original private error layouts, panic/unwind, allocator failure or external effects. Source proof and pre-source expectations are in `research/work-items/RE-013-visor-owned-retry-protocol`.

No source-build qualification is claimed by this initial authored phase. Builds require the later exact source/harness gate. New code is MIT under the repository license. No original-source or whole-Visor equivalence is claimed.
