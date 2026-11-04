# node115-write-progress

Dependency-free, no_std conditional scalar kernel derived from authenticated
node115 prepared-write transitions. See research/work-items/RE-012-write-progress-115.
`charge` applies only on the selected initial entry. `advance` consumes one
conditional raw helper result; CONTINUE returns to the length test, including
when the updated count is zero. Route numbers and probe output are new APIs.
No socket, helper, scheduler or full future ABI is implemented. Original
captured code is not run. New source MIT; imported evidence keeps its rights.
