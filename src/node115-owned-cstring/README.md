# Node115 owned byte-slice to C-string conversion

A real no_std+alloc converter independently authored from complete native
141e960..141eada and its reachable finalizer path. It allocates length+1,
copies all original bytes, then either returns an owned unmodified copy with
first-NUL index or appends one zero and returns the terminated bytes. Embedded
NUL is checked after allocation/copy, not a transactional preflight.

Real Vec/allocator are used, no mock allocation. Safe allocation failure is an
observable boundary replacing native fatal/panic behavior, not a recovered
Result ABI. Original layout/allocator identity, arbitrary general-finalizer
capacity states and caller destruction/OS effects remain excluded.

See research/work-items/RE-012-owned-cstring-115 for actual complete ranges,
whole hashes/RELA, pre-Rust expectation fixture and actual compiled controls.
New source MIT. Probe allocator harness reuses the author's MIT prior
node115-varint-buffer-writer test harness, with new converter observations.
