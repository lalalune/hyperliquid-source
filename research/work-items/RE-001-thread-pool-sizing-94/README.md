# RE-001: pool sizing uses a num_cpus-linked cached/affinity provider

- Component: foundation thread/runtime helpers. Question: which count provider
  feeds the node94 pool-size wrapper, and what exact sizing expression and
  local builder-result flow are supported by the target?
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base/reference pins remain
  `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Actual FDEs: wrapper `0x13cba40..0x13cbb7e` (**318 bytes**); count provider
  `0x4e06870..0x4e069a8` (**312 bytes**). Both are retained in full raw native
  disassembly. No captured process, thread pool or CPU-query function is run.
- No independent Rust implementation, complete pool recovery or progress gate.

## Correcting the provider identity

The unlicensed inferred `base/u.rs` describes `available_parallelism()/4` with
an error fallback and returns a configuration DTO. That source description
alone does not establish the real provider or returned pool ABI. The actual
call at `0x13cba4f` uses slot `0x576e988`, whose RELATIVE addend binds the
312-byte provider at `0x4e06870`. That provider has a nonzero cached-count path,
a fixed **128-byte CPU affinity buffer**, and a `sysconf(84)` fallback.

Two Location records point into **num_cpus 1.17.0 src/linux.rs**, line 114
column 10 and line 45 column 17. Published-source mapping is pinned to
[seanmonstar/num_cpus commit 342af76b](https://github.com/seanmonstar/num_cpus/blob/342af76b486335e5a955c7314fc96cd104e7a17b/src/linux.rs),
file SHA-256
`378ea174d00d560e16fda4b09fb523dda5f4c6f420e46af7d317393a39d88dd1`.
That file's once/cached-count and affinity-count source positions agree with
the retained control flow. This supports a **num_cpus-compatible provider
mapping**, not substitution with the standard-library API or a pristine library
build claim. The cached-count initializer, including any cgroup interpretation,
is not closed here and is not inferred from the published library alone.
No upstream or inferred implementation is copied into new project code.

## Requested-size expression

The wrapper saves original RDI/RSI as two unsigned 64-bit requested bounds,
then takes the provider's returned word P and shifts it right by two. Its
unsigned CMOV sequence orders the bounds, caps the quarter count at the higher
bound, and raises it to the lower bound when below that bound. A subsequent
CMP/ADC increments the result only when it is zero. Therefore, conditional on
the provider and initialization helpers returning:

```
requested = max(1, clamp(P >> 2, min(bound_a, bound_b), max(bound_a, bound_b)))
```

This algebra holds over all unsigned 64-bit P and bounds: ordering ensures
low<=high, the first selection is min(quarter,high), and the second sets low
exactly when quarter<low. The final ADC cannot overflow because it only adds
one to zero. There is no signed interpretation of the bounds, no inverted-bound
panic in this fragment and no multiplication overflow. If both bounds are zero,
the final floor produces **1**, so the result can exceed that raw zero upper
bound. This is observed behavior, not a new policy or bug claim.

Initialization of a separate wrapper global may call the once helper before
returning to the final floor and builder setup. The selected count is stored
at `rsp+0x20`, offset `+0x10` from the builder input pointer `rsp+0x10` passed
to direct call `0x145b110`. The local result word is compared with raw tag **3**;
on that path the wrapper returns word `+8` in RAX. Other tags reach the
source-bound `Result::unwrap` diagnostic. This establishes a selected builder
input field and result flow, not a concrete `ThreadPool` type/lifetime or the
reference DTO as a binary ABI. The builder body and thread creation effects
are not analyzed or executed.

## Count provider paths

1. Read state DWORD `0x5786800`; a nonzero value takes a once-initialization
   helper path. Both returning paths read word `0x57883f8`.
2. If the cached word is nonzero, return it directly. Its producer and precise
   resource-limit semantics are not recovered.
3. Otherwise zero 128 stack bytes and call import slot `0x5776b70` with pid 0,
   size 128 and buffer `rsp+0x10`. Its GLOB_DAT binding is **dynsym index 99,
   sched_getaffinity**. On zero status, count all 1024 buffer bits.
4. On nonzero affinity status, call slot `0x57708a8` with argument **84**.
   Its GLOB_DAT binding is **dynsym index 59, sysconf**. Compare the returned
   word as signed with 2: return it if >=2, otherwise return 1. Negative/error,
   zero and one therefore all produce one in this local fallback.

The [Linux affinity interface](https://man7.org/linux/man-pages/man2/sched_getaffinity.2.html)
supports the pid/size/buffer interpretation. No query of this workstation or
current process affinity is needed. The raw query number 84 is retained rather
than asserted as a portable `sysconf` enumeration value.

### Complete bit-position argument

The decoded counter starts i=0, increases by 2 and stops at 1024. Each
iteration loads word `i>>6`, tests bit `i&0x3e`, then bit `(i&0x3e)+1`.
Those 512 pairs visit **every bit 0..1023 exactly once**. Each contributes its
0/1 indicator, so their sum equals population count for **all 2^1024 masks**.
At most 1024 increments occur, so the u32 overflow branches are unreachable
within this bounded reduction. This is an algebraic bit-coverage argument,
not exhaustive mask execution, a captured run or proof of syscall/cache state
reachability. A successful empty raw mask is included in the model without
claiming it can arise from a valid live Linux thread.

## Source/edge records and reproduction

Wrapper failure Location `0x5666bc8` resolves to `base/src/u.rs:539:68`, path
VA `0x1ef2de`, length 42. Location `0x5669f50` resolves to the compiler-stamped
std once source at `0x1f87cf`, line 219 column 20. Provider Locations
`0x5747fd8` / `0x5747fc0` both point at `0x1f1396`, length 94, the num_cpus
path and positions noted above. The seven RELATIVE bindings, two imported
symbol bindings, original VAs/file offsets/body hashes, instruction controls
and RIP/direct edges are saved in `records.json`. Slow helper correctness,
all transitive call targets, data producers and exception closure stay open.

From repo root, with pinned captures materialized and GNU binutils exposed:

```sh
python3 -B tools/thread_pool_static.py --output work/thread-pool-sizing-94
python3 -B tests/test_thread_pool_static.py
make doctor verify test catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-001-thread-pool-sizing-94/SHA256SUMS
```

Host: macOS, Python 3.12.14, GNU readelf/objdump 2.47.20260726. The generator
reads/authenticates one snapshot, gives that same private temporary snapshot to
`readelf -wf` and `objdump -d -M intel --insn-width=16 --start-address=...
--stop-address=...`, and never spawns captured code. Existing MIT
`foundation_millis.decode_export` verifies complete decoded bytes/contiguity/end
bounds and every selected site must be a decoded instruction start. Temporary
paths alone are replaced with `<authenticated-node94>`; no instruction/data
normalization masks are used. Independent transient Capstone 5.0.6 consumed
all 318/312 bytes in **70/79 instructions** respectively.

`frames.txt` and both `.objdump.txt` files preserve full native evidence.
SHA256SUMS covers all durable files and the two independently authored files.
Five focused tests pass in 31.105 seconds: real range/source/import bindings;
**1,408** sizing/bound vectors and signed fallback boundaries against an
independent ordinary-division/clamp formula; exact disjoint coverage of all
1024 positions, all single-bit basis masks and dense-mask controls against
Python's integer population count; **28** actual-byte instruction/data/Location
changes plus **7** real RELATIVE-addend and **2** dynsym-index changes below the
digest gate; native regeneration and wrong-input admission rejection. The
models never call the OS or create a pool. Required suite/reproduction results
are recorded in the PR after completion.

No captures/imports/pins/generated progress or component gates change. No
pristine-source build, concrete pool ABI, full cached-count producer/cgroup
semantics, caller census, runtime equivalence or hosted-CI result is claimed.
Next close the cached-count initializer before interpreting resource limits,
and the builder/callers before implementing a pool API or lifecycle.
