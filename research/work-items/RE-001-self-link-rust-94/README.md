# RE-001-self-link-rust-94: Recover ordered self-link initialization and exact store widths

- Research allocation: foundation / RE-001 bounded semantics and independent Rust. Ownership is unmeasured; no first-party dependency-byte credit is requested.
- Base: `966865f1637a29ce75b019e1bf11d5529cc6f519`.
- Target: Linux x86-64 node #94; 91,774,280 bytes; SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates: ELF virtual addresses without runtime rebasing.
- Claim: finite static-model/compiled-Rust value, abstract data-event and complete-view agreement. No target process or instruction emulator is used by the qualifier.
- No gate change, integrated node, Docker delivery, current-network compatibility, original ABI or target compiled-byte claim.

## Evidence and implementation

The complete FDE is `[0x4f91ee0,0x4f91efb)`, 27 bytes, followed by five int3
bytes. It has no explicit data loads, branches or outgoing calls. Its data
effects are ordered:

1. RDX = incoming RDI + 16, wrapping as u64.
2. Store a zero qword at base+8.
3. RAX = incoming RDI; store RDX as a qword at base.
4. Store **one zero byte** at base+16, then return.

The new Rust `self_link_initialize` returns the full RAX/RDX projection and
uses those three store primitives in order. Successful ordinary views retain
all initial bytes outside offsets 0..16. In particular offsets 17..23 are not
cleared. The field's meaning, source object type, initialized-node consumer,
source crate/dependency ownership and native calling ABI are unresolved.
The base had static evidence, not an independent Rust implementation here.

The existing foundation checker authenticates the complete body, current and
next FDE/CIE records, padding, zero incoming e8-pattern candidates, and exactly
66 RELATIVE relocation slots naming the entry. These naming slots are not a
complete indirect-call graph or evidence of first-party ownership. This packet
adds full RDX and real mutable byte-view/store-width/order validation, including
high-bit and wrapping bases, guard bytes, every omitted target byte and
failures after an earlier successful store.

Input is `base,seed,missing_byte_mask`. Initially offsets -2..23 have
`(seed+37*offset) mod 256`; mask bits 0..16 remove the selected byte. On a
successful result the register columns are `RAX,RDX,0`; the final zero is only
a format placeholder, **not** a claim about native RSI. A store primitive
preflights its complete byte span. If a later primitive refuses, preceding
successful stores remain. This is the safe view API's error contract, not a
reconstruction of hardware faults or partially faulting native qword stores.

`target.objdump.txt.gz` retains the full fresh GNU objdump 2.42 output without
byte/operand normalization. `preparation/ORACLE-FREEZE.json` pins the original
checker hash, retained facts, both raw FDEs/CIE relationship and body digest.
No call-target implementation needs an application stub: the bounded target
body has no outgoing calls. The captured binary and inferred unlicensed
can1357 source are not part of the new Rust implementation. New code is MIT.

## Frozen observations and safe primitive boundary

`contract.py` was written and run before the new library existed. It admitted
the actual capture, derived observations using a register-oriented sequence
and a separately written byte-polynomial formulation, then froze 6,346
rows with zero disagreement. Both formulations share the static instruction
interpretation; agreement is not native execution or a full-domain ISA proof.
The immutable freeze records the contract/vector/checker hashes and
`new_rust_exists_at_freeze=false`. This is a retained order record, not a signed
timestamp. Normal reproduction uses `verify.py`; freeze refuses after Rust exists.

The new `no_std`, unsafe-free library is built directly with rustc. Its trait
methods are actual byte-view primitives, not substituted application callees.
The stdlib client implements them using a mutable little-endian BTreeMap,
with a complete-span preflight for each primitive store. The projection
counts abstract qword/byte operations, not host allocator/map internals or
CPU atomicity, MMIO, races, stack/return-address aliases or hardware faults.
Numeric wrap/noncanonical addresses are algebraic fixtures, not real mappings.

Each output is `tag,RAX,RDX,aux,event_count,(op,address,value)...,byte_count,
(address,byte)...`. Tag zero denotes a normal view; tag one denotes a view
refusal with zero register placeholders. Op 0 is an attempted qword read
(value placeholder zero), op 1 a qword store, op 2 a byte store. The snapshot
contains **every mapped final byte**, including guards and source/output
aliases. This compares full views, not only a digest or changed bytes.

## Reproduce

Read the repository setup instructions/manifests, materialize the pinned LFS
inputs and submodules normally with `bash scripts/setup.sh`, then:

```sh
python3 -O research/work-items/RE-001-self-link-rust-94/verify.py \
  --rustc "$HOME/.rustup/toolchains/1.94.1-x86_64-unknown-linux-gnu/bin/rustc"
make doctor verify catalogue-check
make reproduce
python3 -m unittest discover -s tests -p 'test_foundation_self_link_init.py' -v
python3 -m unittest discover -s tests -p 'test_foundation_sentinel_field_read.py' -v
```

The legacy sentinel tests document the optional real-capture path
`work/hl-node-94.bin`. The initial invocation reported three skips because
that path was absent. The real, hash-verified canonical capture was hard-linked
there and the file rerun: all 20 passed without skips. The initial skip log
is retained. No checker/test was weakened or given placeholder data.

Rust 1.94.1 / LLVM 21.1.8 runs on Linux x86-64; flags are edition 2021,
opt-level 0/3 and overflow-checks=yes. At both levels the qualifier builds and
runs an actual linked input-only client and whole-corpus unit test. Expected
columns are never passed to the client. It also emits library/client LLVM IR
and compiles four deliberately incorrect variants. Checks remain active under
Python `-O`. The final qualifier SHA and source hashes are retained.

## Observed results and controls

- 6,346 frozen cases: 5,226 normal views and 1,120 safe refusals.
- O0 and O3: **0/6,346 mismatches each**, including complete final byte maps.
- Both whole-corpus unit-test invocations pass. Four raw repeated rlib/client artifact pairs are byte-identical across two qualifications; this is own-build reproducibility, not target identity.
- Two complete-body boundary corruptions, four FDE PC/extent corruptions, one CIE corruption and wrong-capture identity are rejected.
- `wrong-head-bias`: 5,786/6,346 observations differ, with normal process exit.
- `reordered-stores`: 6,346/6,346 observations differ, with normal process exit.
- `wide-flag-store`: 5,282/6,346 observations differ, with normal process exit.
- `wrong-return-base`: 5,226/6,346 observations differ, with normal process exit.

`qualification/` retains exact command argv/exit/stdout/stderr, observed rows,
LLVM IR and hashes. `repository-checks/` retains setup, make targets, focused
tests, and exact own-artifact repeat hashes. Only repository/home prefixes are
normalized in public command logs/IR; no values, instructions or operands are
masked. Normal and refusal denominators are separate above.

The native validation tree is a clean base plus **both independent additions**;
it is not two separate full-head suite runs. Doctor, verify, catalogue-check
and reproduce pass. Focused predecessor tests: 9 self-link + 20 sentinel = 29
passing after normal capture materialization. The full 971-file `make test`
suite was **not rerun** for these additive packets; no whole-suite or hosted
CI pass is claimed. The existing accepted scope for bounded validation is
disclosed here rather than reporting a narrower run as complete.

## Gaps and next question

Raw-equal / relocation-normalized / unmatched target compiled-code counts are
not measured. There is no full-domain formal proof, complete indirect caller
closure, native ABI/fault/flags claim, source crate identity or full component
reconstruction. Imported evidence, pins, generated catalogues and all progress
gates remain unchanged. The next question is to resolve the concrete callers
and object/return types, then validate the stated projection in a separately
authorized isolated native differential harness. No full gate is requested.
