# Node #115 full order-ring growth

Backlog HL115-042. Target: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are ELF virtual addresses. This is independently authored static
research and Rust, with no captured-code execution or emulation. Component gates
remain false.

## Question and prior work

How does the 32-byte ring used by `0x5911890` / `0x5911b30` grow while preserving
wrapped live rows and the saved order word? Prior #2416, #2441, #2864 and #4163
cover append/index/witness work. Their existing append formulas are reused.
#1591 is older-release context. Open #4884 reconstructs shared `0x43bd550`
allocation/refusal behavior; this packet credits that helper and does not claim
its allocator selection as new. The new contract is the caller-specific
`0x455df30 -> 0x43bbe20` capacity and relocation rule, joined to both append sites.

## Observations

* Both owners test `level+0x48 == level+0x30` before growth via GOT `0x64e27a8`.
  The helper receives the descriptor at `level+0x30`: capacity, pointer, head,
  length, each eight bytes. The live element width is 32 bytes.
* `0x43bbe20` chooses `max(2 * capacity, 4)`, asks `0x43bd550` for alignment 8
  and element width 32, then publishes pointer and capacity only on success.
  The credited shared helper rejects multiplication overflow or requested bytes
  greater than `2^63 - 8`. Allocation failure is not a successful return.
* `0x455df30` saves the old capacity before allocation. Contiguous live rows
  need no move. For a wrapped ring let `suffix = old_capacity - head` and
  `prefix = length - suffix`. If `suffix <= prefix`, or the added capacity is
  smaller than `prefix`, it moves the suffix to `new_capacity - suffix` with
  `memmove` and updates head. Otherwise it copies the prefix to the old-capacity
  boundary with `memcpy`, leaving head unchanged. Equality chooses the suffix.
* At the two observed callers length equals old capacity. The second relocation
  condition cannot independently select the suffix under successful doubling:
  the added space is at least the prefix. The owned API consequently accepts
  only this full-ring call domain; it does not claim all generic partial states.
* The helper does not change length. The owners reload capacity/length after
  growth, increment length, and apply the already recovered one-wrap index.
  The saved original `order+0xf0` word lives in a callee-saved register or stack
  and is stored at appended row+0 after growth. This is a byte identity result,
  not a semantic name for that word or a claim that every row byte is initialized.

## Source and witness

`src/node115-order-ring-growth` computes the native full-ring plan and performs
actual moves on owned `[u8;32]` storage. Its unused storage is initialized by the
Rust implementation; native spare/padding bytes are unspecified and never used
as an expected value. It preserves logical live rows without assuming backing
addresses remain fixed. Allocation is supplied by Rust; native allocator internals
and unwind behavior are not reconstructed here.

Before this contribution the append packet stopped at growth. The new witness
rotates each pre-growth backing into an independent logical queue, grows it,
then compares all 32 bytes of every live row through the new head. It exhausts
all 8,256 `(capacity,head)` pairs for capacities 1 through 128, including both
movement branches, ties and contiguous storage. Separate cases cover empty
initialization, the target byte bound, invalid heads, and appending a saved-word
row after growth without disturbing earlier rows.

## Reproduction

Run the packet verifier with the original pinned ELF and installed Capstone:

```
python3 research/work-items/RE-006-node115-order-ring-growth/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-order-ring-growth/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-order-ring-growth/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-order-ring-growth/Cargo.toml
cargo +1.95.0 clippy --manifest-path src/node115-order-ring-growth/Cargo.toml --all-targets -- -D warnings
```

The verifier authenticates the ELF digest, FDE bounds, windows,
relocations/imports and instruction facts. Its 15 corrupted overlays must fail
semantic verification after authenticating the unmodified original; they do not
merely depend on the full-file digest changing. Results are retained alongside
this file. Repository checks and their exact outcomes are recorded in the PR.

## Limits

The source models successful allocation on valid full-ring descriptors. It does
not recover allocation failure handling, physical allocator behavior, arbitrary
corrupt descriptors, order acceptance, row field meanings beyond the saved word,
or the complete order lifecycle. Passing source tests and static evidence checks
is not a target execution equivalence result. No upstream unlicensed inferred
source or machine-code transplant was used.
