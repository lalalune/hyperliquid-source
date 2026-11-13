# Fee traversal: shared bound and child selection

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. Component RE-004, partial. This independently authored source and static packet continue the point classifier in #2689; they do not replace its arithmetic or claim whole-validator completion. No target instruction was executed or emulated.

For valid mode 0 or 1, the adapter's entry (`0x3ebfdd6..0x3ebfe09`) loads the shared unsigned bound and checks the corresponding interval endpoint. Mode 0 stops when bound < left endpoint; mode 1 stops when bound > right endpoint. Equality continues. Tag 2 is stored on this early exit. The selected leaf calls the existing point body at `0x3ebfefa` and reloads the shared bound before proceeding. This packet binds that call and its immediate recheck, but does not reconstruct all leaf iteration or the scheduler.

On the selected formatter-complete path, `0x38769e7..0x3876a6c` reads the previous context tag, pointer, candidate and mode, then enters a locked compare-exchange loop if tag equals 2 or the low mode bit is set. Mode 0 replaces the unsigned bound only with a smaller candidate; mode 1 replaces it only with a larger candidate. A failed exchange reloads and retries. If candidate equals the observed bound, the selected branch is taken without an exchange. A worse candidate takes the other branch. These facts do not by themselves decide which equal-coordinate payload becomes the final result. Formatting, memory management and ownership outside the observed selected continuation remain premises.

At `0x3ec0193..0x3ec01d3`, when split child results are available, mode 0 prefers the left child unless its qword tag is 2; mode 1 prefers the right child unless its qword tag is 2. The alternate child is copied when the preferred tag is 2. Native cleanup of the unchosen result is visible afterward but is not implemented by the source; `Option` is only a logical tag-2 projection and has Rust ownership semantics. This selection may depend on scheduling and range construction; no claim is made that the overall winner is globally deterministic or that returned diagnostic payload identity follows from the atomic value alone.

The source at `src/node115-fee-failure-selection` models the bound, entry pruning and child-result projection for valid Boolean direction. Rust sequentially consistent atomic operations give a stronger source-level ordering than the packet establishes; native memory-order and concurrency equivalence are not claimed. Initial valid state, supplied endpoints, successful formatting/allocation and non-panicking allocator are premises. Value labels `First` and `Last` describe only the two observed unsigned directions.

The verifier checks nine digest-bound instruction windows (787 bytes, 171 instructions), 65 instruction/relocation facts and rejects 26 changed-byte controls. It checks machine instructions, not runtime equivalence. The 5 Rust tests cover both directions, equality, extreme unsigned values, 1,024 small three-value sequences, all four child-presence combinations, a classifier-to-bound witness, prior-result guard and a 32-thread contention check. The classifier is reused as a path dependency; its existing FP and normal-return premises continue to apply. The classifier, actual child construction, cancellation under scheduling, output formatting, deallocator callbacks and any financial meaning remain outside scope.

Reproduce with Capstone 5.0.7 and the exact original input:

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-004-node115-fee-failure-selection/verify.py --target /path/to/hl-node
cargo test --offline --manifest-path src/node115-fee-failure-selection/Cargo.toml
cargo test --offline --release --manifest-path src/node115-fee-failure-selection/Cargo.toml
```
