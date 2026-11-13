# RE-008: which node #115 code turns latency-EMA records into keyed ratio rows?

- Component ID: `consensus`, following the sibling heartbeat packet; the assertion names `foundation` source `base/src/ema_tracker.rs`.
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: repository base `a8616af9432b8d8517b2af677880e117b7c28ef3`. No reference source was consulted.
- Claim status: observations for bytes, edges, relocations and layouts; inferences and unresolved items are listed separately below.
- Scope included: four complete FDE bodies on one direct-call chain, 1,621 bytes and 391 instructions.
- Scope excluded: the two container search helpers, the key iterator, the ordering and container-building helpers, the consumer `0x4e3dfb0`, the contents of the caller's key collection, every writer of the records, and all runtime behaviour.

## Gap

`RE-008-node115-heartbeat-query-static` mapped a sibling row body, `0x5a30130`, which applies a threshold and an age rule; its query `0x5a71e20` also passes its owner's `+0x148` (`0x5a71e73`). `RE-012-exponential-sample-update-115` mapped the update `0x5a72580`. The repository had no record of the second reader. A whole-`.text` byte scan finds exactly two `lea` candidates for the `base/src/ema_tracker.rs:58:13` location record: one in `0x5a30130` and one in `0x5a327a0`. At base `a8616af9` no work item, tool or test cited an address inside `0x5a327a0..0x5a329d8` or the path `base/src/ema_tracker.rs`. The 659 open pull requests listed at 2026-11-12T08:24Z cite no address inside the four bodies below and do not mention that path or the assertion text.

## Evidence

Addresses are ELF virtual addresses. `instructions.tsv` holds every instruction of the four bodies. Each body equals one `.eh_frame` FDE extent.

| Role | Extent | Bytes | Instructions | Body SHA-256 |
| --- | --- | ---: | ---: | --- |
| entry | `0x5a71d90..0x5a71e1d` | 141 | 35 | `9cbb57aae7bc74ecb4e00225028d1b3b3c4ca2129974a47feea3b608c47e1121` |
| sort-build | `0x4d55b50..0x4d55cb2` | 354 | 85 | `9cd4e38f4730af80b023a772d417621036f7a495433e2ad4c41ee7685cabecd9` |
| collector | `0x5b80ea0..0x5b810ce` | 558 | 126 | `f0a310a1839d5c816c6a82f1266d4901eb1daf28c9e4c2ad781ea90db594dcbc` |
| row closure | `0x5a327a0..0x5a329d8` | 568 | 145 | `5ac7705ebb0b56235f4a8c6e917008ba38561e6bbc253cbfaceb912f1ddccf56` |

### Call chain (observed)

- Slot `0x64e8718` carries a `R_X86_64_RELATIVE` relocation with addend `0x5a71d90`. The scan finds no rel32 candidate for `0x5a71d90`. The existing `RE-001-node115-rpc-throttle-expiry/records.json` records an indirect call through this slot at `0x2e0a7f5`; that record was overlooked in the first version of this packet. This verifier now independently checks the call bytes, RIP displacement and relocation, as well as the preceding argument setup. At `0x2e0a7d2`, R12 is set to the owner's pointer plus `0x538`; at `0x2e0a7ea`, RSI is set to the stack buffer at `rsp+0x1d0`, and RDI is set to R12. The call at `0x2e0a7f5` thus reaches this packet's entry with those two arguments. The buffer's contents and any effects of the preceding call through `0x64e8710` remain unresolved.
- `0x5a71e00` calls `0x4d55b50`; `0x4d55b90` calls `0x5b80ea0`; `0x5b80ee9` and `0x5b80fea` call `0x5a327a0`. For each of these three targets the scan over all `e8`/`e9` bytes in `.text` finds only the listed sites, and each site is a retained instruction.
- The entry builds an 80-byte iterator state from its second argument (words at `+0` and `+8`, and the word at `+0x10` only when word `+0` is non-zero) and stores `arg0 + 0x148` at state `+0x48` (`0x5a71db2`, `0x5a71dee`).
- The collector passes `&state[0x48]` as the closure environment (`0x5b80eb7`). The closure dereferences it twice (`0x5a327b4`, `0x5a327b7`), so its container pointer is `arg0 + 0x148`.
- After the build, the entry calls `0x4e3dfb0` with a local, `arg0` and the built collection (`0x5a71e05..0x5a71e10`).

### Row closure `0x5a327a0`

Arguments: `rdi` output, `rsi` environment, `rdx` 20-byte key.

1. **Container form.** Word 0 of the container is negated and tested with `jno` (`0x5a327c0`, `0x5a327c3`). Only `0x8000000000000000` overflows, so that value selects the tree arm and every other value selects the ordinary arm.
2. **Tree arm.** Root pointer at container `+8`; a null root returns tag 0. Depth counter at `+0x10`. In each node the key count is the `u16` at `+0x55e`, keys start at `+0x480` with stride `0x14`, values start at `+8` with stride `0x68`, and child pointers start at `+0x560`. Keys are compared with the `memcmp` import (GLOB_DAT slot `0x64dfb50`, length `0x14`). A greater search key moves to the next key, an equal key selects the value, a smaller key or an exhausted node descends through the child at that index. Descending with a zero depth counter returns tag 0.
3. **Ordinary arm.** `0x57f8090(container, key)` returns a flag in `al` and an index in `rdx`. Bit 0 set, or an index not below container `+0x18`, returns tag 0. Otherwise the index plus container `+0x10` has word 0 subtracted once when it is not below word 0, and the value is at `[container+8] + 0x80 * index + 0x18`.
4. **Quotient.** The denominator is the `f64` at value `+0x18`. If it compares ordered-equal to zero the quotient is `+0.0` and the numerator is not read. Otherwise `jbe` at `0x5a328e4` sends a negative or NaN denominator to the assertion. Otherwise the numerator at value `+0x10` is divided by the denominator with `divsd`.
5. **Assertion.** `0x5a329bf..0x5a329d2` loads the 33-byte literal `assertion failed: self.denom > 0.` at `0x466dc4`, length `0x21`, and the location record at `0x63fdc38`, whose relocated path pointer `0x443c4f`, length 23, line 58 and column 13 read `base/src/ema_tracker.rs:58:13`. It calls through slot `0x64df730`, relocated to `0x1680e60`. The body ends after that call.
6. **Sanitisation.** `0x5a328f3..0x5a32981` works on the quotient's raw bits. `verify.py` transcribes the block branch for branch and checks it against this closed form on 12,314 bit patterns: zero of either sign and positive finite values (subnormal and normal) are kept; positive infinity, every NaN and every negative non-zero value become `+0.0`.
7. **Output.** Found: qword tag 1 at output `+0`, the caller's 20 key bytes at `+8..+0x1b`, the `f64` at `+0x20`. Not found: qword tag 0 and nothing else is written.

### Collector `0x5b80ea0`

- `0x5138730(state)` yields a key pointer or null. Each key is passed to the closure once. The tag byte is tested (`0x5b80eee`, `0x5b80fef`); tag 0 advances to the next key.
- No found row: the result is `{0, 8, 0}` (`0x5b80f02..0x5b80f11`).
- First found row: a 0x80-byte allocation through slot `0x64df480`, capacity 4, length 1. A null return calls slot `0x64df498` with `(8, 0x80)`.
- Each row is the 32 bytes at closure output `+8`: key at row `+0..+0x13`, `f64` at row `+0x18`. Rows are stored at `ptr + 0x20 * len`. When length equals capacity, `0x5963a10` is called with `(vec, len, 1, 8, 0x20)`.
- The result is the three words `{capacity, pointer, length}`.
- The unwind path frees `capacity * 0x20` bytes through slot `0x64df4a0` and calls `_Unwind_Resume` through the PLT.

### Sort-build `0x4d55b50` (call shape only)

- Length below 2 skips the first helper. Length 2 to 20 calls `0x53e5360(ptr, len, 1, closure)`. Length 21 or more calls through slot `0x64eb270`, relocated to `0x4f41090`.
- `0x5b2e730(&vec)` is then called in every case, and the three vector words are read again.
- Re-read length above `0x40`: `0x5168480` receives `output + 8` and the four words `{ptr, ptr, capacity, ptr + 0x20 * len}`, and output word 0 is set to `0x8000000000000000`. Otherwise `0x5806a40` receives `{capacity, ptr, 0, len}` and its 32 bytes are copied to the output.

## Inferences

- The quotient and its assertion are the inlined body of a `base/src/ema_tracker.rs` accessor that returns `num / denom`. The source location is observed; the function name is not.
- The tree arm has the node shape of a 20-byte-key, 0x68-byte-value B-tree, and the ordinary arm that of a sorted ring of 0x80-byte elements. The sentinel that selects the tree arm equals the word the sort-build writes for more than 64 rows. The sort-build output is a different object from the container the closure reads, so this is a shared-shape lead, not an identity.
- `0x53e5360` and `0x4f41090` are ordering helpers and `0x5b2e730` removes adjacent duplicates. These names follow from call shape and thresholds only.
- The heartbeat packet reports the literal `validator_latency_ema` in the adjacent source extent. That the records are per-validator latency averages is an inference from that neighbour.

## Unresolved

- The contracts of `0x57f8090`, `0x5138730`, `0x53e5360`, `0x4f41090`, `0x5b2e730`, `0x5168480`, `0x5806a40` and `0x4e3dfb0`.
- The caller that loads slot `0x64e8718`, the identity of the key collection passed as the second argument, and when this path runs.
- The key position inside a ring element, and the meaning of record bytes other than `+0x10` and `+0x18`.
- Whether any path can store a negative or NaN denominator.
- The scans match raw bytes. They can miss register-indirect calls and computed references.

## Implementation and comparison

`src/node115-latency-ema-projection` is a dependency-free `no_std` crate written from the observations above. It models the quotient, the sanitisation, one closure call and the collector's order-preserving skip-absent loop. The assertion boundary is a returned error. Container search, allocation, ordering, duplicate removal and the built collection are not modelled.

Its 11 tests use hand-derived expectations for each native branch: zero, negative and NaN denominators, each sanitisation class, every key byte, absent keys, iterator order with a repeated key, growth past the first four rows and the assertion boundary. They are synthetic contract tests. No compiled-code comparison, byte window or runtime trace is claimed.

## Reproduce

Host: macOS 27.0.1 arm64, Python 3.14.3. `verify.py` uses the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. `collect.py` needs Capstone 5.0.7. GNU objdump 2.47.20260726 and Apple LLVM objdump 21.0.0 (`objdump -d --start-address --stop-address`) give the same 391 instruction addresses, and GNU `readelf --debug-dump=frames` lists the same four extents.

```sh
python3 -B research/work-items/RE-008-node115-latency-ema-projection/verify.py --self-test
python3 -B tests/test_node115_latency_ema_projection.py
python3 -B research/work-items/RE-008-node115-latency-ema-projection/collect.py --out work/latency-ema-instructions.tsv
cmp work/latency-ema-instructions.tsv research/work-items/RE-008-node115-latency-ema-projection/instructions.tsv
cargo +1.95.0 test --offline --locked --manifest-path src/node115-latency-ema-projection/Cargo.toml
cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-latency-ema-projection/Cargo.toml --all-targets -- -D warnings
```

No command loads, runs or emulates the captured binary.

## Results and limitations

`verification.json` is the output of `verify.py --self-test`:

- 391 of 391 instruction rows match the artifact, and the four bodies match their FDE extents and digests.
- 97 instruction anchors, 14 direct calls, 2 PLT calls, 9 RIP-relative references, 7 RELATIVE relocations and 1 GLOB_DAT import are re-derived.
- 22 of 22 corruptions are rejected: 11 changed instruction rows, 1 dropped row, 3 changed relocations, 1 changed literal byte, 1 planted caller, 2 changed owner-call operands and 3 wrong sanitisation forms.

This packet requests no component gate and adds no byte-window registration. It covers one reader chain. It does not establish quorum, latency units, the update rule, runtime reachability or equivalence of the Rust model with the target.

Next question: how is the stack buffer at `rsp+0x1d0` populated before the owner call, and does the preceding call through `0x64e8710` change it?
