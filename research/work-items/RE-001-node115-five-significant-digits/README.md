# RE-001: five-significant-digit truncation at node #115 `0x269d520`

- Component: foundation (RE-001 function binding), consumed by the TWAP slice family recorded in RE-006. Base revision: `a8a165e65`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. No upstream source is asserted for this leaf.
- Bounded question: for an unsigned 64-bit value in RDI, what does the complete leaf at `0x269d520` return?
- Answer: it rounds the value down to five significant decimal digits. With `s = 10^max(0, digits(x) - 5)` it returns `(x / s) * s` in RAX, so values below 100,000 are returned unchanged, 123,456 becomes 123,450 and `u64::MAX` becomes 18,446,000,000,000,000,000. It reads and writes no memory and makes no calls. This holds for every unsigned 64-bit input, assuming normal execution and a valid return address. The original source name, type, ownership and units remain unknown.

`RE-006-twap-slice-115` lists `0x269d520` among the "other lookups" called by the uncovered slice family `0x2dd34f0` / `0x2dd4530` and does not interpret it. This packet shows it is not a lookup but the rounding step that the four covered slice bodies are documented to perform: "rounding down to five significant figures".

## Binary observations

The half-open FDE is `0x269d520..0x269d69d`, **381 bytes**, original ELF virtual addresses; file offset `0x269c520`. The FDE at VA/file offset `0xd3f984` refers to CIE `0xca6ed8` (`zR`, no LSDA). Three `cc` padding bytes follow the body before the next entry. Body SHA-256 is `52ab6e2c5340311df8f90595108139623145a8bd04204779f2abdea5506d622f`. The complete **79 instructions** and their raw encodings are in `records.json`. They decode contiguously from the FDE start to a terminal `ret`, and every branch target is an instruction boundary inside the extent. There are **0 callees**, direct or indirect, and no memory operands. GNU objdump 2.47 independently decodes the same 79 instruction boundaries; that cross-check is not part of the regeneration.

Structure, read from the decoded instructions:

1. `rax = rdi`. A ladder of unsigned compares selects a scale in RCX. Five compares test `x` against 10^5..10^9 directly. Four test `x >> k` against `9765625 << 0`, `48828125`, `244140625` and `1220703125` with `k = 10..13`; since `(x >> k) < c` is exactly `x < c << k`, these are 10^10..10^13. Two `jbe` compares test `x <= 10^14 - 1` and `x <= 10^15 - 1`. Four compare against 64-bit constants 10^16..10^19, the last selecting with `cmovb`. The selected scale is 1 below 10^5 and 10^(d-5) for a d-digit value, up to 10^15 for 20 digits.
2. The tail computes `x / s` with `div rcx`, or with `div ecx` when `(x | s) >> 32` is zero, then `mul rcx`. On overflow (`jo` / `jno`) it returns `u64::MAX`; this branch is unreachable because `(x / s) * s <= x`.

## Closed form over the whole domain

`tools/node115_five_significant_digits.py` decodes the body with a strict table of the 30 encodings it contains and evaluates the decoded instructions with an exact interpreter for that subset. The interpreter records each compare as `x >> k` against a constant `c`. Every branch predicate is therefore `x < c << k` or `x < (c + 1) << k`: monotone in `x`. The tool partitions `[0, 2^64)` at every such threshold, at 2^32 (the 32-bit fast path) and at every power of ten. It refines the partition until no new threshold appears.

In the final **37 cells** both ends take the identical branch path, RCX is the same constant, and both ends return `(x / s) * s` with `s = 10^max(0, digits(x) - 5)`. All 15 compares are reached. Because each predicate is monotone and agrees at both ends of a cell, every interior value takes the same path with the same constant scale. On that path the tail returns `floor(x / s) * s`. The formula therefore holds for every `u64`. The evaluated points are the proof's case checks, not a sample.

## Callers

The full `.text` bytewise `e8`/`e9` rel32 scan over `[0x1419300, 0x63f0a00)` yields **2 direct-reference candidates**. Both are calls, at `0x2dd3ea1` (unwind range `0x2dd34f0..0x2dd3fa6`, FDE `0x11a63cc`, CIE `0x103d604`) and `0x2dd4e64` (range `0x2dd4530..0x2dd4f02`, FDE `0xd95210`, CIE `0xca6ed8`). Each is preceded by `mov rdi, r15` and followed by `mov r15, rax`, which the tool checks. A linear Capstone 5.0.7 sweep from each FDE start reaches both sites as instruction boundaries. That sweep is a cross-check, not part of the regeneration.

In both callers the value passed in is the end of the same saturating chain: `3 * a + 1`, a min, a max and a min with three other quantities. The call is skipped when `[rsp + 0x18]` is not below a step count. A zero result is then tested. This is the shape of the slice-size rule in `RE-006-twap-slice-115`, step 8. This packet records only the call-adjacent bytes; whole caller behavior, units and reachability are not established.

## Reproduction and novelty

Static only. Python stdlib, Python 3.10 or newer; no disassembler or emulator is needed. From the repository root:

```sh
python3 tools/node115_five_significant_digits.py --out research/work-items/RE-001-node115-five-significant-digits/
python3 -m unittest tests.test_node115_five_significant_digits -v
python3 research/work-items/RE-001-node115-five-significant-digits/verify.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-five-significant-digits/Cargo.toml
```

Before writing anything, the tool checks the whole capture, the ELF section geometry, the FDE/CIE, the body hash, the strict decoding, the closed-form certificate, the padding, every-byte direct references and the call-adjacent bytes. `MANIFEST.sha256` whitelists the packet files, and `verify.py` rejects additions and mismatches. The captured ELF is never executed.

Before choosing this address, `git grep -n '269d520\|40490272'` over `research/`, `src/`, `tests/`, `docs/` and `tools/` found only the RE-006 exclusion line quoted above. Open pull request diffs and bodies cited no address inside `0x269d520..0x269d69d`.

## Controls, non-claims and next step

The focused tests check:

- regeneration
- counts
- complete decoding
- the certificate and boundary vectors around every power of ten
- that a wrong digest, a mutated compare constant, a shifted FDE and a redirected call all fail closed

Unwinding, indirect callers, runtime observations, original Rust source, data type identity, the business meaning of the input, a reconstructed binary, build provenance, whole-ELF equivalence and any component acceptance gate remain unproved. No component progress gate changes.

The next question is the remaining callees of the slice family `0x2dd34f0` / `0x2dd4530` (`0x24c55a0`, `0x24cd630`, `0x2891f50`, `0x2892150`), and whether that family is the TWAP slice for a further market type.
