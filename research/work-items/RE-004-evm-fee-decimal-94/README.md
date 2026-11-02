# RE-004: EVM fee-error amounts and their 256-bit decimal path

The transaction-fee insufficiency message routes two separate four-limb unsigned amounts through a base-10^19 conversion with 19-wide lower chunks, so a reconstruction can retain all 256 bits and validate the required padding without narrowing either amount to u64.

- Component ID: RE-004, quantities and rounding; EVM transaction-fee amount display.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as an unlicensed lead only, with no source copied.
- Claim status: observations are the ELF bytes, FDEs, branches, table entries, format descriptors and relocation addends. The arithmetic proof is conditional on the stated shared helper contracts and ordinary successful allocation and formatting. EVM and wei interpretations are inferences; the input producer and reachable values are unresolved.
- Scope included and excluded: six previously unclaimed FDE ranges along the selected error display path, including the two-level dispatch, 15-entry transaction-error table prefix, quantity conversion, buffer decision and selected failure edges. Excluded are transaction validation and creation of the error, the other outer dispatch arms, shared runtime helper bodies, allocator internals, target execution, node #115 and visor. The 15 entries are the inspected table prefix, not a claim about all possible or valid raw tags.

## Reproduce

Run from the repository root with Python 3.12 and its standard library. The generator checks the input SHA-256 before parsing and imports the repository ELF and FDE readers. It reads file-backed ELF sections, never runs the target, and invokes no external program. Addresses are linked ELF virtual addresses before load bias; file offsets are identified separately in `functions.json`.

```sh
python3 tools/evm_fee_decimal94.py --out research/work-items/RE-004-evm-fee-decimal-94
python3 -m unittest tests.test_evm_fee_decimal94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-004-evm-fee-decimal-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC0 python3 tools/evm_fee_decimal94.py --out work/evm-fee-check-a
PYTHONHASHSEED=2 TZ=Pacific/Honolulu python3 tools/evm_fee_decimal94.py --out work/evm-fee-check-b
diff -r work/evm-fee-check-a work/evm-fee-check-b
```

The generator writes `functions.json`, `anchors.tsv`, `branches.tsv`, `dispatch.tsv`, `error-arms.tsv`, `vectors.tsv`, `limb-trace.tsv`, `wrapper-cases.tsv`, `buffer-cases.tsv`, `pair-cases.tsv` and `proof.json`. The manifest records hashes of these files and this README. The branch and relocation records are read from ELF bytes, not disassembler output. Complete original FDE bytes and their SHA-256 hashes are in `functions.json`; an FDE is an unwind extent, not by itself proof of every source-level boundary.

## Evidence

### Selected path

| Step | FDE start | FDE end, exclusive | Observation |
| --- | --- | --- | --- |
| Tagged wrapper | `0x4e4c710` | `0x4e4c81f` | A nonzero input word with low 32 bits equal to 1 tail-calls the next step with its payload at `+8`. Zero and the other low-word values take different arms. |
| Outer dispatch | `0x4e46e20` | `0x4e47608` | The byte-indexed table entry 36 reaches a tail call with pointer advanced by 8. |
| Transaction error display | `0x4e58610` | `0x4e58836` | Its table entry 0 reads a pointer at `+8` and prepares that pointer and pointer `+0x20` for the same value formatter. |
| Four-limb display | `0x4e589e0` | `0x4e58c36` | Zero takes a direct `0` path. Nonzero loads 10^19, calls the chunk constructor, formats the final chunk first and then the others in reverse. |
| Chunk constructor | `0x4e581c0` | `0x4e58470` | Divides four u64 limbs by a nonzero u64 radix, appends successive remainders low first, and repeats with the quotient. |
| Temporary writer | `0x4e58c40` | `0x4e58ca6` | With ordinary nonaliasing inputs, checks the new length against 256 before copying and updating the length. |

The outer table and the inner table are at `0x7c111c` and `0x7c17b0`. The selected indexed entries, their signed relative displacements, all 15 inspected inner entries, and the first 37 outer entries are in `dispatch.tsv`. There is no input-range check at the table instructions; out-of-range raw tags are not modeled. In the wrapper, `test rcx,rcx` is 64-bit but `cmp ecx,1` is 32-bit. Thus `0x100000001` follows the same selected route as 1, while `0x100000000` does not (`wrapper-cases.tsv`). Canonical tag values and runtime reachability are not established by that machine-level distinction.

The selected inner arm passes the compact format template at `0x1fa6df` and two formatter arguments in order. The template's literal pieces are `sender does not have enough funds (` and `) to cover transaction fees: `; the arguments are read at offsets 0 and `0x20` from the stored pointer. `error-arms.tsv` retains the 15 decoded messages, including distinct nonce, transaction-type, gas and fee-price errors. The two 32-byte values are called the first and second amounts below: their association with funds and transaction fees is supported by the template and argument order. No producer is traced here.

### Radix and full-width arithmetic

The formatter copies four eight-byte words from the input, and the constructor uses the word at `+0x18` first, then `+0x10`, `+8`, and `+0`. The arithmetic therefore treats them as little-endian u64 limbs of one unsigned 256-bit integer. The byte-bound immediate is `0x8ac7230489e80000`, or `10^19`. The shared slot used for the lower three limbs has the existing nonzero-u128 quotient contract documented in `RE-004-u128-division-94`; this item checks the slot relocation and treats that contract as a dependency rather than reanalysing the helper. The top-limb hardware divide has a 32-bit alternative, but the selected radix exceeds 2^32, so this caller takes the 64-bit form.

For each limb from most to least significant, let `r` be the previous remainder, `w` the next word and `D = 10^19`. The code forms a quotient limb of `(r * 2^64 + w) / D`, then computes the next remainder using the low word of `w - quotient_limb * D`. If `0 <= r < D`, the dividend is below `D * 2^64`, the quotient limb fits u64, and the true remainder is below `D` and fits u64. The low-word subtraction is therefore exactly that remainder. Induction over all four limbs proves the lifted long-division step for every u256 input, conditional on the shared quotient contract. Repeating the step gives low-first base-`D` chunks and loses no remainder. This is a mathematical proof of the lifted operation; the generator does not execute or fully interpret x86 instructions.

The last chunk is formatted without a requested width. The earlier chunks use a width of 19 and the compact format descriptor in `proof.json`; its dynamic-width selector and bit `0x01000000` connect to the shared formatting helpers. Interpreting that bit as zero-padding relies on those helpers, which are not reanalysed in this packet. Under that helper behavior, concatenating the most significant chunk with zero-padded 19-digit chunks is exactly the ordinary unsigned decimal representation. For example, `10^19 + 1` has chunks `1, 1` low first and is rendered with the intervening zeroes, as in `vectors.tsv`. No floating-point conversion or rounding appears in this selected integer path.

Since `(10^19)^4 < 2^256 < (10^19)^5`, a u256 needs at most five chunks. The constructor's initial allocation has room for four, so the fifth-chunk path must call the growth helper, assuming allocation succeeds. The first five-chunk value is `(10^19)^4`; the generator gives the exact count of such u256 inputs and the maximum value. The largest value has 78 decimal digits, below the temporary writer's 256-byte capacity. This bound assumes the integer formatter writes the stated digits and its ordinary nonaliasing buffer contract; it does not prove arbitrary callers of the buffer are safe.

### Failure and boundary decisions

| Condition | Selected behavior or checked boundary |
| --- | --- |
| Four input limbs are zero | The display takes the separate literal `0` arm and does not call the chunk constructor. |
| Constructor radix is zero | A separate failure call is reached before division; the selected caller supplies 10^19, so this branch is not reachable through the selected edge. |
| Chunk allocation or growth fails | Control enters allocation/unwind handling; exact allocator effects are outside this packet. |
| Internal numeric formatting reports failure | The display reaches the failure call associated with the `Result::unwrap()` error text. |
| Writer length plus incoming length is at most 256 | The buffer copy and length update are selected. |
| Sum exceeds 256 without u64 wrap | The writer returns the error status without taking the copy path. |
| Length addition wraps u64 | The writer reaches a separate failure call before its capacity test. |

The buffer table assumes a valid object and nonaliasing source. `buffer-cases.tsv` is a lift of the checks and includes the 256/257 and u64-overflow controls. `pair-cases.tsv` is a conditional model of the two-placeholder message, not captured execution.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No Cargo build, target execution, binary comparison, normalized operands, full relocation closure or target differential test is claimed. The Python tool verifies fixed full-body hashes, selected instruction anchors, 12 decoded branches, slot relocations, the two dispatch entries and the error/template bytes. It then compares an independent arbitrary-precision decimal result with a four-limb arithmetic lift on 23 boundary values, recording 260 individual limb transitions. The tests include a separate quotient comparison against Python integer `divmod` for 511 deterministic four-limb/divisor combinations; boundary powers, malformed values, changed hashes, opcodes, displacements, tables, strings, duplicate relocations, FDE extents and unbacked ranges are negative controls. These are static-model checks, not executions of captured instructions.

## Results and limitations

Six selected indexed FDE extents and 22 instruction anchors are bound to the authenticated #94 artifact. The inspected table prefix has 15 transaction-error arms; 23 output vectors and 260 limb transitions have zero model mismatches. Thirteen focused tests pass without skips. The whole-u256 long-division and chunk-count arguments apply only to the pinned code with the cited shared-helper contracts. The surrounding formatter, writer and allocator are not exhaustively interpreted, and the 15-entry table prefix is not a coverage denominator for EVM errors.

The Ethereum transaction-type and fee messages make an EVM quantity interpretation reasonable. Calling these amounts wei is an inference from that context, not a unit established by an inspected producer. The caller that constructs the tag and both payload words, the precise fee computation, actual admitted values, error reachability, and the full shared helper/data/relocation closure remain open. No component progress gate is requested.

Next question: identify a non-overlapping pre-execution validation producer that fills the two amounts and prove the unit and overflow policy before the display edge.
