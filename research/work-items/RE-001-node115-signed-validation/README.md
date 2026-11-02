# RE-001 / RE-008: node115 signed validation decision order

- Component: consensus, observed `node/src/consensus/signed.rs` path.
- Target: node #115 Linux x86-64, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no inferred source copied or treated as an oracle.
- Question: which caller-local identity, collection and ordering guards occur between the initial helper result and the two downstream validators?
- Status: complete static export of one FDE and bounded local control/data-flow observations. The cryptographic, validator and collection helper bodies remain unmeasured. No implementation or gate claim.

## Scope and binding

`0x59d6b80..0x59d70ab` is the complete measured FDE, **1,323 bytes / 257 instructions**. `records.json` preserves raw bytes, body hash, file mapping, FDE/CIE, calls/branches and dependency boundaries. `native.asm` retains the full GNU disassembly. There is no byte normalization. An FDE describes an unwind range, not a guarantee that all semantics or cold parts are closed.

At `0x59d6e65`, LEA binds the diagnostic Location `0x64b6f38`. Its actual `R_X86_64_RELATIVE` relocation and 24 raw bytes resolve `node/src/consensus/signed.rs:194:13`. This is bounded source attribution, not an original symbol name. Input fields below use native offsets; their source-level names are not recovered.

The local incoming convention is output pointer RDI, input pointer RSI and context pointer RDX. The input is preserved in R15, context in RBP and output in RBX. Valid objects and helper ABI preservation are preconditions. The result byte `0x2e` is used as the local continue discriminator; it is not assigned a whole-program Rust enum name here.

## Ordered decisions

1. An imported call through `0x64e86f0` writes a temporary result. The slot's RELATIVE relocation resolves to `0x595cb30`; its body is not measured here. If the temporary first byte differs from `0x2e`, `0x59d6eb2` copies the result fields and discriminator into the caller output and exits. All later guards are bypassed.
2. On `0x2e`, the caller compares **20 bytes** of temporary payload with input bytes `+0x11c..+0x130`: one 16-byte lane and a four-byte tail. The tail values are moved into zero-extended vector lanes; `pcmpeqb`/`pand`/`pmovmskb` require both comparisons. Mismatch takes the diagnostic arm and writes output tag **`0x0d`**, followed by both 20-byte values. Equality alone reaches the collection guards. This establishes identity equality, not signature recovery correctness, identity ownership, or any particular cryptosystem.
3. The unsigned eight-byte count at input `+0x10` is compared with **100**. Values **greater than 100** produce tag **`0x29`** and the count. Exactly 100 continues. This is a caller-local upper bound; it does not validate the memory backing that count.
4. The caller walks count 32-byte rows from input `+8`, copying each into a temporary and calling `0x51d28d0` with one shared temporary state. A nonzero AL produces tag **`0x2a`** plus that 32-byte row and exits through cleanup. A zero AL continues to the next row. The helper appears consistent with a seen-row/duplicate probe, but that semantic identity and its allocation/error behavior remain **inferences**; the proven fact is the per-row nonzero early exit and the order of checks.
5. The sentinel is `0x8000000000000001` (distinct from the min-i64 sentinel used by other collections). If input `+0x18` equals it, the caller directly invokes `0x595fd20` with input `+0x20`, context and the output pointer, then cleans up. That arm bypasses the range guard and the other validator. The sentinel's original source-level variant name is unknown.
6. Otherwise, if input `+0xa8` is not the sentinel, input word `+0xd8` must be **strictly greater than** input `+0x48` and **strictly less than** input `+0xa0`, using unsigned comparisons. Either endpoint or an out-of-range value writes tag **`0x0c`** with the tested word and skips both validator calls. This is an ordering interval on native fields, not a claim that the words are timestamps, rounds or block heights. If `+0xa8` is the sentinel, this range guard is bypassed.
7. The remaining arm calls `0x5960390` on input `+0x18`. A returned tag different from `0x2e` is copied to output and suppresses the later validation. If its tag is `0x2e` and input `+0xa8` is present, the caller then calls `0x595fd20` on `+0xa8`; failure is likewise copied. Only the local continue results reach an output `0x2e`. Cleanup at `0x5246b60` runs on the post-collection paths, including early row rejection and interval failure.

The mismatch diagnostic also computes saturating additions from context fields and an unsigned maximum for a formatted boolean. That boolean does **not** select acceptance or failure here; treating it as an extra admission condition would be unsupported. The full instructions are retained, but no diagnostic helper side-effect closure is claimed. If a helper diverges, panics or unwinds, the normal-return decision sequence does not assert otherwise.

## Reproduction and controls

Run from the repository root with Python **3.12.3**, Capstone **5.0.7**, GNU objdump **2.42**:

```sh
python3 tools/node115_signed_validation.py --write
python3 tools/node115_signed_validation.py
python3 -m unittest discover -s tests -p test_node115_signed_validation.py -v
```

The first command regenerates the static packet, the second checks exact replay. The node is read only; no captured executable, emulator, socket, chain or signing operation runs. All **11 tests** pass. Eight decoded-instruction corruption controls cover inverted helper-result propagation, ignored 20-byte identity tail, OR instead of AND, exclusion of exactly 100, reversed row-helper disposition, inclusion of either interval endpoint, and allowing a failed first validator to proceed to the second. Wrong-artifact and truncated-decode controls also reject. These are structural checks of the authentic target evidence, not execution of the target or a differential source implementation.

## Limits and next work

The measured denominator is one raw exported FDE / 1,323 bytes / 257 instructions. No Rust source has been reconstructed here. Raw-equal, normalized-only and unmatched compiled-comparison counts are **unmeasured**, not zero-percent completion. All gates remain false. Direct validator/collection/cleanup FDE leads and imported-slot relocations are retained without adopting their behaviors. No complete caller census, helper cryptography, error-tag global names, wire encoding or whole-consensus equivalence is claimed.

Next: close `0x595cb30` and bind its result payload to a cryptographic operation, then measure the two downstream validators against the native fields identified here. The decision order above can constrain that reconstruction without pretending those dependencies are already correct.

Native text exports trim trailing whitespace only; instruction bytes, operands and addresses are unchanged.
