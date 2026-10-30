# RE-004: which sites add a value divided by 10000 to a saturating total in node #94?

- Component ID: RE-004 (quantities/rounding)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: 820af5d8c278ac62bd2472edeedb9a0a62b10061 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for instruction shapes, divisions, saturation and site counts; inference for the
  labels of the two fields; unresolved for what the inputs are.
- Scope included and excluded: included are all 79 references to one Rust Location, the 33 functions holding them,
  and three complete helpers. Excluded are the lookup functions, the recorder's internals, the origin of the input
  values, and the 500+ other sites of the same reciprocal that do not pass this Location.

## Reproduce

Run from the repository root. Linux x86-64, Python standard library, GNU objdump (2.42). The tool reads the
binary and never runs it. No network and no side effects outside `--out`.

```
python3 tools/artifacts.py verify
python3 tools/ntl_ten_thousand_add.py --out research/work-items/RE-004-ntl-ten-thousand-add-94
python3 -m unittest discover -s tests -p 'test_ntl_ten_thousand_add.py'
(cd research/work-items/RE-004-ntl-ten-thousand-add-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x2712a00 --stop-address=0x2712ae4 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x2733e0a --stop-address=0x2733e45 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x2714d79 --stop-address=0x2714e13 artifacts/node/94/hl-node
```

## Evidence

Coordinates are ELF VAs. Function extents come from FDEs reached through `.eh_frame_hdr`, 121299 entries.

**Anchor.** The record at 0x5715ef8 is a Rust Location, `l1/src/qtys/impl_ntl.rs:665:1`. Its path pointer is a
RELATIVE relocation. A byte scan finds 79 `lea r64,[rip+disp32]` references in `.text`, in 33 functions. Each passes
it in rsi with edi = 0 to the function behind GOT slot 0x5773190, which is 0x358dcd0.

**Four shapes.** Every site adds a quotient to an i64 at +0x10 or +0x18 of a record. `m` is 0x346dc5d63886594b:

| Shape | Instructions | Value | At +0x10 | At +0x18 | Multiplies |
|---|---|---|---|---|---|
| signed | `imul m; sar 11; add sign bit` | trunc(x / 10000), i64 x | 12 | 15 | 21 |
| neg-signed | `imul -m; sar 11; add sign bit` | trunc(x / -10000), i64 x | 6 | 9 | 9 |
| unsigned | `mul m; shr 11` | floor(x / 10000), u64 x | 12 | 9 | 15 |
| neg-unsigned | `mul m; shr 11; neg` | -floor(x / 10000), u64 x | 9 | 7 | 13 |

The -m constant is 0xcb923a29c779a6b5, which is 2^64 - m. Read as signed it is -m, so the sites divide by -10000.
Both signed shapes round toward zero. So does every shape in practice: no site rounds a negative value away from
zero, and any magnitude below 10000 adds nothing.

**Division proof.** `divide-proof.tsv` holds the exact bound. 10000 * m - 2^75 = 432 > 0, and for the largest magnitude
in each shape, 2^63 or 2^64 - 1, magnitude * 432 < 2^75. That inequality gives the stated value for every 64-bit
input. Tests show the bound is not vacuous: m - 1 and m + 1 fail it, and m + 1 gives a wrong quotient on a concrete
input.

**Saturation.** Each add is followed by `jo` (73 sites) or `jno` (6 sites). On overflow the site calls the recorder and
stores the saturated total, then continues. Signed-delta forms pick i64::MIN or i64::MAX by `sar 63; xor`. Some
unsigned forms hold i64::MAX directly, since a positive delta can only overflow upward.

**Recorder.** The entry path of 0x358dcd0 does a `lock cmpxchg` on 0x5786278, copies the Location to the stack, calls
0x3396b10 with 0x5786280 and the edi byte, does a second `lock cmpxchg` and returns. This was read by hand from the disassembly, and the tool
checks only the GOT slot target. The same recorder appears in RE-004-wei-buffered-cap-94 with another Location.

**Helpers.** 0x2712a00, 0x46f3240 and 0x46f3330 are complete functions of 66 instructions each. They take a key,
a first value in rdx, a flag in bit 0 of cl and a second value in r8:

```
record = lookup(self + displacement, key)
record.+0x10 = saturating(record.+0x10, trunc(first / 10000))
record.+0x18 = saturating(record.+0x18, trunc((flag ? second : first) / 10000))
```

| Helper | Lookup | Displacement | Direct calls |
|---|---|---|---|
| 0x2712a00 | 0x1f849b0 | 0x740 | 6 |
| 0x46f3240 | 0x47d7ca0 | 0x11c0 | 6 |
| 0x46f3330 | 0x47d7ca0 | 0x740 | 6 |

**Paired updates.** At 0x2714d86 one quotient is negated into both totals of one record and added to both totals of a
second record. 3 multiplies are shared by unsigned and neg-unsigned sites this way.

**Completeness of the signed sites.** A byte scan for `sar r64,0xb` within 24 bytes after a one-operand 64-bit `imul`
gives 30 hits in `.text`. All 30 lie in the family, and the family has exactly 30 distinct signed multiplies.

**Reference comparison.** `l1/qtys/mod.rs` has `add_usdc_ntli_to_two_totals` with `second_delta.unwrap_or(delta)`, and it
matches the helper's flag and truncation. The reference uses silent `saturating_add`, while the binary calls the
recorder on overflow. `to_usdc_ntl_trunc` and `to_account_volume_delta` match the signed shape. The reference shows no
division by -10000 or negated u64 form for these totals.

## Implementation and comparison

Rust implementation: not yet implemented. Nothing was compiled, so there is no build, Cargo.lock or byte comparison.

The comparison here is real instructions against the closed forms. A Python evaluator interprets objdump text:

- Site runs: 11178 runs over all 79 sites, with 0 mismatches. Each runs from its multiply to the store into the
  record, through the hot or cold path, on boundary values of x and of the old total.
- Helper runs: 1944 runs over 3 helpers, with 0 mismatches. These are strict, so any unset register or memory word
  stops the run. All 66 instructions of each helper ran. The lookup and recorder are stubs. The stub drops the
  caller-saved registers, so a helper cannot depend on them.

## Results and limitations

Metrics are in `evidence.json`. Denominators: 79 of 79 Location references classified and run, 30 of 30 signed byte hits
inside the family, 3 of 3 helpers fully executed. No progress gate is requested.

- The division is proved for all inputs. Saturation and control flow ran on sampled boundaries only.
- Site runs start mid-function. Other registers and unset memory hold marker values, and narrow or vector moves are
  skipped. A site depending on one of those would disagree with its expected value, but this is weaker than the strict
  helper runs.
- 24 sites reuse an earlier quotient and run from the record load with the delta preset. For those, the link to the
  multiply is a static check on linear instruction order, not an execution.
- Input x is injected. What x is at any site is unresolved.
- The field labels are unverified. The reference calls +0x10 and +0x18 account volume, and the file name suggests Ntl.
- The lookup functions are stubs. The record type and key are unresolved.
- The recorder's contended paths and 0x3396b10 were not followed.
- The signed scan covers the REX.W reciprocal form with `sar r64,0xb`. A one-off text scan for `idiv` near 0x2710 found
  none, but the tool does not repeat it.
- Node #115 is not covered.

Next question: what are the inputs x at the 0x2712a00 call sites, and does `flag` separate two kinds of notional?
