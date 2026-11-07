# RE-001: user-admission key-comparison branch

- Component ID: `exchange` (user admission entry path)
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: current `main` at `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`
- Claim status: observed instruction flow; comparison values are supplied inputs
- Scope: the branch after the existing 20-byte key-comparison frontier at `0x2c77831`

## Result

The [existing entry-graph contribution](../RE-001-user-admission-prefix-115/README.md)
stops before the indirect comparison. This packet maps only the immediate
continuation. The prior packet binds slot `0x64dfb50` to imported `memcmp`; this
packet makes no claim about the loaded runtime address or node-key contents.

The target multiplies the current child count by 20, calls the comparator with
length 20, sign-extends its integer result, and reduces it to signed ordering:

- result `0`: jump to `0x2c776ac`, which re-enters the root-route logic;
- result `> 0`: if another sibling remains, loop to `0x2c77820` for the next key;
- result `< 0`, or a positive result after the last sibling: decrement depth;
- when depth is already zero, the path reaches the empty-route block at
  `0x2c778de`, which writes raw result word `0x98` at `0x2c778e3`.

The standalone Rust projection in
`src/node115-user-admission-prefix/compare_step.rs` expresses only those edges.
It accepts the signed result, sibling-presence bit and depth as explicit
boundary inputs. It does not compare keys, walk native memory, or turn the
equal branch into a final admission decision.

## Reproduce

```sh
python3 -B research/work-items/RE-001-user-admission-compare-branch-115/verify.py
rustup run 1.95.0 rustc --edition=2021 --test src/node115-user-admission-prefix/compare_step.rs -o /tmp/user-admission-compare-test
/tmp/user-admission-compare-test
```

The verifier authenticates the pinned target, the full `0x2c77640..0x2c77ba5`
FDE, all 1,381 owner bytes and 26 instruction anchors. It requires Capstone
5.0.7 and checks a complete instruction partition plus the three branch
destinations. No captured executable, emulator, live service, chain action or
key operation is used.

## Limitations and next question

This does not recover actual tree contents, the comparator's runtime pointer,
or the later helper-dependent admission operation. It advances the entry-path
model by one explicit comparison boundary; it closes no full-component gate.
Next: qualify the parent-pointer selection and determine which child span is
consulted after a negative comparison, without assuming valid container data.
