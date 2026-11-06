# RE-012: node115 temporary-path factory, preparation and fallback

Component: foundation (filesystem/path adapter); task RE-012. Sole target Linux
x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Original ELF VAs,
no rebasing or normalized bytes. New project-authored research is MIT.

## Question and progress

What exact path does `0x1502f90..0x1503323` build, which parent/preparation
checks can select its fallback, and which owned buffer does it return?

The base `RE-009-abci-state-export-115` records slot `0x64e09f0` as an opaque
path-like producer before file writing. This packet resolves the complete
915-byte factory's normal branch/argument/layout relationships, its compact
format descriptors, actual callback bindings, repeated parent-selection logic
and conditional failure/cleanup ordering. It supplies static evidence, not a
mock filesystem or fabricated Rust helper. Live open titles inspected on
2026-11-04 showed the Unix reverse-component and UTF-8 work, but no competing
factory result. Those lower-level outcomes support this caller and do not
close it by themselves. No issue was opened, drafted or claimed.

## Arguments, global field and primary path

Entry RDI is the output destination retained in RBX. RSI/RDX are the input
pointer/length saved at `rsp+0xa8/+0xb0`. At `0x1502fb4..0x1502fce`, the
factory constructs the fat literal pair (pointer `0x465a0e`, length 3), exactly
`tmp`. Slot `0x64e0918` is a unique R_X86_64_RELATIVE writer to `0x64f06c0`.
The factory tests `[global+0x50]`; if nonzero it enters the lazy-helper call at
`0x15032c9` through slot `0x64df9f0` -> `0x5c87d50`, then rejoins. This does
not establish the runtime global value or initialize it by merely reading
file bytes. Existing static-configuration work studies its producer separately.

The first formatting call at `0x1503033` has descriptor bytes at `0x440e47`:

```
c0 01 2f c0 01 2f c0 00
```

Its three 16-byte argument records, in order, are:

1. Address `global+0x18`, callback `0x14fcb40`. This callback reads the
   pointer at argument+8 and length at argument+16.
2. Address of the local `tmp` pair, callback `0x15ebba0`, reading pointer
   at argument+0 and length at argument+8.
3. Address of the original input pair, same slice callback.

Both callbacks tail-call slot `0x64df720` -> `0x167fa70`. The formatting
builder is slot `0x64df6e8` -> `0x141e3a0`, whose real write-dispatch call is
slot `0x64df6f0` -> `0x1680500`. The latter's `0xC0` arm selects the next
argument, increments the argument index and installs default flags
`0x60000020`; a positive byte writes that many following literal bytes, and
zero terminates. The default string callback takes its direct-write arm
because those flags have neither width nor precision bits `0x18000000`.
These actual target rules support the byte-concatenation inference:

```
primary = displayed(global+0x18) + "/" + "tmp" + "/" + input
```

This is formatting, not `Path::join`: no observed reset on an absolute input,
separator collapsing, sanitization or escaping occurs in these default arms.
A slash already at an argument boundary can therefore remain doubled. The
runtime strings and caller provenance remain unknown.

The builder's complete owned result is initially at `rsp+0x70/+0x78/+0x80`;
the factory retains it at `rsp+0x50/+0x58/+0x60`. The observed fields are
allocation-count-like, pointer and length, respectively. This is a local
24-byte layout, not a blanket claim about every native Rust String ABI.

## Parent candidate and preparation

The factory does not shorten the returned buffer when selecting a parent.
It constructs a fresh Unix component cursor from the full primary bytes:
prefix sentinel 6, front/back states 1/2, absolute flag iff length is nonzero
and byte zero equals `/`. Slot `0x64e0938` -> `0x5cab560` obtains the last
component. The exact byte expression `(tag+0xf9) mod 256 < 3` accepts tags
7, 8 and 9 (current, parent and normal in the already-studied component
representation); it excludes root 6 and none 10.

For those tags it calls remaining-view slot `0x64e09b0` -> `0x5c8e8c0`.
Only a nonzero returned pointer leads to the UTF-8 helper `0x64dfca8` ->
`0x16815e0`. A UTF-8 result with dword tag != 1 supplies its +8/+16 pointer
and length as the preparation candidate; otherwise the entire original pair
is retained. The independent main preflight at `0x15020f0..0x15021c2` uses
this same classification, view, UTF-8 and preparation sequence.

The chosen candidate goes to slot `0x64e0928` -> `0x1500a60`. Its selected
metadata-success arm classifies `(mode & 0xf000) == 0x4000`; metadata error
arms dispose of errors and return zero. It can call the metadata slot twice,
so it is not treated as a pure/stable existence oracle. A nonzero predicate
result accepts the candidate. Otherwise the factory sets option dword
`0x1ff` (0777) and byte+4 to one, then calls slot `0x64e0940` ->
`0x5c8f4c0`. Its zero return accepts preparation. A nonzero return is wrapped
by `0x1500b90` with the **selected preparation pair**, not necessarily the full
owned path. The recursive helper's full FDE is retained for argument/branch
context; its complete filesystem, errno and recursive behavior is not claimed.

## Fallback is prefixed to the complete original path

Only a nonzero first preparation return reaches the second formatter. It
uses descriptor `0x438859`:

```
05 2f 74 6d 70 2f c0 00
```

There is exactly one argument: the address of the **retained whole primary
owned triple at rsp+0x50**, with callback `0x14fcb40`. Thus:

```
fallback = "/tmp/" + primary
```

It is not merely `/tmp/` plus the original input basename. An initially
absolute primary can appear after this literal prefix with two slashes.
The new owned result is at `rsp+0x08/+0x10/+0x18`, retained in R12/R15/R14.
Separate RBP/R13 hold its selected preparation parent; returning fallback
uses the full R15/R14 buffer, preserving the distinction.

The factory repeats the component/remaining-view/UTF-8/predicate/create path
for fallback. Its subsequent **conditional** normal returns are:

| Condition, with called helpers returning normally | Returned owned triple | Cleanup/order |
| --- | --- | --- |
| Primary predicate nonzero or primary creation returns zero | Full primary | No fallback allocation |
| Primary creation nonzero; fallback predicate nonzero or fallback creation zero | Full fallback | Store fallback to output; invoke primary wrapped object's dynamic handler; release primary allocation |
| Both creation calls return nonzero | Full primary | Invoke fallback wrapped object's dynamic handler; release fallback allocation; invoke primary wrapped object's dynamic handler; copy primary to output |

The dynamic calls are `0x150321c`, `0x1503239`, and `0x1503274`, each through
the wrapped object's first function pointer. **Their implementation, return,
termination and unwind effects are not closed.** It would be unsupported to
claim the factory always returns a fallback after its first failure, or always
returns an ordinary Result on its second failure. The retained cleanup/landing
pad edges are exported, but not executed or modeled as an unwinder.

`flow.json` records every source/destination offset and output-copy branch.
The normal primary output copies `[rsp+0x50..0x68)` into `[out..out+0x18)`;
the fallback route stores R12/R15/R14 at output +0/+8/+16 before handling the
primary error. No operation in this factory writes the eventual file contents,
renames it or proves atomic/durable state publication.

## Evidence and reproduction

Thirteen complete FDEs total **9248 bytes / 2281 instructions**: factory,
preflight, directory predicate, error wrapper, two callbacks, format builder,
format dispatch, string-format helper, reverse component, remaining view,
UTF-8 validator and recursive-create context. These are export denominators,
not an assertion every helper algorithm is understood or newly reconstructed.
Overlapping earlier exports receive no new byte-equality or component credit.
`records.json` binds full bodies, actual FDE/CIE records and LSDA addresses,
126 calls and 404 direct/dynamic branch records. Dynamic edges stay explicit;
branch-leader lists are not proof of a fully resolved interprocedural CFG.

`collect.py` validates target identity, file-backed VA mappings, full FDE
ownership, complete Capstone instruction partitions and actual RELATIVE
bindings. GNU and LLVM instruction bytes agree independently; GNU readelf
confirms all extents. LLVM's separate LOCK rows are joined only to their
contiguous instruction; bytes are not masked. Raw exports and actual tool
versions are retained.

```sh
python3 -B research/work-items/RE-012-temp-path-factory-115/collect.py --out work/fresh-temp-path-export
 diff -u research/work-items/RE-012-temp-path-factory-115/records.json work/fresh-temp-path-export/records.json
python3 -B research/work-items/RE-012-temp-path-factory-115/verify.py --out work/fresh-temp-path-check.json
```

The focused verifier freshly reproduced the record, rejected 31 instruction
and four literal/descriptor corruptions **without using the full-file hash**,
rejected ten actual relocation-addend mutations with a narrow relocation
check, and rejected two wrong/truncated capture controls. It also exhausts
256 byte values for the component-tag algebra. These are static evidence
qualification counts, not behavioral differential cases or emulator results.
`qualification.json` records actual outcomes; parent publication performs
repository/catalogue checks. No target process, instruction emulator, actual
filesystem path operation, network, hosted CI or container was run.

## Limits and next step

No Rust implementation is claimed: fabricating allocator, directory or error
handlers would replace the still-open semantics with mocks. The exact
initialization value/type and lifecycle of global+0x18, full caller input
provenance, filesystem helper algorithms, error-handler implementation, ABI,
unwinding and file-publish operation remain open. The next bounded work is the
wrapped handler's concrete vtable/termination closure or recursive-create
semantics under an explicitly approved filesystem harness. This result leaves
all 92 full-component gates and registered comparison totals unchanged.
