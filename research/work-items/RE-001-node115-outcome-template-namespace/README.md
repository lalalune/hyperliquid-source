# RE-001: node #115 OutcomeDeploy reserved template namespace

- Component: outcome deployment admission; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Full enclosing FDE: `0x2c59960..0x2c5bac0`, 8,544 bytes. ELF virtual addresses, exclusive interval ends. The enclosing dispatcher is evidence context; this does not claim all its arms or complete outcome deployment. Gates remain false.

## Finding

Three entry arms in the native OutcomeDeploy dispatcher reject names that begin with the exact nine bytes `template:`. One of those arms also applies the same rule to every child name. The refusal precedes the relevant downstream handler calls. Passing the namespace guard only permits the next stage; it is not full admission.

For this dispatcher, a negative leading qword is XORed with `0x8000000000000000` to obtain a raw table index; nonnegative values use index 8. The namespace guards occur in raw arms **0, 1 and 5**. This packet uses raw indices rather than assigning unproved source enum names. Each arm reads its outer name pointer at input `+0x10` and byte length at `+0x18`.

The existing maximum length of 100 bytes is checked first and is credited prior work. A name of fewer than nine bytes then bypasses the prefix read. At length nine or more, the code compares the first eight bytes with `template`, separately compares byte eight with `:`, and rejects only when both match. The comparison is anchored and case-sensitive; it performs no trimming, case folding or Unicode normalization. Any suffix after the colon remains within the reserved prefix, including an empty suffix.

| Name example | Result of this local gate |
| --- | --- |
| `template` | Continue; too short to contain the prefix |
| `template:` or `template:abc` | Reserved-prefix error |
| `Template:` or `xtemplate:` | Continue; prefix bytes differ |
| `template;` | Continue; final prefix byte differs |
| More than 100 bytes, even with the prefix | Earlier length error |

All four refusal sites (three outer guards and the child loop) publish raw error word `0x191`, the pointer to `name cannot start with the template prefix`, and its exact length 42. The prior length-error carrier is `0x158`; this distinction makes their ordering observable.

Raw arm 0 proceeds to `0x2c60f60` only after its outer prefix check. Raw arm 5 proceeds to `0x2c607e0` after its check. Raw arm 1 first passes its outer check, calls the opaque description validator `0x3675d70`, and proceeds to child checks only on result word `0x1a2`. The existing child-count limit is also context, not a new finding.

The child vector has pointer at input `+0x70`, count at `+0x78`, and row stride `0x30`. Each child row supplies name pointer `+8` and length `+0x10`. In iteration order, each child passes the existing length check before the namespace comparison. The first failure returns immediately. Empty child lists and lists whose names pass proceed to `0x2c5fa80`. A bad outer prefix prevents the description validator and child iteration from being reached.

## Limits

Valid native descriptors, byte extents and supported raw variants are assumed. Other dispatcher arms, generated names, description validation, UTF-8/source decoding, duplicate checks, registration state changes and settlement behavior remain outside this question. Raw byte probes distinguish the native comparison; they do not claim malformed encoded names are accepted. Maximum lengths and child-processing order are credited scaffolding needed to locate the newly identified refusal, not newly reconstructed business rules.

Relations test every byte value at every prefix position, boundary lengths, case/anchor distinctions, UTF-8 suffixes and first-failure ordering. Three changes to real target operands distinguish the literal colon, the nine-byte read gate and the published namespace-error code. No captured code is executed or emulated.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-outcome-template-namespace/export_disassembly.py
python3 research/work-items/RE-001-node115-outcome-template-namespace/verify.py --controls
python3 research/work-items/RE-001-node115-outcome-template-namespace/relations.py
python3 -m unittest discover -s tests -p 'test_node115_outcome_template_namespace.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-outcome-template-namespace/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The packet retains an all-state scope audit and census. [PR #997](https://github.com/lalalune/hyperliquid-source/pull/997) already covers node #94 OutcomeDeploy admission, name lengths and name/child processing order. Those remain credited context. Its available evidence does not establish this reserved `template:` refusal across the three entry paths and nested names. [PR #1859](https://github.com/lalalune/hyperliquid-source/pull/1859) covers settlement; [#393](https://github.com/lalalune/hyperliquid-source/pull/393) identifies this node #115 FDE and callers; [#2885](https://github.com/lalalune/hyperliquid-source/pull/2885) covers independent settlement fraction scales. Those findings are not re-claimed here.

GPT-6.1 Terra inspected open and closed PR metadata and available file evidence, including older-release analogues. Missing patches, a capped historical file list and unavailable prior PRs limit the audit. New analysis and relations are independently authored under MIT; ELF/export/corruption scaffolding adapts existing MIT packets. No unlicensed inferred source is copied or input rights changed. Full component completion, source equivalence and hosted CI are not claimed.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
