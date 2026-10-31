# RE-001 / foundation: host-IP caller admission

Question: does the node94 host-IP caller accept arbitrary short text, and does
its override run only after unsuccessful probes? Intended files are the tool,
focused controls and this packet. This is partial static research, not recovered
Rust or a completed component gate.

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
The inferred, unlicensed reference is can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `base/u.rs`; used as a lead,
not copied. That description's 64-byte bound and fallback-only cache do not
establish the captured caller's admission and override order.

## Observed evidence

ELF virtual addresses throughout; no normalization masks. Actual FDE/CIE plus
the complete owner `0x13ca370..0x13cba3e` are exported: **5,838 bytes / 1,120
instructions**. Full-body SHA-256 is
`9bbbf50d25f9842e868621a198bebfe62137fa666eff6154b5b387f1b19423ef`.
Only the selected caller protocol below is modeled; this denominator describes
the complete export, not recovered semantics for every instruction.

The initial copied command literal is `hostname -I | awk '{print $1}'`.
The subsequent path format includes `/override_public_ip_address`. Its reader
call at `0x13ca4b6` resolves through slot `0x576e958` to `0x144c330`.
The first result word is compared with raw `0x8000000000000000`. A different
word branches at `0x13ca4ce` to `0x13ca625`; the normal route subsequently jumps
at `0x13ca759` to `0x13cb50c`, bypassing all three probe blocks. An empty
payload is not separately rejected by this selected word check. Reader behavior,
logging and exceptional paths are not modeled; this is not a typed Result ABI.
The captured read Location resolves to `base/src/u.rs:426:21`.

| Endpoint literal | Execute call | Length compare | Parser call | Rejection target |
| --- | --- | --- | --- | --- |
| ifconfig.me | 0x13ca5d2 | 0x13ca77b | 0x13ca799 | 0x13ca898 |
| api.ipify.org | 0x13caa4d | 0x13caab9 | 0x13caad7 | 0x13cabd8 |
| icanhazip.com | 0x13cad8d | 0x13cadf9 | 0x13cae17 | 0x13caf10 |

All three format references bind the captured `curl -s ` prefix. Their command
call slot `0x576e950` resolves to `0x13e5af0`. This does not establish effective
timeout or shell behavior. On reaching each successful-output length guard,
unsigned `CMP RBP,15; JA reject` refuses lengths above 15 before the parser.
The slice descriptor is passed to `0x1573af0`. On return, each site compares
the remaining word with zero, uses `SETE CL; TEST CL,AL; JE reject`.
Admission into the following collection code therefore requires **length <=15,
AL bit 0 set, remaining word zero**. AL merely being nonzero is insufficient
for the raw predicate (e.g. 2); such raw values need not be reachable parser
outputs. Collection insertion and final returned public-IP list are unclosed.

## Inferences, overlap and unknowns

The host-IP name follows command and endpoint context, not an original symbol.
PR #558 independently studies parser `0x1573af0` in a gossip-bid packet. This
packet neither reimplements nor claims that parser grammar: it establishes the
three host caller's full-consumption/length guards and preceding override route.
All three related sites are grouped here. No actual host command, HTTP request,
configuration file, TLS state, captured executable or user runtime data is used.

Unknown: helper trimming/timeout/IO semantics, parser internals and valid output
domain, collection layout/deduplication, final result type, reader error meaning,
cache writes, allocation/drop/unwind closure and source equivalence. Next step:
close the override reader and final output paths before assigning a typed API.

## Reproduction and controls

Python 3.12.14; optional Capstone 5.0.6 x86-64 Intel export. The verifier uses
only stdlib and existing static ELF readers, with pinned target identity.

```
python tools/host_ip_admission.py --out research/work-items/RE-001-host-ip-admission-94/records.json
python research/work-items/RE-001-host-ip-admission-94/export_disassembly.py
python -m unittest tests.test_host_ip_admission -v
```

Six focused methods pass. The declared abstract predicate checks ten boundary
lengths, all 256 raw AL values and five remainder classes (12,800 combinations),
plus sentinel-neighbor override words. These are conditional abstract checks,
not native execution or a full parser/string differential. Real-capture mutations
cover all three length/remainder/AL operands, literals, format/execute/parser
targets, override sentinel/route, source record, FDE extent and target digest.
The exact focused run is preserved in `controls.txt`. Required-check results
are recorded below; no milestone/progress gate is changed.

Make is unavailable, so the Makefile's Python commands were run directly.
Full discovery: **363 tests in 110.183 seconds; 7 failures, 16 errors, 21
skips**. The six new methods pass; existing Windows newline/POSIX-path and
native-tool constraints remain failures. This branch excludes unmerged #227.
Doctor reports missing analysis prerequisites. Artifact verification with a
workspace temporary directory checks eight sizes/digests, then fails because
GPG is absent; it does not verify signatures. Imports fail on the Windows
reference checkout; catalogue-check rejects backslash source paths. Reproduce
stops at artifact verification. Initial verify/reproduce attempts without the
workspace temp override also encountered Windows temp-cleanup permission errors;
both attempts are preserved in ignored work logs. No full-suite, hosted-CI,
native-build, parser-equivalence or signature success is claimed.
