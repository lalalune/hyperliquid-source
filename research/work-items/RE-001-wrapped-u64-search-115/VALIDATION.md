# Actual checks and limits

Native47.886s PASS8930 distinct family/input rows,572B181starts allvisited,
14output-changing COWs and4independent normalization/stride rejections. Seven
pre-Rust tests PASS5.729s(inner4.644). Pre-Rust seal828d23988090abb80c653115d496c727cadf31a6
contains native/contract/goldens/controls and no new Rust.

Rust172.845s PASS all8930 exact fullRAX/RDX observations at opt0/3/repeat,
same-path opt3 rlib bytes repeat,119sealed fixturecases,12compiledmutants.
Every wrong source emits8930rows and fails ordinary assertions101; no crash
is accepted as a control. Actual mismatch counts:

{
  "signed-key": 4760,
  "strict-span": 2164,
  "ignore-seam": 516,
  "seam-index": 968,
  "reverse-span": 4052,
  "found-index": 2164,
  "short-span": 3796,
  "raw-head-zero": 258,
  "head-zero": 258,
  "status": 8930,
  "miss-index": 5748,
  "empty-index": 50
}

Scoped commands all exit0:

focused=6.71s; fmt=2.829s; clippy=6.205s; scope-gates=52.902s; doctor=9.549s; verify=70.475s; catalogue=64.575s; catalogue-check=58.366s; reproduce=127.481s

Focused7, fmt(lib/driver/exactclient), Clippy-Dwarnings,12packetintegrity tests,
doctor/verify/catalogue/check/actualreproduce passed. Rawlogs retain any macOS
xcrun restricted-cache warnings; actual command return values are reported.
Catalogue generation/check alone uses separately submitted#2655 snapshot helper
for measured39.47GB repeated-read blocker; baseline restored before actual
reproduce/final checks, both hashes/scope in validation-overlay.json. No helper
change included, no unmodified-head local catalogue claim. Own upstream fullCI
pending; no full local make test or combined-node integration claim.

Tools Python3.12.14/Capstone5.0.6/GNUobjdump2.47.20260726; macOSarm64
rustc1.94.1/LLVM21.1.8 edition2021. Source uses logical sorted keys and geometry,
not original descriptors/ABI. Its finite capacity<=32 refusal is not native
malformed-input behavior. Only live key qwords initialized; unusedcapacity and
payload stayunknown. Normalization preserves exact fullRAX/RDX logicalindex,
including duplicates and seam shortcut; no resultbit or pointer mask.

One foundation implementation path, all92gates/bytewindows unchanged. Base560
tracked top-level packetREADMEs vs stale generated559; this one packet561,
Rust areas34->35,Cargo manifests19. No production signature/crypto policy,
original compiler recipe, Linux execution, target-byte equivalence, original
ABI or full caller/integrated-node claim. No captured process or Unicorn.
