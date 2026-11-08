# RE-001: pin node #115 the encryption-provider dispatch factory 0x5ffabd0 and its registry dispatcher 0x5ffa710

## Question

What does the small host 0x5ffabd0 do -- the 2-site RegisterOptions host
from #4372's census and the non-"ROT13" dispatch path left open by #4395
-- and how does its delegate 0x5ffa710 resolve a provider name? Resolves
the open unknowns left by #4395 (the 0x5ffabd0 dispatch) and #4372
(census site 0x5ffacee).

## Answer (one paragraph)

The host 0x5ffabd0 is slot 21 of the CTREncryptionProvider vtable
0x64cffb0: a dispatch factory (Status* out, holder, name, block_size).
If the holder's cipher slot (+0x20) is already occupied it returns
kNotSupported "Cannot add keys to CTREncryptionProvider" (40 bytes,
literal 0x968090). If name == "ROT13" (literal 0x4487d6) it builds a
0x28-byte ROT13BlockCipher in place (vtable 0x64cfea0, block_size from r8
at +0x20), registers group "ROT13BlockCipherOptions" with the block_size
map 0x65052c0, wraps the cipher in a 0x18-byte non-inplace shared_ptr
control block (vtable 0x64d0128, counts (1,1) from 0x459b20) and stores
it into the holder, releasing the old cipher. Otherwise it copies the
name into a stack string, default-inits a ConfigOptions with 0x60bb890,
and delegates to the registry dispatcher 0x5ffa710, which pthread_once-
inits the provider registry map 0x6505278, configures the provider
through the options-map host 0x609e510, and either resets the cipher slot
or dispatches to the registry factory 0x5ff9fe0. The factory has no direct
E8 caller and no lea site: it is reached only through vtable slot 21.

## Evidence

- `records.json` -- semantic records only (no per-instruction mnemonic
  list): the dispatch factory, the registry dispatcher, the "id"-guard
  wrapper, the registry factory dispatch, the ConfigOptions init, the
  string ctor, the two maps, the two vtables, cited context, open
  unknowns.
- `fn-*.objdump.txt` -- whole-function objdump excerpts (repo-relative
  binary path) for the dispatch factory, the dispatcher, the wrapper,
  the twin dispatcher and twin wrapper, the registry factory dispatch,
  the ConfigOptions init, and the string ctor.
- `callers.tsv` -- every lea reference to the maps/vtables/functions
  and every E8 call site in the packet, with the enclosing FDE.
- `maps.tsv` -- the block_size map (one entry "block_size") and the
  provider registry map (init 0x5ff9c50).
- `vtables.tsv` -- all 27 slots of the CTREncryptionProvider vtable
  0x64cffb0 and all 6 slots of the control-block vtable 0x64d0128.
- `literals.tsv` -- the string/immediate literals behind the claims.
- `frames.txt` -- the FDE extents for every pinned window.

## Verification

`verify.py` -- 160 checks, ALL CHECKS PASSED (artifact digest, manifest,
excerpt regeneration, FDEs, 38 raw-binary spot bytes, literals, lea
census, E8 caller census, vtable slots + typeinfo names, GOT slots,
semantic-only records, model tests). `pytest
tests/test_provider_dispatch_factory_115.py` -- 25 passed.

Environment limits (honest): this VM has no cargo/rustc, no git-lfs, no
Ghidra/Java, so `make verify`, `make test` and `make catalogue-check`
were not run in a tooled environment; the packet's own `verify.py`
(byte-identical excerpts, FDEs, spot bytes, censuses, model tests) is
the verification that ran here.

## Open unknowns

- The C++ name of the slot-21 virtual (0x5ffabd0): its behavior is an
  add-cipher entry, but the source name is open.
- The exact C++ type of the factory's holder argument and of the out
  slot.
- The registry factory dispatch 0x5ff9fe0's internals: the lookup key,
  the factory-table layout, and the per-branch Status outcomes.
- The C++ meaning of ConfigOptions byte +0x01 (the gate that chooses
  the code-3 swallow vs the code-0 0x609e2d0 fallback in the dispatcher
  tail); the branch structure itself is pinned.
- The wrapper 0x5ffae10's record arguments (rcx/r8): which option
  records they are, and why the "id" + count-2 + empty-r8 case clears
  the cipher instead of dispatching.
- Why two byte-identical dispatcher/wrapper pairs exist (0x5ffa710 /
  0x5ffae10 vs 0x5ffba10 / 0x5ffbde0): distinct instantiations or
  duplicate emission.
- The ConfigOptions field identities at +0x08/+0x38/+0x40 (0x60bb890)
  and +0x48 (released in the delegate cleanup).
- The CTR vtable slots 19/20/22/23/24/25 and the control-block vtable
  slots 0..4 -- C++ names open.
- The slot-16 override 0x5ff1030's body (the CTR provider's name-match
  predicate).
- The remaining RegisterOptions clusters from #4372's census (2-site
  hosts 0x6029390 / 0x6086e00 / 0x6202a10 / 0x6205790) -- still
  unanalysed.
