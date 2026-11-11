# RE-002 · Node #115 RocksDB Comparator::CreateFromString

Component: storage / comparators / options. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 turn a config-options string into a comparator --
which function does the selection, what does it parse, how does it
dispatch on the three builtin names, what happens for an empty value,
an empty id, or an unknown id, and who calls it? The 2868-byte body
has NO vendor census record (like the forwarder stubs in #5950), so
only the body hash is claimed:
`f8a5ceb9866dd4f351451e1ac48cae7a86db396e3e40ffa0acf5068c17054c3f`,
recomputed from `work/hl-node-115.bin` over the FDE range
0x61c0180..0x61c0cb4. (Earlier packets quoted 3244 B for this
function; the FDE range is 2868 B and that figure is corrected here.)

## Answer (pinned)

**Signature.** `Status Comparator::CreateFromString(const
ConfigOptions&, const std::string& value, const Comparator**
result)`. The 16-byte Status is returned by value (hidden sret
pointer in rdi; the epilogue returns that pointer in rax). The
enclosing signature is pinned by the census symbol of the call_once
lambda at 0x61c1210 (reconstructed in #5958), which names this
function with a `const Comparator**` third parameter. Status layout,
pinned by the Status ctor at 0x61cf670 (writes code to byte 0,
subcode to byte 1, severity to byte 2, zeroes retryable at byte 3,
data_loss at byte 4 and scope at byte 5, stores the state_
unique_ptr at +8) and confirmed by upstream status.h: code 0 is OK,
code 3 is kNotSupported, code 4 is kInvalidArgument; `Status::ok()`
is the single-byte test `cmpb $0x0, (%rsp+0x80)`.

**Call_once.** `std::call_once` with the registration lambda
0x61c1210 (LEA at 0x61c01fa, once-flag at 0x65088c0, `pthread_once`
PLT at 0x63f13d0, call at 0x61c020b). The lambda is
RegisterBuiltinComparators inlined (#5958). A non-zero pthread_once
return throws `std::system_error` (the 0x61c0c3a branch). The
registration runs exactly once per process.

**Parse.** `Customizable::GetOptionsMap` 0x609e510 (call at
0x61c02ea) with (sret at rsp+0x80, config_options, the current
*result as the "customizable", value, name at rsp+0xf0, opts_map at
rsp+0xb0). The name is an SSO std::string (buffer rsp+0x100); the
opts_map is an unordered_map at rsp+0xb0 (bucket count 1,
max_load_factor 1.0f). If the returned Status is not OK it is copied
to the sret slot and returned at once -- no dispatch happens.

**Name dispatch** (on the parsed id: size at rsp+0xf8, bytes at
rsp+0xf0):

1. **Bytewise, size 26** (0x61c0400): four overlapping 8-byte XORs
   against movabs immediates -- "leveldb." at +0, "Bytewise" at +8,
   "tewiseCo" at +10, "mparator" at +18. On a match it calls
   `rocksdb::BytewiseComparator()` 0x61be810 (call at 0x61c0451,
   #5950), stores the pointer into *result (0x61c0aa5), and returns
   the GetOptionsMap Status (OK).
2. **Reverse, size 33** (0x61c0315 / 0x61c0a64): "rocksdb." at +0,
   "ReverseB" at +8, "ytewiseC" at +16, "omparato" at +24, and a
   single byte 'r' (0x72) at +32 (cmpb at 0x61c0a89). On a match it
   calls `rocksdb::ReverseBytewiseComparator()` 0x61be8f0 (call at
   0x61c0a93, #5950) and returns the same way.
3. **U64Ts, otherwise** (0x61c0348): the cached
   `ComparatorWithU64TsImpl<BytewiseComparatorImpl>::kClassName()`
   string (guard 0x6508898, string 0x65088a0, #5852) is compared.
   Guard clear takes the cold path (0x61c068e, the same
   ostringstream build as #5958's block 3: insert the 26-char
   literal at 0x44e0fe, then ".u64ts" at 0x43c8ab, assign into the
   cached string, `__cxa_atexit`, `__cxa_guard_release`) and rejoins
   the warm path; guard set takes the warm path (`strlen` the
   cached c_str, compare with the id length). Equal lengths go to
   `memcmp` (0x61c057c); a zero-length id takes the factory directly
   (memcmp of length 0 is equal by definition). On a match it calls
   `rocksdb::BytewiseComparatorWithU64Ts()` 0x61be9d0 (call at
   0x61c0aa0, #5852) and returns the same way.

**Fall-through** (no builtin matched), from the U64Ts
length-mismatch (0x61c0383) or the memcmp failure (0x61c059f):

* **value empty** (value.size() == 0): `*result = nullptr` and
  return Status::OK() (0x61c0b00).
* **id empty but value non-empty**: build Status::NotSupported
  (code 3, subcode 0 -- the zeroed id length doubles as the
  subcode, severity 0) with msg "Cannot reset object " (the 20-byte
  literal at 0x433f9f, length 0x14) and msg2 = the id string with
  length 0, so the rendered message is exactly the 20-byte literal
  (Status ctor call at 0x61c03e9). Return it. (Correction: earlier
  packets called this error InvalidArgument; the binary's code 3
  plus upstream `Status::NotSupported("Cannot reset object ", id)`
  pin it as kNotSupported. kInvalidArgument is code 4.)
* **id non-empty: the registry path** (0x61c05af).
  `config_options.registry->NewStaticObject<const Comparator>`
  0x61bf530 (call at 0x61c05c3) with (sret at rsp+0xa0, the registry
  object -- `this`, the shared_ptr data pointer held at
  config_options+0x40 -- the parsed name string at rsp+0xf0 as the
  target, result). Inside NewStaticObject the target is passed to
  `ObjectRegistry::FindFactory<const Comparator>` 0x61bf030 (which
  returns the `std::function<const Comparator*(const std::string&,
  std::unique_ptr<const Comparator>*, std::string*)>` for that
  target) and the factory is invoked as `factory(target, guard,
  &errmsg)`; a set guard yields InvalidArgument (code 4, "Cannot
  make a static ... from a guarded one"), otherwise the created
  object is stored through result. The returned Status is moved
  into the rsp+0x80 accumulator (the old state_ buffer is freed):
  - if OK: `Customizable::ConfigureNewObject` 0x609e2d0 (call at
    0x61c0b48) with (sret at rsp+0xa0, config_options, *result,
    opts_map at rsp+0xb0); its Status is moved into rsp+0x80 and
    returned as-is (no swallow check here).
  - if not OK: read the byte at config_options+1 --
    `ignore_unsupported_options` (upstream default true); if that
    byte is non-zero AND the code is 3 (kNotSupported,
    `cmp $0x3,%al` at 0x61c0666), the error is replaced by
    Status::OK() (0x61c0c08: the sret Status is zeroed and the
    error state_ is freed); otherwise the error Status is returned
    unchanged. An InvalidArgument (code 4, e.g. the guarded-object
    failure inside NewStaticObject) is never swallowed.

**Epilogue** (0x61c0481, shared by every path): destroy the opts_map
(iterate its nodes, freeing the key/value strings and the nodes,
then memset the map header), destroy the name string, check the
stack canary, restore the callee-saved registers, and return the
sret pointer in rax. The landing pads at 0x61c0c54..0x61c0caf
(endbr64 + `mov %rax,%rbx` + jump back into the body) are the C++
exception cleanups for the locals.

**Caller.** Exactly one direct call: E8 at 0x607dfc0 inside
`std::_Function_handler<Status(const ConfigOptions&, const
std::string&, const std::string&, void*),
OptionTypeInfo::AsCustomRawPtr<const Comparator>(...)::{lambda}>::_M_invoke`
0x607df90..0x607e013 -- the options-system adapter for the
"comparator" option. It first handles the special case (option name
== "id", the two bytes 0x6469 at the name's data, AND the value
empty), writing nullptr into the target and Status::OK() into the
return slot itself without calling CreateFromString; otherwise it
forwards (sret, config_options, value, addr) to 0x61c0180. No tail
jumps, no LEA refs.

## Cases

2,400 deterministic cases (see cases.tsv, generated by
`tools/create_from_string115.py gen-cases`, replayed by
`tests/test_create_from_string115.py`):

* 600 dispatch: 150 bytewise, 100 reverse, 100 u64ts (warm + cold
  cache), 100 empty-value, 50 empty-id error, 50 registry hit, 25
  registry miss swallowed, 25 registry miss propagated.
* 600 names: 100 bytewise fragments, 100 reverse fragments, 100
  U64Ts cached-name compare, 100 length boundaries, 100 string-copy
  rules, 100 .rodata literals.
* 600 status: 150 layout, 150 error construction, 100 parse-error
  propagation, 100 swallow rule, 100 Status move.
* 600 once-registry: 150 call-once runs once, 100 pthread_once
  error, 150 NewStaticObject contract, 100 ConfigureNewObject
  contract, 100 caller "id" special case.

## What is checked

* Dispatch: the parsed id selects the factory by length + inline
  compare; the factory addresses and call sites match the binary
  (E8 rel32 targets verified); the empty value yields nullptr + OK;
  the empty id yields NotSupported (code 3) with the exact 20-byte
  message; unknown ids go through
  config_options.registry->NewStaticObject (FindFactory by the
  parsed name, factory invoked as factory(target, guard, &errmsg))
  + ConfigureNewObject.
* Names: the bytewise/reverse names are rebuilt from the movabs
  immediates at their binary sites (the bytewise second fragment
  overlaps the first's trailing "tewise"); the U64Ts name comes
  from the cached Name() (26-char literal at 0x44e0fe + ".u64ts"
  at 0x43c8ab); the .rodata literals and the error message bytes
  are checked against the binary.
* Status: the 16-byte layout (code @0, subcode @1, severity @2,
  retryable @3, data_loss @4, scope @5, state_ @8, a
  unique_ptr<const char[]>); the error Status (code 3
  kNotSupported, subcode 0, severity 0, "Cannot reset object "); a
  GetOptionsMap error returns as-is; the swallow needs
  ignore_unsupported_options (+1) set AND code 3 (`cmp $0x3` at
  0x61c0666); a guarded factory's InvalidArgument (code 4) is never
  swallowed; a Status move transfers the state_ and frees the old
  one.
* Once/registry: call_once runs the registration exactly once; a
  pthread_once failure throws SystemError; ConfigureNewObject runs
  only after a successful create and its Status is the result; the
  caller's "id" special case is handled without a call.

## Open unknowns

* GetOptionsMap (0x609e510, 2915 B), NewStaticObject (0x61bf530,
  2744 B), FindFactory (0x61bf030) and ConfigureNewObject
  (0x609e2d0, 274 B) are engine callees modeled only at contract
  level: their parse / lookup / configure internals are not
  reconstructed here. The exact unknown-id message text is
  produced inside NewObject and is not pinned by this packet.
* The libstdc++ once_flag / pthread_once error path is modeled as
  "non-zero return throws std::system_error"; which pthread_once
  failures are reachable in practice is not established.

## Upstream confirmation

RocksDB v8.1.1 (facebook/rocksdb tag, read from the GitHub raw
source), confirmed 2026-11-10. Two earlier-packet claims are
corrected here: `util/comparator.cc` is 383 lines total, so the
637-723 range quoted before does not exist there, and the "Cannot
reset object" error is `Status::NotSupported`, not InvalidArgument.

* `util/comparator.cc:339-382` -- `Comparator::CreateFromString`
  (`const ConfigOptions&`, `const std::string& value`, `const
  Comparator** result`): call_once 342-345, GetOptionsMap 348-349
  (`GetOptionsMap(config_options, *result, value, &id, &opt_map)`;
  on failure `return status`), the three name branches 353-359,
  empty value 360-363 (`*result = nullptr; return Status::OK()`),
  the error 364-365 (`Status::NotSupported("Cannot reset object ",
  id)`), the registry path 367-378
  (`config_options.registry->NewStaticObject(id, result)`; `if
  (config_options.ignore_unsupported_options &&
  status.IsNotSupported()) return Status::OK();`; else
  ConfigureNewObject with the const_cast comparator).
  `RegisterBuiltinComparators` is at 319-337 (three AddFactory
  calls, `return 3`).
* `include/rocksdb/comparator.h:61-63` -- the CreateFromString
  declaration (`const Comparator**`; no shared_ptr overload in
  v8.1.1).
* `include/rocksdb/convenience.h:32-106` -- ConfigOptions. The two
  slots this function reads are +1 `ignore_unsupported_options`
  (default true) and +64 `registry`
  (std::shared_ptr<ObjectRegistry>, 16 bytes). Full layout: +0
  `ignore_unknown_options`, +1 `ignore_unsupported_options`, +2
  `input_strings_escaped`, +3 `invoke_prepare_options`, +4
  `mutable_options_only`, +8 `delimiter` (";"), +40 `depth`, +44
  `sanity_level`, +48 `file_readahead_size`, +56 `env`, +64
  `registry`, sizeof 80. (The +0x40 slot is the registry
  shared_ptr, not a string or a string pointer as earlier packets
  guessed; the binary loads its data pointer as the `this` for
  NewStaticObject.)
* `include/rocksdb/utilities/object_registry.h:390-405` --
  NewStaticObject (template, 2 params: target, T**; via NewObject
  317-338, which invokes the factory as `factory(target, guard,
  &errmsg)`); `FactoryFunc<T> = std::function<T*(const
  std::string&, std::unique_ptr<T>*, std::string*)>`. A set guard
  yields InvalidArgument ("Cannot make a static ... from a guarded
  one").
* `include/rocksdb/customizable.h:183-186` and
  `options/customizable.cc:92-121` -- GetOptionsMap (empty value
  -> id "" and a cleared opts map; else delegate to
  Configurable::GetOptionsMap); ConfigureNewObject declared
  customizable.h:195-197, defined options/customizable.cc:122-124.
* `include/rocksdb/status.h:456-465` -- Status members
  (protected): code_, subcode_, sev_ (all `: unsigned char`),
  retryable_, data_loss_, scope_, state_
  (`std::unique_ptr<const char[]>`); 16 bytes in the default build
  (24 with ROCKSDB_ASSERT_STATUS_CHECKED).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool models the selection routine in Python; the
engine callees above are contract-level only. make verify/test/
catalogue-check in a tooled environment is still owed upstream.
