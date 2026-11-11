"""Tests for tools/register_encryption_builtins_115.py.

Exercises the RegisterEncryptionBuiltins behavior end-to-end:
library registration, the three factory entries in order, the
PatternEntry matcher (modes 2 and 3, empty-vector exact match),
creator dispatch (E0 / E_ / BlockCipher), the std::function
manager ops, and vector growth.  Run from the repository root:

    python3 tests/test_register_encryption_builtins_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from register_encryption_builtins_115 import (  # noqa: E402
    CREATORS, FACTORY_VTABLE_CIPHER, FACTORY_VTABLE_ENC, LIBRARY_COUNTS,
    LIBRARY_NAME, LIBRARY_TYPEINFO, LIBRARY_VERSION, LIBRARY_VTABLE,
    ROT13_OPTIONS, FactoryEntry, GrowableVector, ObjectRegistry,
    PatternEntry, ends_with, invoke_cipher, invoke_e0, invoke_e_,
    manager_op, register_encryption_builtins,
)

CHECKS = [0]


def check(cond, msg):
    CHECKS[0] += 1
    assert cond, msg


# --- registration ------------------------------------------------------

reg = register_encryption_builtins()
check(reg.registered, "registry marked registered")
check(len(reg.libraries) == 1, "one library registered")
lib = reg.libraries[0]
check(lib.name == LIBRARY_NAME, "library name is 'encryption'")
check(lib.version == LIBRARY_VERSION, "library version is 1.0")
check(lib.counts == LIBRARY_COUNTS, "library counts are 0x100000001")
check(lib.control_block_vtable == LIBRARY_VTABLE, "library cb vtable")
check(lib.typeinfo == LIBRARY_TYPEINFO, "library cb typeinfo")
check(sorted(reg.entries) == ["BlockCipher", "EncryptionProvider"],
      "exactly the two map keys")
check(len(reg.find_factory("EncryptionProvider")) == 2,
      "two entries under EncryptionProvider")
check(len(reg.find_factory("BlockCipher")) == 1,
      "one entry under BlockCipher")
check(reg.find_factory("NoSuch") == [], "absent key yields empty vector")
check(reg.mutex_locked is False, "mutex released after registration")

enc_entries = reg.find_factory("EncryptionProvider")
e_under, e_zero = enc_entries
check(e_under.creator == "E_", "first EncryptionProvider entry is E_")
check(e_zero.creator == "E0", "second EncryptionProvider entry is E0")
check(e_under.kind == "EncryptionProvider", "E_ kind")
check(e_zero.kind == "EncryptionProvider", "E0 kind")
check(e_under.vtable == FACTORY_VTABLE_ENC, "E_ factory vtable")
check(e_zero.vtable == FACTORY_VTABLE_ENC, "E0 factory vtable")
check(e_under.pattern_entry.pattern == "CTR", "E_ pattern is CTR")
check(e_zero.pattern_entry.pattern == "1://test", "E0 pattern")
check(e_under.pattern_entry.elements == [("://test", 2)],
      "E_ element is ('://test', mode 2)")
check(e_zero.pattern_entry.elements == [], "E0 has no elements")
check(e_under.pattern_entry.flag == 1, "E_ flag byte is 1")
check(e_zero.pattern_entry.flag == 1, "E0 flag byte is 1")

cipher_entry = reg.find_factory("BlockCipher")[0]
check(cipher_entry.creator == "Cipher", "BlockCipher entry creator")
check(cipher_entry.kind == "BlockCipher", "BlockCipher kind")
check(cipher_entry.vtable == FACTORY_VTABLE_CIPHER, "cipher factory vtable")
check(cipher_entry.pattern_entry.pattern == "ROT13", "cipher pattern")
check(cipher_entry.pattern_entry.elements == [(":", 3)],
      "cipher element is (':', mode 3)")
check(cipher_entry.pattern_entry.flag == 1, "cipher flag byte is 1")

# FactoryEntry layout: +0x10..+0x20 functor storage is 16 zero
# bytes, +0x20 manager, +0x28 invoker.
for entry, creator in ((e_under, "E_"), (e_zero, "E0"),
                       (cipher_entry, "Cipher")):
    check(entry.functor == bytes(16), f"{creator} functor storage is zeros")
    check(entry.manager == CREATORS[creator]["manager"],
          f"{creator} manager address")
    check(entry.invoker == CREATORS[creator]["invoke"],
          f"{creator} invoker address")

# Find-or-insert append semantics: registering a second entry
# under an existing name appends; a new name creates a vector.
reg2 = ObjectRegistry()
reg2.register_entry("EncryptionProvider",
                    FactoryEntry("EncryptionProvider",
                                 PatternEntry("CTR", [("://test", 2)]), "E_"))
check(len(reg2.find_factory("EncryptionProvider")) == 1,
      "first entry under a new name")
reg2.register_entry("EncryptionProvider",
                    FactoryEntry("EncryptionProvider",
                                 PatternEntry("1://test", []), "E0"))
check(len(reg2.find_factory("EncryptionProvider")) == 2,
      "second entry appends under the same name")
check(reg2.find_factory("EncryptionProvider")[0].creator == "E_",
      "append preserves order (E_ first)")
check(reg2.find_factory("EncryptionProvider")[1].creator == "E0",
      "append preserves order (E0 second)")

# --- PatternEntry matching ---------------------------------------------

# Entry 1: pattern CTR, element ('://test', mode 2).  Matches the
# exact pattern (equal lengths, flag set) and CTR://test (element
# at pos, tail reaches the end).
p1 = e_under.pattern_entry
for q in ("CTR", "CTR://test"):
    check(p1.matches(q), f"entry 1 matches {q!r}")
for q in ("CT", "CTRX", "CTR:", "CTR://tes", "CTR://testx",
          "CTR://test/extra", "ctr", "CTR//test", "xCTR://test"):
    check(not p1.matches(q), f"entry 1 rejects {q!r}")

# Entry 2: pattern 1://test, no elements -> exact match only, and
# the flag is NOT consulted on this path.
p2 = e_zero.pattern_entry
check(p2.matches("1://test"), "entry 2 matches its exact pattern")
for q in ("1://tes", "1://testx", "1://test ", "0://test", ""):
    check(not p2.matches(q), f"entry 2 rejects {q!r}")
p2_noflag = PatternEntry("1://test", [], flag=0)
check(p2_noflag.matches("1://test"),
      "empty-vector exact match ignores the flag byte")

# Entry 3: pattern ROT13, element (':', mode 3).  Matches the exact
# pattern, and ROT13:<digits> (element at pos, mode-3 tail needs
# digits after an optional '-').
p3 = cipher_entry.pattern_entry
for q in ("ROT13", "ROT13:42", "ROT13:0", "ROT13:-7", "ROT13:123456"):
    check(p3.matches(q), f"entry 3 matches {q!r}")
for q in ("ROT", "ROT13x", "ROT13:", "ROT13:abc", "ROT13:4a",
          "ROT13::42", "ROT13:42x", "ROT1", "rot13:42"):
    check(not p3.matches(q), f"entry 3 rejects {q!r}")

# Mode-4 tail (dotted digits) through the shared matcher, as
# pinned by PR #3983: a mode-4 element accepts one '.' in the tail.
p4 = PatternEntry("X", [(":", 4)])
check(p4.matches("X:1.2"), "mode 4 accepts one dot in the tail")
check(not p4.matches("X:1.2.3"), "mode 4 rejects two dots in the tail")
check(not p4.matches("X:."), "mode 4 needs at least one digit")

# Mode 0/1 elements may occur anywhere later (find from pos+1);
# the mode stored in element i governs element i+1, so a second
# element is needed to exercise it.
p01 = PatternEntry("A", [("b", 0), ("c", 2)])
check(p01.matches("Abxc"), "mode 0 finds the next element later")
check(not p01.matches("Abc"),
      "mode 0 needs a gap (find starts at pos+1)")
p1m = PatternEntry("A", [("b", 1), ("c", 2)])
check(p1m.matches("Abxc"), "mode 1 finds the next element later")

# Mode 3 element gap must be all digits (after an optional '-'),
# and the mode-3 tail needs a digit remainder after the last element.
p3g = PatternEntry("A", [(":", 3), ("B", 3)])
check(p3g.matches("A:123B4"), "mode 3 gap digits then element then digits")
check(not p3g.matches("A:123B"),
      "mode 3 tail needs a digit remainder")
check(not p3g.matches("A:xB4"), "mode 3 gap rejects non-digits")

# --- creator dispatch ----------------------------------------------------

# E_ (0x5ff6d60): EndsWith(name, "://test") decides the branch.
r = invoke_e_("CTR://test", reg)
check(r["provider"] == "CTREncryptionProvider", "E_ builds CTR provider")
check(r["resolved_rot13_options"] is True,
      "E_ resolves ROT13 options on the ://test suffix")
check(r["options_name"] == ROT13_OPTIONS, "E_ options name")
r = invoke_e_("CTR", reg)
check(r["resolved_rot13_options"] is False,
      "E_ fallback path without the ://test suffix")
check("options_name" not in r, "E_ fallback has no options name")
r = invoke_e_("x://test", reg)
check(r["resolved_rot13_options"] is True, "E_ suffix check is EndsWith")

# E0 (0x5ff6a00): builds the CTR provider from a BlockCipher
# looked up in the registry, registers options.
r = invoke_e0("ROT13:42", reg)
check(r["provider"] == "CTREncryptionProvider", "E0 builds CTR provider")
check(r["options_registered"] is True, "E0 registers options")
check(r["cipher"] is not None and r["cipher"]["cipher"] == "ROT13BlockCipher",
      "E0 resolves the ROT13 cipher through the registry")
r = invoke_e0("CTR://test", reg)
check(r["provider"] == "CTREncryptionProvider",
      "E0 still builds the provider when no cipher matches")
check(r["cipher"] is None, "E0 cipher is None when nothing matches")

# BlockCipher E_ (0x5ff7120): finds ':' and builds the ROT13 cipher.
r = invoke_cipher("ROT13:42")
check(r["cipher"] == "ROT13BlockCipher", "cipher creator builds ROT13")
check(r["options_name"] == ROT13_OPTIONS, "cipher options name")
check(r["colon_pos"] == 5, "cipher colon position")
try:
    invoke_cipher("ROT13")
    check(False, "cipher creator must throw without ':'")
except ValueError as exc:
    check("substr" in str(exc), "cipher creator raises out_of_range")

# EndsWith helper.
check(ends_with("a://test", "://test"), "ends_with true")
check(not ends_with("a://tes", "://test"), "ends_with false")
check(ends_with("", ""), "ends_with empty")

# --- manager ops ---------------------------------------------------------

for creator, info in CREATORS.items():
    check(manager_op(info["manager"], 0) == info["typeinfo"],
          f"{creator} manager op 0 returns the typeinfo")
    check(manager_op(info["manager"], 1) == "clone",
          f"{creator} manager op 1 clones")
    check(manager_op(info["manager"], 2) is False,
          f"{creator} manager op 2 is a no-op")
    check(manager_op(info["manager"], 3) is False,
          f"{creator} manager op 3 is a no-op")
try:
    manager_op(CREATORS["E_"]["manager"], 9)
    check(False, "manager must reject an unknown op")
except ValueError:
    check(True, "manager rejects an unknown op")

# --- vector growth ---------------------------------------------------------

vec = GrowableVector()
check(vec.capacity == 0, "vector starts with capacity 0")
expected_caps = [1, 2, 4, 4, 8, 8, 8, 8]
for i, cap in enumerate(expected_caps):
    vec.append(i)
    check(vec.capacity == cap, f"capacity after {i + 1} appends is {cap}")
    check(list(vec) == list(range(i + 1)), "elements preserved across growth")
check(len(vec) == 8, "vector length after 8 appends")

# The libraries vector grows the same way when many libraries land.
reg3 = ObjectRegistry()
for i in range(5):
    reg3.register_library(f"lib{i}")
check(len(reg3.libraries) == 5, "five libraries registered")
check(reg3.libraries.capacity == 8, "libraries vector doubled to 8")
check([lib.name for lib in reg3.libraries] ==
      [f"lib{i}" for i in range(5)], "library order preserved")

# --- end-to-end create() ---------------------------------------------------

check(reg.create("EncryptionProvider", "CTR")["provider"] ==
      "CTREncryptionProvider", "create CTR via E_")
check(reg.create("EncryptionProvider", "CTR://test")
      ["resolved_rot13_options"] is True,
      "create CTR://test resolves ROT13 options")
check(reg.create("EncryptionProvider", "1://test")["provider"] ==
      "CTREncryptionProvider", "create 1://test via E0")
check(reg.create("BlockCipher", "ROT13:42")["cipher"] ==
      "ROT13BlockCipher", "create ROT13:42 via the cipher entry")
check(reg.create("EncryptionProvider", "nope") is None,
      "create returns None when nothing matches")
try:
    reg.create("BlockCipher", "ROT13")
    check(False, "create ROT13 exact must throw (no colon to parse)")
except ValueError:
    check(True, "create ROT13 exact throws out_of_range")
check(reg.create("NoSuch", "CTR") is None, "create on an absent name")

print(f"{CHECKS[0]} checks passed")
