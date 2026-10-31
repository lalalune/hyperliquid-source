"""First-pass inventory of a stripped Rust x86-64 ELF.

Reports ELF basics, toolchain stamps (.comment), build id, DT_NEEDED,
function count from .eh_frame_hdr, symbol/debug presence, and crates
harvested from panic/source paths embedded in the binary.

usage: python3 -I inv.py BINARY OUT_JSON
"""
import collections
import json
import re
import struct
import sys

path, out_path = sys.argv[1], sys.argv[2]
data = open(path, "rb").read()
assert data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1, "expect ELF64 LE"

e_type, e_machine = struct.unpack_from("<HH", data, 0x10)
e_entry, = struct.unpack_from("<Q", data, 0x18)
shoff, = struct.unpack_from("<Q", data, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)

secs = []
for i in range(shnum):
    name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
        "<IIQQQQIIQQ", data, shoff + i * shentsize)
    secs.append(dict(name=name, type=typ, addr=addr, off=off, size=size, link=link))
stroff = secs[shstrndx]["off"]
strtab = data[stroff:stroff + secs[shstrndx]["size"]]
for s in secs:
    assert s["name"] < len(strtab), "section name offset outside .shstrtab"
    end = strtab.find(b"\0", s["name"])
    assert end >= 0, "unterminated section name"
    s["name"] = strtab[s["name"]:end].decode()
sec = {s["name"]: s for s in secs}


def blob(name):
    s = sec[name]
    return data[s["off"]:s["off"] + s["size"]]


report = collections.OrderedDict()
report["file_size"] = len(data)
report["elf_type"] = {2: "EXEC", 3: "DYN (PIE)"}.get(e_type, e_type)
report["machine"] = {0x3E: "x86-64", 0xB7: "aarch64"}.get(e_machine, e_machine)
report["entry"] = hex(e_entry)
report["sections"] = {s["name"]: s["size"] for s in secs if s["name"]}
report["has_symtab"] = ".symtab" in sec
report["debug_sections"] = sorted(n for n in sec if n.startswith((".debug", ".zdebug")))

if ".comment" in sec:
    report["comment"] = [c.decode() for c in blob(".comment").split(b"\0") if c]

if ".note.gnu.build-id" in sec:
    n = blob(".note.gnu.build-id")
    namesz, descsz, _ = struct.unpack_from("<III", n, 0)
    desc_off = 12 + ((namesz + 3) & ~3)
    report["build_id"] = n[desc_off:desc_off + descsz].hex()

if ".dynamic" in sec and ".dynstr" in sec:
    dyn, dstr = blob(".dynamic"), blob(".dynstr")
    needed = []
    for i in range(0, len(dyn), 16):
        tag, val = struct.unpack_from("<qQ", dyn, i)
        if tag == 1:
            needed.append(dstr[val:dstr.index(b"\0", val)].decode())
    report["needed"] = needed
    report["dynsym_count"] = sec[".dynsym"]["size"] // 24 if ".dynsym" in sec else 0

if ".eh_frame_hdr" in sec:
    h = blob(".eh_frame_hdr")
    version, ptr_enc, cnt_enc, tbl_enc = h[0], h[1], h[2], h[3]
    if cnt_enc == 0x03:  # DW_EH_PE_udata4
        report["fde_count_eh_frame_hdr"] = struct.unpack_from("<I", h, 8)[0]
    report["eh_frame_hdr_encodings"] = [hex(ptr_enc), hex(cnt_enc), hex(tbl_enc)]

stamps = re.findall(rb"([0-9a-f]{40})\|(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \+0000)\|uncommitted=(true|false)", data)
report["git_build_stamps"] = sorted({f"{a.decode()} {b.decode()} uncommitted={c.decode()}" for a, b, c in stamps})
report["rustc_commits"] = sorted({m.decode() for m in re.findall(rb"/rustc/([0-9a-f]{40})/", data)})

# First-party crates: <root>/<crate>/src/<file>.rs (not vendored/forked).
root_re = re.compile(rb"(/home/[\w.-]+/hl/code_\w+)/")
report["source_roots"] = sorted({m.decode() for m in root_re.findall(data)})
fp = collections.defaultdict(set)
for crate, f in re.findall(rb"(?:/home/[\w.-]+/hl/code_\w+/|(?<![\w/.-]))([a-z][a-z0-9_]*)/src/([\w/]+\.rs)", data):
    c = crate.decode()
    if c in ("z_vendor", "z_forks", "library", "src"):
        continue
    fp[c].add(f.decode())
vend = collections.defaultdict(set)
for name, ver in re.findall(rb"z_vendor/([A-Za-z0-9_][A-Za-z0-9_.-]*?)-(\d+\.\d+\.\d+(?:[-+][\w.]+)?)/", data):
    vend[name.decode()].add(ver.decode())
forks = collections.Counter(m.decode() for m in re.findall(rb"z_forks/([A-Za-z0-9_.-]+)/", data))
stddeps = collections.defaultdict(set)
for name, ver in re.findall(rb"/rust/deps/([A-Za-z0-9_][A-Za-z0-9_.-]*?)-(\d+\.\d+\.\d+(?:[-+][\w.]+)?)/", data):
    stddeps[name.decode()].add(ver.decode())
registry = collections.defaultdict(set)
for name, ver in re.findall(rb"\.cargo/registry/src/[^/]+/([A-Za-z0-9_][A-Za-z0-9_.-]*?)-(\d+\.\d+\.\d+(?:[-+][\w.]+)?)/", data):
    registry[name.decode()].add(ver.decode())

# Drop "crates" that are really vendored/forked crate subdirs seen via relative paths.
vendored_names = {n.replace("-", "_") for n in vend} | {n.replace("-", "_") for n in forks}
report["first_party_crates"] = {c: len(fs) for c, fs in sorted(fp.items()) if c not in vendored_names}
report["first_party_files"] = {c: sorted(fs) for c, fs in sorted(fp.items()) if c not in vendored_names}
report["vendored_crates"] = {n: sorted(v) for n, v in sorted(vend.items())}
report["forked_crates"] = dict(sorted(forks.items()))
report["std_deps"] = {n: sorted(v) for n, v in sorted(stddeps.items())}
report["registry_crates"] = {n: sorted(v) for n, v in sorted(registry.items())}

json.dump(report, open(out_path, "w"), indent=1)
summary = {k: v for k, v in report.items() if k not in ("sections", "first_party_files")}
summary["vendored_crates"] = f"{len(report['vendored_crates'])} crates"
print(json.dumps(summary, indent=1)[:6000])
