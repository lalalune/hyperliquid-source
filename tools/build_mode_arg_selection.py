#!/usr/bin/env python3
"""Pin how the build_mode.rs LazyLock initializer picks its value (node 115).

PR #2999 pinned the base crate's `std::sync::LazyLock` cell at
`0x64f01c0`: its initializer is `0x1568de0`, and the cached 24-byte
value is a `String`. The H11 packet (branch `h11/lazylock-consumers`)
pinned the value's source file (`base/src/build_mode.rs`, panic
Locations 28:13 and 30:26) and showed every consumer of the accessor
`0x1560a40` discards the returned pair. Both packets left open what
the initializer actually computes: which process argument it picks,
in which order, and what string comes out.

This tool re-derives, from the materialised artifact alone:

- the body pins (FDE extent + SHA-256) of the initializer, the
  lowercase transform, the accessor (consistency with PR #2999 /
  H11), the argument-iterator constructor and `next`, the UTF-8
  validator `next` calls, the packed-format `format`/`write` pair,
  the `memrchr` used on the extracted component, the `/cham/`
  contains-verify helper, the two `Display` shims the initializer's
  format call passes, and the two neighbouring bodies that use the
  candidate literals (`debug` / `release` / `run-client`);
- the GOT slot targets through `.rela.dyn`;
- the byte pins at every decisive instruction of the initializer's
  argument loop (default accumulator, iterator calls, the `--`
  prefix dispatch, the three `/cham/` search entries by argument
  length, the packed-format call, the ends-with assertion, the
  component extraction, the `memrchr` truncation, the final store);
- the decoded literals: the assertion message, the candidate block,
  the packed format strings (`"{} {}"` for the initializer's merge,
  `"{}/{}"` and `"{}/aws_build/{}"` for the neighbouring body), the
  `std::env::args` unwrap message and its `library/std/src/env.rs`
  Location;
- the two `panic::Location` records inside the initializer
  (`base/src/build_mode.rs:28:13` / `30:26`), re-derived for
  consistency with the earlier packets;
- a whole-`.text` census of RIP-relative references to the packed
  literal block (each candidate literal is loaded by exactly one
  `lea`, in the neighbouring bodies -- never by the initializer);
- a simulation of the derived selection semantics over synthetic
  argument vectors, including the assertion-panic vectors.

Derived semantics (what the records below state, in prose):

The initializer runs `std::env::args()`: the constructor behind
slot `0x64e1290` collects the C `argv` (cells `0x6500000` /
`0x6500008`) into a vector of byte strings starting at index 0, and
the `next` behind slot `0x64e1298` converts each element with the
UTF-8 validator behind slot `0x64dfca8`, unwrapping the result
(its panic Location is `library/std/src/env.rs:864:51`). Arguments
are therefore visited in argv order, argv[0] included, with no
early exit. For each argument the initializer keeps an initially
empty accumulator `String`:

- an argument of length >= 2 starting with `--` is skipped
  entirely (compare at `0x1568f40`);
- an argument containing the substring `/cham/` (scalar search for
  lengths 7..20, a full-string compare for length 6, the verified
  contains machinery for longer arguments) is replaced by a
  derived piece: the assertion at `build_mode.rs:28:13` fires if
  the argument ends with `/`; otherwise the piece is the
  component after the argument's last `/` (the slice at line 30
  is char-boundary checked), truncated at its last `-` (the
  `memrchr` behind slot `0x64e12a0`: if a `-` is found, the piece
  is the prefix before the last `-`, empty when the `-` leads);
- any other argument is the piece itself.

Each piece is lowercased by the transform `0x150caf0` and merged
with the packed-format call behind slot `0x64df6e8`, whose format
string at `0x444a44` decodes to `"{} {}"`: the new accumulator is
`format!("{} {}", accumulator, piece)`. After the last argument
the accumulator is lowercased once more by the same transform and
stored as the cached `String` (length, pointer, length).

Consequences the simulation pins down: the stored value carries a
leading space whenever at least one argument contributed, and it
accumulates *every* non-flag argument, so it is never exactly
`debug`, `release` or `run-client`; through the `/cham/` path
`run-client` contributes only `run`, because the component is cut
at its last `-`. Of the three candidate literals packed beside the
assertion, only `debug` and `release` can appear as a whole piece,
and none can be the whole stored value. No source name for the
static or its getter occurs in the artifact: the only naming
evidence is the module path `base/src/build_mode.rs` and the
assertion's local name `arg`.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = (ROOT / 'research/work-items/'
          'RE-005-node115-build-mode-arg-selection')
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278' \
      'fa39f249e98c3867b5301'
SIZE = 105896032
BASE_COMMIT = '05bc2de303c05525b71e7e257426e741bc66a390'

CELL = 0x64f01c0
ACCESSOR = (0x1560a40, 0x1560aab)
INIT_FN = (0x1568de0, 0x156971c)
TRANSFORM_FN = (0x150caf0, 0x150cd87)
CTOR_FN = 0x5c9a530
NEXT_FN = 0x5caa830
UTF8_FN = 0x16815e0
MEMRCHR_FN = 0x1681990
FMT_FORMAT_FN = 0x141e3a0
FMT_WRITE_FN = 0x1680500
VERIFY_FN = 0x156b230
SHIM_STRING = 0x155c6e0
SHIM_STR = 0x15ebba0
ENUM_BODY = 0x1564870
KEY_BODY = 0x155f8d0

SLOTS = {
    'args_ctor': 0x64e1290,
    'args_next': 0x64e1298,
    'utf8_validate': 0x64dfca8,
    'memrchr': 0x64e12a0,
    'fmt_format': 0x64df6e8,
    'fmt_write': 0x64df6f0,
    'panic_assert': 0x64df730,
    'panic_bounds': 0x64df670,
    'accessor': 0x64e0b20,
}

BYTE_PINS = {
    # initializer: empty-String accumulator (0, 1, 0) at rsp+0
    0x1568df6: '48c7042400000000',
    0x1568dfe: '48c744240801000000',
    0x1568e07: '48c744241000000000',
    # argument-iterator construction / step (adjacent slots)
    0x1568e18: 'ff157284f704',
    0x1568e6b: 'ff152784f704',
    # iterator None tag: word0 == INT_MIN overflows neg -> exit path
    0x1568e79: '48f7d8',
    0x1568e7c: '0f80b7060000',
    # length < 2 arguments bypass the prefix/search dispatch
    0x1568e8c: '4983fd02',
    # per-piece lowercase transform call
    0x1568e9c: 'e84f3cfaff',
    # format arguments: (accumulator, String Display shim),
    # (piece, str Display shim)
    0x1568eb9: '488d052038ffff',
    0x1568ed2: '488d05c72c0800',
    # packed-format merge call through slot 0x64df6e8
    0x1568ef2: 'ff15f067f704',
    # "--" prefix dispatch on the first two bytes
    0x1568f40: '6641813c242d2d',
    # length == 6 / length > 20 (0x14) search entries
    0x1568f49: '4983fd06',
    0x1568f4f: '4983fd14',
    # "/cham/" scalar compares (0x1568f62 / 0x1568f6d)
    0x1568f62: 'be2f636861',
    0x1568f6d: '81f66d2f0000',
    # length == 6: whole-argument compare against "/cham/"
    0x1568f92: '418b0424',
    # contains setup: needle "cham/" at 0x4676f3, length 5
    0x1568fc5: '488d0527e7effe',
    # extraction: last byte must not be '/'
    0x15692ca: '43807c2cff2f',
    # extraction: char-boundary check on the component's first byte
    0x15693f0: '41803c1cc0',
    # memrchr('-') through slot 0x64e12a0; (found == 1) test
    0x15694a5: 'bf2d000000',
    0x15694ad: 'ff15ed7df704',
    0x15694b3: '4883f801',
    # whole accumulator lowercased once more at the end
    0x15695bb: 'e83035faff',
    # sret store of the built String: (len, ptr, len)
    0x1569609: '488b442478',
    0x156960e: '488918',
    0x1569611: '4c897008',
    0x1569615: '48895810',
    # ends_with assertion: message lea + length 0x25 = 37
    0x1569663: '488d3d8ee0effe',
    0x1569671: 'be25000000',
    # assertion panic call through slot 0x64df730
    0x1569676: 'ff15b460f704',
    # bounds-checked slice: line-30 Location record in r8
    0x1569688: '4c8d05014de904',
    # bounds panic call through slot 0x64df670
    0x156969b: 'ff15cf5ff704',
    # iterator constructor reads the argv pointer cell 0x6500008
    # and the argc cell 0x6500000
    0x5c9a541: '488b05c05a8600',
    0x5c9a55b: '4c8b259e5a8600',
    # collection loop index starts at 0 (argv[0] included)
    0x5c9a607: '31db',
    0x5c9a636: '4c8b3cd8',
    # next(): None is the INT_MIN word written over the result
    0x5caa83f: '48b80000000000000080',
    # next(): per-element UTF-8 validation call (slot 0x64dfca8)
    0x5caa87d: 'ff1525548300',
    # next(): unwrap panic message lea (0x949294)
    0x5caa8b6: '488d3dd7e9c9fa',
    # memrchr: backward byte scan, (found = 1) exit
    0x16819dc: '42387c16ff',
    0x1681a63: 'b801000000',
    # packed-format format(): (len << 1) | 1 single-string fast path
    0x141e3b8: '41f6c601',
    0x141e456: '49d1ec',
    # packed-format write(): same fast path, 0xc0 placeholder tag
    0x168051a: 'f6c301',
    0x1680594: '4181ffc0000000',
    0x168068b: '48d1eb',
    # contains-verify helper: short-circuits when the flag is set
    0x156b230: '85c9',
    # transform: Unicode-table lookup byte (PR #2999 / H11 pin)
    0x150cb13: '470fb60c08',
    # neighbouring enum body loads "release" / "debug"
    0x15648d0: '488d054b2ef0fe',
    0x15648f2: '488d05242ef0fe',
}

LITERALS = [
    (0x4676f2, 6, '/cham/'),
    (0x4676f8, 37, "assertion failed: !arg.ends_with('/')"),
    (0x46771d, 5, 'debug'),
    (0x467722, 7, 'release'),
    (0x467729, 10, 'run-client'),
]

LOC_BUILD_MODE_28 = 0x63fe3a8
LOC_BUILD_MODE_30 = 0x63fe390
LOC_ENV_UNWRAP = 0x64c3240
UNWRAP_MSG = (0x949294, 43,
              'called `Result::unwrap()` on an `Err` value')
FMT_PANIC_MSG = (0x456d84, 86,
                 'a formatting trait implementation returned an '
                 'error when the underlying stream did not')

PACKED_FORMATS = {
    'init_merge': (0x444a44, '{0} {1}'),
    'enum_join': (0x43aa84, '{0}/{1}'),
    'enum_aws_build': (0x449a91, '{0}/aws_build/{1}'),
}

CENSUS_TARGETS = [0x4676f2, 0x4676f3, 0x4676f8,
                  0x46771d, 0x467722, 0x467729]

# Simulation of the derived semantics. Arguments are `str` (the
# args() conversion has already succeeded); lowercasing is exact
# for the ASCII vectors used here. A vector whose extraction hits
# the ends_with assertion yields the panic marker instead.
PANIC_28 = 'panic:assertion@build_mode.rs:28:13'

VECTORS = [
    (['/opt/hl/cham/release'], ' release'),
    (['/opt/hl/cham/debug'], ' debug'),
    (['/opt/hl/cham/run-client'], ' run'),
    (['/opt/hl/cham/run-client', '--chain', 'Mainnet'],
     ' run mainnet'),
    (['--chain', 'Mainnet'], ' mainnet'),
    (['--version'], ''),
    ([], ''),
    (['/srv/cham/release/bin/hl-node'], ' hl'),
    (['rel-ease'], ' rel-ease'),
    (['/a/cham/x-y-z'], ' x-y'),
    (['/a/cham/-x'], ' '),
    (['/a/cham/RELEASE'], ' release'),
    (['/a/cham/release', '/b/cham/debug'], ' release debug'),
    (['/a/cham/run_client'], ' run_client'),
    (['single'], ' single'),
    (['-'], ' -'),
    (['--', 'x'], ' x'),
    (['/a/b/cham/'], PANIC_28),
    (['/cham/'], PANIC_28),
]


def va_bytes(data, secs, va, size):
    for s in secs:
        if (s['type'] != 8 and s['address'] <= va
                < s['address'] + s['size']):
            off = s['offset'] + (va - s['address'])
            return data[off:off + size]
    raise ValueError(f'va {va:#x} not in a file-backed section')


def relocation_addends(data, secs):
    """Map r_offset -> (type, addend) for .rela.dyn entries."""
    out = {}
    for s in secs:
        if s.get('name') == '.rela.dyn':
            blob = data[s['offset']:s['offset'] + s['size']]
            for i in range(0, len(blob) - 23, 24):
                off, info, add = struct.unpack_from('<QQq', blob, i)
                out[off] = (info & 0xffffffff, add)
            return out
    raise ValueError('no .rela.dyn section')


def fde_extents(data):
    """(start, end) pairs from .eh_frame FDE headers."""
    out = subprocess.run(['objdump', '--dwarf=frames', str(TARGET)],
                         capture_output=True, text=True).stdout
    extents = []
    import re
    for m in re.finditer(r'pc=0*([0-9a-f]+)\.\.0*([0-9a-f]+)', out):
        extents.append((int(m.group(1), 16), int(m.group(2), 16)))
    return sorted(set(extents))


def extent_of(extents, va):
    import bisect
    starts = [e[0] for e in extents]
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and extents[i][0] <= va < extents[i][1]:
        return extents[i]
    raise ValueError(f'no FDE extent contains {va:#x}')


def body_record(data, secs, extent):
    lo, hi = extent
    b = va_bytes(data, secs, lo, hi - lo)
    return {'start': hex(lo), 'end': hex(hi), 'size': hi - lo,
            'sha256': hashlib.sha256(b).hexdigest()}


def decode_location(data, secs, relocs, record):
    """panic::Location: (file ptr via relocation, file len, line, col)."""
    typ, add = relocs[record]
    if typ != 8:
        raise ValueError(f'location file ptr not RELATIVE at {record:#x}')
    ln = struct.unpack('<Q', va_bytes(data, secs, record + 8, 8))[0]
    line, col = struct.unpack(
        '<II', va_bytes(data, secs, record + 16, 8))
    text = va_bytes(data, secs, add, ln).decode('utf-8')
    return {'record': hex(record), 'file': text, 'file_va': hex(add),
            'line': line, 'column': col}


def decode_packed_format(data, secs, va):
    """Decode this toolchain's packed format-string form.

    Tag bytes: 0x00 ends the string; 0x01..0x7f introduce a literal
    chunk of that many bytes; 0x80 introduces a literal chunk whose
    length is the following u16; 0xc0 is a bare placeholder taking
    the next argument in sequence. Other tags (placeholders with
    inline specs, longer length forms) do not occur in the pinned
    strings and are refused rather than guessed.
    """
    raw = va_bytes(data, secs, va, 512)
    out = []
    argn = 0
    i = 0
    while True:
        b = raw[i]
        if b == 0:
            return ''.join(out)
        if b == 0xc0:
            out.append('{%d}' % argn)
            argn += 1
            i += 1  # decoded placeholders are numbered in order
        elif 1 <= b < 0x80:
            out.append(raw[i + 1:i + 1 + b].decode('utf-8'))
            i += 1 + b
        elif b == 0x80:
            ln = raw[i + 1] | (raw[i + 2] << 8)
            out.append(raw[i + 3:i + 3 + ln].decode('utf-8'))
            i += 3 + ln
        else:
            raise ValueError(
                f'unsupported packed-format tag {b:#x} at {va:#x}+{i}')


def build_mode_value(argv):
    """The derived initializer semantics over one argv (see docstring)."""
    acc = ''
    for arg in argv:
        if len(arg) >= 2 and arg.startswith('--'):
            continue
        piece = arg
        if '/cham/' in arg:
            if arg.endswith('/'):
                return PANIC_28
            piece = arg[arg.rfind('/') + 1:]
            idx = piece.rfind('-')
            if idx >= 0:
                piece = piece[:idx]
        acc = '{} {}'.format(acc, piece.lower())
    return acc.lower()


def rip_ref_census(data, secs):
    """Whole-.text census of RIP-relative references.

    For every 4-byte window in .text, the value is tested as the
    disp32 of an instruction ending at that window: target =
    window_va + 4 + disp32. Matches are candidate references; the
    retained sites are then byte-verified by the pin set / README.
    """
    import numpy as np
    text = next(s for s in secs if s.get('name') == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    base_va = text['address']
    hits = {t: [] for t in CENSUS_TARGETS}
    chunk = 1 << 22
    arr = np.frombuffer(blob, dtype=np.uint8)
    for start in range(0, len(blob) - 3, chunk):
        seg = arr[start:start + chunk + 3].astype(np.int64)
        if len(seg) < 4:
            break
        w = (seg[:-3] + (seg[1:-2] << 8) + (seg[2:-1] << 16)
             + (seg[3:] << 24))
        w = np.where(w >= 2 ** 31, w - 2 ** 32, w)
        js = np.arange(start, start + len(w), dtype=np.int64)
        for t in CENSUS_TARGETS:
            m = np.nonzero(w + js + base_va + 4 == t)[0]
            hits[t] += [hex(base_va + start + int(x)) for x in m]
    return {hex(t): {'count': len(v), 'disp_field_vas': v}
            for t, v in hits.items()}


def analyze(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('artifact digest mismatch')
    if len(data) != SIZE:
        raise ValueError('artifact size mismatch')
    secs = sections(data)
    relocs = relocation_addends(data, secs)
    extents = fde_extents(data)

    bodies = {}
    for name, probe in [('initializer', INIT_FN[0]),
                        ('transform', TRANSFORM_FN[0]),
                        ('accessor', ACCESSOR[0]),
                        ('args_ctor', CTOR_FN),
                        ('args_next', NEXT_FN),
                        ('utf8_validate', UTF8_FN),
                        ('memrchr', MEMRCHR_FN),
                        ('fmt_format', FMT_FORMAT_FN),
                        ('fmt_write', FMT_WRITE_FN),
                        ('contains_verify', VERIFY_FN),
                        ('display_shim_string', SHIM_STRING),
                        ('display_shim_str', SHIM_STR),
                        ('enum_body', ENUM_BODY),
                        ('run_client_key_body', KEY_BODY)]:
        bodies[name] = body_record(data, secs, extent_of(extents, probe))
    if bodies['initializer']['end'] != hex(INIT_FN[1]):
        raise ValueError('initializer extent drift')
    if bodies['transform']['end'] != hex(TRANSFORM_FN[1]):
        raise ValueError('transform extent drift')
    if bodies['accessor']['end'] != hex(ACCESSOR[1]):
        raise ValueError('accessor extent drift')

    slots = {}
    for name, slot in SLOTS.items():
        typ, add = relocs[slot]
        if typ != 8:
            raise ValueError(f'slot {name} not RELATIVE')
        slots[name] = {'slot': hex(slot), 'target': hex(add),
                       'relocation': 'R_X86_64_RELATIVE'}

    pins = {}
    for va, want in BYTE_PINS.items():
        got = va_bytes(data, secs, va, len(bytes.fromhex(want))).hex()
        if got != want:
            raise ValueError(
                f'byte pin drift at {va:#x}: {got} != {want}')
        pins[hex(va)] = want

    literals = []
    for va, ln, text in LITERALS:
        got = va_bytes(data, secs, va, ln).decode('utf-8')
        if got != text:
            raise ValueError(f'literal drift at {va:#x}')
        literals.append({'va': hex(va), 'len': ln, 'text': text})

    for va, ln, text in [UNWRAP_MSG, FMT_PANIC_MSG]:
        got = va_bytes(data, secs, va, ln).decode('utf-8')
        if got != text:
            raise ValueError(f'message drift at {va:#x}')

    packed = {}
    for name, (va, want) in PACKED_FORMATS.items():
        got = decode_packed_format(data, secs, va)
        if got != want:
            raise ValueError(
                f'packed format drift at {va:#x}: {got!r} != {want!r}')
        packed[name] = {'va': hex(va), 'decoded': got}

    vectors = []
    for argv, want in VECTORS:
        got = build_mode_value(list(argv))
        if got != want:
            raise ValueError(
                f'simulation drift for {argv!r}: {got!r} != {want!r}')
        vectors.append({'argv': list(argv), 'value': want})

    payload = {
        'question': (
            'Which process argument does the base/src/build_mode.rs '
            'LazyLock initializer (0x1568de0, cell 0x64f01c0) pick to '
            'build the cached build-mode string -- the iteration '
            'order, the identity of the argument the "/cham/" search '
            'hits, the exact candidate set left after the lowercase '
            'transform (which of debug / release / run-client are '
            'reachable), and the source names of the static and '
            'its getter if the artifact carries them?'),
        'artifact': 'artifacts/node/115/hl-node',
        'artifact_sha256': SHA,
        'base_commit': BASE_COMMIT,
        'bodies': bodies,
        'slots': slots,
        'byte_pins': pins,
        'literals': literals,
        'locations': {
            'build_mode_line28': decode_location(
                data, secs, relocs, LOC_BUILD_MODE_28),
            'build_mode_line30': decode_location(
                data, secs, relocs, LOC_BUILD_MODE_30),
            'env_args_unwrap': decode_location(
                data, secs, relocs, LOC_ENV_UNWRAP),
        },
        'messages': {
            'args_unwrap': {'va': hex(UNWRAP_MSG[0]),
                            'len': UNWRAP_MSG[1],
                            'text': UNWRAP_MSG[2]},
            'fmt_panic': {'va': hex(FMT_PANIC_MSG[0]),
                          'len': FMT_PANIC_MSG[1],
                          'text': FMT_PANIC_MSG[2]},
        },
        'packed_formats': packed,
        'literal_ref_census': rip_ref_census(data, secs),
        'simulation_vectors': vectors,
        'reading': (
            'The initializer runs std::env::args() over the whole '
            'argv in order, argv[0] included, with no early exit: '
            'the constructor collects the C argv cells into a '
            'vector from index 0, and next() converts each element '
            'through the UTF-8 validator, unwrapping at '
            'library/std/src/env.rs:864:51. Each argument of length '
            '>= 2 starting with "--" is skipped. Every other '
            'argument contributes one lowercased piece to an '
            'accumulator via format!("{} {}", acc, piece): the '
            'piece is the argument itself, except that an argument '
            'containing "/cham/" contributes its last path '
            'component truncated at its last "-"; such an argument '
            'ending in "/" fires the build_mode.rs:28:13 assertion '
            'instead. After the last argument the accumulator is '
            'lowercased again and stored. The stored value '
            'therefore starts with a space whenever anything '
            'contributed and is never exactly "debug", "release" '
            'or "run-client"; "run-client" contributes only "run" '
            'through the /cham/ path. The static and getter carry '
            'no source name in the artifact (no BUILD_MODE / '
            'BuildMode / build-mode string exists); the naming '
            'evidence is the module path base/src/build_mode.rs '
            'and the assertion local name "arg".'),
    }
    return payload


def objdump_body(lo, hi):
    out = subprocess.run(
        ['objdump', '-d', '--start-address', hex(lo),
         '--stop-address', hex(hi), str(TARGET)],
        capture_output=True, text=True).stdout
    return out


def frames(payload):
    out = subprocess.run(['objdump', '--dwarf=frames', str(TARGET)],
                         capture_output=True, text=True).stdout
    wanted = set()
    for rec in payload['bodies'].values():
        wanted.add((rec['start'], rec['end']))
    lines = []
    import re
    for line in out.splitlines():
        m = re.search(r'pc=0*([0-9a-f]+)\.\.0*([0-9a-f]+)', line)
        if m and (hex(int(m.group(1), 16)),
                  hex(int(m.group(2), 16))) in wanted:
            lines.append(line)
    return '\n'.join(lines) + '\n'


def generate(binary, outdir):
    data = Path(binary).read_bytes()
    payload = analyze(data)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    files = {
        'records.json': json.dumps(payload, indent=1) + '\n',
        'init_fn.objdump.txt': objdump_body(*INIT_FN),
        'args_ctor.objdump.txt': objdump_body(
            CTOR_FN, CTOR_FN + payload['bodies']['args_ctor']['size']),
        'args_next.objdump.txt': objdump_body(
            NEXT_FN, NEXT_FN + payload['bodies']['args_next']['size']),
        'memrchr.objdump.txt': objdump_body(
            MEMRCHR_FN,
            MEMRCHR_FN + payload['bodies']['memrchr']['size']),
        'fmt_bodies.objdump.txt': objdump_body(
            FMT_FORMAT_FN,
            FMT_FORMAT_FN + payload['bodies']['fmt_format']['size'])
        + objdump_body(
            FMT_WRITE_FN,
            FMT_WRITE_FN + payload['bodies']['fmt_write']['size']),
        'enum_body.objdump.txt': objdump_body(
            ENUM_BODY,
            ENUM_BODY + payload['bodies']['enum_body']['size']),
        'frames.txt': frames(payload),
    }
    for name, text in files.items():
        (outdir / name).write_text(text)
    manifest = []
    for name in sorted(files):
        digest = hashlib.sha256(
            (outdir / name).read_bytes()).hexdigest()
        manifest.append(f'{digest}  {name}')
    (outdir / 'MANIFEST.sha256').write_text(
        '\n'.join(manifest) + '\n')
    return payload


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'generate':
        generate(TARGET, PACKET)
        print(f'packet written to {PACKET}')
        return 0
    payload = analyze(TARGET.read_bytes())
    retained = json.loads((PACKET / 'records.json').read_text())
    if payload != retained:
        print('records drift', file=sys.stderr)
        return 1
    print('check OK: build_mode argument selection re-derived')
    return 0


if __name__ == '__main__':
    sys.exit(main())
