import contextlib
import hashlib
import importlib.util
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from collections import namedtuple
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/subaccount_create.py"
spec = importlib.util.spec_from_file_location("subaccount_create", TOOL)
sac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sac)
sr = sac.sr
BIN = ROOT / "artifacts/node/94/hl-node"
PACKET = ROOT / "research/work-items/vaults-subaccount-create-94"
OUTPUT_SHA256 = "f0b9e4b9addad4fafaa93e82c5f126b73d81a1b02ad3b4b5d31d70df869d8fe6"
DATA = BIN.read_bytes() if BIN.exists() else None
OBJDUMP_LINE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*(?:\t(.*))?$")

# Published Keccak-f[1600] round constants and rotation offsets (FIPS 202), as an
# independent check of the tool's generators.
PUBLISHED_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008)
PUBLISHED_RHO = (0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
                 18, 2, 61, 56, 14)
# 52 distinct message lengths for the sponge vs hashlib.sha3_256 cross-check (273 is in the
# step-7 range, so the extra list uses 408 = 3 * 136 instead).
SHA3_TEST_LENGTHS = list(range(0, 300, 7)) + [135, 136, 137, 160, 271, 272, 408, 1000, 4096]


def _gnu(tool):
    """True when ``tool`` on PATH is GNU binutils (the excerpts and these parsers assume it)."""
    if not shutil.which(tool):
        return False
    p = subprocess.run([tool, "--version"], capture_output=True, text=True)
    return p.returncode == 0 and p.stdout.startswith(f"GNU {tool}")


GNU_OBJDUMP = _gnu("objdump")
GNU_READELF = _gnu("readelf")


def objdump(lo, hi, keep_symbols=False):
    """{va: (bytes, text)} for objdump's decoding of [lo, hi)."""
    out = subprocess.run(["objdump", "-d", "-M", "intel", f"--start-address={lo:#x}",
                          f"--stop-address={hi:#x}", str(BIN)], capture_output=True, text=True,
                         check=True).stdout
    insns, last = {}, None
    for line in out.splitlines():
        m = OBJDUMP_LINE.match(line)
        if not m:
            continue
        va, bs, txt = int(m.group(1), 16), bytes.fromhex(m.group(2).replace(" ", "")), m.group(3)
        if txt is None:
            if last is not None:
                insns[last] = (insns[last][0] + bs, insns[last][1])
            continue
        if not keep_symbols:
            txt = re.sub(r"\s+<[^>]*>", "", txt)
        insns[va] = (bs, re.sub(r"\s+", " ", txt).strip())
        last = va
    return insns


def load_tool(source):
    """Execute a (mutated) copy of the tool source as a fresh module (same ROOT, same state_roots)."""
    mod = types.ModuleType("subaccount_create_mutant")
    mod.__file__ = str(TOOL)
    exec(compile(source, str(TOOL), "exec"), mod.__dict__)
    return mod


# One control: byte patches of the target (the digest is re-pinned unless keep_sha), optionally
# applied to the pinned SHAPES bytes too (repin), optional module overrides (a function of the
# module under test), or a direct call instead of build(); regex is the expected EvidenceError.
Control = namedtuple("Control", "label patches repin overrides call regex keep_sha",
                     defaults=((), False, None, None, None, False))

# ---- Guard inventory: every `raise EvidenceError(` line and every `link(` call of the tool. ----
# GUARDS maps a unique substring of that line to the control that must fail once the guard is
# removed (the raise becomes a no-op call, or the link is skipped). DEFENSIVE lists the guards
# with no control, with the reason. ITEM_MUTANTS remove one item of a guarded loop or one clause.
GUARDS = {
    '{name}: {va:#x} is not an FDE start': "slot target not an FDE start",
    '{section} {r_off:#x}: symbol name offset out of range': "GLOB_DAT symbol name offset",
    'shape {name}: instruction {v:#x} pinned twice': "instruction pinned twice",
    'shapes {n0} and {n1} overlap': "overlapping shapes",
    'no rip-relative ModRM before the disp32': "rip-relative operand without ModRM 00/101",
    'Location slot {slot:#x} has no RELATIVE relocation': "Location without a relocation",
    'Location slot {slot:#x}: bad length {ln}': "Location length 0",
    'binary sha256 {sha} != {expected_sha256}': "wrong binary",
    'function {name}: FDE window {s:#x}..{e:#x} != pinned': "handler FDE length",
    'shape {name} at {va:#x}: {got_b.hex()} != {want.hex()}': "volume threshold imm32",
    'shape {name} at {va:#x} is outside its owner {owner}': "shape outside its owner",
    'call target {tgt:#x} is not an FDE start': "call target not an FDE start",
    '{mn} target {tgt:#x} leaves {owner}': "jump leaves its function",
    '{what}: {va:#x} is not a decoded branch in a pinned window': "decision is not a branch",
    'immediate {name}: {va:#x} is not a pinned instruction start': "immediate not at an instruction start",
    'immediate {name}: offset outside the instruction at {va:#x}': "immediate outside its instruction",
    'cap clamp compare and move disagree': "cap clamp move",
    'name range lea and cmp disagree': "name lea vs cmp",
    '{k} is not 0x186': "0x186 compare after the deriver call",
    'rip-relative {label}: {va:#x} is not a pinned instruction start': "rip-relative site not pinned",
    'rip-relative {label} at {va:#x}: {t:#x} != {want:#x}': "rip-relative literal reference",
    'dispatch: lea bias and cmp bias disagree': "dispatch lea bias",
    'dispatch: table indices reaching arm 0x2759d2a': "dispatch table entry 6",
    'dispatch: table indices reaching arm 0x27592bd': "dispatch table entry 1",
    'dispatch: index-6 arm does not call the handler': "index-6 arm retargeted",
    'dispatch: index-1 arm does not call other_entry': "index-1 arm retargeted",
    'status-store enumeration differs': "injected status store",
    '16-bit store {va:#x} is not a pinned instruction': "16-bit store not pinned",
    'register source {sva:#x} is not pinned': "register source not pinned",
    'status load {lva:#x} is not a pinned movzx': "status load is not a movzx",
    "check {spec['seq']}: {key} {v:#x} outside {spec['owner']}": "check store outside its owner",
    "check {spec['seq']}: call {spec['call']:#x} is not pinned": "check call not pinned",
    "is neither direct nor a slot": "check call neither direct nor a slot",
    "check {spec['seq']}: decision {e['va']:#x} is {e['mnemonic']}, ": "cap jae -> jb",
    "check {spec['seq']}: failure edge goes to": "failure edge target",
    "check {spec['seq']}: pass edge {pva:#x} is {pe['mnemonic']}, not {pmn}": "pass edge mnemonic",
    "check {spec['seq']}: pass edge {pva:#x} goes to": "pass edge target",
    "is not an enumerated status store": "check store not a status store",
    "check {spec['seq']}: store writes": "check status value",
    "check {spec['seq']}: no register source loads": "check register source value",
    "the propagated status is not the callee's u16 loaded at": "status load displacement",
    'slot references differ': "injected slot reference",
    'is not in .got/.data.rel.ro': "slot outside .got",
    'RELATIVE -> {shown} != {want:#x}': "deriver slot addend",
    'GLOB_DAT symbol {sym!r} != {want!r}': "bcmp GLOB_DAT name",
    'carries both GLOB_DAT and RELATIVE': "GLOB_DAT slot also RELATIVE",
    'a used slot has no resolution entry': "used slot without resolution",
    'slot {slot:#x}: no call [rip] to it at {va:#x}': "keccak-f slot use",
    'not an E8 rel32 call inside the window': "direct call site not E8",
    'is not the .plt stub of {want}': "PLT call retargeted",
    'direct call {va:#x}: target {t:#x} != {want:#x}': "direct call retargeted",
    'register call {va:#x} in {w}: bytes differ': "register call changed",
    'callers of {name}:': "extra E8 caller of the producer",
    'RELATIVE references to {name}:': "extra RELATIVE ref to creator",
    'Location {label} at {slot:#x}: {s!r}:{gl}:{gc}': "Location line",
    'Location {label}: not referenced by a lea': "ethabi Location lea",
    'literal createSubAccount at': "createSubAccount literal",
    'literal div_100 at': "f64 100.0",
    'literal insert_assert_string at': "assert string",
    'keccak round constants at 0x7d04c8 differ': "RC table entry 5",
    'keccak_f loop bound is not 24 qwords': "keccak-f round bound",
    'serde literal at {va:#x} differs': "serde literal",
    'user_lookup special key at {va:#x} differs': "user_lookup special key",
    'is outside the table': "formatter table ends early",
    '-> arm {arm:#x}, not {shape_va[sname]:#x}': "formatter entry 0xd6",
    'arm is not lea rsi ; mov edx': "message arm without lea rsi",
    'message {text!r} != {want!r}': "0xd6 message byte",
    'template arm has no single lea rdx': "template arm without lea rdx",
    'template {raw!r} != {want!r}': "0xdd template byte",
    'template marker {raw[i]:#x}': "template marker byte",
    'arm {arm:#x} outside the Debug impl': "Token Debug arm outside",
    'arm prefix {b[:4].hex()}': "Token Debug arm prefix",
    'token_debug: tag {tag} arm body differs': "Token Debug arm body",
    'jump target lacks mov edx': "Token Debug jump target",
    'token_debug: tag {tag} has no length': "Token Debug length",
    'decodes to {name!r} != {want!r}': "Token Debug name",
    'builder tokens are not String, Address, Uint': "token 0 tag",
    'builder payload offsets disagree with the Debug impl': "Address payload offset",
    'builder token stride / count mismatch': "token count",
    'word writer: tag {tag} arm {arm:#x} outside the function': "word writer arm outside",
    'the bswap arm is not reached by exactly tags 3 and 4': "word writer Bool -> bswap arm",
    'the Int/Uint arm does not store limbs 3..0': "word writer bswap register",
    'byte scan: {pname} in {window} at': "threshold injected in sibling",
    'byte scan: {pname} in .text': "threshold pattern injected in .text padding",
    'digest copy layout differs': "finalize digest length",
    'stack offset {stack_off:#x} not a digest copy': "kept xmm source outside the copy",
    'kept digest bytes are not one 20-byte slice': "kept dword source",
    "the 0xdd message's Required constant is not": "0xdd Required constant",
    'record layout differs': "record layout",
    'reciprocal certificate failed': "reciprocal magic - 1",
    'Keccak model failed its known-answer': "Keccak model delimiter",
    'model: the Uint word differs from the word writer': "model Uint word layout",
    # link checks (the first words of each link's description)
    'link("producer result:': "producer slot vs r8 load",
    'link("creator compares r8': "cap operand register r9",
    'link("other_volume_user applies': "other_volume_user threshold",
    'link("name length:': "helper length register r13",
    'link(what, a0 == FUNCS': "prologue: creator compare not first",
    'link("both names pass through slot 0x576e050': "lowercase slot retargeted",
    'link("tracker base:': "tracker field vs producer",
    'link("user table:': "user table field of the later call",
    'link("sub_account_to_master:': "insert map field",
    'link("producer state at rsp+0x20': "producer back iterator",
    'link("alloc_fail:': "alloc_fail window truncated",
    'link("the Vec fold reads the 20-byte address': "Vec fold address displacement",
    'link("deriver count =': "deriver count displacement",
    'link("deriver passes the count': "builder count field",
    'link("the count is Uint limb 0': "encoder words call retargeted",
    'link("vec_entry returns': "vec_entry occupied return",
    'link("the fold hands the exchange': "Vec fold context displacement",
    'link("the step and the Vec fold walk': "step map displacement",
}
DEFENSIVE = {
    'dispatch: table does not terminate': "needs more than 512 consecutive in-function table entries",
    'status_formatter: table does not terminate': "needs more than 4096 consecutive in-function table entries",
}
ITEM_MUTANTS = [  # (label, old, new, control)
    ("0x186 loop without the handler-derive compare", 'for k in ("ok_status_handler_derive", ',
     'for k in (', "0x186 compare after the deriver call"),
    ("0x186 loop without the handler-creator compare", '"ok_status_handler_creator", "ok_status_creator_rederive",',
     '"ok_status_creator_rederive",', "0x186 compare after the creator call"),
    ("0x186 loop without the re-derive compare", '"ok_status_creator_rederive",\n',
     '\n', "0x186 compare after the re-derive"),
    ("0x186 loop without the helper compare", '"ok_status_creator_helper", "status_186_helper_a",',
     '"status_186_helper_a",', "0x186 compare after the helper call"),
    ("0x186 loop without the first helper Ok value", '"status_186_helper_a", "status_186_helper_b"):',
     '"status_186_helper_b"):', "helper Ok value (first)"),
    ("0x186 loop without the second helper Ok value", '"status_186_helper_a", "status_186_helper_b"):',
     '"status_186_helper_a",):', "helper Ok value (second)"),
    ("prologue loop without the creator", '[("c_args", "c_volume_gate", ', '[(', "prologue: creator compare not first"),
    ("prologue loop without the name helper",
     '("n_out", "n_len", "name_helper: the r8 length test is the first instruction after the prologue"),', '',
     "prologue: helper test not first"),
    ("prologue loop without the handler",
     '("h_args", "h_tracker", "handler: prologue, argument moves, then the tracker lea"),', '',
     "prologue: handler lea not first"),
    ("prologue loop without the deriver",
     '("d_args0", "d_guard", "deriver: prologue, argument moves, then the map guard")]:', ']:',
     "prologue: deriver guard not first"),
    ("reciprocal certificate without the error bound", ' and err * M64 < (1 << shift)', '',
     "reciprocal error bound"),
    ("alloc_fail link without the no-ret clause", 'all(table[v][0] not in (b"\\xc3", b"\\xc2")', 'all(True',
     "alloc_fail ret injected"),
]


@unittest.skipIf(DATA is None, "pinned binary not present")
class SubAccountCreateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = sac.build(DATA)
        cls.text = sac.render(cls.r)
        cls.j = json.loads(cls.text)
        cls.elf = sr.Elf(DATA)

    # ---- helpers ----
    def mutated(self, patches):
        b = bytearray(DATA)
        for va, new in patches:
            o = self.elf.off(va)
            b[o:o + len(new)] = new
        return bytes(b)

    def rebuild(self, patches):
        b = self.mutated(patches)
        return sac.build(b, expected_sha256=hashlib.sha256(b).hexdigest())

    def rela_entry_va(self, r_offset):
        sec_va, sec_off, sec_size = self.elf.sections[".rela.dyn"]
        for o in range(sec_off, sec_off + sec_size, 24):
            if struct.unpack_from("<Q", DATA, o)[0] == r_offset:
                return sec_va + (o - sec_off)
        raise AssertionError(f"no .rela.dyn entry for {r_offset:#x}")

    def dynsym_entry_va(self, slot):
        _sv, soff, _ = self.elf.sections[".dynsym"]
        sva = self.elf.sections[".dynsym"][0]
        info = struct.unpack_from("<Q", DATA, self.elf.off(self.rela_entry_va(slot)) + 8)[0]
        return sva + 24 * (info >> 32)

    def dynstr_va(self, slot):
        tva = self.elf.sections[".dynstr"][0]
        return tva + struct.unpack_from("<I", DATA, self.elf.off(self.dynsym_entry_va(slot)))[0]

    def fde_range_va(self, start):
        addr, off, size = self.elf.sections[".eh_frame_hdr"]
        count = struct.unpack_from("<I", DATA, off + 8)[0]
        for i in range(count):
            pos = off + 12 + 8 * i
            if addr + struct.unpack_from("<i", DATA, pos)[0] == start:
                return addr + struct.unpack_from("<i", DATA, pos + 4)[0] + 12
        raise AssertionError(f"no FDE for {start:#x}")

    def word(self, va, n=4):
        return DATA[self.elf.off(va):self.elf.off(va) + n]

    @staticmethod
    def repin_shapes(shapes, patches):
        out = []
        for name, owner, va, hexes, meaning in shapes:
            new_hexes, v = [], va
            for h in hexes:
                b = bytearray(bytes.fromhex(h))
                for pva, nb in patches:
                    for k, byte in enumerate(nb):
                        if v <= pva + k < v + len(b):
                            b[pva + k - v] = byte
                new_hexes.append(b.hex())
                v += len(b)
            out.append((name, owner, va, new_hexes, meaning))
        return out

    def run_control(self, mod, c):
        """Run one control against ``mod``: ('evidence', message), ('other', repr) or (None, None)."""
        data = self.mutated(c.patches) if c.patches else DATA
        sha = sr.EXPECTED_SHA256 if c.keep_sha else hashlib.sha256(data).hexdigest()
        over = dict(c.overrides(mod)) if c.overrides else {}
        if c.repin:
            over["SHAPES"] = self.repin_shapes(over.get("SHAPES", mod.SHAPES), c.patches)
        ctx = mock.patch.multiple(mod, **over) if over else contextlib.nullcontext()
        try:
            with ctx:
                if c.call:
                    c.call(mod)
                else:
                    mod.build(data, expected_sha256=sha)
        except mod.EvidenceError as e:
            return "evidence", str(e)
        except Exception as e:  # a mutant may fail differently; that also kills it
            return "other", repr(e)
        return None, None

    def controls(self):
        """Every fail-closed control of the tool (byte mutations, re-pinned cases, unit controls)."""
        dsp, ftab, ttab, wtab = 0x3EDE28, 0x59A8D0, 0x25FA64, 0x25FBA4
        e = self.word
        rel = lambda site, tgt, n: struct.pack("<i", tgt - (site + n))
        producer_call = b"\xe8" + struct.pack("<i", 0x275FEE0 - (0x3723000 + 5))
        slot_ref = b"\xff\x15" + struct.pack("<i", 0x576E050 - (0x36F3BF6 + 6))
        arms = {v["tag"]: int(v["arm"], 16) for v in self.j["token_debug"]["variants"]}
        k9 = arms[9] + 4 + 16 + 7  # tag 9 (Tuple) reaches its length through a jmp at this VA
        C = Control
        sh = lambda regex: regex + r" at 0x[0-9a-f]+: [0-9a-f]+ != [0-9a-f]+$"  # the byte-mismatch message only

        def rows(i, **kw):
            def f(mod):
                r = [dict(x) for x in mod.CHECK_ORDER]
                r[i] = dict(r[i], **kw)
                return {"CHECK_ORDER": r}
            return f

        def drop_last(shape):
            return lambda mod: {"SHAPES": [(n, o, va, h[:-1] if n == shape else h, m) for n, o, va, h, m in mod.SHAPES]}

        def without_shape(shape):
            return lambda mod: {"SHAPES": [s for s in mod.SHAPES if s[0] != shape]}

        def plus(attr, extra):
            return lambda mod: {attr: getattr(mod, attr) + extra}

        def recip(magic, shift, divisor):
            return lambda mod: mod._reciprocal_proof(magic, shift, divisor, 10_000_000)

        c0 = self.r["constants"]
        words = {0x0: 0x20, 0x8: 0x18, 0x10: 0x10, 0x18: 0x8}
        return [
            # -- byte mutations of the target (digest re-pinned): the first check on the path fails --
            C("volume threshold imm32", [(0x36F362A, b"\x81")], regex=sh(r"shape c_volume_gate")),
            C("volume jae -> jb", [(0x36F362E, b"\x72")], regex=sh(r"shape c_volume_gate")),
            C("cap magic", [(0x36F3736, b"\xbe")], regex=sh(r"shape c_cap_formula")),
            C("cap clamp", [(0x36F374B, b"\x29")], regex=sh(r"shape c_cap_formula")),
            C("cap addend", [(0x36F3758, b"\x0b")], regex=sh(r"shape c_cap_formula")),
            C("cap jae (bytes)", [(0x36F375F, b"\x82")], regex=sh(r"shape c_cap_formula")),
            C("cap operand register (bytes)", [(0x36F36C2, b"\xe1")], regex=sh(r"shape c_cap_operand")),
            C("name bound 100", [(0x36F390F, b"\x65")], regex=sh(r"shape c_name_len")),
            C("name jbe -> ja", [(0x36F3911, b"\x87")], regex=sh(r"shape c_name_len")),
            C("name range lea (bytes)", [(0x36F43D4, b"\xee")], regex=sh(r"shape n_len")),
            C("name range cmp", [(0x36F43D8, b"\xee")], regex=sh(r"shape n_len")),
            C("0x143 store register", [(0x36F39C6, b"\x03")], regex=sh(r"shape c_store_bp")),
            C("handler duplicate branch", [(0x27E3285, b"\x85")], regex=sh(r"shape h_user_match")),
            C("creator duplicate branch", [(0x36F386F, b"\x85")], regex=sh(r"shape c_map2_match")),
            C("helper duplicate branch", [(0x36F4538, b"\x85")], regex=sh(r"shape n_dup_test")),
            C("user table items offset", [(0x27E31D5, b"\x50")], regex=sh(r"shape h_user_guard")),
            C("tracker offset", [(0x27E3160, b"\xe8")], regex=sh(r"shape h_tracker")),
            C("re-derive 0x186 compare (bytes)", [(0x36F378D, b"\x87")], regex=sh(r"shape c_rederive_status")),
            C("creator 0x186 compare (bytes)", [(0x27E33DB, b"\x87")], regex=sh(r"shape h_creator_status")),
            C("deriver count displacement (bytes)", [(0x36F3D12, b"\xf0")], regex=sh(r"shape d_count")),
            C("count argument store", [(0x36F3D68, b"\x90")], regex=sh(r"shape d_args")),
            C("keccak delimiter", [(0x36F3E04, b"\x06")], regex=sh(r"shape d_keccak_init")),
            C("keccak rate", [(0x36F3DF8, b"\x89")], regex=sh(r"shape d_keccak_init")),
            C("finalize length (bytes)", [(0x36F3E45, b"\x14")], regex=sh(r"shape d_keccak_final")),
            C("digest copy source", [(0x36F3E56, b"\x30")], regex=sh(r"shape d_hash_copy")),
            C("kept dword source (bytes)", [(0x36F3E7E, b"\x5c")], regex=sh(r"shape d_hash_keep")),
            C("token String tag", [(0x3C97942, b"\x07")], regex=sh(r"shape b_count")),
            C("token Uint tag", [(0x3C97974, b"\x05")], regex=sh(r"shape b_tok2")),
            C("producer front iterator", [(0x276001C, b"\x01")], regex=sh(r"shape p_iter_call")),
            C("0xdd Required constant (bytes)", [(0x3800E38, b"\x41")], regex=sh(r"shape fmt_dd")),
            C("dispatch tag bias (bytes)", [(0x275929F, b"\x8d")], regex=sh(r"shape disp_bias")),
            C("deriver status load (bytes)", [(0x27E3187, b"\x7c")], regex=sh(r"shape h_derive_load")),
            C("re-derive failure path", [(0x36F38A3, b"\xa8")], regex=sh(r"shape c_rederive_fail")),
            C("vec_entry Vec ptr init", [(0x3596742, b"\x10")], regex=sh(r"shape e_vacant")),
            C("step record stride", [(0x2773BFF, b"\xf8")], regex=sh(r"shape s_loop")),
            C("Vec fold bucket stride", [(0x26B22CF, b"\x70")], regex=sh(r"shape v_bucket")),
            C("word writer limb load", [(0x1591D27, b"\x10")], regex=sh(r"shape ww_int")),
            C("volume_report ret", [(0x358DD54, b"\xcc")], regex=sh(r"shape r_ret_a")),
            C("0x57 store", [(0x342236C, b"\x58")], regex=sh(r"shape oc_57")),
            C("dispatch table entry 6", [(dsp + 24, e(dsp + 4))], regex=r"dispatch: table indices reaching arm 0x2759d2a"),
            C("dispatch table entry 1", [(dsp + 4, e(dsp + 8))], regex=r"dispatch: table indices reaching arm 0x27592bd"),
            C("formatter entry 0xd6", [(ftab + 4 * 0xD6, e(ftab + 4 * 0xD7))], regex=r"status_formatter: status 0xd6 -> arm"),
            C("formatter table ends early", [(ftab + 4 * 0x40, struct.pack("<i", 0))],
              regex=r"status_formatter: status 0x57 is outside the table"),
            C("0xd6 message byte", [(0x59D8D6, b"t")], regex=r"status_formatter: status 0xd6 message"),
            C("0xdd template byte", [(0x1E2B81 + 50, b"X")], regex=r"status_formatter: status 0xdd template"),
            C("0x57 template byte", [(0x1FA4F2 + 10, b"X")], regex=r"status_formatter: status 0x57 template"),
            C("Token Debug entry 6", [(ttab + 24, e(ttab + 28))], regex=r"token_debug: tag 6 decodes to 'FixedArray'"),
            C("Token Debug arm outside", [(ttab, struct.pack("<i", 0))], regex=r"token_debug: tag 0 arm 0x25fa64 outside"),
            C("Token Debug name", [(0x25FAE5 + 5, b"h")], regex=r"token_debug: tag 6 decodes to 'Strinh'"),
            C("Token Debug arm prefix", [(arms[1], b"\x90")], regex=r"token_debug: tag 1 arm prefix"),
            C("Token Debug arm body", [(arms[1] + 4, b"\x49")], regex=r"token_debug: tag 1 arm body differs"),
            C("Token Debug length", [(arms[1] + 4 + 16 + 7, b"\xb9")], regex=r"token_debug: tag 1 has no length"),
            C("Token Debug jump target", [(k9 + 1, rel(k9, arms[9], 5))],
              regex=r"token_debug: tag 9 jump target lacks mov edx"),
            C("word writer arm outside", [(wtab, struct.pack("<i", 0))], regex=r"word writer: tag 0 arm 0x25fba4 outside"),
            C("word writer Bool -> bswap arm", [(wtab + 20, e(wtab + 16))],
              regex=r"word writer: the bswap arm is not reached by exactly tags 3 and 4"),
            C("createSubAccount literal", [(0x2035A0, b"b")], regex=r"literal createSubAccount"),
            C("f64 100.0", [(0x20A966, b"\x5a")], regex=r"literal div_100"),
            C("assert string", [(0x598EAD, b"B")], regex=r"literal insert_assert_string"),
            C("RC table entry 5", [(0x7D04C8 + 40, b"\x02")], regex=r"keccak round constants"),
            C("serde literal", [(0x3AFECA, b"S")], regex=r"serde literal at 0x3afeca differs"),
            C("user_lookup special key", [(0x59C0E4 + 3, b"\x00")], regex=r"user_lookup special key at 0x59c0e4 differs"),
            C("Location line", [(0x56F1C38 + 0x10, struct.pack("<I", 70))], regex=r"Location insert_assert at 0x56f1c38: "),
            C("Location column", [(0x56F1C38 + 0x14, struct.pack("<I", 14))], regex=r"Location insert_assert at 0x56f1c38: "),
            C("Location path", [(0x1E67E5 + len(sac.FIRST_PARTY), b"L")], regex=r"Location insert_assert at 0x56f1c38: "),
            C("Location length 0", [(0x56F1C38 + 8, struct.pack("<Q", 0))], regex=r"Location slot 0x56f1c38: bad length 0"),
            C("Location without a relocation", [(self.rela_entry_va(0x56F1C38), struct.pack("<Q", 0x56F1C38 + 0x100000))],
              regex=r"Location slot 0x56f1c38 has no RELATIVE relocation"),
            C("ethabi Location lea", [(0x15921A3, struct.pack("<i", struct.unpack("<i", e(0x15921A3))[0] + 8))],
              regex=r"Location ethabi_113_65: not referenced"),
            C("deriver slot addend", [(self.rela_entry_va(0x5774F40) + 16, struct.pack("<Q", 0x36F3C21))],
              regex=r"slot 0x5774f40 \(deriver\) RELATIVE -> 0x36f3c21 != 0x36f3c20"),
            C("bcmp GLOB_DAT name", [(self.dynstr_va(0x576E378) + 3, b"q")], regex=r"slot 0x576e378 \(bcmp\) GLOB_DAT"),
            C("GLOB_DAT symbol name offset", [(self.dynsym_entry_va(0x576E378), struct.pack("<I", 0xFFFFFFF0))],
              regex=r"\.rela\.dyn 0x[0-9a-f]+: symbol name offset out of range"),
            C("GLOB_DAT slot also RELATIVE", [(self.rela_entry_va(0x5773D20), struct.pack("<Q", 0x576E378))],
              regex=r"slot 0x576e378 carries both GLOB_DAT and RELATIVE"),
            C("extra RELATIVE ref to creator", [(self.rela_entry_va(0x5773D20) + 16, struct.pack("<Q", 0x36F3610))],
              regex=r"RELATIVE references to creator"),
            C("extra E8 caller of the producer", [(0x3723000, producer_call)], regex=r"callers of volume_producer"),
            C("injected status store", [(0x36F3BF6, b"\x66\xc7\x03\xd6\x00")], regex=r"status-store enumeration differs"),
            C("injected slot reference", [(0x36F3BF6, slot_ref)], regex=r"slot references differ"),
            C("PLT call retargeted", [(0x36F3C11, rel(0x36F3C10, 0x5660120, 5))],
              regex=r"direct call 0x36f3c10: target 0x5660120 is not the \.plt stub of _Unwind_Resume"),
            C("direct call retargeted", [(0x27E31F0, rel(0x27E31EF, 0x399C7A0, 5))],
              regex=r"direct call 0x27e31ef: target 0x399c7a0 != 0x2840fb0"),
            C("threshold injected in sibling", [(0x36F43A6, sac.IMM_989680)], regex=r"byte scan: imm32_0x989680 in name_sibling"),
            C("magic injected in sibling", [(0x36F43A6, sac.MAGIC_BYTES)], regex=r"byte scan: imm64_magic in name_sibling"),
            C("threshold pattern injected in .text padding", [(0x3723008, sac.IMM_989680)],
              regex=r"byte scan: imm32_0x989680 in \.text \(49, "),
            C("handler FDE length", [(self.fde_range_va(0x27E3140), struct.pack("<I", 0x605))], regex=r"function handler"),
            C("wrong binary", [(0x36F362A, b"\x81")], keep_sha=True, regex=r"binary sha256"),
            # -- re-pinned: binary and pinned bytes change together, so the semantic check fires on its own --
            C("call target not an FDE start", [(0x36F3A2D, rel(0x36F3A2C, 0x36F43C1, 5))], True,
              regex=r"edge 0x36f3a2c \(c_call_helper\): call target 0x36f43c1 is not an FDE start"),
            C("jump leaves its function", [(0x36F43E3, rel(0x36F43E2, 0x36F4700, 5))], True,
              regex=r"edge 0x36f43e2 \(n_len\): jmp target 0x36f4700 leaves name_helper"),
            C("rip-relative literal reference", [(0x36F3D2F, rel(0x36F3D2C, 0x2035A1, 7))], True,
              regex=r"rip-relative createSubAccount literal at 0x36f3d2c: 0x2035a1 != 0x2035a0"),
            C("cap jae -> jb", [(0x36F375F, b"\x82")], True, regex=r"check 5: decision 0x36f375e is jb, not jae"),
            C("volume gate jae -> jb", [(0x36F362E, b"\x72")], True, regex=r"check 4: decision 0x36f362e is jb, not jae"),
            C("pass edge mnemonic", [(0x36F3664, b"\x85")], True, regex=r"check 5: pass edge 0x36f3663 is jne, not je"),
            C("producer slot vs r8 load", [(0x27E33B6, b"\x18")], True, regex=r"link failed: producer result"),
            C("cap operand register r9", [(0x36F3669, bytes.fromhex("4d89cd"))], True,
              regex=r"link failed: creator compares r8"),
            C("helper length register r13", [(0x36F3A29, bytes.fromhex("4d89e8"))], True,
              regex=r"link failed: name length"),
            C("cap clamp move", [(0x36F374D, b"\x29")], True, regex=r"cap clamp compare and move disagree"),
            C("name lea vs cmp", [(0x36F43D4, b"\xee")], True, regex=r"name range lea and cmp disagree"),
            C("0x186 compare after the deriver call", [(0x27E319E, b"\x87")], True,
              regex=r"ok_status_handler_derive is not 0x186"),
            C("0x186 compare after the creator call", [(0x27E33DB, b"\x87")], True,
              regex=r"ok_status_handler_creator is not 0x186"),
            C("0x186 compare after the re-derive", [(0x36F378D, b"\x87")], True,
              regex=r"ok_status_creator_rederive is not 0x186"),
            C("0x186 compare after the helper call", [(0x36F3A38, b"\x87")], True,
              regex=r"ok_status_creator_helper is not 0x186"),
            C("helper Ok value (first)", [(0x36F4400, b"\x87")], True, regex=r"status_186_helper_a is not 0x186"),
            C("helper Ok value (second)", [(0x36F45BF, b"\x87")], True, regex=r"status_186_helper_b is not 0x186"),
            C("kept dword source", [(0x36F3E7E, b"\x5c")], True, regex=r"kept digest bytes are not one 20-byte slice"),
            C("kept xmm source outside the copy", [(0x36F3E86, b"\x60")], True,
              regex=r"kept digest bytes: stack offset 0x60 not a digest copy"),
            C("finalize digest length", [(0x36F3E45, b"\x40")], True, regex=r"digest copy layout differs"),
            C("token 0 tag", [(0x3C97942, b"\x07")], True, regex=r"builder tokens are not String, Address, Uint"),
            C("Address payload offset", [(0x3C97969, b"\x2a")], True, regex=r"builder payload offsets disagree"),
            C("Uint limb-0 offset", [(0x3C97978, b"\x60")], True, regex=r"builder payload offsets disagree"),
            C("token count", [(0x3C9799F, b"\x04")], True, regex=r"builder token stride / count mismatch"),
            C("record layout", [(0x36F3AC8, b"\x2c")], True, regex=r"record layout differs"),
            C("tracker field vs producer", [(0x275FF24, b"\xe8")], True, regex=r"link failed: tracker base"),
            C("user table field of the later call", [(0x27E33E8, b"\x48")], True, regex=r"link failed: user table"),
            C("insert map field", [(0x36F3A46, b"\x38")], True, regex=r"link failed: sub_account_to_master"),
            C("producer back iterator", [(0x2760025, b"\x01")], True, regex=r"link failed: producer state"),
            C("other_volume_user threshold", [(0x27677E5, b"\x81")], True, regex=r"link failed: other_volume_user"),
            C("Vec fold address displacement", [(0x26B21ED, b"\x20")], True, regex=r"link failed: the Vec fold reads"),
            C("deriver count displacement", [(0x36F3D12, b"\xf0")], True, regex=r"link failed: deriver count"),
            C("builder count field", [(0x3C9793F, b"\x38")], True, regex=r"link failed: deriver passes the count"),
            C("vec_entry occupied return", [(0x3596764, b"\xe0")], True, regex=r"link failed: vec_entry returns"),
            C("Vec fold context displacement", [(0x258B5DD, b"\x10")], True, regex=r"link failed: the fold hands"),
            C("step map displacement", [(0x2773C06, b"\xf0")], True, regex=r"link failed: the step and the Vec fold"),
            C("encoder words call retargeted", [(0x1592256, rel(0x1592255, 0x1591CD0, 5))], True,
              lambda mod: {"CALLERS": dict(mod.CALLERS, ethabi_words=[0x1592128, 0x1592144],
                                           ethabi_word_writer=[0x159200D, 0x15920D3, 0x1592255])},
              regex=r"link failed: the count is Uint limb 0"),
            C("lowercase slot retargeted", [(self.rela_entry_va(0x576E050) + 16, struct.pack("<Q", 0x1346068))], False,
              lambda mod: {"SLOTS": {**mod.SLOTS, 0x576E050: ("relative", 0x1346068, "to_lowercase")}},
              regex=r"link failed: both names pass through slot 0x576e050"),
            C("dispatch lea bias", [(0x275929F, b"\x8d")], True, regex=r"dispatch: lea bias and cmp bias disagree"),
            C("index-6 arm retargeted", [(0x2759D4E, rel(0x2759D4D, 0x36F3610, 5))], True,
              regex=r"dispatch: index-6 arm does not call the handler"),
            C("index-1 arm retargeted", [(0x27592E1, rel(0x27592E0, 0x36F3610, 5))], True,
              regex=r"dispatch: index-1 arm does not call other_entry"),
            C("keccak-f slot use", [(0x4F59A39, b"\xdb")], True, regex=r"slot 0x5777790: no call \[rip\] to it at 0x4f59a37"),
            C("keccak-f round bound", [(0x4F5991D, b"\xc8")], True, regex=r"keccak_f loop bound is not 24 qwords"),
            C("0xdd Required constant", [(0x3800E38, b"\x6b")], True, regex=r"the 0xdd message's Required constant"),
            C("message arm without lea rsi", [(0x380066D, b"\x3d")], True,
              regex=r"status_formatter: status 0xd6 arm is not lea rsi ; mov edx"),
            C("template arm without lea rdx", [(0x3801ECC, b"\x0d")], True,
              regex=r"status_formatter: status 0xd8 template arm has no single lea rdx"),
            C("word writer bswap register", [(0x1591D3F, b"\xcb")], True,
              regex=r"word writer: the Int/Uint arm does not store limbs 3\.\.0 byte-swapped"),
            C("register call changed", [(0x27E341B, b"\xd3")], True,
              regex=r"register call 0x27e341a in handler: bytes differ from ffd5"),
            C("status load displacement", [(0x27E3187, b"\x7c")], True,
              regex=r"check 1: the propagated status is not the callee's u16 loaded at 0x27e3183"),
            C("re-derive status load displacement", [(0x36F3779, b"\x54")], True,
              regex=r"check 6: the propagated status is not the callee's u16 loaded at 0x36f3775"),
            C("creator status load displacement", [(0x27E33C4, b"\x7c")], True,
              regex=r"check 13: the propagated status is not the callee's u16 loaded at 0x27e33c0"),
            C("creator failure path call", [(0x27E3545, b"\xe8" + rel(0x27E3545, 0x36F3610, 5))], True,
              regex=r"check 13: the propagated status is not the callee's u16"),
            C("template marker byte", [(0x1FD65A, b"\xc1")], False,
              lambda mod: {"STATUS_ARMS": {**mod.STATUS_ARMS, 0xD8: (
                  "fmt_d8", "template", b"\x1bDuplicate sub-account user \xc1\x00", "fmt_d8_arg")}},
              regex=r"status_formatter: status 0xd8 template marker 0xc1"),
            C("alloc_fail ret injected", [(0x1346077, bytes.fromhex("c3cccccccccc"))], False,
              lambda mod: {"SHAPES": [(n, o, va, (h[:-1] + ["c3"] + ["cc"] * 5) if n == "a_body" else h, m)
                                      for n, o, va, h, m in mod.SHAPES]},
              regex=r"link failed: alloc_fail"),
            # -- unit controls: pinned tables changed in memory, or a helper called directly --
            C("slot target not an FDE start", [], False,
              lambda mod: {"SLOTS": {**mod.SLOTS, 0x56F1C38: ("relative", 0x1E67E5, "a Location record")}},
              regex=r"slot 0x56f1c38 target: 0x1e67e5 is not an FDE start"),
            C("slot outside .got", [], False,
              lambda mod: {"SLOTS": {**mod.SLOTS, 0x577A668: ("relative", 0x4F14CA0, "a .data pointer")}},
              regex=r"slot 0x577a668 .* not in \.got/\.data\.rel\.ro"),
            C("used slot without resolution", [], False,
              lambda mod: {"SLOTS": {k: v for k, v in mod.SLOTS.items() if k != 0x576E010}},
              regex=r"a used slot has no resolution entry"),
            C("instruction pinned twice", [], False, plus("SHAPES", [("dup", "creator", 0x36F39CA, ["66c703d600"], "x")]),
              regex=r"shape dup: instruction 0x36f39ca pinned twice"),
            C("overlapping shapes", [], False,
              plus("SHAPES", [("overlap", "creator", 0x36F3628, [DATA[self.elf.off(0x36F3628):][:2].hex()], "x")]),
              regex=r"shapes c_volume_gate and overlap overlap"),
            C("shape outside its owner", [], False,
              lambda mod: {"SHAPES": [(n, "handler" if n == "c_tag_d6" else o, va, h, m) for n, o, va, h, m in mod.SHAPES]},
              regex=r"shape c_tag_d6 at 0x36f39ca is outside its owner handler"),
            C("16-bit store not pinned", [], False, without_shape("c_word_rbx6"),
              regex=r"16-bit store 0x36f3980 is not a pinned instruction"),
            C("rip-relative operand without ModRM 00/101", [], False, plus("RIPREL", [(0x36F3627, 0, "bogus")]),
              regex=r"rip-relative bogus at 0x36f3627: no rip-relative ModRM"),
            C("rip-relative site not pinned", [], False, plus("RIPREL", [(0x36F3628, 0, "bogus")]),
              regex=r"rip-relative bogus: 0x36f3628 is not a pinned instruction start"),
            C("immediate not at an instruction start", [], False, plus("IMMS", [("bogus", 0x36F3628, 0, 1, False)]),
              regex=r"immediate bogus: 0x36f3628 is not a pinned instruction start"),
            C("immediate outside its instruction", [], False, plus("IMMS", [("bogus", 0x36F3627, 6, 4, False)]),
              regex=r"immediate bogus: offset outside the instruction at 0x36f3627"),
            C("register source not pinned", [], False,
              lambda mod: {"REGISTER_SOURCES": {**mod.REGISTER_SOURCES, 0x36F39C5: [(0x36F3917, "status_143")]}},
              regex=r"register source 0x36f3917 is not pinned"),
            C("status load is not a movzx", [], False,
              lambda mod: {"LOAD_SOURCES": {**mod.LOAD_SOURCES, 0x27E356A: [(0x27E3188, "derive_status_load")]}},
              regex=r"status load 0x27e3188 is not a pinned movzx"),
            C("direct call site not E8", [], False,
              lambda mod: {"DIRECT_CALLS": [("handler", 0x27E317D, 0x36F3C20, "x")] + mod.DIRECT_CALLS[1:]},
              regex=r"direct call 0x27e317d in handler: not an E8 rel32 call"),
            C("decision is not a branch", [], False, rows(3, decision=0x36F3627),
              regex=r"check 4 decision: 0x36f3627 is not a decoded branch"),
            C("check call not pinned", [], False, rows(0, call=0x27E3180), regex=r"check 1: call 0x27e3180 is not pinned"),
            C("check call neither direct nor a slot", [], False, rows(2, call=0x27E331C),
              regex=r"check 3: call 0x27e331c is neither direct nor a slot"),
            C("check store outside its owner", [], False, rows(1, store=0x36F3980), regex=r"check 2: store 0x36f3980 outside handler"),
            C("check store not a status store", [], False, rows(3, store=0x36F3980),
              regex=r"check 4: 0x36f3980 is not an enumerated status store"),
            C("failure edge target", [], False, rows(3, fail_to=0x36F3658), regex=r"check 4: failure edge goes to 0x36f3630"),
            C("pass edge target", [], False, rows(4, passes=[(0x36F375E, "jae", "fallthrough", 0x36F3765)]),
              regex=r"check 5: pass edge 0x36f375e goes to 0x36f3764"),
            C("check status value", [], False, rows(4, status=0xD7), regex=r"check 5: store writes 0xd6"),
            C("check register source value", [], False, rows(7, status=0x144), regex=r"check 8: no register source loads 0x144"),
            C("prologue: creator compare not first", [], False, drop_last("c_args"),
              regex=r"link failed: creator: the volume compare is the first instruction"),
            C("prologue: helper test not first", [], False, drop_last("n_out"),
              regex=r"link failed: name_helper: the r8 length test is the first instruction"),
            C("prologue: handler lea not first", [], False, drop_last("h_args"),
              regex=r"link failed: handler: prologue, argument moves, then the tracker lea"),
            C("prologue: deriver guard not first", [], False, drop_last("d_args0"),
              regex=r"link failed: deriver: prologue, argument moves, then the map guard"),
            C("alloc_fail window truncated", [], False, drop_last("a_body"), regex=r"link failed: alloc_fail"),
            C("reciprocal magic - 1", call=recip(c0["reciprocal_magic"] - 1, 97, 10 ** 10),
              regex=r"reciprocal certificate failed"),
            C("reciprocal error bound", call=recip(-((-(1 << 64)) // 3), 64, 3), regex=r"reciprocal certificate failed"),
            C("Keccak model delimiter", call=lambda mod: mod._derivation_model(dict(c0, keccak_delimiter=0x06), (0, 20), words),
              regex=r"Keccak model failed"),
            C("model Uint word layout",
              call=lambda mod: mod._derivation_model(c0, (0, 20), {0x0: 0x8, 0x8: 0x10, 0x10: 0x18, 0x18: 0x20}),
              regex=r"model: the Uint word differs from the word writer's layout"),
        ]

    # ---- Pinned output, byte equality with the packet JSON, determinism. ----
    def test_pinned_output(self):
        self.assertEqual(hashlib.sha256(self.text).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "subaccount-create.json").read_bytes(), self.text)

    def test_hashseed_invariance(self):
        outs = []
        for seed in ("0", "7", "99"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            p = subprocess.run([sys.executable, "-B", str(TOOL)], capture_output=True, env=env, check=True)
            outs.append(hashlib.sha256(p.stdout).hexdigest())
        self.assertEqual(outs, [OUTPUT_SHA256] * 3)

    def test_pinned_facts(self):
        d = self.j
        self.assertEqual((d["dispatch"]["exchange_tag"], d["dispatch"]["index"], d["dispatch"]["tag_bias"],
                          d["dispatch"]["entries_inside_dispatcher"]), (122, 6, 0x74, 88))
        self.assertEqual(d["functions"]["handler"], {"start": "0x27e3140", "end": "0x27e3744", "size": 1540,
                                                      "role": sac.FUNCS["handler"][2]})
        s = d["summary"]
        self.assertEqual((s["functions"], s["shapes"], s["pinned_instructions"], s["links"]), (27, 191, 989, 21))
        self.assertEqual((s["status_stores"], s["status_stores_imm16"], s["status_stores_register"]), (12, 7, 5))
        self.assertEqual((s["status_rows"], s["status_rows_imm16"], s["status_rows_register"], s["control_rows"]),
                         (8, 6, 2, 5))
        rows = [(r["seq"], r["owner"], r["status"], r.get("store_kind")) for r in d["check_order"]]
        self.assertEqual(rows, [
            (1, "handler", None, "register"), (2, "handler", 0xD8, "imm16"), (3, "handler", None, None),
            (4, "creator", 0xDD, "imm16"), (5, "creator", 0xD6, "imm16"), (6, "creator", None, "register"),
            (7, "creator", 0xD8, "imm16"), (8, "creator", 0x143, "register"), (9, "name_helper", 0xD9, "imm16"),
            (10, "name_helper", 0xD7, "register"), (11, "creator", None, None), (12, "creator", 0x186, "imm16"),
            (13, "handler", None, "register")])
        regs = {r["seq"]: (r["store_va"], r["source_va"]) for r in d["check_order"] if "source_va" in r}
        self.assertEqual(regs, {8: ("0x36f39c5", "0x36f3916"), 10: ("0x36f45f4", "0x36f45ec")})
        loads = {r["seq"]: (r["status_load"]["load_va"], r["status_load"]["operand"], r["fail_to_store_path"])
                 for r in d["check_order"] if "status_load" in r}
        self.assertEqual(loads, {1: ("0x27e3183", "[rsp+0x78]", [["0x27e32b5", "0x27e3309"], ["0x27e3565", "0x27e356a"]]),
                                 6: ("0x36f3775", "[rsp+0x50]", [["0x36f389f", "0x36f38ed"]]),
                                 13: ("0x27e33c0", "[rsp+0x78]", [["0x27e3516", "0x27e356a"]])})
        cs = d["call_slots"]["summary"]
        self.assertEqual((cs["references"], cs["distinct_slots_used_by_five_windows"], cs["resolved"],
                          cs["relative"], cs["glob_dat"]), (35, 17, 17, 15, 2))
        self.assertEqual(d["calls"]["summary"], {"calls": 44, "direct": 16, "register": 3, "through_slot": 25,
                                                 "through_slot_distinct_slots": 13, "through_slot_relative": 11,
                                                 "through_slot_glob_dat": 2})
        msgs = {a["status"]: a.get("text", a.get("rendered")) for a in d["status_formatter"]["arms"]}
        self.assertEqual(msgs[0xDD], "Cannot create sub-accounts until enough volume traded. Required: ${}. Traded: ${}.")
        self.assertEqual(msgs[0xD9], "Sub-account name must be between 1 and 16 characters long.")
        self.assertEqual(msgs[0x57], "Too many extra agents for cumulative volume traded. Current limit is {}")
        self.assertEqual(d["status_formatter"]["first_index_outside"], 0x186)
        self.assertEqual([t["variant"] for t in d["token_debug"]["builder_tokens"]], ["String", "Address", "Uint"])
        self.assertEqual([(a["tag"], a["arm"]) for a in d["word_writer"]["arms"] if a["arm"] == "0x1591d24"],
                         [(3, "0x1591d24"), (4, "0x1591d24")])
        self.assertEqual(d["kept_digest"]["slice"], [0, 20])
        c = d["constants"]
        self.assertEqual((c["min_volume_raw"], c["reciprocal_shift"], c["volume_per_extra_sub_raw"],
                          c["cap_quotient_clamp"], c["cap_addend"], c["fmt_required_constant"]),
                         (10_000_000, 97, 10 ** 10, 40, 10, 100000.0))
        self.assertEqual((c["name_len_upper_tier"], c["name_len_accepted_lo"], c["name_len_accepted_hi"]), (100, 1, 16))
        self.assertEqual((c["keccak_rate"], c["keccak_delimiter"], c["keccak_rounds"]), (136, 1, 24))
        self.assertEqual([x["va"] for x in d["callers_e8_rel32"]["volume_producer"]], ["0x27677d4", "0x27e3317"])
        self.assertEqual(d["byte_scans"]["windows"]["name_sibling"], {"imm32_0x989680": [], "imm64_magic": []})
        self.assertEqual({x["label"]: x["file"] for x in d["locations"]}["insert_assert"],
                         "/home/ubuntu/hl/code_Mainnet/l1/src/sub_account.rs")

    # ---- CLI exit codes and --check. ----
    def test_cli_exit_codes(self):
        tool = str(TOOL)
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad"
            bad.write_bytes(b"\x7fELF" + b"\0" * 96)
            p = subprocess.run([sys.executable, "-B", tool, "--binary", str(bad)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 2)
            self.assertIn("binary sha256", p.stderr)
            self.assertEqual(p.stdout, "")
            p = subprocess.run([sys.executable, "-B", tool, "--check", str(PACKET / "subaccount-create.json")],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            other = Path(td) / "other.json"
            other.write_bytes(self.text.replace(b'"seq": 13', b'"seq": 14'))
            p = subprocess.run([sys.executable, "-B", tool, "--check", str(other)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 1)
        for data in (DATA[:4096], b""):
            with self.assertRaisesRegex(sac.EvidenceError, r"binary sha256"):
                sac.build(data)

    # ---- Every control fails closed with its own message. ----
    def test_controls_fail_closed(self):
        cs = self.controls()
        labels = [c.label for c in cs]
        self.assertEqual(len(labels), len(set(labels)), "duplicate control labels")
        for c in cs:
            with self.subTest(c.label):
                kind, msg = self.run_control(sac, c)
                self.assertEqual(kind, "evidence", msg)
                self.assertRegex(msg, c.regex)

    # ---- Guard inventory and mutants: every guard of the tool has a control that kills its removal. ----
    def guard_lines(self):
        lines = TOOL.read_text().splitlines()
        raises = [l for l in lines if "raise EvidenceError(" in l and 'f"link failed: {what}"' not in l]
        links = [l for l in lines if re.match(r"\s+link\(", l)]
        return raises, links

    def test_guard_inventory(self):
        raises, links = self.guard_lines()
        keys = list(GUARDS) + list(DEFENSIVE)
        for line in raises + links:
            hits = [k for k in keys if k in line]
            self.assertEqual(len(hits), 1, f"guard line matched by {hits}: {line.strip()}")
        for k in keys:
            self.assertEqual(sum(k in line for line in raises + links), 1, f"key {k!r} does not name exactly one line")
        labels = {c.label for c in self.controls()}
        self.assertLessEqual(set(GUARDS.values()) | {m[3] for m in ITEM_MUTANTS}, labels)
        self.assertEqual((len(raises), len(links), len(GUARDS), len(DEFENSIVE), len(ITEM_MUTANTS)),
                         (94, 18, 110, 2, 12))

    def test_guard_mutants_killed(self):
        src = TOOL.read_text()
        controls = {c.label: c for c in self.controls()}
        raises, links = self.guard_lines()
        mutants = []
        for line in raises + links:
            key = [k for k in GUARDS if k in line]
            if not key:
                continue  # DEFENSIVE
            new = line.replace("raise EvidenceError(", "(lambda *_a: None)(", 1) if "raise EvidenceError(" in line \
                else line.replace("link(", "(lambda *_a: None)(", 1)
            mutants.append((key[0], line, new, GUARDS[key[0]]))
        mutants += ITEM_MUTANTS
        for label, old, new, ctrl in mutants:
            with self.subTest(label):
                self.assertEqual(src.count(old), 1, f"mutation site not unique: {old.strip()}")
                kind, msg = self.run_control(load_tool(src.replace(old, new, 1)), controls[ctrl])
                self.assertFalse(kind == "evidence" and re.search(controls[ctrl].regex, msg),
                                 f"mutant {label!r} survives control {ctrl!r}: {msg}")

    # ---- Keccak model: KATs, hashlib cross-check, constants. ----
    def test_keccak_model(self):
        self.assertEqual(sac.keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(sac.keccak256(b"abc").hex(),
                         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        self.assertEqual(len(set(SHA3_TEST_LENGTHS)), len(SHA3_TEST_LENGTHS))
        self.assertEqual(len(SHA3_TEST_LENGTHS), 52)
        for n in SHA3_TEST_LENGTHS:
            m = bytes((i * 31 + 7) % 256 for i in range(n))
            self.assertEqual(sac.keccak256(m, delim=0x06), hashlib.sha3_256(m).digest(), n)
        self.assertNotEqual(sac.keccak256(b"", delim=0x06), sac.keccak256(b""))
        self.assertEqual(sac._RC, PUBLISHED_RC)
        self.assertEqual(sac._RO, PUBLISHED_RHO)
        rc = struct.unpack("<24Q", self.elf.read(sac.RC_TABLE_VA, 192))
        self.assertEqual(sum(a == b for a, b in zip(rc, PUBLISHED_RC)), 24)

    def test_ethabi_layout_model(self):
        enc = sac.ethabi_encode_label_addr_uint(sac.LABEL, bytes(range(20)), 0)
        self.assertEqual(len(enc), 160)
        self.assertEqual(enc[:32], (0x60).to_bytes(32, "big"))
        self.assertEqual(enc[32:64], b"\x00" * 12 + bytes(range(20)))
        self.assertEqual(enc[64:96], (0).to_bytes(32, "big"))
        self.assertEqual(enc[96:128], (16).to_bytes(32, "big"))
        self.assertEqual(enc[128:160], sac.LABEL + b"\x00" * 16)
        words = {int(w["word_offset"]): w["token_disp"] for w in self.j["word_writer"]["int_uint_word"]}
        for n in (0, 1, 41, 0x0102030405060708, (1 << 64) - 1):
            self.assertEqual(sac._writer_word(words, [n, 0, 0, 0]), n.to_bytes(32, "big"))

    def test_kept_slice_from_bytes(self):
        kept = tuple(self.j["kept_digest"]["slice"])
        self.assertEqual(kept, (0, 20))
        for s in self.j["derivation_model"]["samples"]:
            enc = sac.ethabi_encode_label_addr_uint(sac.LABEL, bytes.fromhex(s["master"]), s["count"])
            full = sac.keccak256(enc)
            self.assertEqual(s["derived_address"], full[kept[0]:kept[1]].hex())
            self.assertNotEqual(s["derived_address"], s["reference_impl_slice_12_32"])

    # ---- Reciprocal and cap. ----
    def test_reciprocal(self):
        c = self.r["constants"]
        M, s, D = c["reciprocal_magic"], c["reciprocal_shift"], c["volume_per_extra_sub_raw"]
        self.assertEqual(M, -((-(1 << s)) // D))
        err = M * D - (1 << s)
        self.assertTrue(0 <= err and err * ((1 << 64) - 1) < (1 << s))
        rng = random.Random(94)
        xs = [rng.getrandbits(64) for _ in range(20000)]
        xs += [k * D + d for k in range(0, 1844674407, 92233720) for d in (-1, 0, 1) if 0 <= k * D + d < 1 << 64]
        self.assertTrue(all((x * M) >> s == x // D for x in xs))
        self.assertEqual(sum(((x * (M - 1)) >> s) != x // D for x in [D, 2 * D, (1 << 64) - 1]), 2)
        self.assertEqual(self.r["reciprocal_proof"]["wrong_magic_controls"], ["D", "2D", "2^64-1"])

    def test_cap_boundaries(self):
        c = self.r["constants"]
        D = c["volume_per_extra_sub_raw"]
        self.assertEqual([sac._cap(v, c) for v in (0, 39 * D, 40 * D, 41 * D, (1 << 64) - 1)], [10, 49, 50, 50, 50])
        self.assertEqual([(r["volume_raw"], r["cap"]) for r in self.r["cap_boundaries"]["rows"]],
                         [(0, 10), (10_000_000, 10), (39 * D, 49), (40 * D, 50), (41 * D, 50), ((1 << 64) - 1, 50)])

    # ---- GNU objdump / readelf cross-checks (independent decoders). ----
    @unittest.skipUnless(GNU_OBJDUMP, "GNU objdump not on PATH")
    def test_shapes_are_objdump_instructions(self):
        for owner, (lo, hi, _r) in sac.FUNCS.items():
            ins = objdump(lo, hi)
            for name, own, va, hexes, _m in sac.SHAPES:
                if own != owner:
                    continue
                v = va
                for h in hexes:
                    self.assertIn(v, ins, f"{name}: {v:#x} not an objdump instruction start")
                    self.assertEqual(ins[v][0].hex(), h, f"{name} at {v:#x}")
                    v += len(bytes.fromhex(h))

    @unittest.skipUnless(GNU_OBJDUMP, "GNU objdump not on PATH")
    def test_scans_match_objdump(self):
        words, refs, calls = [], [], []
        got_va, _o, got_sz = self.elf.sections[".got"]
        for w in sac.STATUS_FIELD:
            lo, hi, _r = sac.FUNCS[w]
            for va, (_b, t) in sorted(objdump(lo, hi).items()):
                m = re.match(r"mov WORD PTR (\[[^\]]+\]),(\S+)$", t)
                if m:
                    src = int(m.group(2), 16) if m.group(2).startswith("0x") else m.group(2)
                    words.append((w, va, m.group(1).replace("*1", ""), src))
                if t.startswith("call "):
                    calls.append((w, va))
        self.assertEqual(words, [(w, va, op, src) for w, va, op, src, _r in sac.WORD_STORES])
        for w in sac.SLOT_WINDOWS:
            lo, hi, _r = sac.FUNCS[w]
            for va, (_b, t) in sorted(objdump(lo, hi).items()):
                m = re.match(r"(call|mov) (?:\w+,)?QWORD PTR \[rip\+0x[0-9a-f]+\] # ([0-9a-f]+)$", t)
                if m and got_va <= int(m.group(2), 16) < got_va + got_sz:
                    refs.append((w, va, m.group(1), int(m.group(2), 16)))
        self.assertEqual(refs, sac.SLOT_REFS)
        # The 25 slot calls of the four windows go through 13 distinct slots (their kinds: test_readelf_slots).
        slot_calls = [s for w, _va, k, s in refs if k == "call" and w in sac.STATUS_FIELD]
        self.assertEqual((len(slot_calls), len(set(slot_calls))), (25, 13))
        # Every call of the four windows is a slot call, a pinned direct call or a pinned register call.
        listed = sorted([(w, va) for w, va, k, _s in sac.SLOT_REFS if k == "call" and w in sac.STATUS_FIELD] +
                        [(w, va) for w, va, _t, _l in sac.DIRECT_CALLS] + [(w, va) for w, va, _b, _l in sac.REGISTER_CALLS])
        self.assertEqual(sorted(calls), listed)
        self.assertEqual(len(calls), 44)
        raw = {w: objdump(*sac.FUNCS[w][:2], keep_symbols=True) for w in sac.STATUS_FIELD}
        for w, va, tgt, _l in sac.DIRECT_CALLS:
            t = raw[w][va][1]
            want = f"call {tgt:x} <" if isinstance(tgt, int) else f"<{tgt}@plt>"
            self.assertIn(want, t, f"{va:#x}: {t}")
        for w, va, hexb, _l in sac.REGISTER_CALLS:
            self.assertEqual(raw[w][va][0].hex(), hexb)
            self.assertRegex(raw[w][va][1], r"^call (rbp|r15)$")

    @unittest.skipUnless(GNU_OBJDUMP, "GNU objdump not on PATH")
    def test_callers_and_exits_with_objdump(self):
        starts, ends = sr.fde_index(self.elf)
        for name, sites in sac.CALLERS.items():
            for va in sites:
                lo, hi = sr.containing(starts, ends, va)
                ins = objdump(lo, hi)
                self.assertIn(va, ins, f"caller {va:#x} of {name}")
                self.assertEqual(ins[va][1], f"call {sac.FUNCS[name][0]:x}")
        # Exits: the deriver has one ret; its other exits are alloc_fail (no ret) and the unwind landing pad.
        der = objdump(*sac.FUNCS["deriver"][:2], keep_symbols=True)
        self.assertEqual([va for va, (_b, t) in der.items() if t == "ret"], [0x36F3E9F])
        self.assertEqual(max(der), 0x36F3ECB)
        self.assertRegex(der[0x36F3ECB][1], r"^call 5660110 <_Unwind_Resume@plt>$")
        self.assertEqual([va for va, (_b, t) in objdump(*sac.FUNCS["alloc_fail"][:2]).items() if t == "ret"], [])
        # volume_report returns: exactly the two pinned rets.
        self.assertEqual([va for va, (_b, t) in objdump(*sac.FUNCS["volume_report"][:2]).items() if t == "ret"],
                         [0x358DD54, 0x358DE0C])
        # Every memory-destination store in user_lookup goes through rax (= rdi, the output).
        for va, (_b, t) in objdump(*sac.FUNCS["user_lookup"][:2]).items():
            m = re.match(r"(mov\w*|add|sub|or|and|xor|inc|dec) \w+ PTR \[(\w+)", t)
            if m:
                self.assertEqual(m.group(2), "rax", f"{va:#x}: {t}")

    @unittest.skipUnless(GNU_OBJDUMP, "GNU objdump not on PATH")
    def test_status_registers_survive_their_paths(self):
        cre, han = objdump(*sac.FUNCS["creator"][:2]), objdump(*sac.FUNCS["handler"][:2])
        dst = lambda regs: re.compile(rf"^(?!cmp |test |bt )\S+ (?:{regs})(?:,|$)")
        # bp from mov bp,0x143 / the helper reload to the store at 0x36f39c5 (only a callee-saved call between).
        bp = dst("bp|bpl|ebp|rbp")
        for lo, hi in ((0x36F391A, 0x36F39C5), (0x36F3AFE, 0x36F3B86)):
            for va, (_b, t) in cre.items():
                if lo <= va < hi:
                    self.assertIsNone(bp.match(t), f"{va:#x}: {t}")
        # eax from the status load to the 0x186 compare, and along the failure path to the register store:
        # no instruction names an eax-family destination, writes eax implicitly, calls or returns.
        eax = dst("al|ah|ax|eax|rax")
        implicit = re.compile(r"^(call|ret|syscall|cpuid|rdtsc\w*|cdq|cqo|cwd|cwde|cdqe|lods\w*|scas\w*|xchg|"
                              r"cmpxchg\w*|xadd|mul|div|idiv|in|imul \S+$)\b")
        for t in ("mov eax,DWORD PTR [rsp+0x50]", "xor eax,eax", "movzx eax,WORD PTR [rsp+0x78]", "pop rax"):
            self.assertIsNotNone(eax.match(t), t)  # positive controls for the checker itself
        for t in ("call 36f57f0", "cdqe", "xchg ecx,eax", "imul rcx"):
            self.assertIsNotNone(implicit.match(t), t)
        for t in ("cmp eax,0x186", "mov DWORD PTR [rbx+0x1a],ecx", "movups xmm0,XMMWORD PTR [rsp+0xc8]"):
            self.assertIsNone(eax.match(t) or implicit.match(t), t)
        rows = [r for r in self.j["check_order"] if "status_load" in r]
        self.assertEqual([r["seq"] for r in rows], [1, 6, 13])
        for r in rows:
            ins = han if r["owner"] == "handler" else cre
            sl = r["status_load"]
            load = int(sl["load_va"], 16)
            self.assertTrue(ins[load][1].startswith("movzx eax,WORD PTR [rsp+"), ins[load][1])
            self.assertEqual(ins[int(sl["compare_va"], 16)][1], "cmp eax,0x186")
            segs = [[load + len(ins[load][0]), int(sl["compare_va"], 16)]] + \
                   [[int(a, 16), int(b, 16)] for a, b in r["fail_to_store_path"]]
            for lo, hi in segs:
                for va, (_b, t) in ins.items():
                    if lo <= va < hi and not re.match(r"^jmp [0-9a-f]+$", t):
                        self.assertIsNone(eax.match(t), f"row {r['seq']} {va:#x}: {t}")
                        self.assertIsNone(implicit.match(t), f"row {r['seq']} {va:#x}: {t}")

    @unittest.skipUnless(GNU_OBJDUMP, "GNU objdump not on PATH")
    def test_volume_arithmetic_census(self):
        """Multiplies, overflow and signed forms in the step and the Vec fold."""
        signed = re.compile(r"^(jo|jno|js|jns|jl|jge|jle|jg|seto|setno|sets|setns|setl|setge|setle|setg|"
                            r"cmovo|cmovno|cmovs|cmovns|cmovl|cmovge|cmovle|cmovg|idiv|cqo|sar|movsx\w*)\b")
        for t in ("jl 2773c10", "cmovge rax,rbx", "seto al", "sar rax,0x3f", "movsxd rax,DWORD PTR [rcx]"):
            self.assertIsNotNone(signed.match(t), t)  # positive controls for the pattern itself
        for t in ("jb 2773c61", "cmovae rbx,r12", "shr rdx,0x21", "mul rdx"):
            self.assertIsNone(signed.match(t), t)
        found = {}
        for name in ("volume_step", "volume_vec_fold"):
            ins = objdump(*sac.FUNCS[name][:2])
            found[name] = sorted(va for va, (_b, t) in ins.items() if re.match(r"^(i?mul|mulx)\b", t))
            self.assertEqual([va for va, (_b, t) in ins.items() if signed.match(t)], [], name)
        self.assertEqual(found, {"volume_step": [0x2773BFC], "volume_vec_fold": [0x26B2229, 0x26B22CC]})

    @unittest.skipUnless(GNU_OBJDUMP, "GNU objdump not on PATH")
    def test_excerpts_regenerate(self):
        head = (PACKET / "objdump-excerpts.txt").read_text().splitlines()[1]
        ver = subprocess.run(["objdump", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
        if head != f"# tool: {ver}":
            self.skipTest(f"objdump version differs from the recorded one ({ver})")
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "x.txt"
            sac.write_excerpts(BIN, out)
            self.assertEqual(out.read_bytes(), (PACKET / "objdump-excerpts.txt").read_bytes())

    @unittest.skipUnless(GNU_READELF, "GNU readelf not on PATH")
    def test_readelf_slots(self):
        out = subprocess.run(["readelf", "-rW", str(BIN)], capture_output=True, text=True, check=True).stdout
        for slot, (kind, want, _label) in sac.SLOTS.items():
            line = re.search(rf"^0*{slot:x}\s+\S+\s+(R_X86_64_\w+)\s+(.*)$", out, re.M)
            self.assertIsNotNone(line, hex(slot))
            if kind == "relative":
                self.assertEqual((line.group(1), int(line.group(2).split()[-1], 16)), ("R_X86_64_RELATIVE", want))
            else:
                self.assertEqual(line.group(1), "R_X86_64_GLOB_DAT")
                self.assertRegex(line.group(2), rf"\s{want}@")
        self.assertRegex(out, r"(?m)^0*5778db0\s+\S+\s+R_X86_64_JUMP_SLOT\s+0+\s+_Unwind_Resume@")

    # ---- The packet's verify.py: manifest set, regenerated hash and bytes, excerpts, pinned facts. ----
    def test_packet_verify(self):
        for flag in ("-I", "-O"):
            p = subprocess.run([sys.executable, flag, "-B", str(PACKET / "verify.py")], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn("PASS", p.stdout)
        vspec = importlib.util.spec_from_file_location("sac_verify", PACKET / "verify.py")
        v = importlib.util.module_from_spec(vspec)
        vspec.loader.exec_module(v)

        def copy(td):
            t = Path(td)
            for name in v.FILES + ("MANIFEST.sha256",):
                shutil.copy(PACKET / name, t / name)
            return t

        def refresh(t):
            (t / "MANIFEST.sha256").write_text("".join(
                f"{hashlib.sha256((t / n).read_bytes()).hexdigest()}  {n}\n" for n in sorted(v.FILES)))

        with tempfile.TemporaryDirectory() as td:
            t = copy(td)
            self.assertEqual(v.manifest_problems(t), [])
            (t / "extra.txt").write_text("x")
            self.assertRegex(" ".join(v.manifest_problems(t)), r"packet directory holds")
            (t / "extra.txt").unlink()
            lines = (t / "MANIFEST.sha256").read_text().splitlines()
            (t / "MANIFEST.sha256").write_text("\n".join(l for l in lines if "objdump" not in l) + "\n")
            self.assertRegex(" ".join(v.manifest_problems(t)), r"MANIFEST lists")
            shutil.copy(PACKET / "MANIFEST.sha256", t / "MANIFEST.sha256")
            (t / "README.md").write_text("tampered")
            self.assertRegex(" ".join(v.manifest_problems(t)), r"manifest mismatch for README.md")
        cases = [
            ("subaccount-create.json", lambda s: s.replace('"seq": 13', '"seq": 14'),
             r"subaccount-create\.json differs from tool output", False),
            ("objdump-excerpts.txt", lambda s: s.replace("--stop-address=0x2759d52]", "--stop-address=0x2759d53]", 1),
             r"excerpt windows differ from the tool's", False),
            ("objdump-excerpts.txt", lambda s: s.replace("cmovae rax,rcx", "cmovb  rax,rcx", 1),
             r"objdump-excerpts\.txt differs from the regenerated excerpts", True),
        ]
        for name, edit, regex, needs_objdump in cases:
            with self.subTest(name=name, regex=regex):
                if needs_objdump and v.excerpt_regeneration_skip_reason() is not None:
                    self.skipTest(v.excerpt_regeneration_skip_reason())
                with tempfile.TemporaryDirectory() as td:
                    t = copy(td)
                    text = (t / name).read_text()
                    self.assertNotEqual(edit(text), text)
                    (t / name).write_text(edit(text))
                    refresh(t)
                    with self.assertRaisesRegex(v.VerifyError, regex):
                        v.verify(t, ROOT)


if __name__ == "__main__":
    unittest.main()
