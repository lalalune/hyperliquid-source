import importlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import re003_x86_115_check as check  # noqa: E402
import x86_115 as x86  # noqa: E402

IMAGE = None


def image():
    global IMAGE
    if IMAGE is None:
        IMAGE = x86.load_image()
    return IMAGE


def run_code(code, args=None, hook=None):
    """Assemble `code` over the first bytes of .text through the patch table and run it from there."""
    img = image()
    entry = img.named[".text"]["address"]
    machine = x86.Machine(img, {entry + at: byte for at, byte in enumerate(code)})
    if hook:
        machine.calls[entry + 0x1000] = hook
    value = machine.run(entry, args or {})
    return machine, value


def window(raw, base=0):
    data = bytes(raw) + bytes(16)
    return lambda va, count: data[va - base:va - base + count]


class DecodeTests(unittest.TestCase):
    def test_moves_and_branches(self):
        row = x86.decode(window([0x48, 0x89, 0xD8]), 0)            # mov rax, rbx
        self.assertEqual((row.op, row.a, row.b, row.width, row.size), ("mov", ("r", 0), ("r", 3), 8, 3))
        row = x86.decode(window([0x7C, 0x05], 0x100), 0x100)                # jl +5
        self.assertEqual((row.op, row.cc, row.target, row.next), ("jcc", 12, 0x107, 0x102))
        row = x86.decode(window([0xE8, 0xFB, 0xFF, 0xFF, 0xFF], 0x200), 0x200)
        self.assertEqual((row.op, row.target), ("call", 0x200))

    def test_rip_relative_is_resolved(self):
        row = x86.decode(window([0x48, 0x8D, 0x05, 0x10, 0, 0, 0], 0x400), 0x400)   # lea rax, [rip+0x10]
        self.assertEqual(row.b, ("m", None, None, 1, 0x400 + 7 + 0x10, False))

    def test_sib_and_displacement(self):
        row = x86.decode(window([0x4A, 0x8B, 0x44, 0xA1, 0xF8]), 0)    # mov rax, [rcx + r12*4 - 8]
        self.assertEqual(row.b, ("m", 1, 12, 4, -8, False))

    def test_extra_opcodes_from_other_tools(self):
        self.assertEqual(x86.decode(window([0x66, 0x0F, 0x59, 0xC1]), 0).op, "mulpd")
        self.assertEqual(x86.decode(window([0x66, 0x0F, 0x5F, 0xC1]), 0).op, "maxpd")
        self.assertEqual(x86.decode(window([0x66, 0x0F, 0x55, 0xC1]), 0).op, "andnpd")
        self.assertEqual(x86.decode(window([0xF2, 0x0F, 0xC2, 0xC1, 0x00]), 0).op, "cmpeqsd")
        self.assertEqual(x86.decode(window([0x48, 0x0F, 0xAC, 0xD0, 0x05]), 0).target, 5)

    def test_endbr64_is_a_four_byte_nop(self):
        row = x86.decode(window([0xF3, 0x0F, 0x1E, 0xFA, 0x90]), 0)
        self.assertEqual((row.op, row.size), ("nop", 4))
        with self.assertRaises(x86.EvidenceError):
            x86.decode(window([0xF3, 0x0F, 0x1E, 0xFB]), 0)           # only the 0xFA form is endbr64

    def test_negative_undecodable_and_unsupported(self):
        with self.assertRaises(x86.EvidenceError):
            x86.decode(window([0x0F, 0x05]), 0)                       # syscall is not modelled
        with self.assertRaises(x86.EvidenceError):
            x86.decode(window([0xF2, 0x0F, 0xC2, 0xC1, 0x01]), 0)     # cmpltsd is not modelled

    def test_decode_range_must_end_on_the_fde_end(self):
        img = image()
        done = 0
        for start in img.starts[100:400]:
            end = img.fde_ends[start]
            try:
                rows = x86.decode_range(img, start, end)
            except x86.EvidenceError:
                continue
            self.assertEqual(rows[-1].next, end)
            if rows[0].size > 1:
                with self.assertRaises(x86.EvidenceError):
                    x86.decode_range(img, start, start + 1)       # the first instruction overruns a one byte range
            done += 1
        self.assertGreater(done, 20)


class MachineTests(unittest.TestCase):
    def test_add_with_carry_and_flags(self):
        # mov rax, -1 ; add rax, 1 ; setc cl ; sete dl ; ret   (cl and dl are read back through stores into rax is avoided: use two runs)
        code = [0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x83, 0xC0, 0x01, 0xC3]
        machine, value = run_code(code)
        self.assertEqual(value, 0)
        self.assertTrue(machine.cf and machine.zf and not machine.sf and not machine.of)

    def test_signed_compare_conditions(self):
        # cmp rdi, rsi ; setl al ; movzx eax, al ; ret
        code = [0x48, 0x39, 0xF7, 0x0F, 0x9C, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3]
        for left, right, want in ((1, 2, 1), (2, 1, 0), (x86.MASK[8], 1, 1), (1 << 63, 1, 1), (5, 5, 0)):
            self.assertEqual(run_code(code, {x86.RDI: left, x86.RSI: right})[1], want)

    def test_zero_extension_and_sign_extension(self):
        # mov eax, edi ; ret       and       movsxd rax, edi ; ret
        self.assertEqual(run_code([0x89, 0xF8, 0xC3], {x86.RDI: 0xFFFFFFFF12345678})[1], 0x12345678)
        self.assertEqual(run_code([0x48, 0x63, 0xC7, 0xC3], {x86.RDI: 0x80000000})[1], 0xFFFFFFFF80000000)

    def test_rotate_by_register_uses_cl(self):
        # mov rcx, rsi ; ror rdi, cl ; mov rax, rdi ; ret
        code = [0x48, 0x89, 0xF1, 0x48, 0xD3, 0xCF, 0x48, 0x89, 0xF8, 0xC3]
        self.assertEqual(run_code(code, {x86.RDI: 0x10, x86.RSI: 4})[1], 0x1)
        self.assertEqual(run_code(code, {x86.RDI: 1, x86.RSI: 65})[1], 1 << 63)

    def test_division_by_zero_in_sse_is_ieee(self):
        self.assertEqual(x86.to_bits(x86.fdiv(1.0, 0.0)), 0x7FF0000000000000)
        self.assertEqual(x86.sse_arith("div", 0, 0), x86.INDEFINITE)
        self.assertEqual(x86.sse_arith("add", 0x7FF0000000000001, 0), 0x7FF8000000000001)

    def test_call_goes_through_the_hook_table(self):
        seen = []

        def hook(machine):
            seen.append(machine.regs[x86.RDI])
            machine.regs[x86.RAX] = 77

        entry = image().named[".text"]["address"]
        rel = (entry + 0x1000) - (entry + 5)
        code = [0xE8] + list(rel.to_bytes(4, "little", signed=True)) + [0xC3]
        machine, value = run_code(code, {x86.RDI: 9}, hook)
        self.assertEqual((value, seen), (77, [9]))

    def test_negative_unmodelled_call_and_stack_imbalance(self):
        entry = image().named[".text"]["address"]
        rel = 0x1000 - 5
        with self.assertRaises(x86.Halt):
            run_code([0xE8] + list(rel.to_bytes(4, "little", signed=True)) + [0xC3])
        with self.assertRaises((x86.Halt, x86.EvidenceError)):
            run_code([0x50, 0xC3])                                      # push rax ; ret returns to the pushed poison word
        with self.assertRaises(x86.Halt):
            run_code([0xCC])
        self.assertTrue(entry)

    def test_write_outside_stack_and_heap_is_refused(self):
        with self.assertRaises(x86.Halt):
            run_code([0x48, 0x89, 0x3F, 0xC3], {x86.RDI: 0x1234})      # mov [rdi], rdi


class ImageTests(unittest.TestCase):
    def test_digest_is_checked(self):
        with tempfile.TemporaryDirectory() as folder:
            fake = pathlib.Path(folder) / "node"
            fake.write_bytes(b"\x7fELF" + bytes(64))
            with self.assertRaises(x86.EvidenceError):
                x86.load_image(fake)

    def test_addresses_outside_sections_and_fdes_are_refused(self):
        img = image()
        with self.assertRaises(x86.EvidenceError):
            img.offset(0x10)
        with self.assertRaises(x86.EvidenceError):
            img.fde(img.starts[0] - 1)
        with self.assertRaises(x86.EvidenceError):
            img.exact_fde(img.starts[5] + 1)
        self.assertEqual(img.exact_fde(img.starts[5])[0], img.starts[5])


class SharedModuleTests(unittest.TestCase):
    """Properties of x86_115 itself, checked against independent definitions."""

    def test_float_bit_helpers_round_trip(self):
        for value in (0.0, -0.0, 1.5, -2.25, 1e300, 5e-324):
            self.assertEqual(x86.to_float(x86.to_bits(value)), value)
        self.assertEqual(x86.to_bits(1.0), 0x3FF0000000000000)
        self.assertEqual(x86.to_float(0xC000000000000000), -2.0)

    def test_condition_codes_match_the_definitions_for_every_flag_combination(self):
        machine = x86.Machine(image())
        for bits in range(32):
            cf, zf, sf, of, pf = (bool(bits >> shift & 1) for shift in range(5))
            machine.cf, machine.zf, machine.sf, machine.of, machine.pf = cf, zf, sf, of, pf
            truth = [of, cf, zf, cf or zf, sf, pf, sf != of, zf or sf != of]
            for code in range(16):
                self.assertEqual(machine.condition(code), truth[code >> 1] != bool(code & 1), (bits, code))

    def test_byte_add_and_sub_flags_against_integer_arithmetic_for_all_pairs(self):
        machine = x86.Machine(image())
        signed = lambda value: value - 256 if value & 0x80 else value      # noqa: E731
        for left in range(256):
            for right in range(0, 256, 5):
                result = machine.add_sub(left, right, 0, 1, False)
                self.assertEqual((result, machine.cf, machine.of), ((left + right) & 255, left + right > 255,
                                                                   not -128 <= signed(left) + signed(right) <= 127))
                result = machine.add_sub(left, right, 0, 1, True)
                self.assertEqual((result, machine.cf, machine.of, machine.zf, machine.sf),
                                 ((left - right) & 255, left < right, not -128 <= signed(left) - signed(right) <= 127,
                                  left == right, bool((left - right) & 128)))

    def test_memory_regions_statics_overlay_and_copy(self):
        memory = x86.Machine(image()).memory
        memory.write(x86.HEAP_BASE + 8, 4, 0x11223344)
        self.assertEqual(memory.read(x86.HEAP_BASE + 8, 4), 0x11223344)
        self.assertEqual(memory.bytes_at(x86.HEAP_BASE + 8, 2), bytes([0x44, 0x33]))
        memory.copy(x86.HEAP_BASE + 64, x86.HEAP_BASE + 8, 4)
        self.assertEqual(memory.read(x86.HEAP_BASE + 64, 4), 0x11223344)
        memory.statics[0x1234] = 0xAABB
        self.assertEqual(memory.read(0x1234, 2), 0xAABB)
        memory.overlay = bytearray(0x60)
        memory.write(x86.OVERLAY_LOW + 4, 8, 7)
        self.assertEqual(memory.read(x86.OVERLAY_LOW + 4, 8), 7)
        with self.assertRaises(x86.Halt):
            memory.write(x86.OVERLAY_LOW + 0x60, 8, 1)
        with self.assertRaises(x86.Halt):
            memory.read(0x10, 8)
        with self.assertRaises(x86.Halt):
            memory.put_bytes(0x10, b"abc")

    def test_reset_refills_marks(self):
        memory = x86.Machine(image()).memory
        memory.write(x86.HEAP_BASE, 8, 1)
        memory.stack[0] = 0
        memory.reset(used=16)
        self.assertEqual(memory.read(x86.HEAP_BASE, 8), 0xA5A5A5A5A5A5A5A5)
        self.assertEqual(memory.stack[0], x86.STACK_MARK)

    def test_stub_poisons_volatile_registers_and_keeps_callee_saved(self):
        machine = x86.Machine(image())
        machine.regs = list(range(16))
        machine.stub(lambda m: m.regs.__setitem__(x86.RAX, 5))
        for reg in x86.VOLATILE + (x86.RDX,):
            self.assertEqual(machine.regs[reg], x86.POISON)
        for reg in x86.CALLEE_SAVED:
            self.assertEqual(machine.regs[reg], reg)
        self.assertEqual(machine.regs[x86.RAX], 5)
        machine.stub(lambda m: setattr(m, "keep_rdx", True))
        self.assertNotEqual(machine.regs[x86.RDX], x86.POISON + 1)

    def test_stack_arguments_are_placed_above_the_return_address(self):
        img = image()
        entry = img.named[".text"]["address"]
        for offset, want in ((8, 11), (16, 22)):
            machine = x86.Machine(img, {entry + at: byte for at, byte in enumerate([0x48, 0x8B, 0x44, 0x24, offset, 0xC3])})
            self.assertEqual(machine.run(entry, {}, stack=(11, 22)), want)

    def test_runaway_code_and_clobbered_callee_saved_registers_are_refused(self):
        img = image()
        entry = img.named[".text"]["address"]
        machine = x86.Machine(img, {entry: 0xEB, entry + 1: 0xFE})
        machine.step_limit = 50
        with self.assertRaises(x86.Halt):
            machine.run(entry, {})
        with self.assertRaises(x86.Halt):
            run_code([0x48, 0x31, 0xDB, 0xC3])                           # xor rbx, rbx

    def test_division_and_bit_scan_refusals(self):
        with self.assertRaises(x86.Halt):
            run_code([0x48, 0xF7, 0xF1, 0xC3], {x86.RAX: 5, x86.RDX: 0, x86.RCX: 0})
        with self.assertRaises(x86.Halt):
            run_code([0x48, 0xF7, 0xF1, 0xC3], {x86.RAX: 0, x86.RDX: 1, x86.RCX: 1})
        with self.assertRaises(x86.Halt):
            run_code([0x48, 0x0F, 0xBD, 0xC7, 0xC3], {x86.RDI: 0})

    def test_dec_sets_zero_and_sign_without_touching_carry(self):
        machine, value = run_code([0x48, 0xFF, 0xCF, 0x48, 0x89, 0xF8, 0xC3], {x86.RDI: 1})
        self.assertEqual(value, 0)
        self.assertTrue(machine.zf and not machine.sf)
        machine, value = run_code([0x48, 0xFF, 0xCF, 0x48, 0x89, 0xF8, 0xC3], {x86.RDI: 0})
        self.assertEqual(value, x86.MASK[8])
        self.assertTrue(machine.sf and not machine.zf)

    def test_patch_table_overrides_code_bytes(self):
        img = image()
        entry = img.named[".text"]["address"]
        machine = x86.Machine(img, {entry + 1: 0x99})
        self.assertEqual(machine.read_code(entry, 3)[1], 0x99)
        self.assertEqual(bytes(machine.read_code(entry, 3))[0], img.blob[img.offset(entry)])

    def test_image_views(self):
        img = image()
        base, data = img.text_bytes()
        self.assertEqual(base, img.named[".text"]["address"])
        self.assertEqual(len(data), img.named[".text"]["size"])
        relative = img.relative()
        self.assertGreater(len(relative), 1000)
        self.assertIs(relative, img.relative())
        self.assertEqual(sorted(img.starts), img.starts)
        start, end = img.fde(img.starts[7] + 1) if img.fde_ends[img.starts[7]] > img.starts[7] + 1 else (img.starts[7], img.fde_ends[img.starts[7]])
        self.assertEqual(start, img.starts[7])
        self.assertGreater(end, start)


class DecodeTableTests(unittest.TestCase):
    """One line per instruction form: the operation name and that the instruction length is the number of bytes written."""

    FORMS = (
        ([0x55], "push"), ([0x5D], "pop"), ([0xC3], "ret"), ([0x90], "nop"), ([0xCC], "int3"), ([0x0F, 0x0B], "ud2"),
        ([0x48, 0x01, 0xD8], "add"), ([0x48, 0x09, 0xD8], "or"), ([0x48, 0x11, 0xD8], "adc"), ([0x48, 0x19, 0xD8], "sbb"),
        ([0x48, 0x21, 0xD8], "and"), ([0x48, 0x29, 0xD8], "sub"), ([0x48, 0x31, 0xD8], "xor"), ([0x48, 0x39, 0xD8], "cmp"),
        ([0x48, 0x85, 0xC0], "test"), ([0xA8, 0x01], "test"), ([0xA9, 1, 0, 0, 0], "test"), ([0x6A, 0x01], "pushi"),
        ([0x48, 0x8D, 0x04, 0x25, 0, 0, 0, 0], "lea"), ([0x0F, 0xB6, 0xC0], "movzx"), ([0x0F, 0xB7, 0xC0], "movzx"),
        ([0x0F, 0xBE, 0xC0], "movsx"), ([0x48, 0x63, 0xC0], "movsxd"), ([0x48, 0x0F, 0xAF, 0xC0], "imul2"),
        ([0x48, 0x6B, 0xC0, 0x03], "imul3"), ([0x48, 0xF7, 0xD8], "neg"), ([0x48, 0xF7, 0xD0], "not"), ([0x48, 0xF7, 0xE0], "mul"),
        ([0x48, 0xF7, 0xE8], "imul1"), ([0x48, 0xF7, 0xF0], "div"), ([0x48, 0xFF, 0xC0], "inc"), ([0x48, 0xFF, 0xC8], "dec"),
        ([0xFF, 0xD0], "calli"), ([0xFF, 0xE0], "jmpi"), ([0xFF, 0x30], "pushm"), ([0x48, 0xC1, 0xE0, 0x04], "shl"),
        ([0x48, 0xC1, 0xE8, 0x04], "shr"), ([0x48, 0xC1, 0xF8, 0x04], "sar"), ([0x48, 0xD3, 0xE0], "shl"),
        ([0x48, 0xC1, 0xC0, 0x04], "rol"), ([0x48, 0xC1, 0xC8, 0x04], "ror"), ([0x0F, 0x94, 0xC0], "set"),
        ([0x48, 0x0F, 0x44, 0xC1], "cmov"), ([0x0F, 0xC8], "bswap"), ([0x48, 0x0F, 0xBD, 0xC0], "bsr"),
        ([0xF3, 0x48, 0x0F, 0xBC, 0xC0], "tzcnt"), ([0xF2, 0x0F, 0x58, 0xC1], "addsd"), ([0xF2, 0x0F, 0x59, 0xC1], "mulsd"),
        ([0xF2, 0x0F, 0x5C, 0xC1], "subsd"), ([0xF2, 0x0F, 0x5E, 0xC1], "divsd"), ([0xF2, 0x0F, 0x5D, 0xC1], "minsd"),
        ([0xF2, 0x0F, 0x5F, 0xC1], "maxsd"), ([0x66, 0x0F, 0x2E, 0xC1], "ucomisd"), ([0xF3, 0x0F, 0x10, 0x07], "movss"),
        ([0xF2, 0x0F, 0x10, 0x07], "movsd"), ([0x0F, 0x28, 0xC1], "movx"), ([0x66, 0x0F, 0xEF, 0xC0], "xorps"),
        ([0x66, 0x0F, 0xD7, 0xC0], "pmovmskb"), ([0x66, 0x0F, 0x70, 0xC0, 0x1B], "pshufd"), ([0x66, 0x0F, 0x50, 0xC0], "movmskpd"),
        ([0x74, 0x05], "jcc"), ([0x0F, 0x84, 1, 0, 0, 0], "jcc"), ([0xEB, 0x05], "jmp"), ([0xE9, 1, 0, 0, 0], "jmp"),
        ([0xE8, 1, 0, 0, 0], "call"), ([0x66, 0x0F, 0x14, 0xC1], "punpcklqdq"), ([0x66, 0x0F, 0x59, 0xC1], "mulpd"),
        ([0x66, 0x0F, 0x5F, 0xC1], "maxpd"), ([0x66, 0x0F, 0x55, 0xC1], "andnpd"), ([0xF3, 0x0F, 0x1E, 0xFA], "nop"),
    )

    def test_every_form_decodes_to_its_operation_and_length(self):
        for raw, op in self.FORMS:
            row = x86.decode(window(raw), 0)
            self.assertEqual((row.op, row.size), (op, len(raw)), raw)

    def test_lock_prefix_is_skipped_and_segment_prefix_is_refused(self):
        self.assertEqual(x86.decode(window([0xF0, 0x48, 0x0F, 0xB1, 0x17]), 0).op, "cmpxchg")
        with self.assertRaises(x86.EvidenceError):
            x86.decode(window([0x64, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0]), 0)

    def test_branch_targets_are_relative_to_the_next_instruction(self):
        self.assertEqual(x86.decode(window([0xEB, 0x05], 0x100), 0x100).target, 0x107)
        self.assertEqual(x86.decode(window([0xE9, 0xFB, 0xFF, 0xFF, 0xFF], 0x200), 0x200).target, 0x200)
        self.assertEqual(x86.decode(window([0x0F, 0x84, 0x10, 0, 0, 0], 0x300), 0x300).target, 0x316)

    def test_high_byte_registers_need_the_absence_of_rex(self):
        row = x86.decode(window([0x88, 0xE0]), 0)                      # mov al, ah
        self.assertEqual((row.a, row.b), (("r", 0), ("h", 0)))
        row = x86.decode(window([0x40, 0x88, 0xE0]), 0)                # mov al, spl
        self.assertEqual((row.a, row.b), (("r", 0), ("r", 4)))
        with self.assertRaises(x86.EvidenceError):
            x86.decode(window([0x00, 0xE0]), 0)                        # add al, ah is refused: only mov may touch a high byte register

    def test_truncated_and_empty_windows_fail_closed(self):
        self.assertEqual(x86.decode(window([]), 0).op, "add")          # a zero window is the two byte `add [rax], al`
        with self.assertRaises(IndexError):
            x86.decode(lambda va, count: b"", 0)


class DataMovementTests(unittest.TestCase):
    def test_bswap_by_width(self):
        self.assertEqual(run_code([0x0F, 0xC8, 0xC3], {x86.RAX: 0x11223344})[1], 0x44332211)
        self.assertEqual(run_code([0x48, 0x0F, 0xC8, 0xC3], {x86.RAX: 0x1122334455667788})[1], 0x8877665544332211)

    def test_movsd_store_then_load_through_the_heap(self):
        code = [0x66, 0x48, 0x0F, 0x6E, 0xC7, 0xF2, 0x0F, 0x11, 0x06, 0x48, 0x8B, 0x06, 0xC3]
        self.assertEqual(run_code(code, {x86.RDI: 0xCAFEF00D12345678, x86.RSI: x86.HEAP_BASE + 0x40})[1], 0xCAFEF00D12345678)

    def test_sixteen_byte_move_keeps_both_halves(self):
        # movq xmm0, rdi ; movq xmm1, rdx ; punpcklqdq xmm0, xmm1 ; movups [rsi], xmm0 ; mov rax, [rsi+8] ; ret
        code = [0x66, 0x48, 0x0F, 0x6E, 0xC7, 0x66, 0x48, 0x0F, 0x6E, 0xCA, 0x66, 0x0F, 0x6C, 0xC1, 0x0F, 0x11, 0x06,
                0x48, 0x8B, 0x46, 0x08, 0xC3]
        machine, value = run_code(code, {x86.RDI: 1, x86.RDX: 2, x86.RSI: x86.HEAP_BASE + 0x80})
        self.assertEqual(value, 2)
        self.assertEqual(machine.memory.read(x86.HEAP_BASE + 0x80, 8), 1)

    def test_partial_register_writes_keep_the_upper_bits_only_below_32_bits(self):
        # mov ax, si (66 89 F0) keeps bits 16.. ; mov eax, esi (89 F0) clears bits 32..
        self.assertEqual(run_code([0x66, 0x89, 0xF0, 0xC3], {x86.RAX: 0x1111111111111111, x86.RSI: 0x2222})[1], 0x1111111111112222)
        self.assertEqual(run_code([0x89, 0xF0, 0xC3], {x86.RAX: 0x1111111111111111, x86.RSI: 0x22222222})[1], 0x22222222)


class CheckToolTests(unittest.TestCase):
    def test_mutation_targets_are_unique_and_applicable(self):
        source = pathlib.Path(x86.__file__).read_text()
        for name, _, old, new in check.MUTATIONS:
            self.assertEqual(source.count(old), 1, name)
            self.assertNotEqual(old, new, name)
        with self.assertRaises(check.CheckError):
            check.build_mutant(source, "this text is not in the module", "x")

    def test_survey_counts_are_consistent(self):
        old = check.SURVEY_STRIDE
        check.SURVEY_STRIDE = 3000
        try:
            totals, ops, stops, rows = check.survey(image())
        finally:
            check.SURVEY_STRIDE = old
        self.assertEqual(totals["functions"], len(image().starts[::3000]))
        self.assertEqual(totals["functions"], totals["complete"] + totals["stopped"] + totals["overran"])
        self.assertEqual(sum(ops.values()), totals["instructions"])
        self.assertEqual(sum(stops.values()), totals["stopped"])

    def test_probes_pass_and_a_flag_mutation_fails_them(self):
        rows = check.run_probes(x86, image())
        self.assertGreater(len(rows), 80)
        self.assertTrue(all(row[2] for row in rows))
        source = pathlib.Path(x86.__file__).read_text()
        mutant = check.build_mutant(source, "6: self.sf != self.of,", "6: self.sf == self.of,")
        failed = [row for row in check.run_probes(mutant, image(), stop=True) if not row[2]]
        self.assertEqual(failed[0][0], "setl-signed-compare")

    def test_probe_runner_reports_a_wrong_expectation(self):
        original = check.PROBES
        try:
            check.PROBES = (("wrong", "48 89 F8 C3", (({x86.RDI: 5}, {}, {"rax": 6}),)),)
            rows = check.run_probes(x86, image())
        finally:
            check.PROBES = original
        self.assertEqual([row[2] for row in rows], [False])

    def test_the_listed_equivalent_mutation_really_gives_the_same_register(self):
        source = pathlib.Path(x86.__file__).read_text()
        name, kind, old, new = next(item for item in check.MUTATIONS if item[0] == "carry-cvttsd2si-edge")
        mutant = check.build_mutant(source, old, new)
        entry = image().named[".text"]["address"]
        code = bytes.fromhex("66480F6EC7F2480F2CC0C3")
        for bits in (0xC3E0000000000000, 0xC3DFFFFFFFFFFFFF, 0xBFF0000000000000):
            results = []
            for module in (x86, mutant):
                machine = module.Machine(image(), {entry + at: byte for at, byte in enumerate(code)})
                results.append(machine.run(entry, {x86.RDI: bits}))
            self.assertEqual(results[0], results[1])
        self.assertIn(name, check.EQUIVALENT)

    def test_all_tool_decoder_comparison_lists_the_five_compared_tools(self):
        old = check.ALL_TOOLS_STRIDE
        check.ALL_TOOLS_STRIDE = 20000
        try:
            rows = check.compare_all_decoders(image())
        finally:
            check.ALL_TOOLS_STRIDE = old
        names = {row[0] for row in rows}
        for name, _, _ in check.TOOLS:
            self.assertIn(name, names)
        for row in rows:
            if row[6].startswith("import failed"):
                continue
            self.assertGreaterEqual(row[1], row[2] + row[3] + row[4] + row[5])
            self.assertGreater(row[1], 0)

    def test_prefix_key_skips_legacy_prefixes_and_rex(self):
        self.assertEqual(check.prefix_key(bytes([0xF3, 0x48, 0x0F, 0xBC, 0xC7]) + bytes(16)), "0fbcc7")
        self.assertEqual(check.prefix_key(bytes([0x66, 0x0F, 0x72, 0xD0, 0x01]) + bytes(16)), "0f72d0")

    def test_pick_spreads_evenly_and_never_exceeds_the_request(self):
        chosen = check.pick(list(range(1000)), 10)
        self.assertEqual(len(chosen), 10)
        self.assertEqual(chosen[0], 0)
        self.assertLess(chosen[-1], 1000)
        self.assertEqual(check.pick(list(range(5)), 10), [0, 1, 2, 3, 4])

    def test_canon_any_tolerates_a_row_with_missing_fields(self):
        class Partial:
            va, size, op = 1, 2, "shrdi"
        row = check.canon_any(Partial())
        self.assertEqual((row[0], row[1], row[2], row[8]), (1, 2, "shrd", None))

    def test_run_pass_stops_at_the_first_digest_that_differs(self):
        module = importlib.import_module("funding_premium115")
        img = module.load_image()
        adapter = check.ADAPTERS["funding_premium115"]
        digests, _, _, _, indexes = check.run_pass(module, img, adapter, 30, limit=None)
        wrong = list(digests)
        wrong[4] = bytes(8)
        again, _, _, _, _ = check.run_pass(module, img, adapter, 30, chosen=indexes, stop_at=wrong)
        self.assertEqual(len(again), 5)

    def test_table_has_a_header_and_one_line_per_row(self):
        self.assertEqual(check.table(("a", "b"), [(1, 2), (3, 4)]), "a\tb\n1\t2\n3\t4\n")

    def test_alias_and_canon_ignore_the_old_shrd_name(self):
        row = x86.decode(window([0x48, 0x0F, 0xAC, 0xD0, 0x05]), 0)
        self.assertEqual(check.canon(row)[2], "shrd")

    def test_a_broken_decoder_is_detected_in_the_decode_comparison(self):
        source = pathlib.Path(x86.__file__).read_text()
        mutant = check.build_mutant(source, "scale = 1 << (sib >> 6)", "scale = 1 << (sib >> 5)")
        module = importlib.import_module("funding_rate115")
        machine = x86.Machine(image())
        entry = module.RATE
        found = False
        for va in range(entry, entry + 0x400):
            try:
                want = check.canon(x86.decode(machine.read_code, va))
            except (x86.EvidenceError, IndexError):
                continue
            try:
                got = check.canon(mutant.decode(machine.read_code, va))
            except (x86.EvidenceError, IndexError):
                found = True
                break
            if got != want:
                found = True
                break
        self.assertTrue(found)

    def test_a_tampered_digest_list_is_reported_as_different(self):
        module = importlib.import_module("funding_rate115")
        img = module.load_image()
        digests, _, rec, _, indexes = check.run_pass(module, img, check.ADAPTERS["funding_rate115"], 20, limit=None)
        with check.bound(module, x86):
            again, _, _, _, _ = check.run_pass(module, img, check.ADAPTERS["funding_rate115"], 20, chosen=indexes)
        self.assertEqual(digests, again)
        tampered = list(again)
        tampered[3] = bytes(8)
        self.assertNotEqual(digests, tampered)
        self.assertGreater(rec.run_count, 0)

    def test_binding_is_undone(self):
        module = importlib.import_module("funding_rate115")
        before = (module.Machine, module.Memory, module.decode, x86.Halt)
        with check.bound(module, x86):
            self.assertIs(module.Machine, x86.Machine)
            self.assertIs(x86.Halt, module.Halt)
        self.assertEqual(before, (module.Machine, module.Memory, module.decode, x86.Halt))


class UnsupportedSemanticsTests(unittest.TestCase):
    def test_parity_consumers_refuse_unmodeled_integer_parity(self):
        for prefix in ([0x48, 0x31, 0xC0], [0x48, 0x83, 0xC0, 1], [0x48, 0x39, 0xF7]):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(x86.Halt, "flag read: pf"):
                run_code(prefix + [0x0F, 0x9A, 0xC0, 0xC3])

    def test_shifts_refuse_unmodeled_carry_and_overflow_consumers(self):
        for suffix in ([0x0F, 0x92, 0xC0], [0x0F, 0x90, 0xC0], [0x48, 0x83, 0xD0, 0]):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(x86.Halt, "flag read"):
                run_code([0x48, 0xD1, 0xE7] + suffix + [0xC3], {x86.RDI: 1 << 63})

    def test_zero_count_shift_and_rotate_preserve_prior_flags(self):
        for opcode in (0xE7, 0xC7, 0xCF):  # shl, rol, ror rdi, cl
            code = [0x48, 0x39, 0xF7, 0xB9, 0, 0, 0, 0, 0x48, 0xD3, opcode,
                    0x0F, 0x92, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3]
            self.assertEqual(run_code(code, {x86.RDI: 1, x86.RSI: 2})[1], 1)
        for rotate in ([0xC0, 0xC0, 32], [0x66, 0xC1, 0xC8, 32],
                       [0xC1, 0xC7, 32], [0x48, 0xC1, 0xCF, 64]):
            code = [0x48, 0x39, 0xF7] + rotate + [0x0F, 0x92, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3]
            self.assertEqual(run_code(code, {x86.RDI: 1, x86.RSI: 2})[1], 1)

    def test_nonzero_rotate_and_double_shift_refuse_unmodeled_flags(self):
        for prefix in ([0x48, 0xD1, 0xC7], [0x48, 0xD1, 0xCF],
                       [0xC0, 0xC0, 8], [0x66, 0xC1, 0xC8, 16],
                       [0x48, 0x0F, 0xAC, 0xF7, 4]):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(x86.Halt, "flag read"):
                run_code(prefix + [0x0F, 0x92, 0xC0, 0xC3], {x86.RDI: 1, x86.RSI: 2})
        code = [0x48, 0xD1, 0xFF, 0x0F, 0x90, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3]
        self.assertEqual(run_code(code, {x86.RDI: 1 << 63})[1], 0)  # SAR by one defines OF=0

    def test_multiply_and_divide_refuse_unimplemented_narrow_widths(self):
        for code in ([0xF7, 0xE7, 0xC3], [0xF7, 0xEF, 0xC3], [0x66, 0xF7, 0xF1, 0xC3]):
            with self.subTest(code=code), self.assertRaisesRegex(x86.Halt, "width"):
                run_code(code, {x86.RAX: 5, x86.RDI: 2, x86.RCX: 2, x86.RDX: 0})

    def test_integer_float_conversions_refuse_missing_rex_w(self):
        for code in ([0xF2, 0x0F, 0x2C, 0xC0, 0xC3], [0xF2, 0x0F, 0x2A, 0xC7, 0xC3]):
            with self.subTest(code=code), self.assertRaisesRegex(x86.Halt, "32-bit"):
                run_code(code, {x86.RDI: 3})

    def test_bsr_sets_its_defined_zero_flag(self):
        code = [0x48, 0x39, 0xFF, 0x48, 0x0F, 0xBD, 0xC7,
                0x0F, 0x94, 0xC1, 0x0F, 0xB6, 0xC1, 0xC3]
        self.assertEqual(run_code(code, {x86.RDI: 16})[1], 0)

    def test_stub_flags_require_a_new_defined_producer(self):
        entry = image().named[".text"]["address"]
        displacement = 0x1000 - 5
        call = [0xE8] + list(displacement.to_bytes(4, "little", signed=True))
        hook = lambda m: m.regs.__setitem__(x86.RAX, 0)
        with self.assertRaisesRegex(x86.Halt, "flag read"):
            run_code(call + [0x0F, 0x94, 0xC0, 0xC3], hook=hook)
        self.assertEqual(run_code(call + [0x85, 0xC0, 0x0F, 0x94, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3], hook=hook)[1], 1)
        self.assertTrue(entry)

    def test_high_byte_extension_refuses_the_disclosed_decode_gap(self):
        with self.assertRaisesRegex(x86.Halt, "high-byte"):
            run_code([0x0F, 0xB6, 0xC4, 0xC3], {x86.RAX: 0x1234})
        self.assertEqual(run_code([0x40, 0x0F, 0xB6, 0xC7, 0xC3], {x86.RDI: 0x1234})[1], 0x34)

    def test_memory_bit_strings_refuse_offsets_outside_the_modeled_word(self):
        img = image()
        entry = img.named[".text"]["address"]
        address = x86.HEAP_BASE + 0x100
        for opcode in (0xA3, 0xAB):  # BT/BTS [rdi], rsi
            code = [0x48, 0x0F, opcode, 0x37, 0x0F, 0x92, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3]
            for bit in (64, x86.MASK[8]):
                machine = x86.Machine(img, {entry + at: byte for at, byte in enumerate(code)})
                machine.memory.write(address, 8, 0)
                machine.memory.write(address + 8, 8, 1)
                with self.subTest(opcode=opcode, bit=bit), self.assertRaisesRegex(x86.Halt, "bit-string"):
                    machine.run(entry, {x86.RDI: address, x86.RSI: bit})
            for initial, expected_carry in ((0, 0), (8, 1)):
                machine = x86.Machine(img, {entry + at: byte for at, byte in enumerate(code)})
                machine.memory.write(address, 8, initial)
                self.assertEqual(machine.run(entry, {x86.RDI: address, x86.RSI: 3}), expected_carry)
                self.assertEqual(machine.memory.read(address, 8), initial | 8 if opcode == 0xAB else initial)
        register_code = [0x48, 0x0F, 0xA3, 0xF7, 0x0F, 0x92, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3]
        self.assertEqual(run_code(register_code, {x86.RDI: 1, x86.RSI: 64})[1], 1)


if __name__ == "__main__":
    unittest.main()
