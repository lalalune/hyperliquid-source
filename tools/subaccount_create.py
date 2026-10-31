#!/usr/bin/env python3
"""vaults: node #94 createSubAccount (exchange tag 122) checks, status stores and address derivation.

Stdlib only and deterministic. It reuses the ELF, FDE and R_X86_64_RELATIVE
readers in ``tools/state_roots.py`` (imported by file) and adds four small
readers of its own: a GLOB_DAT reader (``.rela.dyn`` -> ``.dynsym`` ->
``.dynstr``), byte-pattern scans for 16-bit stores and RIP-relative slot
references inside named FDE windows, a rel8/rel32 branch decoder for the
pinned instructions, and decoders for four jump tables (the execute-action
dispatcher, the status formatter, the ethabi ``Token`` Debug impl and the
ethabi word writer).

Against the pinned node #94 digest it checks the following and fails closed
(``EvidenceError``, exit 2) on the first difference:

* the function windows (``.eh_frame_hdr`` FDE starts and ends);
* the pinned instruction windows (every instruction's bytes), each inside its
  owner window, with every direct branch/call target decoded from the bytes;
* the decoded immediates and displacements (thresholds, cap formula, field
  offsets, record layout, Keccak parameters, kept digest bytes);
* the check order: each row's decision branch, its pass and fail edges, its
  status store and (for propagated statuses) the load and the path to the
  store, against a byte scan of every 16-bit store in the four windows;
* every call site of the four windows (direct E8 targets, register calls, and
  the slots used by the five windows: RELATIVE -> FDE start, GLOB_DAT ->
  symbol; PLT stubs -> JUMP_SLOT symbol), and the direct (E8 rel32) callers of
  the key functions in ``.text``;
* the status-formatter arms (status -> message bytes), the Token variant names,
  the ethabi word writer's Int/Uint arm, the dispatch arm for tag 122, the panic
  ``Location`` records and the lea that references each of them, the literals;
* the negative-control byte scans (sibling ``0x36f40d0``; the other caller of
  the volume producer, ``0x2766f70``).

It then proves the magic-number division for all u64, evaluates the cap at its
boundaries, and ships a stdlib Keccak-256 and an ethabi word encoder as a
labelled **model**. No target-produced address vector exists offline, so the
derived addresses are model outputs, not target vectors.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("state_roots", ROOT / "tools/state_roots.py")
sr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sr)
EvidenceError = sr.EvidenceError

TARGET_REL = "artifacts/node/94/hl-node"
TARGET = ROOT / TARGET_REL
FIRST_PARTY = "/home/ubuntu/hl/code_Mainnet/"
CRATES = "/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/"
RUSTC = "/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/"
M64 = (1 << 64) - 1

# ---- Function windows: name -> (FDE start, FDE end (exclusive), role). ----
# Roles are descriptions of what the bytes below show; names marked
# "label inferred" are not established by a symbol.
FUNCS = {
    "dispatcher": (0x2759240, 0x275A376, "execute-action dispatcher (jump table 0x3ede28)"),
    "handler": (0x27E3140, 0x27E3744, "callee of dispatcher table index 6 (tag 122)"),
    "creator": (0x36F3610, 0x36F3C15, "volume gate, cap, re-derive, address probe, name, insert, push"),
    "deriver": (0x36F3C20, 0x36F3ED0, "count lookup, 3 ethabi tokens, Keccak, keep 20 digest bytes"),
    "name_helper": (0x36F43C0, 0x36F4627, "name byte length 1..=16, duplicate-name check on 0x1344900 outputs"),
    "name_sibling": (0x36F40D0, 0x36F43BC, "the other direct caller of name_helper (negative control)"),
    "vec_entry": (0x3596680, 0x35967A8, "creator's callee before the push: returns X-0x18 on both paths; X is a "
                                        "bucket end on the vacant path; on the occupied path X comes from "
                                        "0x379a4d0 (inference)"),
    "ethabi_build3": (0x3C97900, 0x3C97A65, "writes 3 Token values, calls the encoder"),
    "ethabi_encode": (0x1592160, 0x15923AB, "contains ethabi-18.0.0 encoder.rs Location references"),
    "ethabi_words": (0x1591F20, 0x159215D, "called by ethabi_encode; calls the word writer per token"),
    "ethabi_word_writer": (0x1591CD0, 0x1591F16, "per-token word writer (jump table 0x25fba4)"),
    "ethabi_token_debug": (0x15906A0, 0x1590C59, "ethabi Token Debug impl (variant name per tag)"),
    "keccak_update": (0x4F59A10, 0x4F59E3A, "contains tiny-keccak-2.0.2 lib.rs Location references"),
    "keccak_finalize": (0x4F59E40, 0x4F5A13D, "contains tiny-keccak-2.0.2 lib.rs Location references"),
    "keccak_f": (0x4F59480, 0x4F59A02, "24-round loop over the table at 0x7d04c8"),
    "to_lowercase": (0x1344900, 0x1345578, "alloc str.rs:415/416 references + final-sigma compare (label inferred)"),
    "alloc_fail": (0x1346068, 0x134607D, "21 bytes, ends in a call, no ret (label inferred)"),
    "volume_producer": (0x275FEE0, 0x2760040, "folds once(master) + the master's records"),
    "volume_fold": (0x258B4E0, 0x258B64B, "fold over the producer's iterator state"),
    "volume_step": (0x2773BB0, 0x2773D5C, "per-user value; scaled_vlm/raw_vlm/impl_ntl references"),
    "volume_vec_fold": (0x26B2180, 0x26B252E, "per-record fold over the master's Vec (same references)"),
    "volume_report": (0x358DCD0, 0x358DE41, "callee of slot 0x5773190 on every volume carry; two ret paths"),
    "status_formatter": (0x37FFD40, 0x38033EB, "u16 status -> message (jump table 0x59a8d0)"),
    "user_lookup": (0x3743DF0, 0x374401F, "per-user record lookup used twice after success"),
    "other_volume_user": (0x2766F70, 0x2767BA9, "the other direct caller of volume_producer"),
    "other_consumer": (0x3421E20, 0x34224DE, "callee of other_volume_user through slot 0x5774dc0; a 0x57 store"),
    "other_entry": (0x1E5F770, 0x1E5FA62, "callee of dispatcher table index 1; calls other_volume_user"),
}

# ---- Pinned instruction windows: (name, owner, va, [instruction bytes], meaning). ----
# Generated once from GNU objdump 2.47 over each owner FDE window; every instruction's
# bytes are checked, and tests/test_subaccount_create.py re-decodes them with objdump.
SHAPES = [
    ('disp_bias', 'dispatcher', 0x2759298,
     ['498b0424', '488d488c', '4883f874', 'b814000000', '480f43c1'],
     'mov rax,[r12] ; lea rcx,[rax-0x74] ; cmp rax,0x74 ; mov eax,0x14 ; cmovae rax,rcx (table index = tag-0x74, tags below 0x74 -> index 20)'),
    ('disp_table', 'dispatcher', 0x27592ad,
     ['488d0d744bc9fd', '48630481', '4801c8', 'ffe0'],
     'lea rcx,[rip->table] ; movsxd rax,[rcx+rax*4] ; add rax,rcx ; jmp rax'),
    ('disp_arm', 'dispatcher', 0x2759d2a,
     ['4983c408', '418b4510', '89442410', '410f104500', '0f290424', '488d7c2468', '4889e2', '4c89e6', '4c89f9', 'e8ee930800'],
     'table-index-6 arm: build args, call the handler 0x27e3140'),
    ('disp_arm1', 'dispatcher', 0x27592bd,
     ['4983c408', '418b4510', '89442410', '410f104500', '0f290424', '488d7c2468', '4889e2', '4c89e6', '4c89f9', 'e88b6470ff'],
     'table-index-1 arm: build args, call 0x1e5f770'),
    ('h_args', 'handler', 0x27e3140,
     ['55', '4157', '4156', '4155', '4154', '53', '4881ecb8010000', '4989ce', '4989d7', '4989f5', '4889fb'],
     'prologue (6 pushes ; sub rsp,0x1b8) ; mov r14,rcx ; mov r15,rdx ; mov r13,rsi ; mov rbx,rdi (exchange*, master*, action*, out)'),
    ('h_tracker', 'handler', 0x27e315d,
     ['4c8da1e0370000'],
     'lea r12,[rcx+0x37e0] (tracker base passed to deriver and creator)'),
    ('h_derive_args', 'handler', 0x27e3164,
     ['8b4210', '89442410', '0f1002', '0f290424', '488d7c2478', '4889e2', '4c89e6'],
     'copy the master to rsp ; lea rdi,[rsp+0x78] ; mov rdx,rsp ; mov rsi,r12 (out = rsp+0x78, tracker, &master)'),
    ('h_call_derive', 'handler', 0x27e317d,
     ['ff15bd1df902'],
     'call [rip->0x5774f40] (deriver), out = rsp+0x78'),
    ('h_derive_load', 'handler', 0x27e3183,
     ['0fb7442478', '0f1044247a', '0f29442440', '8b8c248a000000', '894c2450'],
     'movzx eax,WORD PTR [rsp+0x78] (the deriver status) ; copy the address at rsp+0x7a to rsp+0x40 (xmm0, ecx)'),
    ('h_derive_status', 'handler', 0x27e319d,
     ['3d86010000', '0f850d010000'],
     'cmp eax,0x186 ; jne (non-0x186 deriver status -> propagate)'),
    ('h_user_guard', 'handler', 0x27e31d2,
     ['4983be5807000000', '0f8429010000'],
     'cmp QWORD PTR [r14+0x758],0x0 ; je (table at exchange+0x740 empty -> skip probe)'),
    ('h_user_ctrl', 'handler', 0x27e31fb,
     ['498b8e40070000', '498b9648070000'],
     'mov rcx,[r14+0x740] ; mov rdx,[r14+0x748] (table control bytes, bucket mask)'),
    ('h_user_stride', 'handler', 0x27e324d,
     ['4d6bc958'],
     'imul r9,r9,0x58 (0x58-byte buckets)'),
    ('h_user_match', 'handler', 0x27e327d,
     ['4181f9ffff0000', '0f84be000000'],
     'cmp r9d,0xffff ; je (all 20 key bytes equal -> 0xd8)'),
    ('h_user_exit', 'handler', 0x27e32a0,
     ['4585c0', '7564'],
     'test r8d,r8d ; jne (empty control byte seen -> key absent)'),
    ('h_derive_fail', 'handler', 0x27e32b5,
     ['0f108424c8000000', '0f114358', '0f1084248e000000', 'f30f6f8c249e000000', 'f30f6f9424ae000000',
      'f30f6f9c24be000000', 'f30f7f5b4e', 'f30f7f533e', 'f30f7f4b2e', '0f11431e', '8b4c2450', '894b1a',
      '660f6f442440', 'e95c020000'],
     "deriver failure path: copy the callee's payload (xmm0..xmm3, ecx) to [rbx+0x1a..0x68] ; jmp 0x27e3565"),
    ('h_dup_copy', 'handler', 0x27e3348,
     ['8b842430010000', '89431a', '0f28842420010000', '0f11430a', '66c74308d800', 'e905020000'],
     'copy the derived address to [rbx+0xa..0x1e] ; mov WORD PTR [rbx+0x8],0xd8 ; jmp (error envelope)'),
    ('h_call_volume', 'handler', 0x27e3309,
     ['4c89a42418010000', '4c89f7', '4c89fe', 'e8c4cbf7ff', '4889842410010000'],
     'mov [rsp+0x118],r12 ; mov rdi,r14 ; mov rsi,r15 ; call 0x275fee0 ; mov [rsp+0x110],rax (producer result saved)'),
    ('h_call_creator', 'handler', 0x27e339d,
     ['488d7c2478', '488d542440', '4889e1', '488bb42418010000', '4c8b842410010000', 'ff15881bf902'],
     'lea rdi,[rsp+0x78] ; lea rdx,[rsp+0x40] ; mov rcx,rsp ; mov rsi,[rsp+0x118] ; mov r8,[rsp+0x110] ; call [rip->0x5774f48] (creator; r8 = volume)'),
    ('h_creator_load', 'handler', 0x27e33c0,
     ['0fb7442478', '0f1044247a', '0f29442460', '8b8c248a000000', '894c2470'],
     'movzx eax,WORD PTR [rsp+0x78] (the creator status) ; copy the address at rsp+0x7a to rsp+0x60 (xmm0, ecx)'),
    ('h_creator_status', 'handler', 0x27e33da,
     ['3d86010000', '0f8531010000'],
     'cmp eax,0x186 ; jne (non-0x186 creator status -> propagate)'),
    ('h_r12_users', 'handler', 0x27e33e5,
     ['4d8da640070000'],
     'lea r12,[r14+0x740]'),
    ('h_lookup_slot', 'handler', 0x27e33fe,
     ['4d8daed0050000', '488b2dec14f902'],
     'lea r13,[r14+0x5d0] ; mov rbp,[rip->0x57748f8] (per-user lookup 0x3743df0)'),
    ('h_lookup_master', 'handler', 0x27e340c,
     ['488dbc2440010000', '4c89ee', '4c89fa', 'ffd5'],
     'lea rdi,[rsp+0x140] ; mov rsi,r13 ; mov rdx,r15 ; call rbp (lookup(master) -> rsp+0x140)'),
    ('h_lookup_sub', 'handler', 0x27e342d,
     ['488d7c2478', '4889e2', '4c89ee', 'ffd5'],
     'lea rdi,[rsp+0x78] ; mov rdx,rsp ; mov rsi,r13 ; call rbp (lookup(sub) -> rsp+0x78)'),
    ('h_lookup_cmp', 'handler', 0x27e343a,
     ['f20f108424b0010000', '660f2e8424e8000000', '0f85fc010000', '0f8af6010000'],
     'movsd xmm0,[rsp+0x1b0] ; ucomisd xmm0,[rsp+0xe8] ; jne ; jp (first of the field compares; any difference -> insert)'),
    ('h_record_insert', 'handler', 0x27e364e,
     ['498dbe90060000', '8b442430', '89442410', '0f28442420', '0f290424', '4889e6', 'e8d2117aff', '48c70001000000', '0f10842440010000'],
     "lea rdi,[r14+0x690] ; .. ; mov rsi,rsp ; call 0x1f84840 ; mov QWORD PTR [rax],0x1 ; movups xmm0,[rsp+0x140] (copy the master's lookup result under the sub key)"),
    ('h_record_tail', 'handler', 0x27e36d1,
     ['488b8c24b0010000', '48894878'],
     'mov rcx,[rsp+0x1b0] ; mov [rax+0x78],rcx (last qword of the 0x78-byte record)'),
    ('h_user_insert', 'handler', 0x27e36ee,
     ['4889e6', '4c89e7', 'e8b7127aff', '4981c618030000'],
     'mov rsi,rsp ; mov rdi,r12 ; call 0x1f849b0 ; add r14,0x318'),
    ('h_entry_insert', 'handler', 0x27e3711,
     ['4889e6', '4c89f7', 'e814147aff', 'c60306'],
     'mov rsi,rsp ; mov rdi,r14 ; call 0x1f84b30 ; mov BYTE PTR [rbx],0x6 (outer success byte)'),
    ('h_creator_fail', 'handler', 0x27e3516,
     ['0f108424c8000000', '0f114358', '0f1084248e000000', 'f30f6f8c249e000000', 'f30f6f9424ae000000',
      'f30f6f9c24be000000', 'f30f7f5b4e', 'f30f7f533e', 'f30f7f4b2e', '0f11431e', '8b4c2470', '894b1a',
      '660f6f442460', 'f30f7f430a'],
     "creator failure path: copy the callee's payload (xmm0..xmm3, ecx) to [rbx+0xa..0x68]; 0x27e3565 is the deriver path's jmp target"),
    ('h_err_envelope', 'handler', 0x27e356a,
     ['66894308', 'c6030e'],
     'mov WORD PTR [rbx+0x8],ax ; mov BYTE PTR [rbx],0xe (u16 status into the error envelope)'),
    ('c_args', 'creator', 0x36f3610,
     ['55', '4157', '4156', '4155', '4154', '53', '4881ec28010000', '4989cf', '4889fb'],
     'prologue (6 pushes ; sub rsp,0x128) ; mov r15,rcx ; mov rbx,rdi (name String*, out)'),
    ('c_volume_gate', 'creator', 0x36f3627,
     ['4981f880969800', '7328'],
     'cmp r8,0x989680 ; jae (volume >= 0x989680 continues)'),
    ('c_volume_report', 'creator', 0x36f3630,
     ['f2490f2ac0', 'f20f5e052373b1fc', '66c703dd00', 'f20f114308'],
     'cvtsi2sd xmm0,r8 ; divsd xmm0,[rip->0x20a960] ; mov WORD PTR [rbx],0xdd ; movsd [rbx+0x8],xmm0'),
    ('c_cap_guard', 'creator', 0x36f3658,
     ['4989d6', '4989f4', '48837e1800', '0f84fb000000'],
     'mov r14,rdx ; mov r12,rsi ; cmp QWORD PTR [rsi+0x18],0x0 ; je (user_to_sub_accounts empty -> no cap check)'),
    ('c_cap_save', 'creator', 0x36f3669,
     ['4d89c5'],
     'mov r13,r8 (keep the volume operand)'),
    ('c_cap_ctrl', 'creator', 0x36f3680,
     ['498b3424', '498b542408'],
     'mov rsi,[r12] ; mov rdx,[r12+0x8] (user_to_sub_accounts control bytes, mask)'),
    ('c_cap_operand', 'creator', 0x36f36c0,
     ['4c89e9'],
     'mov rcx,r13 (volume operand for the cap multiply)'),
    ('c_cap_stride', 'creator', 0x36f36d1,
     ['4f8d1452', '49c1e204'],
     'lea r10,[r10+r10*2] ; shl r10,0x4 (0x30-byte buckets)'),
    ('c_cap_match', 'creator', 0x36f3702,
     ['4181fbffff0000', '7429'],
     'cmp r11d,0xffff ; je (master found)'),
    ('c_cap_absent', 'creator', 0x36f3718,
     ['660f74d1', '660fd7ca', '85c9', '7540'],
     'pcmpeqb ; pmovmskb ; test ecx,ecx ; jne (master absent -> no cap check)'),
    ('c_cap_formula', 'creator', 0x36f3734,
     ['48babfd5edbdcefee6db', '4889c8', '48f7e2', '48c1ea21', '4883fa28', 'b828000000', '480f42c2', '4883c00a', '4a394416f8', '0f8366020000'],
     'movabs rdx,M ; mov rax,rcx ; mul rdx ; shr rdx,0x21 ; cmp rdx,0x28 ; mov eax,0x28 ; cmovb rax,rdx ; add rax,0xa ; cmp [rsi+r10-0x8],rax ; jae (count >= cap -> 0xd6)'),
    ('c_rederive', 'creator', 0x36f3764,
     ['488d7c2450', '4c89e6', '4c89f2', 'ff15cb170802'],
     'lea rdi,[rsp+0x50] ; mov rsi,r12 ; mov rdx,r14 ; call [rip->0x5774f40] (re-derive)'),
    ('c_rederive_load', 'creator', 0x36f3775,
     ['0fb7442450', '0f10442452', '0f29442430', '8b4c2462', '894c2440'],
     'movzx eax,WORD PTR [rsp+0x50] (the deriver status) ; copy the address at rsp+0x52 to rsp+0x30 (xmm0, ecx)'),
    ('c_rederive_status', 'creator', 0x36f378c,
     ['3d86010000', '0f8508010000'],
     'cmp eax,0x186 ; jne (propagate)'),
    ('c_once', 'creator', 0x36f37ab,
     ['8b05e7730802', '85c0', '0f85cd030000'],
     'mov eax,[rip->0x577ab98] ; test eax,eax ; jne (once-init global)'),
    ('c_map2_guard', 'creator', 0x36f37cd,
     ['49837c244800', '0f8428010000'],
     'cmp QWORD PTR [r12+0x48],0x0 ; je (sub_account_to_master empty -> skip probe)'),
    ('c_map2_ctrl', 'creator', 0x36f37ef,
     ['498b4c2430', '498b542438'],
     'mov rcx,[r12+0x30] ; mov rdx,[r12+0x38]'),
    ('c_map2_stride', 'creator', 0x36f383d,
     ['4f8d0c89', 'f3420f6f1cce'],
     'lea r9,[r9+r9*4] ; movdqu xmm3,[rsi+r9*8] (0x28-byte buckets)'),
    ('c_map2_match', 'creator', 0x36f3867,
     ['4181f9ffff0000', '0f8465010000'],
     'cmp r9d,0xffff ; je (derived address already a key -> 0xd8)'),
    ('c_map2_exit', 'creator', 0x36f388a,
     ['4585c0', '7572'],
     'test r8d,r8d ; jne (key absent)'),
    ('c_rederive_fail', 'creator', 0x36f389f,
     ['0f108424a0000000', '0f114350', '0f10442466', 'f30f6f4c2476', 'f30f6f942486000000', 'f30f6f9c2496000000',
      'f30f7f5b46', 'f30f7f5336', 'f30f7f4b26', '0f114316', '8b4c2440', '894b12', '660f6f442430', 'f30f7f4302'],
     "re-derive failure path: copy the callee's payload (xmm0..xmm3, ecx) to [rbx+0x2..0x60]"),
    ('c_rederive_prop', 'creator', 0x36f38ed,
     ['668903'],
     'mov WORD PTR [rbx],ax (propagate a non-0x186 re-derive status)'),
    ('c_word_rbx6', 'creator', 0x36f3980,
     ['66894306'],
     'mov WORD PTR [rbx+0x6],ax (not the status field)'),
    ('c_word_rsp_c', 'creator', 0x36f3b03,
     ['668944240c'],
     'mov WORD PTR [rsp+0xc],ax (local, not the status field)'),
    ('c_name_len', 'creator', 0x36f3901,
     ['4d8b2f', '498b4708', '4d8b7f10', '4983ff64', '0f8601010000'],
     'mov r13,[r15] ; mov rax,[r15+0x8] ; mov r15,[r15+0x10] ; cmp r15,0x64 ; jbe (String cap, ptr, byte length; > 100 -> 0x143)'),
    ('c_tag_143', 'creator', 0x36f3916,
     ['66bd4301'],
     'mov bp,0x143'),
    ('c_store_bp', 'creator', 0x36f39c5,
     ['66892b', 'eb38'],
     "mov WORD PTR [rbx],bp ; jmp (0x143 or the name helper's status)"),
    ('c_tag_d6', 'creator', 0x36f39ca,
     ['66c703d600'],
     'mov WORD PTR [rbx],0xd6'),
    ('c_dup_d8', 'creator', 0x36f39d9,
     ['8b442420', '894312', '0f28442410', '0f114302', '66c703d800'],
     'copy the derived address to [rbx+0x2..0x16] ; mov WORD PTR [rbx],0xd8'),
    ('c_call_helper', 'creator', 0x36f3a17,
     ['488d7c2450', '4c89e6', '4c89f2', '48890424', '4889c1', '4d89f8', 'e88f090000'],
     'lea rdi,[rsp+0x50] ; mov rsi,r12 ; mov rdx,r14 ; mov [rsp],rax ; mov rcx,rax ; mov r8,r15 ; call 0x36f43c0 (rcx = name ptr, r8 = byte length)'),
    ('c_helper_status', 'creator', 0x36f3a31,
     ['0fb76c2450', '81fd86010000', '0f85bc000000'],
     'movzx ebp,WORD PTR [rsp+0x50] ; cmp ebp,0x186 ; jne (helper status -> bp -> propagate)'),
    ('c_insert', 'creator', 0x36f3a42,
     ['498d742430', '488d7c2450', '488d542410', '4c89f1', 'e807b20a00', '807c245001', '0f8462010000'],
     'lea rsi,[r12+0x30] ; lea rdi,[rsp+0x50] ; lea rdx,[rsp+0x10] ; mov rcx,r14 ; call 0x379ec60 ; cmp BYTE PTR [rsp+0x50],0x1 ; je (previous value present -> assert panic)'),
    ('c_vec_entry', 'creator', 0x36f3a64,
     ['418b4610', '89442460', 'f3410f6f06', '660f7f442450', '488d742450', '4c89e7', 'e8fc2beaff', '4989c4',
      '488b6810', '483b28', '7509', '4c89e7', 'ff15df090802'],
     'copy the master (r14) to rsp+0x50 ; lea rsi,[rsp+0x50] ; mov rdi,r12 (tracker+0) ; call 0x3596680 ; mov r12,rax ; mov rbp,[rax+0x10] (len) ; cmp rbp,[rax] (cap) ; jne ; .. ; call [rip->0x5774478] (grow)'),
    ('c_push', 'creator', 0x36f3a99,
     ['498b442408', '4889e9', '48c1e106', '4c892c08', '488b1424', '4889540808', '4c897c0810', '0f28442410', '0f11440818', '8b542420', '89540828', '410f1006', '0f1144082c', '418b5610', '8954083c', '48ffc5', '49896c2410'],
     'push {name String at +0x0/+0x8/+0x10, sub address at +0x18..+0x2c, master address at +0x2c..+0x40} (shl rcx,0x6 = 0x40-byte records); len += 1'),
    ('c_tag_186', 'creator', 0x36f3ae2,
     ['8b442420', '894312', '660f6f442410', 'f30f7f4302', '66c7038601'],
     'copy the sub address to [rbx+0x2..0x16] ; mov WORD PTR [rbx],0x186'),
    ('c_assert_panic', 'creator', 0x36f3bc6,
     ['488d3de052eafc', '488d1564e0ff01', 'be55000000', 'ff1529a50702', '0f0b'],
     'lea rdi,[rip->0x598ead] ; lea rdx,[rip->0x56f1c38] ; mov esi,0x55 ; call [rip->0x576e108] ; ud2'),
    ('d_args0', 'deriver', 0x36f3c20,
     ['4157', '4156', '53', '4881ec60020000', '4989d6', '4889fb'],
     'prologue (3 pushes ; sub rsp,0x260) ; mov r14,rdx ; mov rbx,rdi (master*, out)'),
    ('d_guard', 'deriver', 0x36f3c32,
     ['48837e1800', '0f84d8000000'],
     'cmp QWORD PTR [rsi+0x18],0x0 ; je (no entries -> count 0)'),
    ('d_ctrl', 'deriver', 0x36f3c53,
     ['498b0f', '498b5708'],
     'mov rcx,[r15] ; mov rdx,[r15+0x8]'),
    ('d_stride', 'deriver', 0x36f3ca1,
     ['4f8d0c49', '49c1e104'],
     'lea r9,[r9+r9*2] ; shl r9,0x4 (0x30-byte buckets)'),
    ('d_match', 'deriver', 0x36f3cd2,
     ['4181faffff0000', '7433'],
     'cmp r10d,0xffff ; je (master found)'),
    ('d_exit', 'deriver', 0x36f3cf9,
     ['4585c0', '751a'],
     'test r8d,r8d ; jne (master absent, r15 = 0)'),
    ('d_count', 'deriver', 0x36f3d0e,
     ['4e8b7c09f8', 'eb03', '4531ff'],
     "mov r15,[rcx+r9-0x8] ; jmp ; xor r15d,r15d (count = [bucket_end-0x8] = bucket+0x28, the Vec len of the master's entry; else 0)"),
    ('d_alloc16', 'deriver', 0x36f3d18,
     ['bf10000000', 'ff15b5a20702'],
     'mov edi,0x10 ; call [rip->0x576dfd8]'),
    ('d_label', 'deriver', 0x36f3d2c,
     ['0f10056df8b0fc', '0f1100'],
     "movups xmm0,[rip->0x2035a0] ; movups [rax],xmm0 (b'createSubAccount')"),
    ('d_args', 'deriver', 0x36f3d36,
     ['48c744246810000000', '4889442470', '48c744247810000000', '410f1006', '0f11842480000000', '418b4610', '89842490000000', '4c89bc2498000000', '488d7c2408', '488d742468', 'e8853b5a00'],
     'String{cap 0x10, ptr, len 0x10} at rsp+0x68, master at rsp+0x80, count (r15) at rsp+0x98 ; call 0x3c97900'),
    ('d_keccak_init', 'deriver', 0x36f3df0,
     ['48c784247001000088000000', '66c78424780100000100'],
     'mov QWORD PTR [rsp+0x170],0x88 ; mov WORD PTR [rsp+0x178],0x1 (rate 136, delimiter 0x01)'),
    ('d_keccak_update', 'deriver', 0x36f3e06,
     ['4c8b742410', '488b542418', '488dbc24a0000000', '4c89f6', 'ff15b7a30702'],
     'mov r14,[rsp+0x10] ; mov rdx,[rsp+0x18] ; lea rdi,[rsp+0xa0] ; mov rsi,r14 ; call [rip->0x576e1d8] (absorb the encoded bytes)'),
    ('d_keccak_final', 'deriver', 0x36f3e21,
     ['4c8dbc2480010000', '488db424a0000000', 'bae0000000', '4c89ff', 'ff15a1a10702', '488d742420', 'ba20000000', '4c89ff', 'ff158ea30702'],
     'copy the 0xe0-byte state (memcpy) ; lea rsi,[rsp+0x20] ; mov edx,0x20 ; mov rdi,r15 ; call [rip->0x576e1e0] (32-byte digest at rsp+0x20)'),
    ('d_hash_copy', 'deriver', 0x36f3e52,
     ['0f28442420', '0f284c2430', '0f29442440', '0f294c2450'],
     'movaps xmm0,[rsp+0x20] ; movaps xmm1,[rsp+0x30] ; movaps [rsp+0x40],xmm0 ; movaps [rsp+0x50],xmm1'),
    ('d_hash_keep', 'deriver', 0x36f3e7b,
     ['8b442450', '894312', '0f28442440', '0f114302', '66c7038601'],
     'mov eax,[rsp+0x50] ; mov [rbx+0x12],eax ; movaps xmm0,[rsp+0x40] ; movups [rbx+0x2],xmm0 ; mov WORD PTR [rbx],0x186'),
    ('d_ret', 'deriver', 0x36f3e90,
     ['4889d8', '4881c460020000', '5b', '415e', '415f', 'c3'],
     'mov rax,rbx ; add rsp,0x260 ; pop rbx ; pop r14 ; pop r15 ; ret'),
    ('d_alloc_fail', 'deriver', 0x36f3ea0,
     ['bf01000000', 'be10000000', 'ff1508a10702'],
     'mov edi,0x1 ; mov esi,0x10 ; call [rip->0x576dfb8] (-> 0x1346068)'),
    ('e_entry', 'vec_entry', 0x3596680,
     ['4883ec38', '4889f2', '4889fe', '488d7c2410', 'e83c3e2000', '488b4c2410', '4885c9', '0f84ba000000'],
     'sub rsp,0x38 ; mov rdx,rsi (key) ; mov rsi,rdi (map) ; lea rdi,[rsp+0x10] ; call 0x379a4d0 ; mov rcx,[rsp+0x10] ; test rcx,rcx ; je (null -> occupied path)'),
    ('e_vacant', 'vec_entry', 0x3596703,
     ['49f7d9', '4b8d3c49', '48c1e704', '4180e001', '410fb6c0', '48294110', '488d043a', '4889743ad0', '488b3424',
      '4889743ad8', '8b742408', '89743ae0', '48c7443ae800000000', '48c7443af008000000', '48c7443af800000000',
      '48ff4118', '4883c0e8', '4883c438', 'c3'],
     'bucket_end = ctrl - idx*0x30 ; 20-byte key at bucket_end-0x30 ; Vec {cap 0, ptr 8, len 0} at bucket_end-0x18..-0x8 ; items += 1 ; return bucket_end-0x18'),
    ('e_occupied', 'vec_entry', 0x359675c,
     ['488b442418', '4883c0e8', '4883c438', 'c3'],
     'mov rax,[rsp+0x18] ; add rax,-0x18 ; add rsp,0x38 ; ret (occupied path: X = [rsp+0x18], which comes from '
     '0x379a4d0 (inference); returns X-0x18)'),
    ('n_out', 'name_helper', 0x36f43c0,
     ['55', '4157', '4156', '4155', '4154', '53', '4883ec48', '4989fc'],
     'prologue (6 pushes ; sub rsp,0x48) ; mov r12,rdi (out)'),
    ('n_len', 'name_helper', 0x36f43d1,
     ['498d40ef', '4883f8ef', '770c', '6641c70424d900', 'e9f6010000'],
     'lea rax,[r8-0x11] ; cmp rax,0xffffffffffffffef ; ja ; mov WORD PTR [r12],0xd9 ; jmp'),
    ('n_lower_new', 'name_helper', 0x36f43ed,
     ['488d7c2418', '4889ce', '4c89c2', 'ff15529c0702'],
     'lea rdi,[rsp+0x18] ; mov rsi,rcx ; mov rdx,r8 ; call [rip->0x576e050] (0x1344900 on the new name)'),
    ('n_ok_init', 'name_helper', 0x36f43fe,
     ['66bb8601', '49837f1800', '0f84b4010000'],
     'mov bx,0x186 ; cmp QWORD PTR [r15+0x18],0x0 ; je'),
    ('n_ctrl', 'name_helper', 0x36f4420,
     ['498b0f', '498b5708'],
     'mov rcx,[r15] ; mov rdx,[r15+0x8]'),
    ('n_stride', 'name_helper', 0x36f446b,
     ['4f8d0c49', '49c1e104'],
     'lea r9,[r9+r9*2] ; shl r9,0x4 (0x30-byte buckets)'),
    ('n_match', 'name_helper', 0x36f449c,
     ['4181faffff0000', '742f'],
     'cmp r10d,0xffff ; je (master found)'),
    ('n_exit', 'name_helper', 0x36f44bb,
     ['4585c0', '0f85fd000000'],
     'test r8d,r8d ; jne (master absent -> ok)'),
    ('n_vec', 'name_helper', 0x36f44d4,
     ['4a8b5c09f8', '4885db', '0f84db000000', '4c892424', '4e8b7409f0', '48c1e306'],
     'mov rbx,[rcx+r9-0x8] ; test rbx,rbx ; je ; mov [rsp],r12 ; mov r14,[rcx+r9-0x10] ; shl rbx,0x6 (Vec len, ptr; 0x40-byte records)'),
    ('n_new_lowered', 'name_helper', 0x36f44ef,
     ['488b442420', '4889442408', '488b6c2428'],
     'mov rax,[rsp+0x20] ; mov [rsp+0x8],rax ; mov rbp,[rsp+0x28] (lowered new name ptr, len)'),
    ('n_lower_slot', 'name_helper', 0x36f4506,
     ['4c8b3d439b0702'],
     'mov r15,[rip->0x576e050]'),
    ('n_dup_test', 'name_helper', 0x36f4520,
     ['85ed', '4989dd', '4c89fb', '4c89f5', '4c8b742410', '4c8b3d199b0702', '0f84af000000'],
     'test ebp,ebp ; .. ; je (bcmp result 0 -> 0xd7)'),
    ('n_next', 'name_helper', 0x36f453d,
     ['4983c440', '4c39e3', '7473'],
     "add r12,0x40 ; cmp rbx,r12 ; je (end of the master's Vec)"),
    ('n_lower_existing', 'name_helper', 0x36f4546,
     ['4b8b742608', '4b8b542610', '4c89ef', '41ffd7'],
     "mov rsi,[r14+r12+0x8] ; mov rdx,[r14+r12+0x10] ; mov rdi,r13 ; call r15 (0x1344900 on an existing record's name)"),
    ('n_len_cmp', 'name_helper', 0x36f4556,
     ['48396c2440', '7543'],
     'cmp [rsp+0x40],rbp ; jne (lowered lengths differ -> next)'),
    ('n_bcmp', 'name_helper', 0x36f455d,
     ['4989df', '4c89eb', '4c8b6c2438', '4c89ef', '488b742408', '4989ee', '4889ea', 'ff15fc9d0702', '89c5'],
     '.. ; mov rdi,r13 ; mov rsi,[rsp+0x8] ; .. ; mov rdx,rbp ; call [rip->0x576e378] ; mov ebp,eax (bcmp of the two lowered names)'),
    ('n_ok_store', 'name_helper', 0x36f45b9,
     ['4c8b2424', '66bb8601', '6641891c24'],
     'mov r12,[rsp] ; mov bx,0x186 ; mov WORD PTR [r12],bx'),
    ('n_dup_store', 'name_helper', 0x36f45ec,
     ['66bbd700', '4c8b2424', '6641891c24'],
     'mov bx,0xd7 ; mov r12,[rsp] ; mov WORD PTR [r12],bx'),
    ('b_args', 'ethabi_build3', 0x3c97900,
     ['4157', '4156', '4155', '4154', '53', '4883ec20', '4989f7', '4989fe'],
     'prologue (5 pushes ; sub rsp,0x20) ; mov r15,rsi (the deriver\'s args) ; mov r14,rdi (out)'),
    ('b_alloc', 'ethabi_build3', 0x3c97913,
     ['bf78000000', 'ff15ba66ad01'],
     'mov edi,0x78 ; call [rip->0x576dfd8] (3 tokens of 0x28 bytes)'),
    ('b_count', 'ethabi_build3', 0x3c9793c,
     ['498b4730', 'c60306'],
     'mov rax,[r15+0x30] (count) ; mov BYTE PTR [rbx],0x6 (token 0 tag)'),
    ('b_tok1', 'ethabi_build3', 0x3c9795d,
     ['c6432800', '410f104718', '0f114329', '418b4f28', '894b39'],
     'mov BYTE PTR [rbx+0x28],0x0 (token 1 tag) ; copy the 20-byte master to [rbx+0x29..0x3d]'),
    ('b_tok2', 'ethabi_build3', 0x3c97971,
     ['c6435004', '48894358', '0f57c0', '0f114360', '48c7437000000000'],
     'mov BYTE PTR [rbx+0x50],0x4 (token 2 tag) ; mov [rbx+0x58],rax ; zero [rbx+0x60..0x78] (limbs: count, 0, 0, 0)'),
    ('b_encode', 'ethabi_build3', 0x3c9799e,
     ['ba03000000', '4c89f7', '4889de', 'ff157173ad01'],
     'mov edx,0x3 ; mov rdi,r14 ; mov rsi,rbx ; call [rip->0x576ed20] (encode 3 tokens)'),
    ('enc_words', 'ethabi_encode', 0x159224a,
     ['488d7c2418', '4889de', '4c89f2', 'e8c6fcffff'],
     'lea rdi,[rsp+0x18] ; mov rsi,rbx ; mov rdx,r14 ; call 0x1591f20'),
    ('words_call_a', 'ethabi_words', 0x1592004,
     ['498b742408', '488b3c24', 'e8befcffff'],
     'mov rsi,[r12+0x8] ; mov rdi,[rsp] ; call 0x1591cd0 (rsi = a Token pointer)'),
    ('words_call_b', 'ethabi_words', 0x15920cb,
     ['4a8b742308', '4c89f7', 'e8f8fbffff'],
     'mov rsi,[rbx+r12+0x8] ; mov rdi,r14 ; call 0x1591cd0'),
    ('ww_dispatch', 'ethabi_word_writer', 0x1591ce3,
     ['0fb606', '4883f806', '0f87f7010000', '4889fb', '488d0daadeccfe', '48630481', '4801c8', 'ffe0'],
     'movzx eax,BYTE PTR [rsi] (Token tag) ; cmp rax,0x6 ; ja ; mov rbx,rdi ; lea rcx,[rip->0x25fba4] ; movsxd rax,[rcx+rax*4] ; add rax,rcx ; jmp rax'),
    ('ww_int', 'ethabi_word_writer', 0x1591d24,
     ['4c8b7608', '4c8b7e10', '4c8b6618', '4c8b6e20', '490fcd', '490fcc', '490fcf', '490fce', '488b6b10', '483b2b',
      '7509', '4889df', 'ff1596eb1d04', '488b4308', '4889e9', '48c1e105', '4c892c08', '4c89640808', '4c897c0810',
      '4c89740818', '48ffc5', '48896b10', 'e949010000'],
     'Int/Uint arm: load limbs [rsi+0x8..0x28] ; bswap each ; push one 32-byte word (shl rcx,0x5): limb 3 at +0x0 .. limb 0 at +0x18 ; len += 1'),
    ('p_args', 'volume_producer', 0x275fee7,
     ['4989f6', '4889fb'],
     'mov r14,rsi ; mov rbx,rdi (master*, exchange*)'),
    ('p_guard', 'volume_producer', 0x275fefd,
     ['4883bff837000000', '0f84e6000000'],
     'cmp QWORD PTR [rdi+0x37f8],0x0 ; je (no user_to_sub_accounts entries)'),
    ('p_ctrl', 'volume_producer', 0x275ff21,
     ['488b8be0370000', '488bb3e8370000'],
     'mov rcx,[rbx+0x37e0] ; mov rsi,[rbx+0x37e8]'),
    ('p_stride', 'volume_producer', 0x275ff76,
     ['4f8d1452', '49c1e204'],
     'lea r10,[r10+r10*2] ; shl r10,0x4 (0x30-byte buckets)'),
    ('p_match', 'volume_producer', 0x275ffa3,
     ['4181fbffff0000', '7432'],
     'cmp r11d,0xffff ; je (master found)'),
    ('p_vecptr', 'volume_producer', 0x275ffde,
     ['4c01d1', '4889ca', '488d42e8', '4885d2', '480f44c2', 'eb02', '31c0'],
     'rdx = bucket end ; lea rax,[rdx-0x18] ; cmove (rax = &Vec at bucket+0x18, or null) ; xor eax,eax'),
    ('p_iter_call', 'volume_producer', 0x275fff3,
     ['c644245001', '410f1006', '0f11442451', '418b4e10', '894c2461', '48c744242001000000', '4889442428', '48c744243000000000', '48c744244000000000', '488d7c2420', '31f6', '4889da', 'e8a8b4e2ff', '4883c468', '5b', '415e', 'c3'],
     'once(master) tag 1 at rsp+0x50, master at rsp+0x51 ; [rsp+0x20]=1, [rsp+0x28]=&Vec, [rsp+0x30]=0, [rsp+0x40]=0 ; call 0x258b4e0(&state, 0, exchange) ; add rsp,0x68 ; pop ; pop ; ret'),
    ('f_ctx', 'volume_fold', 0x258b4ee,
     ['4889f0', '4889542410'],
     'mov rax,rsi (acc) ; mov [rsp+0x10],rdx (exchange, the third argument)'),
    ('f_once', 'volume_fold', 0x258b4f6,
     ['0fb64f30', '80f902', '743c', '488d542410', '48891424', 'f6c101', '742e'],
     'movzx ecx,BYTE PTR [rdi+0x30] ; cmp cl,0x2 ; je ; .. ; test cl,0x1 ; je'),
    ('f_once_call', 'volume_fold', 0x258b50d,
     ['488d542430', '8b4f41', '894c2440', '0f104731', '0f11442430', '4889442428', '4889e1', '4889fb', '4889cf', '4889c6', 'e878861e00'],
     'copy the once() address to rsp+0x30 ; call 0x2773bb0(ctx, acc, &address)'),
    ('f_state', 'volume_fold', 0x258b53b,
     ['488b17', '4883fa02', '0f84f4000000', '488b7708', '488b5f10', '488b6f18', '4c8b6720', '4c8b6f28'],
     'mov rdx,[rdi] ; cmp rdx,0x2 ; je ; load Vec ptr and front/back slice iterators'),
    ('f_ctx2', 'volume_fold', 0x258b55c,
     ['488b4c2410', '48894c2408'],
     'mov rcx,[rsp+0x10] ; mov [rsp+0x8],rcx (exchange copy for the Vec fold context)'),
    ('f_front', 'volume_fold', 0x258b566,
     ['4885db', '7469'],
     'test rbx,rbx ; je (front slice iterator null)'),
    ('f_front_loop', 'volume_fold', 0x258b5bc,
     ['e8ef851e00', '4883c340', '48ffcd', '75d6'],
     'call 0x2773bb0 ; add rbx,0x40 ; dec rbp ; jne'),
    ('f_vec', 'volume_fold', 0x258b5d4,
     ['f6c201', '7410', '488d542408', '4889f7', '4889c6', 'e8976b1200'],
     "test dl,0x1 ; je ; lea rdx,[rsp+0x8] ; mov rdi,rsi ; mov rsi,rax ; call 0x26b2180 (fold the master's Vec)"),
    ('f_back', 'volume_fold', 0x258b5e9,
     ['4d85e4', '744e'],
     'test r12,r12 ; je (back slice iterator null)'),
    ('v_null', 'volume_vec_fold', 0x26b2191,
     ['4889f5', '4885ff', '0f847c030000', '488b4710', '4889442430', '4885c0', '0f846a030000'],
     'mov rbp,rsi ; test rdi,rdi ; je ; mov rax,[rdi+0x10] ; mov [rsp+0x30],rax ; test rax,rax ; je (null or empty Vec -> return acc)'),
    ('v_ctx', 'volume_vec_fold', 0x26b21af,
     ['488b1a', '488d8380000000', '4889442420'],
     'mov rbx,[rdx] (exchange) ; lea rax,[rbx+0x80] ; mov [rsp+0x20],rax (base lookup map)'),
    ('v_ptr', 'volume_vec_fold', 0x26b21be,
     ['488b4708', '4889442418'],
     'mov rax,[rdi+0x8] ; mov [rsp+0x18],rax (Vec data pointer)'),
    ('v_entry', 'volume_vec_fold', 0x26b21d5,
     ['4889c8', '48c1e006', '488b542418', '8b4c0228', '894c2470', '0f10440218', '0f29442460'],
     'mov rax,rcx ; shl rax,0x6 ; .. ; movups xmm0,[rdx+rax+0x18] (the 20-byte sub address of record i)'),
    ('v_records', 'volume_vec_fold', 0x26b220d,
     ['488b83c8050000', '4885c0', '0f8443020000', '48896c2438', '4c8ba3c0050000', '4869c0f0020000', '4c01e0',
      '4889442448'],
     'mov rax,[rbx+0x5c8] ; test ; je ; .. ; mov r12,[rbx+0x5c0] ; imul rax,rax,0x2f0 ; add rax,r12 ; mov [rsp+0x48],rax (end of the 0x2f0-byte records)'),
    ('v_map', 'volume_vec_fold', 0x26b2253,
     ['4983bc241001000000', '0f84ee000000', '4989ce', '498dbc2418010000', '4889e6', 'e82ba52e01', '4889c6', '48c1ee39',
      '498b8c24f8000000', '498b942400010000'],
     'cmp QWORD PTR [r12+0x110],0x0 ; je ; .. ; lea rdi,[r12+0x118] ; mov rsi,rsp ; call 0x399c7a0 ; .. ; mov rcx,[r12+0xf8] ; mov rdx,[r12+0x100] (the map at record+0xf8)'),
    ('v_bucket', 'volume_vec_fold', 0x26b22be,
     ['f3450fbcc8', '4901c1', '4921d1', '49f7d9', '4d6bc978'],
     'tzcnt r9d,r8d ; add r9,rax ; and r9,rdx ; neg r9 ; imul r9,r9,0x78 (0x78-byte buckets)'),
    ('v_value', 'volume_vec_fold', 0x26b23a2,
     ['488d59a0', '4885c9', '480f44d9', '4c89f1', '8b054a3f0d03', '85c0', '75a2', '4885db', '488d05dc3e0d03',
      '480f44d8', '4c8b6b40', '4c8b7b48'],
     'lea rbx,[rcx-0x60] (value = bucket_end-0x60, or 0) ; .. ; cmove rbx,[rip->0x57862a0] (default) ; mov r13,[rbx+0x40] ; mov r15,[rbx+0x48]'),
    ('v_next', 'volume_vec_fold', 0x26b23e0,
     ['4981c4f0020000', '4c89f5', '4889d9', '4c3b642448', '0f8548feffff', 'eb56'],
     'add r12,0x2f0 ; mov rbp,r14 ; mov rcx,rbx ; cmp r12,[rsp+0x48] ; jne ; jmp'),
    ('s_entry', 'volume_step', 0x2773bb0,
     ['55', '4157', '4156', '4155', '4154', '53', '4883ec58', '4889f5', '488b07', '488b38', '8b4210', '89442430',
      '4889542418', '0f1002', '0f29442420'],
     'prologue ; mov rbp,rsi (acc) ; mov rax,[rdi] ; mov rdi,[rax] (exchange = [[ctx]]) ; copy the user (rdx) to rsp+0x20'),
    ('s_records', 'volume_step', 0x2773bdb,
     ['488b87c8050000', '4885c0', '0f84d5000000'],
     'mov rax,[rdi+0x5c8] ; test rax,rax ; je (no records -> R = 0)'),
    ('s_loop', 'volume_step', 0x2773beb,
     ['48896c2410', '48897c2408', '4c8ba7c0050000', '4869e8f0020000', '4981c4f8000000', '31db', '4531f6', '90',
      '488b4c2418', '8b4110', '89442450', '0f1001', '0f29442440', '4c89e7', '488d742440', 'e8bf1bf800'],
     'mov r12,[rdi+0x5c0] ; imul rbp,rax,0x2f0 ; add r12,0xf8 ; xor ebx,ebx ; xor r14d,r14d ; .. ; mov rdi,r12 (record+0xf8) ; lea rsi,[rsp+0x40] (&user) ; call 0x36f57f0'),
    ('s_sum', 'volume_step', 0x2773c31,
     ['4c8b6840', '488b4048', '4d89ef', '4901df', '7220', '4989c5', '4d01f5', '7246'],
     'mov r13,[rax+0x40] ; mov rax,[rax+0x48] ; mov r15,r13 ; add r15,rbx ; jb ; mov r13,rax ; add r13,r14 ; jb'),
    ('s_next', 'volume_step', 0x2773c49,
     ['4981c4f0020000', '4c89fb', '4d89ee', '4881c510fdffff', '75b1', 'eb50'],
     'add r12,0x2f0 ; mov rbx,r15 ; mov r14,r13 ; add rbp,-0x2f0 ; jne (next record) ; jmp'),
    ('s_join', 'volume_step', 0x2773cb1,
     ['49f7d5', '488b6c2410', '488b7c2408', 'eb0a', '49c7c5ffffffff', '4531ff'],
     'not r13 (complement of the parallel sum) ; mov rbp,[rsp+0x10] ; mov rdi,[rsp+0x8] ; jmp ; mov r13,-1 ; xor r15d,r15d (no records)'),
    ('s_sat_a', 'volume_step', 0x2773c61,
     ['31ff', '488d35fe21fa02', '4989c7', 'ff151df5ff02', '4901dd', '48c7c0ffffffff', '4c0f42e8'],
     'xor edi,edi ; lea rsi,[rip->0x5715e68] ; mov r15,rax ; call [rip->0x5773190] ; add r13,rbx ; mov rax,-1 ; cmovb r13,rax'),
    ('s_sat_b', 'volume_step', 0x2773c8f,
     ['31ff', '488d35d021fa02', '4989c5', 'ff15eff4ff02', '4d01f5', '48c7c0ffffffff', '4c0f42e8'],
     'xor edi,edi ; lea rsi,[rip->0x5715e68] ; mov r13,rax ; call [rip->0x5773190] ; add r13,r14 ; mov rax,-1 ; cmovb r13,rax'),
    ('s_tail', 'volume_step', 0x2773cca,
     ['4883ef80', '488d742420', 'ff1597f4ff02', '4c8b20', '4c8b7008', '4c89e3', '4c01fb', '721c', '4d39ee', '7739', '4889d8', '4801e8', '7248'],
     'sub rdi,-0x80 ; lea rsi,[rsp+0x20] ; call [rip->0x5773170] ; mov r12,[rax] ; mov r14,[rax+0x8] ; mov rbx,r12 ; add rbx,r15 ; jb ; cmp r14,r13 ; ja ; mov rax,rbx ; add rax,rbp ; jb'),
    ('s_ret', 'volume_step', 0x2773cf5,
     ['4883c458', '5b', '415c', '415d', '415e', '415f', '5d', 'c3'],
     'add rsp,0x58 ; pop x6 ; ret (rax = acc + (L + R))'),
    ('s_sat_c', 'volume_step', 0x2773d04,
     ['488d35dd76f702', '31ff', 'ff157df4ff02', '4d01fc', '48c7c3ffffffff', '490f43dc'],
     'lea rsi,[rip->0x56eb3e8] ; xor edi,edi ; call [rip->0x5773190] ; add r12,r15 ; mov rbx,-1 ; cmovae rbx,r12'),
    ('s_sat_d', 'volume_step', 0x2773d26,
     ['488d350377f702', '31ff', 'ff155bf4ff02', '4889d8', '4801e8', '73b8'],
     'lea rsi,[rip->0x56eb430] ; xor edi,edi ; call [rip->0x5773190] ; mov rax,rbx ; add rax,rbp ; jae'),
    ('s_sat_e', 'volume_step', 0x2773d3d,
     ['488d35bc9bf402', '31ff', 'ff1544f4ff02', '4801eb', '48c7c0ffffffff', '480f43c3'],
     'lea rsi,[rip->0x56bd900] ; xor edi,edi ; call [rip->0x5773190] ; add rbx,rbp ; mov rax,-1 ; cmovae rax,rbx'),
    ('r_ret_a', 'volume_report', 0x358dd4d,
     ['4883c438', '5b', '415e', 'c3'],
     'add rsp,0x38 ; pop rbx ; pop r14 ; ret at 0x358dd54 (after the unlock cmpxchg)'),
    ('r_ret_b', 'volume_report', 0x358de05,
     ['4883c438', '5b', '415e', 'c3'],
     'add rsp,0x38 ; pop rbx ; pop r14 ; ret at 0x358de0c (after the contended-unlock call)'),
    ('o_gate', 'other_volume_user', 0x27677c9,
     ['4c89ff', '488b5c2430', '4889de', 'e80787ffff', '4c8b642410', '0fb66c2407', '483d80969800', '7375', '4531c9'],
     'mov rdi,r15 ; .. ; call 0x275fee0 ; .. ; cmp rax,0x989680 ; jae ; xor r9d,r9d'),
    ('o_cap', 'other_volume_user', 0x2767860,
     ['48b9bfd5edbdcefee6db', '48f7e1', '48c1ea21', '4883fa28', '41b928000000', '4c0f42ca', '4983c10a'],
     'movabs rcx,M ; mul rcx ; shr rdx,0x21 ; cmp rdx,0x28 ; mov r9d,0x28 ; cmovb r9,rdx ; add r9,0xa'),
    ('o_ten', 'other_volume_user', 0x27677aa,
     ['41b90a000000'],
     'mov r9d,0xa (a third path)'),
    ('o_callee', 'other_volume_user', 0x2767925,
     ['ff1595d40003'],
     'call [rip->0x5774dc0] (r9 = the value computed above)'),
    ('o_entry_call', 'other_entry', 0x1e5f8ec,
     ['e87f769000'],
     'call 0x2766f70'),
    ('oc_args', 'other_consumer', 0x3421e20,
     ['55', '4157', '4156', '4155', '4154', '53', '4881ecf8000000', '4c894c2430', '4c89c5', '4989ff'],
     'prologue ; mov [rsp+0x30],r9 (the sixth argument) ; mov rbp,r8 ; mov r15,rdi (out)'),
    ('oc_ret', 'other_consumer', 0x3422345,
     ['4c89f8', '4881c4f8000000', '5b', '415c', '415d', '415e', '415f', '5d', 'c3'],
     'mov rax,r15 ; add rsp,0xf8 ; pop x6 ; ret (returns the out pointer)'),
    ('oc_57', 'other_consumer', 0x342235a,
     ['8b0538883502', '85c0', '0f85b2000000', '6641c7075700', '4d897708'],
     'mov eax,[rip->0x577ab98] ; test eax,eax ; jne ; mov WORD PTR [r15],0x57 ; mov [r15+0x8],r14'),
    ('sib_name_len', 'name_sibling', 0x36f41ce,
     ['4d8b4610', '4983f864', '7666', '66c7034301'],
     'mov r8,[r14+0x10] ; cmp r8,0x64 ; jbe ; mov WORD PTR [rbx],0x143'),
    ('sib_dc_a', 'name_sibling', 0x36f4211,
     ['66c703dc00'],
     'mov WORD PTR [rbx],0xdc'),
    ('sib_helper', 'name_sibling', 0x36f424d,
     ['4889e9', 'e86b010000'],
     'mov rcx,rbp ; call 0x36f43c0'),
    ('sib_dc_b', 'name_sibling', 0x36f434c,
     ['66c703dc00'],
     'mov WORD PTR [rbx],0xdc'),
    ('fmt_dispatch', 'status_formatter', 0x37ffd44,
     ['0fb707', '488d0d82abd9fc', '48630481', '4801c8', 'ffe0'],
     'movzx eax,WORD PTR [rdi] ; lea rcx,[rip->0x59a8d0] ; movsxd rax,[rcx+rax*4] ; add rax,rcx ; jmp rax'),
    ('fmt_d6', 'status_formatter', 0x3800660,
     ['488b3e', '488b4608', '488b4018', '488d3564d2d9fc', 'ba16000000', '4883c448', 'ffe0'],
     'write_str(0x59d8d6, 0x16)'),
    ('fmt_d7', 'status_formatter', 0x3802421,
     ['488b3e', '488b4608', '488b4018', '488d35b9b4d9fc', 'ba1f000000', '4883c448', 'ffe0'],
     'write_str(0x59d8ec, 0x1f)'),
    ('fmt_d8', 'status_formatter', 0x3801ea7,
     ['4883c702', '48893c24', '4889e0', '4889442410', '488d0592adfeff', '4889442418', '488b3e', '488b7608', '488d156db79ffc', '488d4c2410', 'ff152cc1f601', '4883c448', 'c3'],
     'arg = status+2 ; template 0x1fd63e'),
    ('fmt_d9', 'status_formatter', 0x380292e,
     ['488b3e', '488b4608', '488b4018', '488d35cbafd9fc', 'ba3a000000', '4883c448', 'ffe0'],
     'write_str(0x59d90b, 0x3a)'),
    ('fmt_dd', 'status_formatter', 0x3800e28,
     ['4883c708', '48897c2440', '48b800000000006af840', '48890424', '4889e0', '4889442410', '488b05622bf701', '4889442418', '488d442440', '4889442420', '488d05ecbffeff', '4889442428', '488b3e', '488b7608', '488d150a1d9efc', '488d4c2410', 'ff1586d1f601', '4883c448', 'c3'],
     'arg1 = status+8 (f64) ; arg0 = 100000.0 ; template 0x1e2b81'),
    ('fmt_143', 'status_formatter', 0x38011e8,
     ['488b3e', '488b4608', '488b4018', '488d3549d2d9fc', 'ba14000000', '4883c448', 'ffe0'],
     'write_str(0x59e443, 0x14)'),
    ('fmt_57', 'status_formatter', 0x3800578,
     ['4883c708', '48893c24', '4889e0', '4889442410', '488d0551c7feff', '4889442418', '488b3e', '488b7608',
      '488d15509f9ffc', '488d4c2410', 'ff155bdaf601', '4883c448', 'c3'],
     'arg = status+8 ; template 0x1fa4f2'),
    ('tok_dispatch', 'ethabi_token_debug', 0x15906af,
     ['488b07', '0fb608', '488d15a8f3ccfe', '48630c8a', '4801d1', 'ffe1'],
     'mov rax,[rdi] ; movzx ecx,BYTE PTR [rax] ; lea rdx,[rip->0x25fa64] ; movsxd rcx,[rdx+rcx*4] ; add rcx,rdx ; jmp rcx'),
    ('tok_arm_address', 'ethabi_token_debug', 0x15906c5,
     ['48ffc0', '4889442408', '4c8b33', '4c8b7b08', '4d8b6718', '488d35edf3ccfe', 'ba07000000'],
     'tag 0 arm: inc rax (payload at +1) ; .. ; lea rsi,[rip->name] ; mov edx,len'),
    ('tok_arm_uint', 'ethabi_token_debug', 0x159072b,
     ['4883c008', '4889442408', '4c8b33', '4c8b7b08', '4d8b6718', '488d35ee98c7fe', 'ba04000000'],
     'tag 4 arm: add rax,0x8 (payload at +8) ; .. ; lea rsi,[rip->name] ; mov edx,len'),
    ('tok_arm_string', 'ethabi_token_debug', 0x15908eb,
     ['4883c008', '4889442408', '4c8b33', '4c8b7b08', '4d8b6718', '488d35dff1ccfe', 'ba06000000'],
     'tag 6 arm: add rax,0x8 (payload at +8) ; .. ; lea rsi,[rip->name] ; mov edx,len'),
    ('k_update_f', 'keccak_update', 0x4f59a37,
     ['ff1553dd8100'],
     'call [rip->0x5777790] (keccak-f)'),
    ('k_final_f', 'keccak_finalize', 0x4f59f14,
     ['ff1576d88100'],
     'call [rip->0x5777790] (keccak-f)'),
    ('k_rc', 'keccak_f', 0x4f598f0,
     ['4c8d05d16b87fb', '488b0424', '4a330402'],
     'lea r8,[rip->0x7d04c8] ; mov rax,[rsp] ; xor rax,[rdx+r8] (round constant)'),
    ('k_loop', 'keccak_f', 0x4f59916,
     ['4883c208', '4881fac0000000', '0f8539fcffff'],
     'add rdx,0x8 ; cmp rdx,0xc0 ; jne (24 rounds)'),
    ('t_sigma', 'to_lowercase', 0x1344b89,
     ['81fea3030000'],
     'cmp esi,0x3a3 (U+03A3 capital sigma: the final-sigma case)'),
    ('a_body', 'alloc_fail', 0x1346068,
     ['55', '4889e5', '4885ff', '7506', 'ff1549804204', 'ff15a37f4204'],
     'the whole 21-byte window: push ; mov ; test rdi,rdi ; jne ; call [rip->0x576e0c0] ; call [rip->0x576e020] (no ret)'),
    ('u_out', 'user_lookup', 0x3743df7,
     ['4889f8'],
     'mov rax,rdi (output pointer)'),
    ('u_special', 'user_lookup', 0x3743dfa,
     ['f30f6f02', 'f30f6f0dde82e5fc', '660f74c8', '660f6e4210', '660f6e15dd82e5fc', '660f74d0', '660fdbd1',
      '660fd7ca', '81f9ffff0000', '0f8423010000', 'f30f6f02', 'f30f6f0dbd82e5fc', '660f74c8', '660f6e4210',
      '660f6e15bc82e5fc', '660f74d0', '660fdbd1', '660fd7ca', '81f9ffff0000', '0f84ee000000'],
     'compare the 20-byte key with 0x59c0e4..0x59c0f8, then with 0x59c0f8..0x59c10c ; je (either -> zeroed result)'),
    ('u_probe', 'user_lookup', 0x3743e64,
     ['4883bed800000000', '0f8449010000'],
     'cmp QWORD PTR [rsi+0xd8],0x0 ; je'),
    ('u_stride', 'user_lookup', 0x3743ef0,
     ['4d69ffe8000000'],
     'imul r15,r15,0xe8 (0xe8-byte buckets)'),
]

# ---- Immediates / displacements decoded from pinned instructions. ----
# (name, instruction VA, byte offset in the instruction, size, signed)
IMMS = [
    ("dispatch_bias_lea", 0x275929C, 3, 1, True),
    ("dispatch_bias_cmp", 0x27592A0, 3, 1, False),
    ("dispatch_default_index", 0x27592A4, 1, 4, False),
    ("tracker_field", 0x27E315D, 3, 4, False),
    ("user_table_items_field", 0x27E31D2, 3, 4, False),
    ("user_table_ctrl_field", 0x27E31FB, 3, 4, False),
    ("user_table_mask_field", 0x27E3202, 3, 4, False),
    ("user_table_stride", 0x27E324D, 3, 1, False),
    ("volume_slot_store", 0x27E331C, 4, 4, False),
    ("volume_slot_load", 0x27E33B2, 4, 4, False),
    ("ok_status_handler_derive", 0x27E319D, 1, 4, False),
    ("ok_status_handler_creator", 0x27E33DA, 1, 4, False),
    ("user_table_field_r12", 0x27E33E5, 3, 4, False),
    ("lookup_base_field", 0x27E33FE, 3, 4, False),
    ("lookup_master_out", 0x27E340C, 4, 4, False),
    ("lookup_sub_out", 0x27E342D, 4, 1, False),
    ("record_map_field", 0x27E364E, 3, 4, False),
    ("record_tail_disp", 0x27E36D9, 3, 1, False),
    ("entry_index_field", 0x27E36F9, 3, 4, False),
    ("handler_status_disp", 0x27E356A, 3, 1, False),
    ("handler_err_byte", 0x27E356E, 2, 1, False),
    ("handler_ok_byte", 0x27E371C, 2, 1, False),
    ("min_volume", 0x36F3627, 3, 4, False),
    ("map1_items_field", 0x36F365E, 3, 1, False),
    ("map1_mask_field", 0x36F3684, 4, 1, False),
    ("cap_magic", 0x36F3734, 2, 8, False),
    ("cap_shift", 0x36F3744, 3, 1, False),
    ("cap_clamp_cmp", 0x36F3748, 3, 1, False),
    ("cap_clamp_mov", 0x36F374C, 1, 4, False),
    ("cap_base", 0x36F3755, 3, 1, False),
    ("cap_count_disp", 0x36F3759, 4, 1, True),
    ("ok_status_creator_rederive", 0x36F378C, 1, 4, False),
    ("map2_items_field", 0x36F37CD, 4, 1, False),
    ("map2_ctrl_field", 0x36F37EF, 4, 1, False),
    ("map2_mask_field", 0x36F37F4, 4, 1, False),
    ("name_ptr_field", 0x36F3904, 3, 1, False),
    ("name_len_field", 0x36F3908, 3, 1, False),
    ("name_upper", 0x36F390C, 3, 1, False),
    ("status_143", 0x36F3916, 2, 2, False),
    ("ok_status_creator_helper", 0x36F3A36, 2, 4, False),
    ("insert_map_field", 0x36F3A42, 4, 1, False),
    ("insert_some_tag", 0x36F3A59, 4, 1, False),
    ("record_shift", 0x36F3AA1, 3, 1, False),
    ("record_name_ptr", 0x36F3AAD, 4, 1, False),
    ("record_name_len", 0x36F3AB2, 4, 1, False),
    ("record_sub_lo", 0x36F3ABC, 4, 1, False),
    ("record_sub_hi", 0x36F3AC5, 3, 1, False),
    ("record_master_lo", 0x36F3ACD, 4, 1, False),
    ("record_master_hi", 0x36F3AD6, 3, 1, False),
    ("assert_msg_len", 0x36F3BD4, 1, 4, False),
    ("derive_items_field", 0x36F3C32, 3, 1, False),
    ("count_disp", 0x36F3D0E, 4, 1, True),
    ("label_alloc", 0x36F3D18, 1, 4, False),
    ("label_cap", 0x36F3D36, 5, 4, False),
    ("label_len", 0x36F3D44, 5, 4, False),
    ("count_arg_disp", 0x36F3D64, 4, 4, False),
    ("derive_args_lea", 0x36F3D71, 4, 1, False),
    ("keccak_rate", 0x36F3DF0, 8, 4, False),
    ("keccak_delim_mode", 0x36F3DFC, 8, 2, False),
    ("state_copy_len", 0x36F3E31, 1, 4, False),
    ("digest_out", 0x36F3E3F, 4, 1, False),
    ("digest_len", 0x36F3E44, 1, 4, False),
    ("copy_src0", 0x36F3E52, 4, 1, False),
    ("copy_src1", 0x36F3E57, 4, 1, False),
    ("copy_dst0", 0x36F3E5C, 4, 1, False),
    ("copy_dst1", 0x36F3E61, 4, 1, False),
    ("keep_dword_src", 0x36F3E7B, 3, 1, False),
    ("keep_dword_dst", 0x36F3E7F, 2, 1, False),
    ("keep_xmm_src", 0x36F3E82, 4, 1, False),
    ("keep_xmm_dst", 0x36F3E87, 3, 1, False),
    ("name_lea_disp", 0x36F43D1, 3, 1, True),
    ("name_cmp_imm", 0x36F43D5, 3, 1, True),
    ("status_d7", 0x36F45EC, 2, 2, False),
    ("status_186_helper_a", 0x36F43FE, 2, 2, False),
    ("status_186_helper_b", 0x36F45BD, 2, 2, False),
    ("name_rec_shift", 0x36F44EB, 3, 1, False),
    ("name_rec_stride", 0x36F453D, 3, 1, False),
    ("name_rec_ptr", 0x36F4546, 4, 1, False),
    ("name_rec_len", 0x36F454B, 4, 1, False),
    ("token_alloc", 0x3C97913, 1, 4, False),
    ("count_field", 0x3C9793C, 3, 1, False),
    ("tok0_tag", 0x3C97940, 2, 1, False),
    ("tok1_disp", 0x3C9795D, 2, 1, False),
    ("tok1_tag", 0x3C9795D, 3, 1, False),
    ("tok1_payload_src", 0x3C97961, 4, 1, False),
    ("tok1_payload_dst", 0x3C97966, 3, 1, False),
    ("tok2_disp", 0x3C97971, 2, 1, False),
    ("tok2_tag", 0x3C97971, 3, 1, False),
    ("tok2_limb0_dst", 0x3C97975, 3, 1, False),
    ("ntokens", 0x3C9799E, 1, 4, False),
    ("prod_items_field", 0x275FEFD, 3, 4, False),
    ("prod_ctrl_field", 0x275FF21, 3, 4, False),
    ("prod_vec_off", 0x275FFE4, 3, 1, True),
    ("prod_once_tag", 0x275FFF3, 4, 1, False),
    ("fold_once_disp", 0x258B4F6, 3, 1, False),
    ("prod_state_base", 0x2760029, 4, 1, False),
    ("prod_iter_tag_disp", 0x2760009, 4, 1, False),
    ("prod_iter_tag", 0x2760009, 5, 4, False),
    ("prod_vec_disp", 0x2760012, 4, 1, False),
    ("prod_front_disp", 0x2760017, 4, 1, False),
    ("prod_front_val", 0x2760017, 5, 4, False),
    ("prod_back_disp", 0x2760020, 4, 1, False),
    ("prod_back_val", 0x2760020, 5, 4, False),
    ("prod_once_disp", 0x275FFF3, 3, 1, False),
    ("fold_vec_field", 0x258B548, 3, 1, False),
    ("fold_front_field", 0x258B54C, 3, 1, False),
    ("fold_back_field", 0x258B554, 3, 1, False),
    ("fold_front_stride", 0x258B5C1, 3, 1, False),
    ("vec_len_field", 0x26B219D, 3, 1, False),
    ("vec_ptr_field", 0x26B21BE, 3, 1, False),
    ("vec_shift", 0x26B21D8, 3, 1, False),
    ("vec_addr_disp", 0x26B21E9, 4, 1, False),
    ("step_rec_count_field", 0x2773BDB, 3, 4, False),
    ("other_min_volume", 0x27677E3, 2, 4, False),
    ("other_magic", 0x2767860, 2, 8, False),
    ("other_shift", 0x276786D, 3, 1, False),
    ("other_clamp_cmp", 0x2767871, 3, 1, False),
    ("other_clamp_mov", 0x2767875, 2, 4, False),
    ("other_base", 0x276787F, 3, 1, False),
    ("other_ten", 0x27677AA, 2, 4, False),
    ("sibling_name_upper", 0x36F41D2, 3, 1, False),
    ("fmt_dd_required", 0x3800E31, 2, 8, False),
    ("fmt_dd_arg", 0x3800E28, 3, 1, False),
    ("fmt_d8_arg", 0x3801EA7, 3, 1, False),
    ("keccak_round_bytes", 0x4F5991A, 3, 4, False),
    ("sigma", 0x1344B89, 2, 4, False),
    ("user_lookup_stride", 0x3743EF0, 3, 4, False),
    # Result-typed calls: the callee's out pointer (lea rdi,[rsp+X]) and the status load (movzx eax,[rsp+X]).
    ("derive_out_lea", 0x27E3172, 4, 1, False),
    ("derive_status_load", 0x27E3183, 4, 1, False),
    ("creator_out_lea", 0x27E339D, 4, 1, False),
    ("creator_status_load", 0x27E33C0, 4, 1, False),
    ("rederive_out_lea", 0x36F3764, 4, 1, False),
    ("rederive_status_load", 0x36F3775, 4, 1, False),
    # vec_entry (0x3596680) and the creator's use of its result.
    ("entry_stride_shift", 0x359670A, 3, 1, False),
    ("entry_key_disp", 0x359671E, 4, 1, True),
    ("entry_cap_disp", 0x3596734, 4, 1, True),
    ("entry_cap_val", 0x3596734, 5, 4, False),
    ("entry_ptr_disp", 0x359673D, 4, 1, True),
    ("entry_ptr_val", 0x359673D, 5, 4, False),
    ("entry_len_disp", 0x3596746, 4, 1, True),
    ("entry_len_val", 0x3596746, 5, 4, False),
    ("entry_ret_vacant", 0x3596753, 3, 1, True),
    ("entry_ret_occupied", 0x3596761, 3, 1, True),
    ("push_len_field", 0x36F3A87, 3, 1, False),
    ("push_ptr_field", 0x36F3A99, 4, 1, False),
    ("push_len_store", 0x36F3ADD, 4, 1, False),
    # Volume step, fold and Vec fold: context, record table, per-record map, lookups.
    ("fold_ctx_store", 0x258B4F1, 4, 1, False),
    ("fold_ctx_lea", 0x258B4FF, 4, 1, False),
    ("fold_ctx_copy_src", 0x258B55C, 4, 1, False),
    ("fold_ctx_copy_dst", 0x258B561, 4, 1, False),
    ("fold_vec_ctx", 0x258B5D9, 4, 1, False),
    ("step_rec_base_field", 0x2773BF5, 3, 4, False),
    ("step_rec_stride", 0x2773BFC, 3, 4, False),
    ("step_map_disp", 0x2773C03, 3, 4, False),
    ("step_sum_field", 0x2773C31, 3, 1, False),
    ("step_raw_field", 0x2773C35, 3, 1, False),
    ("step_rec_next", 0x2773C49, 3, 4, False),
    ("step_rec_countdown", 0x2773C56, 3, 4, True),
    ("step_lookup_disp", 0x2773CCA, 3, 1, True),
    ("vec_lookup_disp", 0x26B21B2, 3, 4, False),
    ("vec_rec_count_field", 0x26B220D, 3, 4, False),
    ("vec_rec_base_field", 0x26B2222, 3, 4, False),
    ("vec_rec_stride", 0x26B2229, 3, 4, False),
    ("vec_map_items", 0x26B2253, 4, 4, False),
    ("vec_map_hasher", 0x26B2265, 4, 4, False),
    ("vec_map_ctrl", 0x26B227C, 4, 4, False),
    ("vec_map_mask", 0x26B2284, 4, 4, False),
    ("vec_bucket_stride", 0x26B22CC, 3, 1, False),
    ("vec_value_off", 0x26B23A2, 3, 1, True),
    ("vec_sum_field", 0x26B23C8, 3, 1, False),
    ("vec_raw_field", 0x26B23CC, 3, 1, False),
    ("vec_rec_next", 0x26B23E0, 3, 4, False),
    # ethabi word writer, Int/Uint arm.
    ("ww_max_tag", 0x1591CE6, 3, 1, False),
    ("ww_word_shift", 0x1591D59, 3, 1, False),
    # The second gate's consumer and the 0x57 formatter arm.
    ("oc_r9_save", 0x3421E31, 4, 1, False),
    ("oc_status_57", 0x3422368, 4, 2, False),
    ("oc_payload_disp", 0x342236E, 3, 1, False),
    ("fmt_57_arg", 0x3800578, 3, 1, False),
]

# ---- RIP-relative data references in pinned instructions: (va, expected target, label). ----
# Each instruction has no immediate, so its disp32 is its last 4 bytes; the
# ModRM byte before it must say mod=00 rm=101.
RIPREL = [
    (0x27592AD, 0x3EDE28, "dispatch jump table"),
    (0x36F3635, 0x20A960, "f64 divisor"),
    (0x36F37AB, 0x577AB98, "once-init global"),
    (0x36F3BC6, 0x598EAD, "insert assert message"),
    (0x36F3BCD, 0x56F1C38, "Location sub_account.rs:69:13"),
    (0x36F3D2C, 0x2035A0, "createSubAccount literal"),
    (0x37FFD47, 0x59A8D0, "status formatter jump table"),
    (0x3800E47, 0x57739B0, "0xdd arm: mov rax,[x] loads the formatter pointer of args[0] (&100000.0)"),
    (0x3800E5D, 0x37ECE50, "0xdd arm: lea rax,[x] is the formatter of args[1] (&[rsp+0x40], which holds status+8)"),
    (0x15906B5, 0x25FA64, "Token Debug jump table"),
    (0x4F598F0, 0x7D04C8, "Keccak round-constant table"),
    (0x2773C63, 0x5715E68, "Location impl_ntl.rs:664:1"),
    (0x2773C91, 0x5715E68, "Location impl_ntl.rs:664:1"),
    (0x2773D04, 0x56EB3E8, "Location scaled_vlm.rs:15:21"),
    (0x2773D26, 0x56EB430, "Location raw_vlm.rs:17:21"),
    (0x2773D3D, 0x56BD900, "Location impl_ntl.rs:664:1"),
    (0x26B23B0, 0x5786300, "once-init flag of the default per-record value"),
    (0x26B23BD, 0x57862A0, "default per-record value"),
    (0x1591CF3, 0x25FBA4, "word writer jump table"),
    (0x342235A, 0x577AB98, "once-init global (other_consumer)"),
    (0x3743DFE, 0x59C0E4, "special key 1, bytes 0..16"),
    (0x3743E0F, 0x59C0F4, "special key 1, bytes 16..20"),
    (0x3743E33, 0x59C0F8, "special key 2, bytes 0..16"),
    (0x3743E44, 0x59C108, "special key 2, bytes 16..20"),
]

# ---- Check order. Each row names the branch that decides it, which edge of
# that branch leads to the failure block, and the edges that continue. ----
CHECK_ORDER = [
    dict(seq=1, owner="handler", kind="call",
         condition=("derive the sub-account address for (master, current count): call through slot "
                    "0x5774f40 (deriver); the u16 result is compared with 0x186"),
         call=0x27E317D, decision=0x27E31A2, decision_mnemonic="jne", fail_edge="taken", fail_to=0x27E32B5,
         passes=[(0x27E31A2, "jne", "fallthrough", 0x27E31A8)], status=None, store=0x27E356A,
         note=("failure edge propagates the callee's status (eax = movzx [rsp+0x78] at 0x27e3183) to "
               "0x27e356a; the deriver's only status store is 0x186 (0x36f3e8b), so this edge is not "
               "reached from the callee's return")),
    dict(seq=2, owner="handler", kind="check",
         condition=("derived address already a key of the table at exchange+0x740 (probed only when "
                    "[exchange+0x758] != 0; 0x58-byte buckets; 16+4 key bytes compared)"),
         call=None, decision=0x27E3284, decision_mnemonic="je", fail_edge="taken", fail_to=0x27E3348,
         passes=[(0x27E31DA, "je", "taken", 0x27E3309), (0x27E32A3, "jne", "taken", 0x27E3309)],
         status=0xD8, store=0x27E335E, note="status at [out+0x8]; outer byte 0xe at 0x27e356e"),
    dict(seq=3, owner="handler", kind="call",
         condition=("volume operand ('volume traded' in the 0xdd message): call 0x275fee0(exchange, &master); rax is saved at "
                    "[rsp+0x110] and loaded into r8 for the creator call"),
         call=0x27E3317, decision=None, decision_mnemonic=None, fail_edge=None, fail_to=None, passes=[], status=None,
         store=None, note="no status of its own"),
    dict(seq=4, owner="creator", kind="check",
         condition="volume < 0x989680 (cmp r8,imm32 ; jae: unsigned)",
         call=None, decision=0x36F362E, decision_mnemonic="jae", fail_edge="fallthrough", fail_to=0x36F3630,
         passes=[(0x36F362E, "jae", "taken", 0x36F3658)], status=0xDD, store=0x36F363D,
         note="payload [out+0x8] = (f64)r8 / 100.0 (cvtsi2sd 0x36f3630, divsd 0x36f3635, movsd 0x36f3642)"),
    dict(seq=5, owner="creator", kind="check",
         condition=("only when the master has a user_to_sub_accounts entry: count ([bucket_end-0x8] = "
                    "bucket+0x28, the Vec len) >= min(volume*M >> 97, 40) + 10"),
         call=None, decision=0x36F375E, decision_mnemonic="jae", fail_edge="taken", fail_to=0x36F39CA,
         passes=[(0x36F375E, "jae", "fallthrough", 0x36F3764), (0x36F3663, "je", "taken", 0x36F3764),
                 (0x36F3722, "jne", "taken", 0x36F3764)],
         status=0xD6, store=0x36F39CA, note="the cap is skipped (no 0xd6 possible) when the master has no entry"),
    dict(seq=6, owner="creator", kind="call",
         condition="re-derive the sub-account address (call through slot 0x5774f40); compared with 0x186",
         call=0x36F376F, decision=0x36F3791, decision_mnemonic="jne", fail_edge="taken", fail_to=0x36F389F,
         passes=[(0x36F3791, "jne", "fallthrough", 0x36F3797)], status=None, store=0x36F38ED,
         note=("eax = movzx [rsp+0x50] at 0x36f3775; as row 1, the failure edge is not reached from the "
               "deriver's return")),
    dict(seq=7, owner="creator", kind="check",
         condition=("derived address already a key of sub_account_to_master (tracker+0x30; probed only "
                    "when [tracker+0x48] != 0; 0x28-byte buckets)"),
         call=None, decision=0x36F386E, decision_mnemonic="je", fail_edge="taken", fail_to=0x36F39D9,
         passes=[(0x36F37D3, "je", "taken", 0x36F3901), (0x36F388D, "jne", "taken", 0x36F3901)],
         status=0xD8, store=0x36F39E9, note=""),
    dict(seq=8, owner="creator", kind="check",
         condition="name byte length (String len, [name+0x10]) > 100",
         call=None, decision=0x36F3910, decision_mnemonic="jbe", fail_edge="fallthrough", fail_to=0x36F3916,
         passes=[(0x36F3910, "jbe", "taken", 0x36F3A17)], status=0x143, store=0x36F39C5,
         note="register-mediated: mov bp,0x143 at 0x36f3916, stored by mov [rbx],bp at 0x36f39c5"),
    dict(seq=9, owner="name_helper", kind="check",
         condition="name byte length (r8) not in 1..=16 (lea rax,[r8-0x11] ; cmp rax,-0x11 ; ja)",
         call=None, decision=0x36F43D9, decision_mnemonic="ja", fail_edge="fallthrough", fail_to=0x36F43DB,
         passes=[(0x36F43D9, "ja", "taken", 0x36F43E7)], status=0xD9, store=0x36F43DB,
         note=("the creator reloads a non-0x186 helper status into ebp (0x36f3a31) and re-stores it "
               "through 0x36f39c5")),
    dict(seq=10, owner="name_helper", kind="check",
         condition=("0x1344900(new name) equal (length compare, then bcmp) to 0x1344900(name) of a record "
                    "in the master's Vec (0x1344900 is inferred to be str::to_lowercase)"),
         call=None, decision=0x36F4537, decision_mnemonic="je", fail_edge="taken", fail_to=0x36F45EC,
         passes=[(0x36F4544, "je", "taken", 0x36F45B9), (0x36F44DC, "je", "taken", 0x36F45BD),
                 (0x36F4407, "je", "taken", 0x36F45C1), (0x36F44BE, "jne", "taken", 0x36F45C1)],
         status=0xD7, store=0x36F45F4,
         note="register-mediated: mov bx,0xd7 at 0x36f45ec, stored by mov [r12],bx at 0x36f45f4"),
    dict(seq=11, owner="creator", kind="assert",
         condition=("insert (sub -> master) into sub_account_to_master (call 0x379ec60, rsi = tracker+0x30); "
                    "a returned tag byte 1 panics"),
         call=0x36F3A54, decision=0x36F3A5E, decision_mnemonic="je", fail_edge="taken", fail_to=0x36F3BC6,
         passes=[(0x36F3A5E, "je", "fallthrough", 0x36F3A64)], status=None, store=None,
         note="panic Location l1/src/sub_account.rs:69:13 (lea 0x36f3bcd)"),
    dict(seq=12, owner="creator", kind="success",
         condition=("push the 0x40-byte record (shl rcx,0x6) into the Vec returned by 0x3596680(tracker+0, "
                    "&master) (call 0x36f3a7f); status 0x186"),
         call=0x36F3A7F, decision=None, decision_mnemonic=None, fail_edge=None, fail_to=None, passes=[],
         status=0x186, store=0x36F3AF4,
         note=("the sub address is copied to [out+0x2..0x16] first; that the Vec is the master's bucket "
               "value is an inference (0x379a4d0, the entry probe inside 0x3596680, is not decoded)")),
    dict(seq=13, owner="handler", kind="success",
         condition=("creator status == 0x186: lookup 0x3743df0 for master then sub, insert of the "
                    "master's record under the sub key at exchange+0x690 only if the two differ, "
                    "0x1f849b0(exchange+0x740, &sub), 0x1f84b30(exchange+0x318, &sub); outer byte 0x6"),
         call=None, decision=0x27E33DF, decision_mnemonic="jne", fail_edge="taken", fail_to=0x27E3516,
         passes=[(0x27E33DF, "jne", "fallthrough", 0x27E33E5)], status=None, store=0x27E356A,
         note=("outer byte 0x6 at 0x27e371c; the failure edge propagates the creator's status (eax = "
               "movzx [rsp+0x78] at 0x27e33c0)")),
]
# Result-typed calls whose failure edge stores a register: row -> (call VA, IMMS name of the
# out-pointer lea, IMMS name of the status load). The load must follow the call directly, read the
# u16 at the out pointer into eax, and feed the cmp eax,0x186 just before the row's decision.
RESULT_CALLS = {1: (0x27E317D, "derive_out_lea", "derive_status_load"),
                6: (0x36F376F, "rederive_out_lea", "rederive_status_load"),
                13: (0x27E33BA, "creator_out_lea", "creator_status_load")}

# Every 16-bit store found by the byte scan in the four windows, with its role.
# window -> status field operand (the u16 written to the out pointer).
STATUS_FIELD = {"handler": "[rbx+0x8]", "creator": "[rbx]", "deriver": "[rbx]", "name_helper": "[r12]"}
WORD_STORES = [
    ("handler", 0x27E335E, "[rbx+0x8]", 0xD8, "row 2"),
    ("handler", 0x27E356A, "[rbx+0x8]", "ax", "propagates a non-0x186 deriver or creator status"),
    ("creator", 0x36F363D, "[rbx]", 0xDD, "row 4"),
    ("creator", 0x36F38ED, "[rbx]", "ax", "propagates a non-0x186 re-derive status"),
    ("creator", 0x36F3980, "[rbx+0x6]", "ax", "not the status field"),
    ("creator", 0x36F39C5, "[rbx]", "bp", "row 8 (0x143) and the name helper's statuses"),
    ("creator", 0x36F39CA, "[rbx]", 0xD6, "row 5"),
    ("creator", 0x36F39E9, "[rbx]", 0xD8, "row 7"),
    ("creator", 0x36F3AF4, "[rbx]", 0x186, "row 12"),
    ("creator", 0x36F3B03, "[rsp+0xc]", "ax", "stack local, not the status field"),
    ("deriver", 0x36F3DFC, "[rsp+0x178]", 0x1, "Keccak delimiter and mode bytes, not the status field"),
    ("deriver", 0x36F3E8B, "[rbx]", 0x186, "the deriver's only status store"),
    ("name_helper", 0x36F43DB, "[r12]", 0xD9, "row 9"),
    ("name_helper", 0x36F45C1, "[r12]", "bx", "helper success (bx = 0x186 from 0x36f43fe or 0x36f45bd)"),
    ("name_helper", 0x36F45F4, "[r12]", "bx", "row 10 (bx = 0xd7 from 0x36f45ec)"),
]
# Register-mediated status values: store VA -> [(source mov VA, IMMS name)].
REGISTER_SOURCES = {
    0x36F39C5: [(0x36F3916, "status_143")],
    0x36F45F4: [(0x36F45EC, "status_d7")],
    0x36F45C1: [(0x36F43FE, "status_186_helper_a"), (0x36F45BD, "status_186_helper_b")],
}
# Register stores that propagate a callee's status: store VA -> [(load VA, IMMS name of its disp)].
LOAD_SOURCES = {
    0x27E356A: [(0x27E3183, "derive_status_load"), (0x27E33C0, "creator_status_load")],
    0x36F38ED: [(0x36F3775, "rederive_status_load")],
}

# ---- Every call instruction of the four windows: direct (E8 rel32) and through a register. ----
# (window, VA, target or register, target label). Calls through .got slots are SLOT_REFS below.
# The objdump test checks that SLOT_REFS calls + DIRECT_CALLS + REGISTER_CALLS are all the calls.
DIRECT_CALLS = [
    ("handler", 0x27E31EF, 0x2840FB0, "not decoded; precedes the exchange+0x740 probe"),
    ("handler", 0x27E3317, 0x275FEE0, "volume_producer"),
    ("handler", 0x27E3669, 0x1F84840, "insert at exchange+0x690 (not decoded)"),
    ("handler", 0x27E36F4, 0x1F849B0, "call with exchange+0x740 (not decoded)"),
    ("handler", 0x27E3717, 0x1F84B30, "call with exchange+0x318 (not decoded)"),
    ("creator", 0x36F3674, 0x399C7A0, "not decoded; precedes the user_to_sub_accounts probe"),
    ("creator", 0x36F37E3, 0x399C7A0, "not decoded; precedes the sub_account_to_master probe"),
    ("creator", 0x36F3A2C, 0x36F43C0, "name_helper"),
    ("creator", 0x36F3A54, 0x379EC60, "insert into sub_account_to_master (not decoded)"),
    ("creator", 0x36F3A7F, 0x3596680, "vec_entry"),
    ("creator", 0x36F3C10, "_Unwind_Resume", "PLT stub, end of the unwind landing pad"),
    ("deriver", 0x36F3C47, 0x399C7A0, "not decoded; precedes the user_to_sub_accounts probe"),
    ("deriver", 0x36F3D76, 0x3C97900, "ethabi_build3"),
    ("deriver", 0x36F3ECB, "_Unwind_Resume", "PLT stub, end of the unwind landing pad"),
    ("name_helper", 0x36F4414, 0x399C7A0, "not decoded; precedes the user_to_sub_accounts probe"),
    ("name_helper", 0x36F4622, "_Unwind_Resume", "PLT stub, end of the unwind landing pad"),
]
REGISTER_CALLS = [
    ("handler", 0x27E341A, "ffd5", "call rbp (rbp = [0x57748f8] -> user_lookup, loaded at 0x27e3405)"),
    ("handler", 0x27E3438, "ffd5", "call rbp (user_lookup)"),
    ("name_helper", 0x36F4553, "41ffd7", "call r15 (r15 = [0x576e050] -> to_lowercase, loaded at 0x36f4506/0x36f4530)"),
]

# ---- Slots referenced by call/mov [rip+x] in the five windows (byte scan). ----
SLOT_WINDOWS = ("handler", "creator", "deriver", "name_helper", "ethabi_build3")
SLOT_REFS = [
    ("handler", 0x27E317D, "call", 0x5774F40), ("handler", 0x27E3334, "call", 0x576DFD8),
    ("handler", 0x27E3378, "call", 0x576DFE0), ("handler", 0x27E33BA, "call", 0x5774F48),
    ("handler", 0x27E3405, "mov", 0x57748F8), ("handler", 0x27E373E, "call", 0x576DFB8),
    ("creator", 0x36F376F, "call", 0x5774F40), ("creator", 0x36F3927, "call", 0x576E010),
    ("creator", 0x36F39FC, "call", 0x576E010), ("creator", 0x36F3A93, "call", 0x5774478),
    ("creator", 0x36F3BBB, "call", 0x576E8B8), ("creator", 0x36F3BD9, "call", 0x576E108),
    ("creator", 0x36F3C07, "call", 0x576E010),
    ("deriver", 0x36F3D1D, "call", 0x576DFD8), ("deriver", 0x36F3E1B, "call", 0x576E1D8),
    ("deriver", 0x36F3E39, "call", 0x576DFE0), ("deriver", 0x36F3E4C, "call", 0x576E1E0),
    ("deriver", 0x36F3E75, "call", 0x576E010), ("deriver", 0x36F3EAA, "call", 0x576DFB8),
    ("deriver", 0x36F3EC2, "call", 0x576E010),
    ("name_helper", 0x36F43F8, "call", 0x576E050), ("name_helper", 0x36F4506, "mov", 0x576E050),
    ("name_helper", 0x36F4530, "mov", 0x576E050), ("name_helper", 0x36F4576, "call", 0x576E378),
    ("name_helper", 0x36F458D, "call", 0x576E010), ("name_helper", 0x36F45B1, "call", 0x576E010),
    ("name_helper", 0x36F45D7, "call", 0x576E010), ("name_helper", 0x36F4619, "call", 0x576E010),
    ("ethabi_build3", 0x3C97918, "call", 0x576DFD8), ("ethabi_build3", 0x3C979A9, "call", 0x576ED20),
    ("ethabi_build3", 0x3C979E1, "call", 0x576E010), ("ethabi_build3", 0x3C97A02, "call", 0x576E020),
    ("ethabi_build3", 0x3C97A17, "call", 0x576E128), ("ethabi_build3", 0x3C97A40, "call", 0x576E128),
    ("ethabi_build3", 0x3C97A57, "call", 0x576E010),
]
# slot -> (kind, RELATIVE target or GLOB_DAT symbol, label or None). The last
# four are referenced from other pinned functions and are checked the same way.
SLOTS = {
    0x5774F40: ("relative", 0x36F3C20, "deriver"),
    0x5774F48: ("relative", 0x36F3610, "creator"),
    0x57748F8: ("relative", 0x3743DF0, "user_lookup"),
    0x576DFB8: ("relative", 0x1346068, "alloc_fail"),
    0x576DFD8: ("relative", 0x54C06B0, None),
    0x576DFE0: ("glob_dat", "memcpy", "memcpy"),
    0x576E010: ("relative", 0x54C8CB0, None),
    0x576E020: ("relative", 0x1345E2A, None),
    0x576E050: ("relative", 0x1344900, "to_lowercase"),
    0x576E108: ("relative", 0x157B7F0, None),
    0x576E128: ("relative", 0x157B63B, None),
    0x576E1D8: ("relative", 0x4F59A10, "keccak_update"),
    0x576E1E0: ("relative", 0x4F59E40, "keccak_finalize"),
    0x576E378: ("glob_dat", "bcmp", "bcmp"),
    0x576E8B8: ("relative", 0x4EE3B20, None),
    0x576ED20: ("relative", 0x1592160, "ethabi_encode"),
    0x5774478: ("relative", 0x32D6350, None),
    0x5777790: ("relative", 0x4F59480, "keccak_f"),
    0x5774DC0: ("relative", 0x3421E20, "other_consumer"),
    0x5773190: ("relative", 0x358DCD0, "volume_report"),
    0x5773170: ("relative", 0x371B3A0, None),
}
OTHER_SLOT_USES = {0x5777790: [0x4F59A37, 0x4F59F14], 0x5774DC0: [0x2767925],
                   0x5773190: [0x2773C6D, 0x2773C9B, 0x2773D0D, 0x2773D2F, 0x2773D46,
                               0x26B2406, 0x26B2434, 0x26B24BF, 0x26B24E4, 0x26B2500],
                   0x5773170: [0x2773CD3, 0x26B2477]}

# ---- Direct E8 rel32 callers in .text (byte-pattern hits). ----
CALLERS = {
    "handler": [0x2759D4D],
    "name_helper": [0x36F3A2C, 0x36F4250],
    "volume_producer": [0x27677D4, 0x27E3317],
    "volume_fold": [0x2751DAA, 0x2760033, 0x27688A3],
    "volume_step": [0x258B533, 0x258B5BC, 0x258B62E],
    "volume_vec_fold": [0x258B5E4],
    "other_volume_user": [0x1E5F8EC],
    "other_entry": [0x27592E0],
    "vec_entry": [0x36F3A7F],
    "ethabi_words": [0x1592128, 0x1592144, 0x1592255],
    "ethabi_word_writer": [0x159200D, 0x15920D3],
    "creator": [],
    "deriver": [],
    "volume_report": [],
    "other_consumer": [],
}
RELATIVE_REFS = {"creator": [0x5774F48], "deriver": [0x5774F40], "name_sibling": [0x5773D20],
                 "user_lookup": [0x57748F8], "volume_report": [0x5773190], "other_consumer": [0x5774DC0]}

# ---- Panic Location records: label, slot, path, line, col, [(lea VA, owner)]. ----
LOCATIONS = [
    ("insert_assert", 0x56F1C38, FIRST_PARTY + "l1/src/sub_account.rs", 69, 13, [(0x36F3BCD, "creator")]),
    ("ethabi_113_65", 0x5675908, CRATES + "ethabi-18.0.0/src/encoder.rs", 113, 65, [(0x15921A0, "ethabi_encode")]),
    ("ethabi_113_90", 0x5675920, CRATES + "ethabi-18.0.0/src/encoder.rs", 113, 90, [(0x159230B, "ethabi_encode")]),
    ("ethabi_115_41", 0x56758F0, CRATES + "ethabi-18.0.0/src/encoder.rs", 115, 41, [(0x1592324, "ethabi_encode")]),
    ("tiny_keccak_312_32", 0x5754428, CRATES + "tiny-keccak-2.0.2/src/lib.rs", 312, 32,
     [(0x4F59CFE, "keccak_update"), (0x4F5A04B, "keccak_finalize")]),
    ("alloc_str_415_63", 0x5663340, RUSTC + "alloc/src/str.rs", 415, 63, [(0x1344AB5, "to_lowercase")]),
    ("alloc_str_416_51", 0x5663358, RUSTC + "alloc/src/str.rs", 416, 51, [(0x1345529, "to_lowercase")]),
    ("scaled_vlm_15_21", 0x56EB3E8, FIRST_PARTY + "l1/src/scaled_vlm.rs", 15, 21,
     [(0x2773D04, "volume_step"), (0x26B24B8, "volume_vec_fold")]),
    ("raw_vlm_17_21", 0x56EB430, FIRST_PARTY + "l1/src/raw_vlm.rs", 17, 21,
     [(0x2773D26, "volume_step"), (0x26B24DD, "volume_vec_fold")]),
    ("impl_ntl_664_1_a", 0x5715E68, FIRST_PARTY + "l1/src/qtys/impl_ntl.rs", 664, 1,
     [(0x2773C63, "volume_step"), (0x2773C91, "volume_step"), (0x26B23FC, "volume_vec_fold"),
      (0x26B242A, "volume_vec_fold")]),
    ("impl_ntl_664_1_b", 0x56BD900, FIRST_PARTY + "l1/src/qtys/impl_ntl.rs", 664, 1,
     [(0x2773D3D, "volume_step"), (0x26B24F9, "volume_vec_fold")]),
]

# ---- Literals (VA, exact bytes). ----
LABEL_VA, LABEL = 0x2035A0, b"createSubAccount"
DIV100_VA = 0x20A960
ASSERT_STR_VA = 0x598EAD
ASSERT_STR = (b"assertion failed: self.sub_account_to_master."
              b"insert(sub_account_user, user).is_none()")
RC_TABLE_VA = 0x7D04C8
SERDE_LITERALS = [  # serde "expecting" strings; leads for names, no xref established here
    (0x3AFECA, b"struct SubAccount with 3 elements"),
    (0x3B02E5, b"user_to_sub_accountssub_account_to_masterstruct SubAccountTracker with 2 elements"),
]
SPECIAL_KEYS = [(0x59C0E4, b"\xff" * 20), (0x59C0F8, b"\xfe" * 20)]  # compared by user_lookup (u_special)

# ---- Status formatter arms: status -> (pinned arm shape, kind, expected bytes, IMMS name of the
# argument's offset from the status, for templates). ----
STATUS_ARMS = {
    0xD6: ("fmt_d6", "message", b"Too many sub-accounts.", None),
    0xD7: ("fmt_d7", "message", b"Sub-account name already taken.", None),
    0xD9: ("fmt_d9", "message", b"Sub-account name must be between 1 and 16 characters long.", None),
    0x143: ("fmt_143", "message", b"Invalid input length", None),
    0xD8: ("fmt_d8", "template", b"\x1bDuplicate sub-account user \xc0\x00", "fmt_d8_arg"),
    0xDD: ("fmt_dd", "template", (b"BCannot create sub-accounts until enough volume traded. Required: $"
                                  b"\xc0\x0b. Traded: $\xc0\x01.\x00"), "fmt_dd_arg"),
    0x57: ("fmt_57", "template", (b"\x45Too many extra agents for cumulative volume traded. Current limit is "
                                  b"\xc0\x00"), "fmt_57_arg"),  # other_consumer's status (negative control)
}
TOKEN_NAMES = ["Address", "FixedBytes", "Bytes", "Int", "Uint", "Bool", "String", "FixedArray",
               "Array", "Tuple"]

# ---- Negative-control byte scans. ----
IMM_989680 = (0x989680).to_bytes(4, "little")
MAGIC_BYTES = (0xDBE6FECEBDEDD5BF).to_bytes(8, "little")
SCAN_EXPECT = {  # window -> {pattern: [hit VAs]}
    "name_sibling": {"imm32_0x989680": [], "imm64_magic": []},
    "creator": {"imm32_0x989680": [0x36F362A], "imm64_magic": [0x36F3736]},
    "other_volume_user": {"imm32_0x989680": [0x27677E5], "imm64_magic": [0x2767862]},
}
TEXT_SCAN_EXPECT = {"imm32_0x989680": (48, 30), "imm64_magic": (7, 7)}  # (hits, FDE windows)

EXCERPT_GAP = 0x40  # pinned windows closer than this share one objdump excerpt
# Whole windows excerpted because a claim rests on their full body (shape windows inside them are dropped).
EXTRA_EXCERPTS = [("user_lookup", 0x3743DF0, 0x374401F, "whole window: every store goes through rax = rdi"),
                  ("volume_report", 0x358DCD0, 0x358DE41, "whole window: two ret paths"),
                  ("vec_entry", 0x3596680, 0x35967A8, "whole window: both return paths")]
JCC = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"]
R64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
       "r14", "r15"]
R16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w",
       "r14w", "r15w"]


# ======================================================================
# Readers and decoders
# ======================================================================

def _s(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=True)


def _fde_window(starts, ends, va, name="?"):
    """(start, end) of the FDE that starts exactly at ``va``; otherwise EvidenceError."""
    c = sr.containing(starts, ends, va)
    if c is None or c[0] != va:
        raise EvidenceError(f"{name}: {va:#x} is not an FDE start")
    return c


def _reloc_symbols(elf, section: str, rtype: int) -> dict:
    """Relocations of one type in ``section``: r_offset -> symbol name (via .dynsym/.dynstr)."""
    _rv, roff, rsz = elf.sections[section]
    _sv, soff, _ssz = elf.sections[".dynsym"]
    _tv, toff, tsz = elf.sections[".dynstr"]
    d = elf.data
    out = {}
    for o in range(roff, roff + rsz, 24):
        r_off, info, _add = struct.unpack_from("<QQq", d, o)
        if info & 0xFFFFFFFF != rtype:
            continue
        st_name = struct.unpack_from("<I", d, soff + 24 * (info >> 32))[0]
        if st_name >= tsz:
            raise EvidenceError(f"{section} {r_off:#x}: symbol name offset out of range")
        end = d.index(b"\0", toff + st_name)
        out[r_off] = d[toff + st_name:end].decode("ascii", "replace")
    return out


def _glob_dat(elf) -> dict:
    """R_X86_64_GLOB_DAT relocations: slot -> symbol name."""
    return _reloc_symbols(elf, ".rela.dyn", 6)


def _plt_symbol(elf, jump_slots: dict, va: int):
    """Symbol of the .plt stub at ``va`` (jmp [rip+x], x an R_X86_64_JUMP_SLOT slot), else None."""
    p_va, _po, p_sz = elf.sections[".plt"]
    if not p_va <= va < p_va + p_sz:
        return None
    b = elf.read(va, 6)
    if b[:2] != b"\xff\x25":
        return None
    return jump_slots.get(va + 6 + _s(b[2:6]))


def _path(table: dict, edges: dict, start: int, stop: int, limit: int = 256):
    """Pinned path from ``start`` to ``stop`` that follows direct jmps only.

    Returns the list of [lo, hi) segments, or None if the walk meets an unpinned address, a
    conditional branch, a call (direct or indirect), an indirect jmp or a ret before ``stop``.
    """
    segs, seg0, v = [], start, start
    for _ in range(limit):
        if v == stop:
            segs.append([seg0, v])
            return segs
        if v not in table:
            return None
        b = table[v][0]
        e = edges.get(v)
        if e is not None:
            if e["mnemonic"] != "jmp":
                return None
            segs.append([seg0, v + len(b)])
            seg0 = v = e["target"]
            continue
        k = 1 if 0x40 <= b[0] <= 0x4F and len(b) > 1 else 0
        if b[k] in (0xC2, 0xC3) or (b[k] == 0xFF and len(b) > k + 1 and (b[k + 1] & 0x38) in (0x10, 0x18, 0x20, 0x28)):
            return None
        v += len(b)
    return None


def _contiguous(table: dict, lo: int, hi: int) -> bool:
    """Every instruction from ``lo`` up to ``hi`` is pinned and they tile [lo, hi) exactly."""
    v = lo
    while v < hi:
        if v not in table:
            return False
        v += len(table[v][0])
    return v == hi


def _shape_table():
    """Instruction table of the pinned shapes: va -> (bytes, shape name, owner)."""
    insns = {}
    spans = []
    for name, owner, va, hexes, _m in SHAPES:
        v = va
        for h in hexes:
            b = bytes.fromhex(h)
            if v in insns:
                raise EvidenceError(f"shape {name}: instruction {v:#x} pinned twice")
            insns[v] = (b, name, owner)
            v += len(b)
        spans.append((va, v, name))
    spans.sort()
    for (a0, a1, n0), (b0, _b1, n1) in zip(spans, spans[1:]):
        if b0 < a1:
            raise EvidenceError(f"shapes {n0} and {n1} overlap")
    return insns


def _branch(va: int, b: bytes):
    """Direct rel8/rel32 branch or call: (mnemonic, target, fallthrough) or None."""
    n = len(b)
    if n == 5 and b[0] in (0xE8, 0xE9):
        return ("call" if b[0] == 0xE8 else "jmp"), va + 5 + _s(b[1:5]), va + 5
    if n == 2 and b[0] == 0xEB:
        return "jmp", va + 2 + _s(b[1:2]), va + 2
    if n == 2 and 0x70 <= b[0] <= 0x7F:
        return JCC[b[0] - 0x70], va + 2 + _s(b[1:2]), va + 2
    if n == 6 and b[0] == 0x0F and 0x80 <= b[1] <= 0x8F:
        return JCC[b[1] - 0x80], va + 6 + _s(b[2:6]), va + 6
    return None


def _mem_operand(b: bytes, j: int, rex: int):
    """Decode a ModRM memory operand at b[j]: (reg field, operand text, next index) or None."""
    modrm = b[j]
    mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
    if mod == 3:
        return None
    k = j + 1
    base = index = None
    scale = 1
    disp = 0
    if rm == 4:
        sib = b[k]
        k += 1
        scale = 1 << (sib >> 6)
        idx = ((sib >> 3) & 7) | ((rex & 2) << 2)
        if idx != 4:
            index = R64[idx]
        if (sib & 7) == 5 and mod == 0:
            disp = _s(b[k:k + 4])
            k += 4
        else:
            base = R64[(sib & 7) | ((rex & 1) << 3)]
    elif rm == 5 and mod == 0:
        return None  # RIP-relative: not a store to the out pointer
    else:
        base = R64[rm | ((rex & 1) << 3)]
    if mod == 1:
        disp = _s(b[k:k + 1])
        k += 1
    elif mod == 2:
        disp = _s(b[k:k + 4])
        k += 4
    text = base or ""
    if index:
        text += ("+" if text else "") + index + (f"*{scale}" if scale != 1 else "")
    if disp:
        text += ("+" if disp > 0 else "-") + hex(abs(disp))
    return reg, "[" + text + "]", k


def _word_stores(elf, lo: int, hi: int):
    """Byte scan for 16-bit stores (66 [REX] C7 /0 imm16 or 66 [REX] 89 r16) in [lo, hi)."""
    b = elf.read(lo, hi - lo + 16)
    out = []
    for i in range(hi - lo):
        if b[i] != 0x66:
            continue
        j = i + 1
        rex = 0
        if 0x40 <= b[j] <= 0x4F:
            rex = b[j]
            j += 1
        if rex & 8 or b[j] not in (0xC7, 0x89):
            continue
        m = _mem_operand(b, j + 1, rex)
        if m is None:
            continue
        reg, operand, k = m
        if b[j] == 0xC7:
            if reg != 0:
                continue
            src = struct.unpack_from("<H", b, k)[0]
            k += 2
        else:
            src = R16[reg | ((rex & 4) << 1)]
        out.append((lo + i, operand, src, b[i:k].hex()))
    return out


def _slot_refs(elf, lo: int, hi: int, got):
    """Byte scan for call/jmp [rip+x] and mov r64,[rip+x] whose x lies in .got."""
    gva, gsz = got
    b = elf.read(lo, hi - lo + 16)
    out = []
    for i in range(hi - lo):
        if b[i] == 0xFF and b[i + 1] in (0x15, 0x25):
            t = lo + i + 6 + _s(b[i + 2:i + 6])
            if gva <= t < gva + gsz:
                out.append((lo + i, "call" if b[i + 1] == 0x15 else "jmp", t))
        elif b[i] in (0x48, 0x4C) and b[i + 1] == 0x8B and (b[i + 2] & 0xC7) == 0x05:
            t = lo + i + 7 + _s(b[i + 3:i + 7])
            if gva <= t < gva + gsz:
                out.append((lo + i, "mov", t))
    return out


def _e8_callers(elf, targets: dict):
    """Byte-pattern scan of .text for E8 rel32 whose target is one of ``targets`` (va -> name)."""
    t_va, t_off, t_size = elf.sections[".text"]
    text = elf.data[t_off:t_off + t_size]
    hits = {name: [] for name in targets.values()}
    pos, find = 0, text.find
    while True:
        i = find(b"\xe8", pos)
        if i < 0 or i + 5 > len(text):
            break
        tgt = t_va + i + 5 + int.from_bytes(text[i + 1:i + 5], "little", signed=True)
        if tgt in targets:
            hits[targets[tgt]].append(t_va + i)
        pos = i + 1
    return hits


def _count_pattern(elf, lo, hi, pat: bytes):
    b = elf.read(lo, hi - lo)
    out, i = [], b.find(pat)
    while i >= 0:
        out.append(lo + i)
        i = b.find(pat, i + 1)
    return out


def _rip_target(va: int, b: bytes, label: str) -> int:
    if len(b) < 6 or (b[-5] & 0xC7) != 0x05:
        raise EvidenceError(f"rip-relative {label} at {va:#x}: no rip-relative ModRM before the disp32")
    return va + len(b) + _s(b[-4:])


def _int_arm_words(ins):
    """Int/Uint word-writer arm: {word byte offset: token displacement of the limb stored there}.

    Only limbs loaded by ``mov r64,[rsi+disp8]``, byte-swapped by ``bswap r64`` and stored by
    ``mov [rax+rcx*1(+disp8)],r64`` are counted; the result also lists the swapped registers.
    """
    loads, swapped, stores = {}, set(), {}
    for b in ins:
        if len(b) == 4 and b[0] in (0x48, 0x4C) and b[1] == 0x8B and (b[2] & 0xC7) == 0x46:
            loads[(((b[0] >> 2) & 1) << 3) | ((b[2] >> 3) & 7)] = b[3]
        elif len(b) == 3 and b[0] == 0x49 and b[1] == 0x0F and 0xC8 <= b[2] <= 0xCF:
            swapped.add(8 + b[2] - 0xC8)
        elif len(b) in (4, 5) and b[0] in (0x48, 0x4C) and b[1] == 0x89 and (b[2] & 7) == 4 and b[3] == 0x08:
            mod = b[2] >> 6
            if (mod, len(b)) in ((0, 4), (1, 5)):
                stores[b[4] if mod == 1 else 0] = (((b[0] >> 2) & 1) << 3) | ((b[2] >> 3) & 7)
    words = {off: loads.get(reg) for off, reg in sorted(stores.items()) if reg in swapped}
    return words, sorted(swapped), sorted(loads)


def _location(elf, relocs, slot):
    """Panic Location {&str file, u32 line, u32 col} at a .data.rel.ro slot."""
    a = relocs.get(slot)
    if a is None:
        raise EvidenceError(f"Location slot {slot:#x} has no RELATIVE relocation")
    ln, line, col = struct.unpack_from("<QII", elf.read(slot + 8, 16))
    if not 0 < ln < 512:
        raise EvidenceError(f"Location slot {slot:#x}: bad length {ln}")
    return a, elf.read(a, ln), line, col


def _rc_lfsr():
    """The 24 Keccak-f[1600] round constants from the rc(t) LFSR definition."""
    def rc(t):
        if t % 255 == 0:
            return 1
        r = 1
        for _ in range(t % 255):
            r <<= 1
            if r & 0x100:
                r ^= 0x171
        return r & 1
    out = []
    for i in range(24):
        c = 0
        for j in range(7):
            if rc(j + 7 * i):
                c |= 1 << ((1 << j) - 1)
        out.append(c)
    return tuple(out)


def _rho():
    """Rotation offsets r[x + 5y] from the (x, y) -> (y, 2x+3y) walk."""
    r = [0] * 25
    x, y = 1, 0
    for t in range(24):
        r[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return tuple(r)


_RC = _rc_lfsr()
_RO = _rho()


# ======================================================================
# build
# ======================================================================

def build(data: bytes, expected_sha256: str = sr.EXPECTED_SHA256) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    if sha != expected_sha256:
        raise EvidenceError(f"binary sha256 {sha} != {expected_sha256}")
    elf = sr.Elf(data)
    starts, ends = sr.fde_index(elf)
    relocs = sr.relative_relocs(elf)
    glob = _glob_dat(elf)
    got = elf.sections[".got"][0], elf.sections[".got"][2]
    relro = elf.sections[".data.rel.ro"][0], elf.sections[".data.rel.ro"][2]

    # 1) Function windows: FDE start and end both pinned.
    functions = {}
    for name, (lo, hi, role) in FUNCS.items():
        s, e = _fde_window(starts, ends, lo, f"function {name}")
        if e != hi:
            raise EvidenceError(f"function {name}: FDE window {s:#x}..{e:#x} != pinned {lo:#x}..{hi:#x}")
        functions[name] = {"start": s, "end": e, "size": e - s, "role": role}

    # 2) Pinned instruction windows (every byte), each inside its owner window.
    table = _shape_table()
    shapes = []
    for name, owner, va, hexes, meaning in SHAPES:
        want = bytes.fromhex("".join(hexes))
        got_b = elf.read(va, len(want))
        if got_b != want:
            raise EvidenceError(f"shape {name} at {va:#x}: {got_b.hex()} != {want.hex()}")
        lo, hi, _r = FUNCS[owner]
        if not (lo <= va and va + len(want) <= hi):
            raise EvidenceError(f"shape {name} at {va:#x} is outside its owner {owner}")
        shapes.append({"name": name, "owner": owner, "va": va, "end": va + len(want),
                       "insns": len(hexes), "bytes": want.hex(), "meaning": meaning})

    # 3) Direct branch/call edges inside the pinned windows, decoded from the bytes.
    edges = {}
    for va in sorted(table):
        b, sname, owner = table[va]
        br = _branch(va, b)
        if br is None:
            continue
        mn, tgt, ft = br
        if mn == "call":
            c = sr.containing(starts, ends, tgt)
            if c is None or c[0] != tgt:
                raise EvidenceError(f"edge {va:#x} ({sname}): call target {tgt:#x} is not an FDE start")
        else:
            lo, hi, _r = FUNCS[owner]
            if not lo <= tgt < hi:
                raise EvidenceError(f"edge {va:#x} ({sname}): {mn} target {tgt:#x} leaves {owner}")
        edges[va] = {"va": va, "mnemonic": mn, "target": tgt, "fallthrough": ft, "shape": sname}

    def edge(va, what):
        if va not in edges:
            raise EvidenceError(f"{what}: {va:#x} is not a decoded branch in a pinned window")
        return edges[va]

    # 4) Immediates and displacements.
    imm = {}
    for name, va, off, size, signed in IMMS:
        if va not in table:
            raise EvidenceError(f"immediate {name}: {va:#x} is not a pinned instruction start")
        b = table[va][0]
        if off + size > len(b):
            raise EvidenceError(f"immediate {name}: offset outside the instruction at {va:#x}")
        imm[name] = int.from_bytes(b[off:off + size], "little", signed=signed)
    imm_va = {name: va for name, va, _off, _size, _signed in IMMS}

    # Consistency of the decoded values that encode one fact twice.
    if imm["cap_clamp_cmp"] != imm["cap_clamp_mov"]:
        raise EvidenceError("cap clamp compare and move disagree")
    if imm["name_lea_disp"] != imm["name_cmp_imm"]:
        raise EvidenceError("name range lea and cmp disagree")
    for k in ("ok_status_handler_derive", "ok_status_handler_creator", "ok_status_creator_rederive",
              "ok_status_creator_helper", "status_186_helper_a", "status_186_helper_b"):
        if imm[k] != 0x186:
            raise EvidenceError(f"{k} is not 0x186")

    # 5) RIP-relative data references.
    riprefs = []
    for va, want, label in RIPREL:
        if va not in table:
            raise EvidenceError(f"rip-relative {label}: {va:#x} is not a pinned instruction start")
        t = _rip_target(va, table[va][0], label)
        if t != want:
            raise EvidenceError(f"rip-relative {label} at {va:#x}: {t:#x} != {want:#x}")
        riprefs.append({"va": va, "target": t, "label": label})

    # 6) Dispatch: tag bias, jump table, and the arm whose call reaches the handler.
    if imm["dispatch_bias_lea"] != -imm["dispatch_bias_cmp"]:
        raise EvidenceError("dispatch: lea bias and cmp bias disagree")
    bias = imm["dispatch_bias_cmp"]
    d_lo, d_hi, _r = FUNCS["dispatcher"]
    dtab = 0x3EDE28
    entries = []
    while True:
        t = dtab + _s(elf.read(dtab + 4 * len(entries), 4))
        if not d_lo <= t < d_hi:
            break
        entries.append(t)
        if len(entries) > 512:
            raise EvidenceError("dispatch: table does not terminate")
    arm6 = [i for i, t in enumerate(entries) if t == 0x2759D2A]
    if arm6 != [6]:
        raise EvidenceError(f"dispatch: table indices reaching arm 0x2759d2a are {arm6} (expected [6])")
    arm1 = [i for i, t in enumerate(entries) if t == 0x27592BD]
    if arm1 != [1]:
        raise EvidenceError(f"dispatch: table indices reaching arm 0x27592bd are {arm1} (expected [1])")
    if edge(0x2759D4D, "dispatch arm call")["target"] != FUNCS["handler"][0]:
        raise EvidenceError("dispatch: index-6 arm does not call the handler")
    if edge(0x27592E0, "dispatch arm call")["target"] != FUNCS["other_entry"][0]:
        raise EvidenceError("dispatch: index-1 arm does not call other_entry")
    dispatch = {"tag_bias": bias, "default_index": imm["dispatch_default_index"], "table": dtab,
                "entries_inside_dispatcher": len(entries), "index": 6, "exchange_tag": bias + 6,
                "arm": 0x2759D2A, "call_site": 0x2759D4D, "handler": FUNCS["handler"][0],
                "index1_tag": bias + 1, "index1_arm": 0x27592BD, "index1_call_site": 0x27592E0,
                "index1_callee": FUNCS["other_entry"][0]}

    # 7) 16-bit store enumeration in the four windows.
    stores = []
    found = []
    for window in STATUS_FIELD:
        lo, hi, _r = FUNCS[window]
        found += [(window,) + s for s in _word_stores(elf, lo, hi)]
    want_set = [(w, va, op, src) for w, va, op, src, _role in WORD_STORES]
    if [(w, va, op, src) for w, va, op, src, _h in found] != want_set:
        raise EvidenceError(f"status-store enumeration differs: {[(w, hex(v), o, s) for w, v, o, s, _h in found]}")
    for (w, va, op, src, role), (_w, _va, _op, _src, hexb) in zip(WORD_STORES, found):
        if va not in table:
            raise EvidenceError(f"16-bit store {va:#x} is not a pinned instruction")
        is_status = op == STATUS_FIELD[w]
        rec = {"window": w, "va": va, "operand": op, "kind": "imm16" if isinstance(src, int) else "register",
               "status_field": is_status, "bytes": hexb, "role": role}
        if isinstance(src, int):
            rec["value"] = src
        else:
            rec["register"] = src
            if va in REGISTER_SOURCES:
                rec["sources"] = []
                for sva, iname in REGISTER_SOURCES[va]:
                    if sva not in table:
                        raise EvidenceError(f"register source {sva:#x} is not pinned")
                    rec["sources"].append({"va": sva, "value": imm[iname]})
            if va in LOAD_SOURCES:
                rec["sources"] = []
                for lva, iname in LOAD_SOURCES[va]:
                    if src != "ax" or lva not in table or table[lva][0][:4] != b"\x0f\xb7\x44\x24":
                        raise EvidenceError(f"status load {lva:#x} is not a pinned movzx eax,WORD PTR [rsp+disp8] "
                                            f"feeding the {src} store at {va:#x}")
                    rec["sources"].append({"va": lva, "load": f"[rsp+{imm[iname]:#x}]"})
        stores.append(rec)
    status_stores = [s for s in stores if s["status_field"]]
    by_store = {s["va"]: s for s in stores}

    # 8) Check order: decision edges, pass edges, status stores.
    rows = []
    for spec in CHECK_ORDER:
        r = {"seq": spec["seq"], "owner": spec["owner"], "kind": spec["kind"],
             "condition": spec["condition"], "note": spec["note"], "status": spec["status"]}
        lo, hi, _r = FUNCS[spec["owner"]]
        for key in ("call", "decision", "store"):
            v = spec[key]
            if v is not None and not lo <= v < hi:
                raise EvidenceError(f"check {spec['seq']}: {key} {v:#x} outside {spec['owner']}")
        if spec["call"] is not None:
            if spec["call"] not in table:
                raise EvidenceError(f"check {spec['seq']}: call {spec['call']:#x} is not pinned")
            r["call_va"] = spec["call"]
            br = edges.get(spec["call"])
            if br is not None:
                r["call_target"] = br["target"]
            else:  # call through a slot
                ref = [x for x in SLOT_REFS if x[1] == spec["call"]]
                if len(ref) != 1:
                    raise EvidenceError(f"check {spec['seq']}: call {spec['call']:#x} is neither direct nor a slot")
                r["call_slot"] = ref[0][3]
        if spec["decision"] is not None:
            e = edge(spec["decision"], f"check {spec['seq']} decision")
            if e["mnemonic"] != spec["decision_mnemonic"]:
                raise EvidenceError(f"check {spec['seq']}: decision {e['va']:#x} is {e['mnemonic']}, "
                                    f"not {spec['decision_mnemonic']}")
            fail = e["target"] if spec["fail_edge"] == "taken" else e["fallthrough"]
            if fail != spec["fail_to"]:
                raise EvidenceError(f"check {spec['seq']}: failure edge goes to {fail:#x}, not {spec['fail_to']:#x}")
            r.update({"decision_va": e["va"], "decision": e["mnemonic"], "fail_edge": spec["fail_edge"],
                      "fail_to": fail})
            r["pass"] = []
            for pva, pmn, how, pto in spec["passes"]:
                pe = edge(pva, f"check {spec['seq']} pass edge")
                if pe["mnemonic"] != pmn:
                    raise EvidenceError(f"check {spec['seq']}: pass edge {pva:#x} is {pe['mnemonic']}, not {pmn}")
                t = pe["target"] if how == "taken" else pe["fallthrough"]
                if t != pto:
                    raise EvidenceError(f"check {spec['seq']}: pass edge {pva:#x} goes to {t:#x}, not {pto:#x}")
                r["pass"].append({"va": pva, "mnemonic": pe["mnemonic"], "edge": how, "target": t})
        if spec["store"] is not None:
            st = by_store.get(spec["store"])
            if st is None or not st["status_field"]:
                raise EvidenceError(f"check {spec['seq']}: {spec['store']:#x} is not an enumerated status store")
            r["store_va"] = st["va"]
            r["store_kind"] = st["kind"]
            if spec["status"] is not None:
                if st["kind"] == "imm16":
                    if st["value"] != spec["status"]:
                        raise EvidenceError(f"check {spec['seq']}: store writes {st['value']:#x}, not {spec['status']:#x}")
                else:
                    vals = [x.get("value") for x in st.get("sources", [])]
                    if spec["status"] not in vals:
                        raise EvidenceError(f"check {spec['seq']}: no register source loads {spec['status']:#x}")
                    r["source_va"] = [x["va"] for x in st["sources"] if x.get("value") == spec["status"]][0]
            # Pinned path from the failure target to the store: straight line, direct jmps followed,
            # no call, no conditional branch, no ret in between.
            if r.get("fail_to") is not None:
                path = _path(table, edges, r["fail_to"], st["va"])
                r["fail_to_store_straight_line"] = path is not None
                if path is not None:
                    r["fail_to_store_path"] = path
        if spec["seq"] in RESULT_CALLS:
            # The propagated status: eax = the callee's u16 at its out pointer, loaded right after the
            # call and compared with 0x186 just before the decision; the failure path must reach the
            # register store without a call, a conditional branch or a ret (direct jmps are followed).
            cva, lea_name, load_name = RESULT_CALLS[spec["seq"]]
            lea_va, load_va = imm_va[lea_name], imm_va[load_name]
            cmp_va = spec["decision"] - 5
            ok = (cva in table and load_va == cva + len(table[cva][0]) and
                  table[lea_va][0][:4] == b"\x48\x8d\x7c\x24" and table[load_va][0][:4] == b"\x0f\xb7\x44\x24" and
                  imm[lea_name] == imm[load_name] and
                  table.get(cmp_va, (b"",))[0] == b"\x3d\x86\x01\x00\x00" and _contiguous(table, load_va, cmp_va) and
                  load_va in [x["va"] for x in by_store[spec["store"]].get("sources", [])] and
                  r.get("fail_to_store_straight_line") is True)
            if not ok:
                raise EvidenceError(f"check {spec['seq']}: the propagated status is not the callee's u16 loaded at "
                                    f"{load_va:#x} and carried on a pinned path to {spec['store']:#x}")
            r["status_load"] = {"call_va": cva, "out_lea_va": lea_va, "load_va": load_va, "compare_va": cmp_va,
                                "operand": f"[rsp+{imm[load_name]:#x}]"}
        rows.append(r)
    status_rows = [r for r in rows if r["status"] is not None]

    # 9) Call slots: byte scan of the five windows, then resolution.
    refs = []
    for window in SLOT_WINDOWS:
        lo, hi, _r = FUNCS[window]
        refs += [(window,) + x for x in _slot_refs(elf, lo, hi, got)]
    if refs != SLOT_REFS:
        raise EvidenceError(f"slot references differ: {[(w, hex(v), k, hex(s)) for w, v, k, s in refs]}")
    used = sorted({s for _w, _v, _k, s in SLOT_REFS})
    slot_out = []
    for slot in sorted(SLOTS):
        kind, want, label = SLOTS[slot]
        in_got = got[0] <= slot < got[0] + got[1]
        in_relro = relro[0] <= slot < relro[0] + relro[1]
        if not (in_got or in_relro):
            raise EvidenceError(f"slot {slot:#x} ({label}) is not in .got/.data.rel.ro")
        rec = {"slot": slot, "kind": kind, "label": label, "section": ".got" if in_got else ".data.rel.ro",
               "used_by_five_windows": slot in used}
        if kind == "relative":
            t = relocs.get(slot)
            if t != want:
                shown = "none" if t is None else f"{t:#x}"
                raise EvidenceError(f"slot {slot:#x} ({label}) RELATIVE -> {shown} != {want:#x}")
            _fde_window(starts, ends, t, f"slot {slot:#x} target")
            rec["target"] = t
        else:
            sym = glob.get(slot)
            if sym != want:
                raise EvidenceError(f"slot {slot:#x} ({label}) GLOB_DAT symbol {sym!r} != {want!r}")
            if slot in relocs:
                raise EvidenceError(f"slot {slot:#x} carries both GLOB_DAT and RELATIVE")
            rec["symbol"] = sym
        slot_out.append(rec)
    if set(used) - set(SLOTS):
        raise EvidenceError("a used slot has no resolution entry")
    for slot, sites in OTHER_SLOT_USES.items():
        for va in sites:
            b = elf.read(va, 6)
            if b[:2] != b"\xff\x15" or va + 6 + _s(b[2:6]) != slot:
                raise EvidenceError(f"slot {slot:#x}: no call [rip] to it at {va:#x}")
    call_slots = {"windows": list(SLOT_WINDOWS), "references": [
        {"window": w, "va": v, "kind": k, "slot": s} for w, v, k, s in SLOT_REFS],
        "slots": slot_out,
        "summary": {"references": len(SLOT_REFS), "distinct_slots_used_by_five_windows": len(used),
                    "resolved": sum(1 for x in slot_out if x["used_by_five_windows"]),
                    "relative": sum(1 for x in slot_out if x["used_by_five_windows"] and x["kind"] == "relative"),
                    "glob_dat": sum(1 for x in slot_out if x["used_by_five_windows"] and x["kind"] == "glob_dat"),
                    "other_cited_slots": len(SLOTS) - len(used)}}

    # 9b) The other call sites of the four windows: direct E8 calls (FDE start or .plt stub) and
    # calls through a register. With the slot calls above they are every call (objdump test).
    jump_slots = _reloc_symbols(elf, ".rela.plt", 7)
    call_sites = []
    for w, va, want, label in DIRECT_CALLS:
        lo, hi, _r = FUNCS[w]
        b = elf.read(va, 5)
        if not lo <= va < hi or b[0] != 0xE8:
            raise EvidenceError(f"direct call {va:#x} in {w}: not an E8 rel32 call inside the window")
        t = va + 5 + _s(b[1:5])
        rec = {"window": w, "va": va, "kind": "direct", "target": t, "label": label}
        if isinstance(want, str):
            sym = _plt_symbol(elf, jump_slots, t)
            if sym != want:
                raise EvidenceError(f"direct call {va:#x}: target {t:#x} is not the .plt stub of {want}")
            rec["plt_symbol"] = sym
        else:
            if t != want:
                raise EvidenceError(f"direct call {va:#x}: target {t:#x} != {want:#x}")
            _fde_window(starts, ends, t, f"direct call {va:#x} target")
        call_sites.append(rec)
    for w, va, hexb, label in REGISTER_CALLS:
        lo, hi, _r = FUNCS[w]
        if not lo <= va < hi or elf.read(va, len(hexb) // 2).hex() != hexb:
            raise EvidenceError(f"register call {va:#x} in {w}: bytes differ from {hexb}")
        call_sites.append({"window": w, "va": va, "kind": "register", "bytes": hexb, "label": label})
    for w, va, kind, slot in SLOT_REFS:
        if kind == "call" and w in STATUS_FIELD:
            call_sites.append({"window": w, "va": va, "kind": "slot", "slot": slot,
                               "label": SLOTS[slot][2] or "not decoded"})
    call_sites.sort(key=lambda c: (list(STATUS_FIELD).index(c["window"]), c["va"]))
    call_slot_set = {c["slot"] for c in call_sites if c["kind"] == "slot"}
    calls = {"sites": call_sites,
             "summary": {"calls": len(call_sites),
                         "direct": sum(1 for c in call_sites if c["kind"] == "direct"),
                         "register": sum(1 for c in call_sites if c["kind"] == "register"),
                         "through_slot": sum(1 for c in call_sites if c["kind"] == "slot"),
                         "through_slot_distinct_slots": len(call_slot_set),
                         "through_slot_relative": sum(1 for s in call_slot_set if SLOTS[s][0] == "relative"),
                         "through_slot_glob_dat": sum(1 for s in call_slot_set if SLOTS[s][0] == "glob_dat")}}

    # 10) Direct callers (E8 rel32 byte patterns over .text) and RELATIVE references.
    tmap = {FUNCS[n][0]: n for n in CALLERS}
    hits = _e8_callers(elf, tmap)
    callers = {}
    for name, want in CALLERS.items():
        got_h = sorted(hits[name])
        if got_h != want:
            raise EvidenceError(f"callers of {name}: {[hex(x) for x in got_h]} != {[hex(x) for x in want]}")
        callers[name] = [{"va": v, "function": (sr.containing(starts, ends, v) or (None,))[0],
                          "pinned_instruction": v in table} for v in got_h]
    relrefs = {}
    for name, want in RELATIVE_REFS.items():
        got_r = sorted(k for k, v in relocs.items() if v == FUNCS[name][0])
        if got_r != want:
            raise EvidenceError(f"RELATIVE references to {name}: {[hex(x) for x in got_r]} != {[hex(x) for x in want]}")
        relrefs[name] = got_r

    # 11) Panic Location records and the lea that references each one.
    locations = []
    for label, slot, path, line, col, sites in LOCATIONS:
        a, s, gl, gc = _location(elf, relocs, slot)
        if s != path.encode() or gl != line or gc != col:
            raise EvidenceError(f"Location {label} at {slot:#x}: {s!r}:{gl}:{gc} != {path!r}:{line}:{col}")
        for va, owner in sites:
            lo, hi, _r = FUNCS[owner]
            b = elf.read(va, 7)
            ok = (lo <= va < hi and b[0] in (0x48, 0x4C) and b[1] == 0x8D and (b[2] & 0xC7) == 0x05
                  and va + 7 + _s(b[3:7]) == slot)
            if not ok:
                raise EvidenceError(f"Location {label}: not referenced by a lea at {va:#x} in {owner}")
        locations.append({"label": label, "slot": slot, "addr": a, "file": path, "line": line, "col": col,
                          "lea_sites": [{"va": va, "function": owner} for va, owner in sites]})

    # 12) Literals.
    if elf.read(LABEL_VA, len(LABEL)) != LABEL:
        raise EvidenceError(f"literal createSubAccount at {LABEL_VA:#x} differs")
    div = struct.unpack("<d", elf.read(DIV100_VA, 8))[0]
    if div != 100.0:
        raise EvidenceError(f"literal div_100 at {DIV100_VA:#x} is {div}")
    if elf.read(ASSERT_STR_VA, len(ASSERT_STR)) != ASSERT_STR or imm["assert_msg_len"] != len(ASSERT_STR):
        raise EvidenceError(f"literal insert_assert_string at {ASSERT_STR_VA:#x} differs")
    rc = tuple(struct.unpack("<24Q", elf.read(RC_TABLE_VA, 8 * 24)))
    if rc != _RC:
        raise EvidenceError("keccak round constants at 0x7d04c8 differ from the rc(t) LFSR values")
    if imm["keccak_round_bytes"] != 8 * len(_RC):
        raise EvidenceError("keccak_f loop bound is not 24 qwords")
    for va, text in SERDE_LITERALS:
        if elf.read(va, len(text)) != text:
            raise EvidenceError(f"serde literal at {va:#x} differs")
    for va, key in SPECIAL_KEYS:
        if elf.read(va, len(key)) != key:
            raise EvidenceError(f"user_lookup special key at {va:#x} differs")
    literals = {"createSubAccount": {"va": LABEL_VA, "len": len(LABEL), "loaded_by": 0x36F3D2C},
                "user_lookup_special_keys": [{"va": va, "bytes": key.hex(), "loaded_by": lb}
                                             for (va, key), lb in zip(SPECIAL_KEYS, (0x3743DFE, 0x3743E33))],
                "div_100": {"va": DIV100_VA, "value": div, "loaded_by": 0x36F3635},
                "insert_assert_string": {"va": ASSERT_STR_VA, "len": len(ASSERT_STR),
                                         "text": ASSERT_STR.decode(), "loaded_by": 0x36F3BC6},
                "keccak_rc_table": {"va": RC_TABLE_VA, "qwords": len(rc), "equal_to_lfsr": 24,
                                    "loaded_by": 0x4F598F0},
                "serde": [{"va": va, "text": t.decode()} for va, t in SERDE_LITERALS]}

    # 13) Status formatter: table, then the pinned arms.
    f_lo, f_hi, _r = FUNCS["status_formatter"]
    ftab = 0x59A8D0
    n = 0
    while f_lo <= ftab + _s(elf.read(ftab + 4 * n, 4)) < f_hi:
        n += 1
        if n > 4096:
            raise EvidenceError("status_formatter: table does not terminate")
    shape_va = {s[0]: s[2] for s in SHAPES}
    arms = []
    for status in sorted(STATUS_ARMS):
        sname, kind, want, arg_name = STATUS_ARMS[status]
        if status >= n:
            raise EvidenceError(f"status_formatter: status {status:#x} is outside the table")
        arm = ftab + _s(elf.read(ftab + 4 * status, 4))
        if arm != shape_va[sname]:
            raise EvidenceError(f"status_formatter: status {status:#x} -> arm {arm:#x}, not {shape_va[sname]:#x}")
        ins = [table[v][0] for v in sorted(table) if table[v][1] == sname]
        rec = {"status": status, "arm": arm, "kind": kind}
        if kind == "message":
            lea, mov = ins[3], ins[4]
            if lea[:3] != b"\x48\x8d\x35" or mov[0] != 0xBA:
                raise EvidenceError(f"status_formatter: status {status:#x} arm is not lea rsi ; mov edx")
            sva = arm + sum(len(x) for x in ins[:4]) + _s(lea[3:7])
            ln = _s(mov[1:5])
            text = elf.read(sva, ln)
            if text != want:
                raise EvidenceError(f"status_formatter: status {status:#x} message {text!r} != {want!r}")
            rec.update({"text_va": sva, "len": ln, "text": text.decode()})
        else:
            k = [i for i, x in enumerate(ins) if x[:3] == b"\x48\x8d\x15"]
            if len(k) != 1:
                raise EvidenceError(f"status_formatter: status {status:#x} template arm has no single lea rdx")
            k = k[0]
            tva = arm + sum(len(x) for x in ins[:k]) + 7 + _s(ins[k][3:7])
            raw = elf.read(tva, len(want))
            if raw != want:
                raise EvidenceError(f"status_formatter: status {status:#x} template {raw!r} != {want!r}")
            pieces, i = [], 0
            while True:
                ln = raw[i]
                pieces.append(raw[i + 1:i + 1 + ln].decode())
                i += 1 + ln
                if raw[i] == 0:
                    break
                if raw[i] != 0xC0:
                    raise EvidenceError(f"status_formatter: status {status:#x} template marker {raw[i]:#x}")
                i += 1
                if raw[i] == 0:
                    pieces.append("")
                    break
            rec.update({"template_va": tva, "template_bytes": raw.hex(), "pieces": pieces,
                        "rendered": "{}".join(pieces), "argument_base_offset": imm[arg_name]})
            if status == 0xDD:
                rec["constant_argument"] = struct.unpack("<d", imm["fmt_dd_required"].to_bytes(8, "little"))[0]
        arms.append(rec)
    formatter = {"table": ftab, "entries_inside_formatter": n, "first_index_outside": n, "arms": arms}

    # 14) ethabi Token Debug: tag -> variant name and payload offset.
    t_lo, t_hi, _r = FUNCS["ethabi_token_debug"]
    ttab = 0x25FA64
    variants = []
    for tag, want in enumerate(TOKEN_NAMES):
        arm = ttab + _s(elf.read(ttab + 4 * tag, 4))
        if not t_lo <= arm < t_hi:
            raise EvidenceError(f"token_debug: tag {tag} arm {arm:#x} outside the Debug impl")
        b = elf.read(arm, 0x30)
        if b[:3] == b"\x48\xff\xc0":
            poff, k = 1, 3
        elif b[:4] == b"\x48\x83\xc0\x08":
            poff, k = 8, 4
        else:
            raise EvidenceError(f"token_debug: tag {tag} arm prefix {b[:4].hex()}")
        mid = bytes.fromhex("48894424084c8b334c8b7b084d8b6718")
        if b[k:k + len(mid)] != mid or b[k + len(mid):k + len(mid) + 3] != b"\x48\x8d\x35":
            raise EvidenceError(f"token_debug: tag {tag} arm body differs")
        k += len(mid)
        nva = arm + k + 7 + _s(b[k + 3:k + 7])
        k += 7
        if b[k] == 0xBA:
            ln = _s(b[k + 1:k + 5])
        elif b[k] in (0xE9, 0xEB):
            j = arm + k + (5 + _s(b[k + 1:k + 5]) if b[k] == 0xE9 else 2 + _s(b[k + 1:k + 2]))
            jb = elf.read(j, 5)
            if jb[0] != 0xBA:
                raise EvidenceError(f"token_debug: tag {tag} jump target lacks mov edx")
            ln = _s(jb[1:5])
        else:
            raise EvidenceError(f"token_debug: tag {tag} has no length")
        name = elf.read(nva, ln).decode("ascii", "replace")
        if name != want:
            raise EvidenceError(f"token_debug: tag {tag} decodes to {name!r} != {want!r}")
        variants.append({"tag": tag, "name": name, "payload_offset": poff, "arm": arm, "name_va": nva})
    vmap = {v["tag"]: v for v in variants}
    builder_tokens = []
    for idx, (disp, tag) in enumerate([(0, imm["tok0_tag"]), (imm["tok1_disp"], imm["tok1_tag"]),
                                        (imm["tok2_disp"], imm["tok2_tag"])]):
        builder_tokens.append({"index": idx, "offset": disp, "tag": tag, "variant": vmap[tag]["name"],
                               "payload_offset": vmap[tag]["payload_offset"]})
    if [t["variant"] for t in builder_tokens] != ["String", "Address", "Uint"]:
        raise EvidenceError("builder tokens are not String, Address, Uint")
    if imm["tok1_payload_dst"] != imm["tok1_disp"] + vmap[imm["tok1_tag"]]["payload_offset"] or \
            imm["tok2_limb0_dst"] != imm["tok2_disp"] + vmap[imm["tok2_tag"]]["payload_offset"]:
        raise EvidenceError("builder payload offsets disagree with the Debug impl")
    if imm["token_alloc"] != 3 * imm["tok1_disp"] or imm["tok2_disp"] != 2 * imm["tok1_disp"] or imm["ntokens"] != 3:
        raise EvidenceError("builder token stride / count mismatch")

    # 14b) ethabi word writer 0x1591cd0 (reached from the encoder through 0x1591f20): tag table and the
    # Int/Uint arm's word layout.
    w_lo, w_hi, _r = FUNCS["ethabi_word_writer"]
    wtab = 0x25FBA4
    ww_arms = []
    for tag in range(imm["ww_max_tag"] + 1):
        arm = wtab + _s(elf.read(wtab + 4 * tag, 4))
        if not w_lo <= arm < w_hi:
            raise EvidenceError(f"word writer: tag {tag} arm {arm:#x} outside the function")
        ww_arms.append({"tag": tag, "variant": TOKEN_NAMES[tag], "arm": arm})
    if [a["tag"] for a in ww_arms if a["arm"] == shape_va["ww_int"]] != [3, 4]:
        raise EvidenceError("word writer: the bswap arm is not reached by exactly tags 3 and 4 (Int, Uint)")
    words, swapped, loaded = _int_arm_words([table[v][0] for v in sorted(table) if table[v][1] == "ww_int"])
    if words != {0x0: 0x20, 0x8: 0x18, 0x10: 0x10, 0x18: 0x8} or swapped != loaded or (1 << imm["ww_word_shift"]) != 32:
        raise EvidenceError(f"word writer: the Int/Uint arm does not store limbs 3..0 byte-swapped as one 32-byte "
                            f"word: {words}")
    word_writer = {"function": w_lo, "table": wtab, "max_tag": imm["ww_max_tag"], "arms": ww_arms,
                   "int_uint_arm": shape_va["ww_int"], "word_bytes": 1 << imm["ww_word_shift"],
                   "int_uint_word": [{"word_offset": k, "token_disp": v, "limb": (v - 8) // 8, "bswap": True}
                                     for k, v in words.items()],
                   "reading": "big-endian 256-bit word: bswap(limb3) || bswap(limb2) || bswap(limb1) || bswap(limb0)",
                   "reached_by": "0x1592160 -> call 0x1591f20 at 0x1592255 -> call 0x1591cd0 at 0x159200d / 0x15920d3"}

    # 15) Cross-checks between decoded values (links between the pinned sites).
    links = []

    def link(what, ok, sites):
        if not ok:
            raise EvidenceError(f"link failed: {what}")
        links.append({"what": what, "sites": sites})

    link("producer result: stored to [rsp+0x110] after call 0x275fee0, loaded into r8 before the creator call",
         imm["volume_slot_store"] == imm["volume_slot_load"] and
         edge(0x27E3317, "producer call")["target"] == FUNCS["volume_producer"][0], [0x27E331C, 0x27E33B2])
    link("creator compares r8 (5th argument) with the threshold and keeps it in r13 for the cap multiply",
         table[0x36F3669][0] == bytes.fromhex("4d89c5") and table[0x36F36C0][0] == bytes.fromhex("4c89e9"),
         [0x36F3627, 0x36F3669, 0x36F36C0, 0x36F373E])
    link("other_volume_user applies the same threshold and cap constants",
         (imm["other_min_volume"], imm["other_magic"], imm["other_shift"], imm["other_clamp_cmp"],
          imm["other_clamp_mov"], imm["other_base"]) ==
         (imm["min_volume"], imm["cap_magic"], imm["cap_shift"], imm["cap_clamp_cmp"],
          imm["cap_clamp_mov"], imm["cap_base"]), [0x27677E3, 0x2767860])
    link("name length: r15 = [name+0x10] is compared with 100 and passed as r8 to name_helper",
         imm["name_len_field"] == 0x10 and table[0x36F3A29][0] == bytes.fromhex("4d89f8") and
         edge(0x36F3A2C, "helper call")["target"] == FUNCS["name_helper"][0], [0x36F3908, 0x36F3A29, 0x36F3A2C])
    shape_span = {s["name"]: (s["va"], s["end"]) for s in shapes}
    for first, second, what in [("c_args", "c_volume_gate", "creator: the volume compare is the first instruction after the prologue"),
                                ("n_out", "n_len", "name_helper: the r8 length test is the first instruction after the prologue"),
                                ("h_args", "h_tracker", "handler: prologue, argument moves, then the tracker lea"),
                                ("d_args0", "d_guard", "deriver: prologue, argument moves, then the map guard")]:
        a0, a1 = shape_span[first]
        link(what, a0 == FUNCS[dict((x[0], x[1]) for x in SHAPES)[first]][0] and a1 == shape_span[second][0],
             [a0, shape_span[second][0]])
    link("both names pass through slot 0x576e050 (0x1344900) before the length compare and bcmp",
         SLOTS[0x576E050][1] == FUNCS["to_lowercase"][0], [0x36F43F8, 0x36F4506, 0x36F4553, 0x36F4576])
    link("tracker base: handler passes exchange+0x37e0; the producer reads the same map at exchange+0x37e0",
         imm["tracker_field"] == imm["prod_ctrl_field"] and imm["prod_items_field"] == imm["tracker_field"] + imm["map1_items_field"],
         [0x27E315D, 0x275FF21, 0x275FEFD])
    link("user table: the handler probes exchange+0x740 (ctrl) / +0x758 (items) and later calls 0x1f849b0(exchange+0x740)",
         imm["user_table_ctrl_field"] == imm["user_table_field_r12"] == 0x740 and imm["user_table_items_field"] == 0x758,
         [0x27E31FB, 0x27E31D2, 0x27E33E5, 0x27E36F4])
    link("sub_account_to_master: probed at tracker+0x30 (items at +0x48) and inserted at tracker+0x30",
         imm["map2_ctrl_field"] == imm["insert_map_field"] == 0x30 and imm["map2_items_field"] == 0x48,
         [0x36F37EF, 0x36F37CD, 0x36F3A42])
    base = imm["prod_state_base"]
    link("producer state at rsp+0x20 as the fold reads it: [+0]=1, [+0x8]=&Vec (bucket+0x18), "
         "front [+0x10]=0, back [+0x20]=0, once(master) tag 1 at [+0x30]; so the fold steps the master, "
         "skips both slice loops and folds the Vec through 0x26b2180",
         imm["prod_iter_tag_disp"] == base and imm["prod_iter_tag"] == 1 and
         imm["prod_vec_disp"] - base == imm["fold_vec_field"] == 8 and imm["prod_vec_off"] == -0x18 and
         imm["prod_front_disp"] - base == imm["fold_front_field"] == 0x10 and imm["prod_front_val"] == 0 and
         imm["prod_back_disp"] - base == imm["fold_back_field"] == 0x20 and imm["prod_back_val"] == 0 and
         imm["prod_once_disp"] - base == imm["fold_once_disp"] == 0x30 and imm["prod_once_tag"] == 1 and
         edge(0x2760033, "fold call")["target"] == FUNCS["volume_fold"][0] and
         edge(0x258B5E4, "vec fold call")["target"] == FUNCS["volume_vec_fold"][0],
         [0x275FFF3, 0x2760009, 0x2760012, 0x2760017, 0x2760020, 0x2760029, 0x258B4F6, 0x258B53B, 0x258B5E4])
    a_lo, a_hi = shape_span["a_body"]
    link("alloc_fail: the pinned window is its whole FDE window and holds no ret instruction",
         (a_lo, a_hi) == FUNCS["alloc_fail"][:2] and
         all(table[v][0] not in (b"\xc3", b"\xc2") for v in table if table[v][1] == "a_body"),
         [a_lo, a_hi])
    link("the Vec fold reads the 20-byte address at record+0x18 of 0x40-byte records, as the creator writes it",
         (1 << imm["vec_shift"]) == (1 << imm["record_shift"]) == 0x40 and imm["vec_addr_disp"] == imm["record_sub_lo"] == 0x18,
         [0x26B21D8, 0x26B21E9, 0x36F3AA1, 0x36F3ABC])
    link("deriver count = [bucket_end-0x8] (bucket+0x28, the Vec len), the same field the creator's cap compares",
         imm["count_disp"] == imm["cap_count_disp"] == -8, [0x36F3D0E, 0x36F3759])
    link("deriver passes the count at args+0x30 (rsp+0x98, args = rsi = rsp+0x68); the builder keeps rsi in r15 "
         "and loads [r15+0x30] into limb 0",
         imm["count_arg_disp"] - imm["derive_args_lea"] == imm["count_field"] == 0x30 and
         table[0x3C9790D][0] == bytes.fromhex("4989f7"), [0x36F3D64, 0x36F3D71, 0x3C9790D, 0x3C9793C, 0x3C97975])
    link("the count is Uint limb 0 (token 2 at +0x50, limb 0 at +0x58 = token+0x8); the word writer stores the limb "
         "at token+0x8 byte-swapped at word+0x18, so the count fills word bytes 24..32 big-endian",
         imm["tok2_limb0_dst"] - imm["tok2_disp"] == vmap[4]["payload_offset"] == words[0x18] == 8 and
         edge(0x1592255, "encoder words call")["target"] == FUNCS["ethabi_words"][0] and
         edge(0x159200D, "word writer call")["target"] == edge(0x15920D3, "word writer call")["target"] ==
         FUNCS["ethabi_word_writer"][0],
         [0x3C97971, 0x3C97975, 0x1592255, 0x159200D, 0x15920D3, 0x1591D24, 0x1591D6B])
    link("vec_entry returns X-0x18 on both paths; X is a bucket end on the vacant path, which writes the 20-byte key "
         "at X-0x30 and Vec {cap 0, ptr 8, len 0} at X-0x18..-0x8 of a 0x30-byte bucket; on the occupied path X "
         "comes from 0x379a4d0 (inference); the creator compares len [ret+0x10] (= X-0x8; on the vacant path "
         "bucket_end-0x8, the field the cap and the deriver read) with cap [ret], pushes through ptr [ret+0x8] and "
         "stores len+1 to [ret+0x10]",
         imm["entry_ret_vacant"] == imm["entry_ret_occupied"] == imm["entry_cap_disp"] == -0x18 and
         imm["entry_ptr_disp"] == -0x10 and imm["entry_len_disp"] == -0x8 and imm["entry_key_disp"] == -0x30 and
         (3 << imm["entry_stride_shift"]) == 0x30 and
         (imm["entry_cap_val"], imm["entry_ptr_val"], imm["entry_len_val"]) == (0, 8, 0) and
         imm["entry_ret_vacant"] + imm["push_len_field"] == imm["entry_len_disp"] == imm["count_disp"] and
         imm["entry_ret_vacant"] + imm["push_ptr_field"] == imm["entry_ptr_disp"] and
         imm["push_len_store"] == imm["push_len_field"] and
         edge(0x36F3A7F, "vec_entry call")["target"] == FUNCS["vec_entry"][0],
         [0x36F3A7F, 0x359671E, 0x3596734, 0x3596753, 0x3596761, 0x36F3A87, 0x36F3A99, 0x36F3ADD])
    link("the fold hands the exchange to both callees: rdx (the producer's rbx) is stored at [rsp+0x10]; the step "
         "gets ctx = rsp with [rsp] = rsp+0x10 and reads [[ctx]]; the Vec fold gets rdx = rsp+0x8, a copy of "
         "[rsp+0x10], and reads [rdx]",
         imm["fold_ctx_store"] == imm["fold_ctx_lea"] == imm["fold_ctx_copy_src"] == 0x10 and
         imm["fold_ctx_copy_dst"] == imm["fold_vec_ctx"] == 0x8 and
         all(table[va][0] == bytes.fromhex(h) for va, h in [
             (0x275FEEA, "4889fb"), (0x2760030, "4889da"), (0x258B504, "48891424"), (0x258B527, "4889e1"),
             (0x258B52D, "4889cf"), (0x2773BC1, "488b07"), (0x2773BC4, "488b38"), (0x26B21AF, "488b1a")]),
         [0x275FEEA, 0x2760030, 0x258B4F1, 0x258B4FF, 0x258B504, 0x258B527, 0x258B55C, 0x258B561, 0x258B5D9,
          0x2773BC1, 0x26B21AF])
    link("the step and the Vec fold walk the same table, [exchange+0x5c8] records of 0x2f0 bytes from "
         "[exchange+0x5c0]: the step passes record+0xf8 to 0x36f57f0 and sums [result+0x40]/[result+0x48]; the "
         "Vec fold probes the map at record+0xf8 (mask +0x100, items +0x110, hasher +0x118, 0x78-byte buckets) "
         "inline and sums [value+0x40]/[value+0x48]; both look the user up at exchange+0x80 through slot 0x5773170",
         imm["step_rec_count_field"] == imm["vec_rec_count_field"] == 0x5C8 and
         imm["step_rec_base_field"] == imm["vec_rec_base_field"] == 0x5C0 and
         imm["step_rec_stride"] == imm["step_rec_next"] == -imm["step_rec_countdown"] == imm["vec_rec_stride"] ==
         imm["vec_rec_next"] == 0x2F0 and imm["step_map_disp"] == imm["vec_map_ctrl"] == 0xF8 and
         (imm["vec_map_mask"], imm["vec_map_items"], imm["vec_map_hasher"], imm["vec_bucket_stride"]) ==
         (0x100, 0x110, 0x118, 0x78) and
         (imm["step_sum_field"], imm["step_raw_field"]) == (imm["vec_sum_field"], imm["vec_raw_field"]) == (0x40, 0x48) and
         -imm["step_lookup_disp"] == imm["vec_lookup_disp"] == 0x80 and
         edge(0x2773C2C, "per-record lookup call")["target"] == 0x36F57F0,
         [0x2773BDB, 0x2773BF5, 0x2773BFC, 0x2773C03, 0x2773C2C, 0x2773C31, 0x2773C49, 0x2773CCA, 0x26B21B2,
          0x26B220D, 0x26B2222, 0x26B2229, 0x26B2253, 0x26B227C, 0x26B22CC, 0x26B23C8, 0x26B23E0])

    # 16) Byte scans (negative controls and positive controls).
    scans = {}
    for window, pats in SCAN_EXPECT.items():
        lo, hi, _r = FUNCS[window]
        scans[window] = {}
        for pname, pat in (("imm32_0x989680", IMM_989680), ("imm64_magic", MAGIC_BYTES)):
            h = _count_pattern(elf, lo, hi, pat)
            if h != pats[pname]:
                raise EvidenceError(f"byte scan: {pname} in {window} at {[hex(x) for x in h]}, expected "
                                    f"{[hex(x) for x in pats[pname]]}")
            scans[window][pname] = h
    t_va, _to, t_sz = elf.sections[".text"]
    text_counts = {}
    for pname, pat in (("imm32_0x989680", IMM_989680), ("imm64_magic", MAGIC_BYTES)):
        h = _count_pattern(elf, t_va, t_va + t_sz, pat)
        fdes = {sr.containing(starts, ends, x)[0] for x in h if sr.containing(starts, ends, x)}
        got_c = (len(h), len(fdes))
        if got_c != TEXT_SCAN_EXPECT[pname]:
            raise EvidenceError(f"byte scan: {pname} in .text {got_c} != {TEXT_SCAN_EXPECT[pname]}")
        text_counts[pname] = {"hits": got_c[0], "fde_windows": got_c[1]}

    # 17) Kept digest bytes, derived from the copy and store displacements.
    if not (imm["digest_out"] == imm["copy_src0"] and imm["copy_src1"] == imm["copy_src0"] + 16 and
            imm["digest_len"] == 32):
        raise EvidenceError("digest copy layout differs")
    copy = {imm["copy_dst0"]: imm["copy_src0"] - imm["digest_out"],
            imm["copy_dst1"]: imm["copy_src1"] - imm["digest_out"]}

    def hash_off(stack_off):
        for dst, src in copy.items():
            if dst <= stack_off < dst + 16:
                return src + stack_off - dst
        raise EvidenceError(f"kept digest bytes: stack offset {stack_off:#x} not a digest copy")
    pieces = sorted([(imm["keep_xmm_dst"], hash_off(imm["keep_xmm_src"]), 16),
                     (imm["keep_dword_dst"], hash_off(imm["keep_dword_src"]), 4)])
    addr_lo = pieces[0][0]
    contiguous = all(p[0] - addr_lo == p[1] - pieces[0][1] for p in pieces)
    kept = (pieces[0][1], pieces[-1][1] + pieces[-1][2])
    if not contiguous or kept[1] - kept[0] != 20:
        raise EvidenceError(f"kept digest bytes are not one 20-byte slice: {pieces}")
    kept_digest = {"out_address_offset": addr_lo,
                   "stores": [{"out_offset": o, "digest_offset": h, "len": n_} for o, h, n_ in pieces],
                   "slice": list(kept)}

    # 18) Constants decoded from the bytes, and the map and record layouts.
    shift = 64 + imm["cap_shift"]
    magic = imm["cap_magic"]
    divisor = -((-(1 << shift)) // magic)  # ceil(2^shift / M)
    a = -imm["name_lea_disp"]                       # len - a
    b_ = imm["name_cmp_imm"] & M64                  # unsigned compare bound
    name_lo = (a + b_ + 1) & M64                    # (len - a) mod 2^64 > b  <=>  len in [lo, hi]
    name_hi = a - 1
    delim, mode = imm["keccak_delim_mode"] & 0xFF, imm["keccak_delim_mode"] >> 8
    constants = {
        "min_volume_raw": imm["min_volume"],
        "reciprocal_magic": magic, "reciprocal_shift": shift, "volume_per_extra_sub_raw": divisor,
        "cap_quotient_clamp": imm["cap_clamp_cmp"], "cap_addend": imm["cap_base"],
        "name_len_upper_tier": imm["name_upper"], "name_len_accepted_lo": name_lo,
        "name_len_accepted_hi": name_hi,
        "keccak_rate": imm["keccak_rate"], "keccak_delimiter": delim, "keccak_mode_byte": mode,
        "keccak_rounds": imm["keccak_round_bytes"] // 8, "digest_len": imm["digest_len"],
        "ok_status": 0x186, "status_143": imm["status_143"], "status_d7": imm["status_d7"],
        "handler_error_byte": imm["handler_err_byte"], "handler_ok_byte": imm["handler_ok_byte"],
        "handler_status_offset": imm["handler_status_disp"],
        "f64_divisor": div,
        "fmt_required_constant": [x for x in arms if x["status"] == 0xDD][0]["constant_argument"],
    }
    if constants["fmt_required_constant"] != imm["min_volume"] / div:
        raise EvidenceError("the 0xdd message's Required constant is not min_volume / 100.0")

    map_layouts = {
        "tracker": {"base_field": imm["tracker_field"], "owner": "handler (lea r12,[rcx+0x37e0])"},
        "user_to_sub_accounts": {"ctrl_field": 0, "mask_field": imm["map1_mask_field"],
                                 "items_field": imm["map1_items_field"], "bucket_stride": 0x30,
                                 "value": "Vec at bucket+0x18 (cap, ptr, len); len at bucket+0x28 = [bucket_end-0x8]"},
        "sub_account_to_master": {"ctrl_field": imm["map2_ctrl_field"], "mask_field": imm["map2_mask_field"],
                                  "items_field": imm["map2_items_field"], "bucket_stride": 0x28},
        "exchange_740_table": {"exchange_ctrl_field": imm["user_table_ctrl_field"],
                               "exchange_mask_field": imm["user_table_mask_field"],
                               "exchange_items_field": imm["user_table_items_field"],
                               "bucket_stride": imm["user_table_stride"],
                               "name": "not established (the reference labels it a global user-account table)"},
        "volume_records": {"exchange_count_field": imm["step_rec_count_field"],
                           "exchange_base_field": imm["step_rec_base_field"], "stride": imm["step_rec_stride"],
                           "map_field": imm["step_map_disp"], "map_bucket_stride": imm["vec_bucket_stride"],
                           "value_fields_summed": [imm["step_sum_field"], imm["step_raw_field"]],
                           "base_lookup_field": imm["vec_lookup_disp"]},
        "record": {"stride": 1 << imm["record_shift"],
                   "fields": {"name_cap": 0, "name_ptr": imm["record_name_ptr"], "name_len": imm["record_name_len"],
                              "sub_address": [imm["record_sub_lo"], imm["record_sub_hi"] + 4],
                              "master_address": [imm["record_master_lo"], imm["record_master_hi"] + 4]}},
        "post_success": {"lookup_base_field": imm["lookup_base_field"], "record_map_field": imm["record_map_field"],
                         "inserted_value": "qword 1 at +0x0, then the master's lookup result at +0x8",
                         "lookup_result_len": imm["record_tail_disp"], "entry_index_field": imm["entry_index_field"],
                         "user_lookup_bucket_stride": imm["user_lookup_stride"]},
    }
    if map_layouts["record"]["fields"]["sub_address"] != [0x18, 0x2C] or \
            map_layouts["record"]["fields"]["master_address"] != [0x2C, 0x40]:
        raise EvidenceError("record layout differs")

    # 19) Arithmetic: reciprocal proof, cap boundaries, model.
    recip = _reciprocal_proof(magic, shift, divisor, constants["min_volume_raw"])
    caps = _cap_boundaries(constants)
    model = _derivation_model(constants, kept, words)

    summary = {
        "functions": len(functions), "shapes": len(shapes), "pinned_instructions": len(table),
        "pinned_bytes": sum(len(v[0]) for v in table.values()), "decoded_edges": len(edges),
        "rip_relative_refs": len(riprefs), "immediates": len(imm),
        "word_stores_in_four_windows": len(stores), "status_stores": len(status_stores),
        "status_stores_imm16": sum(1 for s in status_stores if s["kind"] == "imm16"),
        "status_stores_register": sum(1 for s in status_stores if s["kind"] == "register"),
        "check_rows": len(rows), "status_rows": len(status_rows),
        "status_rows_imm16": sum(1 for r in status_rows if r.get("store_kind") == "imm16"),
        "status_rows_register": sum(1 for r in status_rows if r.get("store_kind") == "register"),
        "control_rows": len(rows) - len(status_rows),
        "locations": len(locations), "location_lea_sites": sum(len(x[5]) for x in LOCATIONS),
        "formatter_arms": len(arms), "token_variants": len(variants), "links": len(links),
        "calls_in_four_windows": len(call_sites), "word_writer_arms": len(ww_arms),
    }

    return {
        "binary_sha256": sha,
        "question": ("createSubAccount (exchange tag 122) in node #94: the ordered checks, their constants, "
                     "decision edges and status stores across handler 0x27e3140 and its callees, what the "
                     "volume operand is, and how the sub-account address is derived."),
        "coordinate_system": ("linked virtual addresses of instruction starts; four LOAD segments: R "
                              "(.rodata, .eh_frame, .rela.*) VA = file offset; RE (.text, .plt) VA = file "
                              "offset + 0x1000; RELRO (.data.rel.ro, .got, .got.plt) VA = file offset + 0x2000; "
                              "RW (.data; .bss has no file bytes) VA = file offset + 0x3000"),
        "completeness": ("FDE-bounded windows only (the functions listed here); inside them, only the pinned "
                         "instruction windows, the call sites, the byte scans and the decoded tables listed "
                         "here are checked by this tool"),
        "summary": summary,
        "functions": functions,
        "shapes": shapes,
        "edges": [edges[k] for k in sorted(edges)],
        "rip_relative_refs": riprefs,
        "immediates": dict(sorted(imm.items())),
        "dispatch": dispatch,
        "word_stores": stores,
        "check_order": rows,
        "call_slots": call_slots,
        "callers_e8_rel32": callers,
        "relative_references": relrefs,
        "locations": locations,
        "literals": literals,
        "status_formatter": formatter,
        "token_debug": {"table": ttab, "variants": variants, "builder_tokens": builder_tokens},
        "word_writer": word_writer,
        "calls": calls,
        "byte_scans": {"windows": scans, "text": text_counts},
        "links": links,
        "kept_digest": kept_digest,
        "constants": constants,
        "map_layouts": map_layouts,
        "volume_operand": {
            "producer": FUNCS["volume_producer"][0], "fold": FUNCS["volume_fold"][0],
            "step": FUNCS["volume_step"][0], "vec_fold": FUNCS["volume_vec_fold"][0],
            "message": ("status 0xdd: format args[0] = &100000.0, args[1] = &(status+8) = operand / 100.0; "
                        "template 'Required: $' marker '. Traded: $' marker (marker-to-argument order assumed)"),
            "aggregate": ("step(master) via 0x2773bb0, then 0x26b2180 over the Vec at the master's bucket "
                          "(address at record+0x18); front/back slice iterators are null in this state"),
            "step": ("returns acc + (L + R): R = sum over the [exchange+0x5c8] records (0x2f0 bytes from "
                     "[exchange+0x5c0]) of [0x36f57f0(record+0xf8, &user)+0x40]; L = [lookup(exchange+0x80, "
                     "&user)+0x0] through slot 0x5773170; the +0x48 / +0x8 parallel sum is only checked"),
            "arithmetic": ("u64 adds checked with jb/jae; on carry the step calls slot 0x5773190 (volume_report, "
                           "two ret paths) and saturates to 0xffffffffffffffff (cmov)"),
            "admission_compare": "cmp r8,0x989680 ; jae (unsigned)",
            "cap_multiply": "mul rdx (unsigned 64x64 -> 128)",
            "sub_threshold_format": "cvtsi2sd r8 only on the < 0x989680 branch, then / 100.0",
        },
        "other_volume_user": {
            "function": FUNCS["other_volume_user"][0], "producer_call": 0x27677D4,
            "threshold_compare": 0x27677E3, "cap_formula": 0x2767860, "below_threshold": "r9 = 0 (0x27677eb)",
            "third_path": "r9 = 10 (0x27677aa)", "consumer_call": 0x2767925, "consumer_slot": 0x5774DC0,
            "reached_from": "dispatcher table index 1 (tag 117) -> 0x1e5f770 -> call 0x2766f70 at 0x1e5f8ec",
            "consumer": {"function": FUNCS["other_consumer"][0], "r9_saved_at": f"[rsp+{imm['oc_r9_save']:#x}]",
                         "status_store": 0x3422368, "status": imm["oc_status_57"],
                         "payload": f"[r15+{imm['oc_payload_disp']:#x}] = r14", "returns": "r15 = rdi (out)",
                         "r9_to_payload": "not traced"},
            "purpose": "not established here",
        },
        "reciprocal_proof": recip,
        "cap_boundaries": caps,
        "derivation_model": model,
    }


# ======================================================================
# Arithmetic and the derivation model
# ======================================================================

def _reciprocal_proof(magic: int, shift: int, divisor: int, min_volume: int) -> dict:
    """floor(x*M >> shift) == x // D for every u64, with M and shift from the bytes."""
    ceil_val = -((-(1 << shift)) // divisor)
    err = magic * divisor - (1 << shift)
    certificate_ok = ceil_val == magic and 0 <= err and err * M64 < (1 << shift)
    vectors = []
    for x in [0, 1, divisor - 1, divisor, 40 * divisor, min_volume, M64]:
        lhs = (x * magic) >> shift
        vectors.append({"x": x, "magic_result": lhs, "true_quotient": x // divisor, "equal": lhs == x // divisor})
    wrong = magic - 1
    wrong_fail = sum(1 for x in [divisor, 2 * divisor, M64] if ((x * wrong) >> shift) != x // divisor)
    if not certificate_ok or not all(v["equal"] for v in vectors):
        raise EvidenceError("reciprocal certificate failed")
    return {
        "magic": magic, "shift": shift, "divisor": divisor,
        "divisor_from": "ceil(2^shift / magic)",
        "magic_equals_ceil_2pow_shift_over_divisor": ceil_val == magic,
        "m_times_d_minus_2pow_shift": err,
        "certificate": "0 <= M*D - 2^s and (M*D - 2^s)*(2^64-1) < 2^s",
        "certificate_ok": certificate_ok,
        "boundary_vectors": vectors,
        "all_boundary_vectors_pass": all(v["equal"] for v in vectors),
        "wrong_magic_controls": ["D", "2D", "2^64-1"],
        "wrong_magic_minus1_failures_of_3": wrong_fail,
    }


def _cap(volume: int, c: dict) -> int:
    return min(volume // c["volume_per_extra_sub_raw"], c["cap_quotient_clamp"]) + c["cap_addend"]


def _cap_boundaries(c: dict) -> dict:
    d = c["volume_per_extra_sub_raw"]
    rows = []
    for q, vol in [(0, 0), (0, c["min_volume_raw"]), (39, 39 * d), (40, 40 * d), (41, 41 * d),
                   (M64 // d, M64)]:
        cap = _cap(vol, c)
        rows.append({"quotient": q, "volume_raw": vol, "cap": cap, "admit_while_count_below": cap})
    return {"formula": "cap = min(volume_raw // 10^10, 40) + 10 (evaluated only when the master has an entry)",
            "min_cap": _cap(0, c), "max_cap": _cap(M64, c), "rows": rows}


def _keccak_f(a):
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & M64) for x in range(5)]
        for x in range(5):
            for y in range(0, 25, 5):
                a[x + y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                r = _RO[x + 5 * y]
                v = a[x + 5 * y]
                b[y + 5 * ((2 * x + 3 * y) % 5)] = ((v << r) | (v >> (64 - r))) & M64 if r else v
        for x in range(5):
            for y in range(0, 25, 5):
                a[x + y] = b[x + y] ^ ((~b[((x + 1) % 5) + y] & M64) & b[((x + 2) % 5) + y])
        a[0] ^= rc
    return a


def keccak256(data: bytes, rate: int = 0x88, delim: int = 0x01) -> bytes:
    """Sponge over Keccak-f[1600]: rate 136 and delimiter 0x01 (legacy Keccak-256) by default."""
    a = [0] * 25
    pad = bytearray(data)
    pad.append(delim)
    while len(pad) % rate:
        pad.append(0)
    pad[-1] ^= 0x80
    for off in range(0, len(pad), rate):
        for i in range(rate // 8):
            a[i] ^= struct.unpack_from("<Q", pad, off + 8 * i)[0]
        a = _keccak_f(a)
    return b"".join(struct.pack("<Q", x) for x in a)[:32]


def ethabi_encode_label_addr_uint(label: bytes, master: bytes, n: int) -> bytes:
    """Model of ethabi encode([String(label), Address(master), Uint(n)]) (standard head/tail layout)."""
    if len(master) != 20:
        raise ValueError("master must be 20 bytes")
    head = (0x60).to_bytes(32, "big") + b"\x00" * 12 + master + (n % (1 << 256)).to_bytes(32, "big")
    tail = len(label).to_bytes(32, "big") + label + b"\x00" * ((-len(label)) % 32)
    return head + tail


def derive_sub_account(master: bytes, count: int, kept=(0, 20)) -> bytes:
    return keccak256(ethabi_encode_label_addr_uint(LABEL, master, count))[kept[0]:kept[1]]


SHA3_LENGTHS = (0, 1, 55, 135, 136, 137, 160, 271, 272, 273, 1000)


def _writer_word(words: dict, limbs) -> bytes:
    """The 32-byte word the decoded Int/Uint arm writes for the 64-bit limbs [l0, l1, l2, l3]."""
    out = bytearray(32)
    for off, disp in words.items():
        out[off:off + 8] = limbs[(disp - 8) // 8].to_bytes(8, "big")  # LE store of bswap(limb)
    return bytes(out)


def _derivation_model(c: dict, kept, words) -> dict:
    rate, delim = c["keccak_rate"], c["keccak_delimiter"]
    kats = {"keccak256_empty": keccak256(b"", rate, delim).hex(),
            "keccak256_abc": keccak256(b"abc", rate, delim).hex()}
    kat_ok = (kats["keccak256_empty"] == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
              and kats["keccak256_abc"] == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    # The same sponge with the SHA3 delimiter must equal hashlib.sha3_256 (covers multi-block input).
    sha3_eq = [n for n in SHA3_LENGTHS
               if keccak256(bytes(i % 251 for i in range(n)), rate, 0x06) ==
               hashlib.sha3_256(bytes(i % 251 for i in range(n))).digest()]
    if not kat_ok or len(sha3_eq) != len(SHA3_LENGTHS):
        raise EvidenceError("Keccak model failed its known-answer or hashlib.sha3_256 cross-checks")
    samples = []
    for desc, master, count in [
        ("zero master, count 0", bytes(20), 0),
        ("0x00..0x13 master, count 0", bytes(range(20)), 0),
        ("0xff master, count 5", b"\xff" * 20, 5),
        ("mixed master, count 41", bytes.fromhex("1122334455667788990011223344556677889900"), 41),
    ]:
        enc = ethabi_encode_label_addr_uint(LABEL, master, count)
        if enc[64:96] != _writer_word(words, [count, 0, 0, 0]):
            raise EvidenceError("model: the Uint word differs from the word writer's layout")
        full = keccak256(enc, rate, delim)
        samples.append({"description": desc, "master": master.hex(), "count": count,
                        "model_preimage_len": len(enc), "keccak256_full": full.hex(),
                        "derived_address": full[kept[0]:kept[1]].hex(),
                        "reference_impl_slice_12_32": full[12:32].hex()})
    return {
        "status": "self-derived model (not a target-produced vector)",
        "rule": ("address = keccak256(ethabi::encode([String('createSubAccount'), Address(master), "
                 "Uint(count)]))[%d..%d]" % kept),
        "from_bytes": ("literal, token order and tags, count source and limb, the Uint word (word writer "
                       "0x1591cd0: big-endian), rate, delimiter, round constants, digest length and kept slice"),
        "modelled": ("the head/tail layout of 0x1592160: which word goes where, the 0x60 offset word, the "
                     "Address word and the String length and padding (standard ethabi layout assumed, not "
                     "proven word by word)"),
        "count_source": ("Vec len in the master's user_to_sub_accounts bucket ([bucket_end-0x8] = bucket+0x28), "
                         "0 if absent"),
        "uint_word_checked_against_word_writer": len(samples),
        "model_preimage_len": 160,
        "kats": kats, "kats_pass": kat_ok,
        "sha3_crosscheck_lengths": list(SHA3_LENGTHS), "sha3_crosscheck_equal": len(sha3_eq),
        "samples": samples,
    }


# ======================================================================
# Output
# ======================================================================

ADDR_KEYS = {"va", "end", "start", "target", "fallthrough", "slot", "addr", "table", "arm", "handler",
             "call_site", "call_va", "call_target", "call_slot", "decision_va", "fail_to", "store_va",
             "source_va", "text_va", "template_va", "name_va", "function", "producer", "fold", "step",
             "vec_fold", "producer_call", "threshold_compare", "cap_formula", "consumer_call",
             "consumer_slot", "loaded_by", "index1_arm", "index1_call_site", "index1_callee", "sites",
             "base_field", "ctrl_field", "mask_field", "items_field", "exchange_ctrl_field",
             "exchange_mask_field", "exchange_items_field", "lookup_base_field", "record_map_field",
             "entry_index_field", "imm32_0x989680", "imm64_magic", "out_lea_va", "load_va", "compare_va",
             "fail_to_store_path", "int_uint_arm", "status_store", "exchange_count_field", "exchange_base_field",
             "map_field", "base_lookup_field"}
LIST_ADDR_KEYS = set(RELATIVE_REFS)  # relative_references lists


def render(result: dict) -> bytes:
    def hexify(o, addr=False):
        if isinstance(o, dict):
            return {k: hexify(v, k in ADDR_KEYS or k in LIST_ADDR_KEYS) for k, v in o.items()}
        if isinstance(o, list):
            return [hexify(v, addr) for v in o]
        if addr and isinstance(o, int) and not isinstance(o, bool):
            return f"{o:#x}"
        return o
    return (json.dumps(hexify(result), indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode()


def excerpt_windows():
    """objdump windows covering every pinned shape: shapes of one owner closer than EXCERPT_GAP merge."""
    by_owner = {}
    for name, owner, va, hexes, _m in SHAPES:
        by_owner.setdefault(owner, []).append((va, va + len(bytes.fromhex("".join(hexes))), name))
    out = []
    for owner in [o for o in FUNCS if o in by_owner]:  # FUNCS order: dispatch -> handler -> callees
        cur = None
        for lo, hi, name in sorted(by_owner[owner]):
            if cur and lo - cur[1] < EXCERPT_GAP:
                cur = (cur[0], max(cur[1], hi), cur[2] + [name])
            else:
                if cur:
                    out.append((owner,) + cur)
                cur = (lo, hi, [name])
        out.append((owner,) + cur)
    for owner, lo, hi, title in EXTRA_EXCERPTS:
        inside = [w for w in out if w[0] == owner and lo <= w[1] and w[2] <= hi]
        names = [n for w in inside for n in w[3]]
        out = [w for w in out if w not in inside]
        out.append((owner, lo, hi, [title] + names))
    order = list(FUNCS)
    return sorted(out, key=lambda w: (order.index(w[0]), w[1]))


def write_excerpts(binary: Path, out: Path) -> None:
    """Regenerate objdump-excerpts.txt (needs GNU objdump; runs from the repository root)."""
    ver = subprocess.run(["objdump", "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    rel = TARGET_REL if binary.resolve() == TARGET.resolve() else str(binary)
    lines = [
        "# objdump -d -M intel excerpts for vaults-subaccount-create-94 (node #94)",
        f"# tool: {ver}",
        f"# binary sha256: {sha}",
        "# coordinate system: linked virtual addresses (instruction starts, REX prefix included).",
        "# Each window: objdump -d -M intel --start-address=<lo> --stop-address=<hi> " + rel,
        "# Normalisation: objdump's leading file/section header lines are dropped and trailing",
        "# whitespace is stripped from every line; nothing else is changed. The <symbol+off>",
        "# annotations come from the dynamic symbol table and are not evidence.",
        "# Written by: python3 -B tools/subaccount_create.py --excerpts <path>",
        "",
    ]
    for owner, lo, hi, names in excerpt_windows():
        p = subprocess.run(["objdump", "-d", "-M", "intel", f"--start-address={lo:#x}",
                            f"--stop-address={hi:#x}", rel], capture_output=True, text=True, check=True,
                           cwd=ROOT)
        body = p.stdout.splitlines()
        k = next(i for i, ln in enumerate(body) if ln.startswith("Disassembly of section"))
        body = [ln.rstrip() for ln in body[k + 1:]]
        while body and not body[0]:
            body.pop(0)
        while body and not body[-1]:
            body.pop()
        lines.append(f"## {owner} {FUNCS[owner][0]:#x}: {', '.join(names)}  "
                     f"[objdump --start-address={lo:#x} --stop-address={hi:#x}]")
        lines += body
        lines.append("")
    out.write_text("\n".join(lines))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", type=Path, default=TARGET)
    ap.add_argument("--out", type=Path, help="write the JSON here (default: stdout)")
    ap.add_argument("--check", type=Path, help="compare the JSON with this file; exit 1 if it differs")
    ap.add_argument("--excerpts", type=Path, help="also write the objdump excerpts file (needs objdump)")
    a = ap.parse_args(argv)
    try:
        text = render(build(a.binary.read_bytes()))
    except EvidenceError as e:
        print(f"subaccount_create: {e}", file=sys.stderr)
        return 2
    if a.excerpts:
        write_excerpts(a.binary, a.excerpts)
    if a.check:
        same = a.check.read_bytes() == text
        print(f"subaccount_create: {a.check} {'matches' if same else 'DIFFERS FROM'} the regenerated output")
        return 0 if same else 1
    if a.out:
        a.out.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
