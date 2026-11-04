#!/usr/bin/env python3
"""RE-002: digest-bound node115 XCR0 composition trace of the refresh helper.

Traces the composed words built by the refresh helper FDE
0x5cadd50..0x5cae3da from the XCR0 probe leaf's return (pinned by the
RE-002 xcr0-leaf packet) to the publication suffix entry at 0x5cae39b
(equations pinned by the merged RE-002 cache-publication packet), and
separates the XCR0-derived terms from the CPUID-derived ones: which
fields of A (R13 at the suffix) and B (RDX at the suffix) each XCR0
term drives, and hence which fields of the published words C0-C2.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET=ROOT/'artifacts/node/115/hl-node'
PACKET=ROOT/'research/work-items/RE-002-node115-xcr0-composition'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'refresh_helper':(0x5cadd50,0x5cae3da,'f4cc818ee02b994599bfc53910323d3edf8420d0b404c2e5060faab72524c349'),
 'xcr0_leaf':(0x5cae3e0,0x5cae3ed,'f347a1395ba474e85f6c71330ca7f30e1d067cc6af42548744b6310ae2dbf0be')}
HELPER=0x5cadd50
LEAF=0x5cae3e0
CALL_SITE=0x5cae04c
SUFFIX=0x5cae39b
LIMITS=('XCR0 composition of the refresh helper only: the value-flow taint '
 'verdict, the three post-call reads of the leaf result, the four XCR0 '
 'control gates and the cache fields they drive, the A/B selection at '
 '0x5cae35e and the suffix store sites. The publication equations '
 'themselves are the merged RE-002 cache-publication packet\'s and are '
 'cited, not re-derived; the leaf result rule is the RE-002 xcr0-leaf '
 'packet\'s. The field-by-field CPUID attribution of the always-on early '
 'compositions of R12 and R15 outside the XCR0-gated regions, feature/ISA '
 'names for any bit, runtime XCR0/CPUID values, and any gate are not '
 'claimed. Taint tracks value flow only: flag-mediated selection (test, '
 'sete, cmov) propagates the taint of the selected values, never of the '
 'condition. No captured code executed.')

# Byte pins over the refresh-helper body. Every load-bearing instruction
# of the trace is pinned at its full encoding; a mutation anywhere in the
# body is additionally stopped by the pinned body hash in analyze().
PINS=[
 # Intake: the leaf call and the result move (RE-002 xcr0-leaf packet).
 (0x5cae04c,'e88f030000','intake call'),
 (0x5cae051,'4989c6','intake result move'),
 # Pre-call R14: the slot load and its two CPUID-side reads.
 (0x5cadeb6,'4c8b75a8','pre-call r14 slot load'),
 (0x5cadeba,'4d89f7','pre-call r14 to r15 seed'),
 (0x5cadfa6,'41f7c600008000','pre-call r14 cpuid 0x19 gate'),
 # XCR0 gate field: EDI = R14d & 0x60000 (bits 17,18).
 (0x5cae054,'4489f7','gate field move'),
 (0x5cae057,'81e700000600','gate field mask'),
 # First branch on the result: NOT EAX / TEST AL,0x6 / JNE taken arm.
 (0x5cae05d,'f7d0','branch not'),
 (0x5cae05f,'a806','branch test'),
 (0x5cae061,'0f85f9010000','branch jne'),
 # Mask field and the H set, fall-through only.
 (0x5cae067,'4589f0','mask field move'),
 (0x5cae06a,'4181e0e0000000','mask field and'),
 (0x5cae071,'48b80000000000000080','h set movabs'),
 (0x5cae07b,'4909c4','h set or'),
 # Complement of the mask field and its only consumer.
 (0x5cae0c4,'4981f0e0000000','mask field complement'),
 (0x5cae152,'2500100020','complement branch and'),
 (0x5cae157,'4c09c0','complement composed or'),
 (0x5cae15a,'0f85dc000000','complement branch jne'),
 # First RAX writes on each successor path of 0x5cae157 (value deadness).
 (0x5cae165,'4489e8','deadness extra block first rax write'),
 (0x5cae278,'89d0','deadness shared block first rax write'),
 (0x5cae2fd,'4c89e0','deadness convergence first rax write'),
 # H-set survival carriers through the fall-through rebuild.
 (0x5cae0c1,'4c89e1','rebuild r12 save'),
 (0x5cae14f,'4909cc','rebuild r12 restore'),
 (0x5cae1c3,'4c89e0','extra block r12 save'),
 (0x5cae239,'4909c4','extra block r12 restore'),
 # CPUID leaf 0xd subleaf 1 block: fields into R15 (B), XCR0-gated.
 (0x5cae07e,'837dc40c','leaf 0xd max leaf cmp'),
 (0x5cae082,'7639','leaf 0xd max leaf jbe'),
 (0x5cae084,'b80d000000','leaf 0xd leaf id'),
 (0x5cae089,'b901000000','leaf 0xd subleaf'),
 (0x5cae091,'0fa2','leaf 0xd cpuid'),
 (0x5cae096,'4c89f9','leaf 0xd rcx seed'),
 (0x5cae099,'4883c901','leaf 0xd rcx bit0'),
 (0x5cae09d,'a801','leaf 0xd bit0 test'),
 (0x5cae09f,'4d0f44e4','leaf 0xd cmove r12 nop'),
 (0x5cae0a3,'490f44cf','leaf 0xd cmove rcx'),
 (0x5cae0a7,'89c2','leaf 0xd edx move'),
 (0x5cae0a9,'83e202','leaf 0xd bit1 mask'),
 (0x5cae0ac,'01d2','leaf 0xd bit1 shift'),
 (0x5cae0ae,'83e008','leaf 0xd bit3 mask'),
 (0x5cae0b1,'c1e802','leaf 0xd bit3 shift'),
 (0x5cae0b4,'4809d0','leaf 0xd compose or 1'),
 (0x5cae0b7,'4809c8','leaf 0xd compose or 2'),
 (0x5cae0ba,'4989c7','leaf 0xd r15 store'),
 # Fall-through composition chain (R12 rebuild), XCR0-branch-gated.
 (0x5cae0bd,'488b75c8','fallthrough rsi slot load'),
 (0x5cae0cb,'89d8','fallthrough eax copy'),
 (0x5cae0cd,'f7d0','fallthrough eax not'),
 (0x5cae0cf,'89da','fallthrough edx copy'),
 (0x5cae0d1,'81e200100000','fallthrough ecx bit12 mask'),
 (0x5cae0d7,'48c1e22c','fallthrough ecx bit12 shift'),
 (0x5cae0db,'c1eb0e','fallthrough ebx shift'),
 (0x5cae0de,'81e300400000','fallthrough ecx bit28 mask'),
 (0x5cae0e4,'4809d3','fallthrough rbx compose'),
 (0x5cae0e7,'4489ea','fallthrough edx r13d'),
 (0x5cae0ea,'83e220','fallthrough ebx7 bit5 mask'),
 (0x5cae0ed,'c1e20a','fallthrough ebx7 bit5 shift'),
 (0x5cae0f0,'4809da','fallthrough rdx compose 1'),
 (0x5cae0f3,'4189f1','fallthrough r9d esi'),
 (0x5cae0f6,'4183e110','fallthrough eax71 bit4 mask'),
 (0x5cae0fa,'49c1e124','fallthrough eax71 bit4 shift'),
 (0x5cae0fe,'4909d1','fallthrough r9 compose'),
 (0x5cae101,'89f2','fallthrough edx esi'),
 (0x5cae103,'81e200008000','fallthrough eax71 bit23 mask'),
 (0x5cae109,'48c1e20f','fallthrough eax71 bit23 shift'),
 (0x5cae10d,'4c09ca','fallthrough rdx compose 2'),
 (0x5cae110,'488b5da0','fallthrough rbx slot reload'),
 (0x5cae114,'4189d9','fallthrough r9d ebx'),
 (0x5cae117,'4183e110','fallthrough edx71 bit4 mask'),
 (0x5cae11b,'49c1e126','fallthrough edx71 bit4 shift'),
 (0x5cae11f,'4189da','fallthrough r10d ebx'),
 (0x5cae122,'4183e220','fallthrough edx71 bit5 mask'),
 (0x5cae126,'49c1e222','fallthrough edx71 bit5 shift'),
 (0x5cae12a,'4189db','fallthrough r11d ebx'),
 (0x5cae12d,'4181e300040000','fallthrough edx71 bit10 mask'),
 (0x5cae134,'49c1e31f','fallthrough edx71 bit10 shift'),
 (0x5cae138,'4d09d3','fallthrough r11 compose'),
 (0x5cae13b,'4189f4','fallthrough r12 seed'),
 (0x5cae13e,'4183e407','fallthrough r12 seed mask'),
 (0x5cae142,'41c1e410','fallthrough r12 seed shift'),
 (0x5cae146,'4909d4','fallthrough r12 or rdx'),
 (0x5cae149,'4d09cc','fallthrough r12 or r9'),
 (0x5cae14c,'4d09dc','fallthrough r12 or r11'),
 # Extra block chain (entered iff the 0x5cae15a test value is zero).
 (0x5cae160,'b900000080','extra ecx constant'),
 (0x5cae168,'2500000100','extra ebx7 bit16 mask'),
 (0x5cae16d,'4489ea','extra edx r13d 1'),
 (0x5cae170,'c1e207','extra ebx7 bit17 shift'),
 (0x5cae173,'81e200000001','extra ebx7 bit17 mask'),
 (0x5cae179,'8d04c2','extra lea compose'),
 (0x5cae17c,'4489ea','extra edx r13d 2'),
 (0x5cae17f,'c1e205','extra ebx7 bit21 shift'),
 (0x5cae182,'81e200000004','extra ebx7 bit21 mask'),
 (0x5cae188,'09c2','extra edx compose 1'),
 (0x5cae18a,'4489e8','extra eax r13d 3'),
 (0x5cae18d,'c1e804','extra ebx7 bit26 shift'),
 (0x5cae190,'2500004000','extra ebx7 bit26 mask'),
 (0x5cae195,'09d0','extra eax compose 1'),
 (0x5cae197,'4489ea','extra edx r13d 4'),
 (0x5cae19a,'c1ea06','extra ebx7 bit27 shift'),
 (0x5cae19d,'81e200002000','extra ebx7 bit27 mask'),
 (0x5cae1a3,'09c2','extra edx compose 2'),
 (0x5cae1a5,'4489e8','extra eax r13d 5'),
 (0x5cae1a8,'c1e808','extra ebx7 bit28 shift'),
 (0x5cae1ab,'2500001000','extra ebx7 bit28 mask'),
 (0x5cae1b0,'09d0','extra eax compose 2'),
 (0x5cae1b2,'4489ea','extra edx r13d 6'),
 (0x5cae1b5,'c1ea07','extra ebx7 bit23 shift'),
 (0x5cae1b8,'81e200008000','extra ebx7 bit23 mask'),
 (0x5cae1be,'09c2','extra edx compose 3'),
 (0x5cae1c0,'4909d4','extra r12 or rdx'),
 (0x5cae1c6,'480d00000002','extra rax bit25'),
 (0x5cae1cc,'4939cd','extra compare'),
 (0x5cae1cf,'490f42c4','extra cmovb'),
 (0x5cae1d3,'4c8b5da8','extra r11 slot load'),
 (0x5cae1d7,'4489da','extra edx r11d'),
 (0x5cae1da,'83e202','extra ecx7 bit1 mask'),
 (0x5cae1dd,'c1e21a','extra ecx7 bit1 shift'),
 (0x5cae1e0,'4489d9','extra ecx r11d'),
 (0x5cae1e3,'83e140','extra ecx7 bit6 mask'),
 (0x5cae1e6,'c1e117','extra ecx7 bit6 shift'),
 (0x5cae1e9,'09d1','extra ecx compose'),
 (0x5cae1eb,'41c1e30e','extra ecx7 bit14 shift'),
 (0x5cae1ef,'4181e300000010','extra ecx7 bit14 mask'),
 (0x5cae1f6,'4c8b45b0','extra r8 slot load'),
 (0x5cae1fa,'4489c2','extra edx r8d'),
 (0x5cae1fd,'81e200010000','extra edx7 bit8 mask'),
 (0x5cae203,'48c1e21c','extra edx7 bit8 shift'),
 (0x5cae207,'4181e000008000','extra edx7 bit23 mask'),
 (0x5cae20e,'49c1e00e','extra edx7 bit23 shift'),
 (0x5cae212,'83e620','extra eax71 bit5 mask'),
 (0x5cae215,'48c1e61e','extra eax71 bit5 shift'),
 (0x5cae219,'49ba0000000006000000','extra slot mask constant'),
 (0x5cae223,'4c8b6598','extra r12 slot overwrite'),
 (0x5cae227,'4d21d4','extra r12 slot mask'),
 (0x5cae22a,'4909cc','extra r12 or rcx'),
 (0x5cae22d,'4d09dc','extra r12 or r11'),
 (0x5cae230,'4909d4','extra r12 or rdx'),
 (0x5cae233,'4d09c4','extra r12 or r8'),
 (0x5cae236,'4909f4','extra r12 or rsi'),
 # Shared block: gate comparisons on both arms and the field chain.
 (0x5cae23c,'4c8b5db8','taken-fallthrough r11 reload'),
 (0x5cae240,'448b45d4','taken-fallthrough r8d reload'),
 (0x5cae244,'81ff00000600','fallthrough gate cmp'),
 (0x5cae24a,'7428','fallthrough gate je'),
 (0x5cae24c,'e9a2000000','fallthrough gate jmp'),
 (0x5cae260,'4c8b5db8','taken arm r11 reload'),
 (0x5cae264,'448b45d4','taken arm r8d reload'),
 (0x5cae268,'488b5da0','taken arm rbx reload'),
 (0x5cae26c,'81ff00000600','taken arm gate cmp'),
 (0x5cae272,'757f','taken arm gate jne'),
 (0x5cae274,'488b55b0','shared rdx slot load'),
 (0x5cae27a,'2500000003','shared edx7 bits24-25 mask'),
 (0x5cae27f,'48c1e013','shared edx7 bits24-25 shift'),
 (0x5cae283,'81e200004000','shared edx7 bit22 mask'),
 (0x5cae289,'48c1e217','shared edx7 bit22 shift'),
 (0x5cae28d,'4809c2','shared rdx compose'),
 (0x5cae290,'488b4dc8','shared rcx slot load'),
 (0x5cae294,'81e100002000','shared eax71 bit21 mask'),
 (0x5cae29a,'48c1e119','shared eax71 bit21 shift'),
 (0x5cae29e,'4809d1','shared rcx compose'),
 (0x5cae2a1,'89d8','shared eax ebx'),
 (0x5cae2a3,'2500010000','shared edx71 bit8 mask'),
 (0x5cae2a8,'48c1e027','shared edx71 bit8 shift'),
 (0x5cae2ac,'4809c8','shared rax compose'),
 (0x5cae2af,'4909c4','shared r12 or'),
 # CPUID leaf 0x1e subleaf 1 block inside the shared region.
 (0x5cae2b2,'837dc41e','leaf 0x1e max leaf cmp'),
 (0x5cae2b6,'723b','leaf 0x1e max leaf jb'),
 (0x5cae2b8,'b81e000000','leaf 0x1e leaf id'),
 (0x5cae2bd,'b901000000','leaf 0x1e subleaf'),
 (0x5cae2c5,'0fa2','leaf 0x1e cpuid'),
 (0x5cae2cc,'89c1','leaf 0x1e ecx move'),
 (0x5cae2ce,'83e150','leaf 0x1e bits4-6 mask'),
 (0x5cae2d1,'48c1e12d','leaf 0x1e bits4-6 shift'),
 (0x5cae2d5,'89c2','leaf 0x1e edx move'),
 (0x5cae2d7,'81e280000000','leaf 0x1e bit7 mask'),
 (0x5cae2dd,'48c1e229','leaf 0x1e bit7 shift'),
 (0x5cae2e1,'4809ca','leaf 0x1e rdx compose'),
 (0x5cae2e4,'2500010000','leaf 0x1e bit8 mask'),
 (0x5cae2e9,'48c1e02a','leaf 0x1e bit8 shift'),
 (0x5cae2ed,'4809d0','leaf 0x1e rax compose'),
 (0x5cae2f0,'4909c4','leaf 0x1e r12 or'),
 # Bit-52 term at the convergence: XCR0 bit 19 AND slot bit 21.
 (0x5cae2f3,'48bf0000000000000080','convergence h movabs'),
 (0x5cae300,'41f7c600000800','bit52 xcr0 bit19 test'),
 (0x5cae307,'0f94c1','bit52 xcr0 sete'),
 (0x5cae30a,'f7c300002000','bit52 slot bit21 test'),
 (0x5cae310,'0f94c2','bit52 slot sete'),
 (0x5cae313,'08ca','bit52 condition or'),
 (0x5cae315,'49bc0000000000001000','bit52 constant'),
 (0x5cae31f,'4909c4','bit52 or'),
 (0x5cae322,'84d2','bit52 condition test'),
 (0x5cae324,'4c0f45e0','bit52 cmovne'),
 # CPUID leaf 0x24 block: constants into R12 (CPUID-side boundary).
 (0x5cae328,'f7c300000800','leaf 0x24 gate test'),
 (0x5cae32e,'742e','leaf 0x24 gate je'),
 (0x5cae330,'b824000000','leaf 0x24 leaf id'),
 (0x5cae335,'31c9','leaf 0x24 subleaf'),
 (0x5cae337,'4889de','leaf 0x24 rsi partner'),
 (0x5cae33a,'0fa2','leaf 0x24 cpuid'),
 (0x5cae33c,'4887f3','leaf 0x24 xchg restore'),
 (0x5cae33f,'40f6c6fe','leaf 0x24 low byte test'),
 (0x5cae343,'48b80000000000002000','leaf 0x24 constant bit53'),
 (0x5cae34d,'48b90000000000006000','leaf 0x24 constant bits57-58'),
 (0x5cae357,'480f44c8','leaf 0x24 cmove'),
 (0x5cae35b,'4909cc','leaf 0x24 r12 or'),
 # A/B selection: vendor compare and the mask/cmov chain.
 (0x5cae35e,'48b847656e75696e6549','selection vendor constant 1'),
 (0x5cae368,'4931c3','selection vendor xor 1'),
 (0x5cae36b,'4489c0','selection vendor eax'),
 (0x5cae36e,'48356e74656c','selection vendor constant 2'),
 (0x5cae374,'4c09d8','selection vendor or'),
 (0x5cae377,'4489e1','selection bit14 move'),
 (0x5cae37a,'81e100400000','selection bit14 mask'),
 (0x5cae380,'49bdffbffffffffffff9','selection a mask'),
 (0x5cae38a,'4d21e5','selection a and'),
 (0x5cae38d,'4809c1','selection condition or'),
 (0x5cae390,'4489fa','selection b move'),
 (0x5cae393,'4d0f45ec','selection a cmovne'),
 (0x5cae397,'490f45d7','selection b cmovne'),
 # Publication suffix stores (equations: merged cache-publication packet).
 (0x5cae39b,'4c89e8','suffix a move'),
 (0x5cae39e,'4809f8','suffix c0 or h'),
 (0x5cae3a1,'488b0db8168300','suffix cache slot load'),
 (0x5cae3a8,'488901','suffix c0 store'),
 (0x5cae3ab,'4889d0','suffix b move'),
 (0x5cae3ae,'4c0fa4e801','suffix c1 shld'),
 (0x5cae3b3,'4809f8','suffix c1 or h'),
 (0x5cae3b6,'48894108','suffix c1 store'),
 (0x5cae3ba,'4889d0','suffix b move 2'),
 (0x5cae3bd,'48c1e83e','suffix c2 shr'),
 (0x5cae3c1,'4809f8','suffix c2 or h'),
 (0x5cae3c4,'48894110','suffix c2 store'),
 (0x5cae3c8,'4c89e8','suffix return move'),
 # RDI = H assignments (merged packet's reaching definitions).
 (0x5cadd70,'48bf0000000000000080','h assignment entry'),
 (0x5cae251,'48bf0000000000000080','h assignment early arm'),
 # Early paths: max-leaf-zero exit and the leaf-1 gate into the XCR0 region.
 (0x5cadd6d,'4531ed','early r13 zero'),
 (0x5cadd7c,'7475','early max leaf je'),
 (0x5caddf3,'31d2','early b zero'),
 (0x5caddf5,'e9a1050000','early jmp suffix'),
 (0x5cae039,'89d8','region gate eax copy'),
 (0x5cae03b,'f7d0','region gate not'),
 (0x5cae03d,'a90000000c','region gate test'),
 (0x5cae042,'0f8509020000','region gate jne'),
 (0x5cae25b,'e9fe000000','early arm jmp selection'),
 (0x5cae048,'4c895db8','region vendor slot store'),
 # Slot provenance for the shared/bit-52 sources.
 (0x5caddde,'48894da8','slot 58 store'),
 (0x5cadde4,'488945c8','slot 38 store'),
 (0x5cadded,'488945b0','slot 50 store'),
 (0x5cade2c,'4c8955a0','slot 60 store'),
 (0x5caddb6,'0fa2','slot leaf7 subleaf0 cpuid'),
 (0x5caddd0,'0fa2','slot leaf7 subleaf1 cpuid'),
 (0x5caddd8,'4589d5','slot r13d leaf7 ebx'),
 # B composition boundary sites (seed rebuild + leaf 0x19 block).
 (0x5cadf8e,'8d0442','b rebuild lea'),
 (0x5cadf91,'4989c7','b rebuild store'),
 (0x5cadf94,'4981cf00020000','b rebuild bit9'),
 (0x5cadfa2,'4c0f44f8','b rebuild cmove'),
 (0x5cadfaf,'b819000000','leaf 0x19 leaf id'),
 (0x5cadfb9,'0fa2','leaf 0x19 cpuid'),
 (0x5cadfbe,'89f0','leaf 0x19 eax move'),
 (0x5cadfc0,'83e001','leaf 0x19 bit0 mask'),
 (0x5cadfc3,'c1e004','leaf 0x19 bit0 shift'),
 (0x5cadfc6,'83e604','leaf 0x19 bit2 mask'),
 (0x5cadfc9,'8d04f0','leaf 0x19 lea compose'),
 (0x5cadfcc,'4909c7','leaf 0x19 r15 or'),
 (0x5cae016,'89f8','vendor block eax move'),
 (0x5cae033,'4909ff','vendor block r15 or'),
 (0x5cae036,'4909cc','vendor block r12 or'),
 # R12 early-composition seed and bounded-source sites.
 (0x5cadd99,'4189d4','r12 seed leaf1 edx'),
 (0x5cadf4b,'41c1ec13','r12 seed shift'),
 (0x5cadf4f,'4181e4c0000000','r12 seed mask'),
 (0x5cadefd,'49ba1000000000000020','r10 mask bits 4 and 61'),
 (0x5cadf07,'4d21c2','r10 mask and'),
 (0x5cadf80,'4d09d4','r12 or r10 bounded'),
 (0x5cadf83,'4d09cc','r12 or r9 bounded'),
 (0x5cadee9,'49ba0000000001000000','r9 bit32 constant'),
 (0x5cadef7,'4d21fa','r9 bit32 and'),
]
BRANCH_TARGETS=[
 (0x5cae04c,5,0x5cae3e0,'intake call target'),
 (0x5cae061,6,0x5cae260,'branch jne target'),
 (0x5cae082,2,0x5cae0bd,'leaf 0xd jbe target'),
 (0x5cae15a,6,0x5cae23c,'complement jne target'),
 (0x5cae24a,2,0x5cae274,'fallthrough gate je target'),
 (0x5cae24c,5,0x5cae2f3,'fallthrough gate jmp target'),
 (0x5cae272,2,0x5cae2f3,'taken gate jne target'),
 (0x5cae2b6,2,0x5cae2f3,'leaf 0x1e jb target'),
 (0x5cae042,6,0x5cae251,'region gate jne target'),
 (0x5cae25b,5,0x5cae35e,'early arm jmp target'),
 (0x5cadd7c,2,0x5caddf3,'early max leaf je target'),
 (0x5caddf5,5,0x5cae39b,'early jmp target'),
 (0x5cae32e,2,0x5cae35e,'leaf 0x24 je target'),
]
FIELD_MAP=[
 {'cache_word':'C1','bit':0,'a_bit':63,
  'driver':'xcr0 bits 1 and 2 both set (fall-through at 0x5cae061)',
  'mechanism':'the movabs/or at 0x5cae071/0x5cae07b sets A bit 63; the suffix shld carries A bit 63 into C1 bit 0; the raw return (A) carries it as bit 63 too. C0 bit 63 is the suffix\'s own H on every path and is not driven by this term',
  'value_bits_from_xcr0':False},
 {'cache_word':'C0','bit':52,'a_bit':52,
  'driver':'xcr0 bit 19 AND cpuid leaf 7 subleaf 1 edx bit 21 ([rbp-0x60] slot)',
  'mechanism':'test/sete at 0x5cae300 and 0x5cae30a, combined at 0x5cae313, insert the 2^52 constant at 0x5cae315..0x5cae324 only when both bits are set',
  'value_bits_from_xcr0':False},
 {'cache_word':'C1','bit':1,'b_bit':0,
  'driver':'cpuid leaf 0xd subleaf 1 eax bit 0, gated by xcr0 bits 1,2 and max leaf > 0xc',
  'mechanism':'0x5cae096..0x5cae0ba ORs the bit into B bit 0',
  'value_bits_from_xcr0':False},
 {'cache_word':'C1','bit':2,'b_bit':1,
  'driver':'cpuid leaf 0xd subleaf 1 eax bit 3, gated by xcr0 bits 1,2 and max leaf > 0xc',
  'mechanism':'0x5cae0ae..0x5cae0b4 ORs the bit into B bit 1',
  'value_bits_from_xcr0':False},
 {'cache_word':'C1','bit':3,'b_bit':2,
  'driver':'cpuid leaf 0xd subleaf 1 eax bit 1, gated by xcr0 bits 1,2 and max leaf > 0xc',
  'mechanism':'0x5cae0a7..0x5cae0b4 ORs the bit into B bit 2',
  'value_bits_from_xcr0':False},
]
def _shared(bit,src_bit,src):
    return {'cache_word':'C0','bit':bit,'a_bit':bit,
            'driver':f'{src}, gated by xcr0 bits 17,18 both set (shared block 0x5cae274)',
            'mechanism':f'shared block carries {src} bit {src_bit} into A bit {bit}',
            'value_bits_from_xcr0':False}
FIELD_MAP+=[
 _shared(43,24,'cpuid leaf 7 subleaf 0 edx ([rbp-0x50] slot)'),
 _shared(44,25,'cpuid leaf 7 subleaf 0 edx ([rbp-0x50] slot)'),
 _shared(45,22,'cpuid leaf 7 subleaf 0 edx ([rbp-0x50] slot)'),
 _shared(46,21,'cpuid leaf 7 subleaf 1 eax ([rbp-0x38] slot)'),
 _shared(47,8,'cpuid leaf 7 subleaf 1 edx ([rbp-0x60] slot, reloaded into rbx on both arms)'),
]
def _l1e(bit,src_bit):
    return {'cache_word':'C0','bit':bit,'a_bit':bit,
            'driver':f'cpuid leaf 0x1e subleaf 1 eax bit {src_bit}, gated by xcr0 bits 17,18 and max leaf >= 0x1e',
            'mechanism':f'leaf 0x1e block at 0x5cae2b8..0x5cae2f0 carries the bit into A bit {bit}',
            'value_bits_from_xcr0':False}
FIELD_MAP+=[_l1e(48,7),_l1e(49,4),_l1e(50,8),_l1e(51,6)]
def _ft(bit,src_bit,src):
    return {'cache_word':'C0','bit':bit,'a_bit':bit,
            'driver':f'{src}, gated by xcr0 bits 1,2 fall-through (composition at 0x5cae0bd..0x5cae14f)',
            'mechanism':f'fall-through rebuild carries {src} bit {src_bit} into A bit {bit}',
            'value_bits_from_xcr0':False}
FIELD_MAP+=[
 _ft(14,28,'cpuid leaf 1 ecx'),
 _ft(15,5,'cpuid leaf 7 subleaf 0 ebx (r13d)'),
 _ft(16,0,'cpuid leaf 7 subleaf 1 eax ([rbp-0x38] slot)'),
 _ft(17,1,'cpuid leaf 7 subleaf 1 eax ([rbp-0x38] slot)'),
 _ft(18,2,'cpuid leaf 7 subleaf 1 eax ([rbp-0x38] slot)'),
 _ft(38,23,'cpuid leaf 7 subleaf 1 eax ([rbp-0x38] slot)'),
 _ft(39,5,'cpuid leaf 7 subleaf 1 edx ([rbp-0x60] slot)'),
 _ft(40,4,'cpuid leaf 7 subleaf 1 eax ([rbp-0x38] slot)'),
 _ft(41,10,'cpuid leaf 7 subleaf 1 edx ([rbp-0x60] slot)'),
 _ft(42,4,'cpuid leaf 7 subleaf 1 edx ([rbp-0x60] slot)'),
 _ft(44,12,'cpuid leaf 1 ecx'),
]
def _ex(bit,src_bit,src):
    return {'cache_word':'C0','bit':bit,'a_bit':bit,
            'driver':f'{src}, gated by (xcr0 & 0xe0) == 0xe0 and cpuid leaf 1 ecx bits 12,29 both set (extra block 0x5cae160..0x5cae239)',
            'mechanism':f'extra block carries {src} bit {src_bit} into A bit {bit}',
            'value_bits_from_xcr0':False}
FIELD_MAP+=[
 _ex(19,16,'cpuid leaf 7 subleaf 0 ebx (r13d)'),
 _ex(20,28,'cpuid leaf 7 subleaf 0 ebx (r13d)'),
 _ex(21,27,'cpuid leaf 7 subleaf 0 ebx (r13d)'),
 _ex(22,26,'cpuid leaf 7 subleaf 0 ebx (r13d)'),
 _ex(24,17,'cpuid leaf 7 subleaf 0 ebx (r13d)'),
 _ex(26,21,'cpuid leaf 7 subleaf 0 ebx (r13d)'),
 {'cache_word':'C0','bit':25,'a_bit':25,
  'driver':'unsigned compare of cpuid leaf 7 subleaf 0 ebx (r13) against the saved composed word (rcx) at 0x5cae1cc, gated by (xcr0 & 0xe0) == 0xe0 and cpuid leaf 1 ecx bits 12,29 both set',
  'mechanism':'extra block sets A bit 25 unless r13 <u rcx (cmovb at 0x5cae1cf)',
  'value_bits_from_xcr0':False},
 _ex(27,1,'cpuid leaf 7 subleaf 0 ecx ([rbp-0x58] slot)'),
 _ex(28,14,'cpuid leaf 7 subleaf 0 ecx ([rbp-0x58] slot)'),
 _ex(29,6,'cpuid leaf 7 subleaf 0 ecx ([rbp-0x58] slot)'),
 _ex(33,11,'cpuid leaf 7 subleaf 0 ecx ([rbp-0x58] slot, via [rbp-0x68] = slot << 0x16 and the 0x600000000 mask)'),
 _ex(34,12,'cpuid leaf 7 subleaf 0 ecx ([rbp-0x58] slot, via [rbp-0x68] = slot << 0x16 and the 0x600000000 mask)'),
 _ex(35,5,'cpuid leaf 7 subleaf 1 eax ([rbp-0x38] slot, in rsi)'),
 _ex(36,8,'cpuid leaf 7 subleaf 0 edx ([rbp-0x50] slot)'),
 _ex(37,23,'cpuid leaf 7 subleaf 0 edx ([rbp-0x50] slot)'),
]


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'xcr0 composition {what} changed')


def trace(data):
    """Verify every pinned site of the composition trace inside the
    refresh helper and verify the decoded branch targets."""
    start,end,_=OWNERS['refresh_helper']
    _,body=read(data,start,end-start)
    for va,hx,what in PINS:
        _pin(body,start,va,hx,what)
    for va,length,target,what in BRANCH_TARGETS:
        disp=struct.unpack_from('<i' if length>=5 else '<b',body,va+length-(4 if length>=5 else 1)-start)[0]
        if va+length+disp!=target:
            raise ValueError(f'xcr0 composition {what} changed')
    # The suffix cache slot load must name the merged packet's slot.
    disp=struct.unpack_from('<i',body,0x5cae3a1+3-start)[0]
    if 0x5cae3a1+7+disp!=0x64dfa60:
        raise ValueError('xcr0 composition suffix cache slot changed')
    return True


def call_census(data):
    text=next(s for s in sections(data) if s['name']=='.text')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    sites=[];index=body.find(b'\xe8')
    while index!=-1:
        if base+index+5+struct.unpack_from('<i',body,index+1)[0]==LEAF:
            sites.append(base+index)
        index=body.find(b'\xe8',index+1)
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    rela_hits=0
    for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']]):
        if v==LEAF:
            rela_hits+=1
    return sites,rela_hits


def frame_records(data,fdes,role,a,b,sha):
    if (a,b) not in fdes:
        raise ValueError(f'xcr0 composition {role} scope FDE changed')
    offset,raw=read(data,a,b-a)
    if hashlib.sha256(raw).hexdigest()!=sha:
        raise ValueError(f'xcr0 composition {role} body changed')
    records={}
    for kind in ['fde','cie']:
        va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
        records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
    return {'role':role,'start':hex(a),'end':hex(b),'file_offset':hex(offset),
            'bytes':b-a,'sha256':sha,'frames':records}


def analyze(data):
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    owners=[frame_records(data,fdes,role,a,b,sha) for role,(a,b,sha) in OWNERS.items()]
    trace(data)
    sites,rela_hits=call_census(data)
    if sites!=[CALL_SITE]:
        raise ValueError('xcr0 composition leaf direct call census changed')
    if rela_hits!=0:
        raise ValueError('xcr0 composition leaf relocation reference appeared')
    return {'target_sha256':SHA,'owners':owners,
            'call_census':{'direct_call_sites':[hex(s) for s in sites],
                           'relocation_references':rela_hits},
            'intake':{
              'call_site':'0x5cae04c','leaf':'0x5cae3e0..0x5cae3ed',
              'result':'rax = xcr0 (RE-002 xcr0-leaf packet)',
              'result_register':'r14',
              'pre_call_r14':{'definition':'0x5cadeb6',
                              'value':'cpuid leaf 7 subleaf 0 ecx, via the [rbp-0x58] slot',
                              'reads':['0x5cadeba','0x5cadfa6']},
              'post_call_reads':{
                'gate_field':['0x5cae054','0x5cae057'],
                'mask_field_and_branch':['0x5cae067','0x5cae05d'],
                'bit_19_test':'0x5cae300'}},
            'field_map':FIELD_MAP,
            'dead_field':{
              'term':'(xcr0 & 0xe0) ^ 0xe0 in r8, OR\'d into rax at 0x5cae157',
              'value_use':'only the ZF of the or is consumed, by the jne at 0x5cae15a',
              'first_rax_writes':{'extra_block':'0x5cae165','shared_block':'0x5cae278',
                                  'convergence':'0x5cae2fd'},
              'cache_fields':[]},
            'selection':{
              'site':'0x5cae35e..0x5cae39b',
              'a_mask':'0xf9ffffffffffbfff','cleared_bits':[14,57,58],
              'condition':'rcx = (r12 bit 14) | (vendor != "GenuineIntel" compare residue) is nonzero',
              'a_rule':'A = r12 if the condition holds, else r12 & 0xf9ffffffffffbfff',
              'b_rule':'B = r15 if the condition holds, else zero-extended low 32 bits of r15',
              'xcr0_fields_cleared':[]},
            'suffix':{
              'entry':'0x5cae39b','cache_slot':'0x64dfa60',
              'equations':'C0 = A | H; C1 = ((B << 1) | (A >> 63)) | H; C2 = (B >> 62) | H; raw rax return = A (merged RE-002 cache-publication packet)',
              'h_assignments':['0x5cadd70','0x5cae251','0x5cae2f3']},
            'early_paths':{
              'max_leaf_zero':'0x5caddf3 jumps to the suffix with A = 0 and B = 0; the leaf is never called',
              'region_gate':'unless cpuid leaf 1 ecx bits 26,27 are both set, 0x5cae042 jumps to 0x5cae251 and then to the selection at 0x5cae35e; the leaf is never called and none of the xcr0 terms executes'},
            'captured_code_executed':False,'limits':LIMITS}


REG64={'rax':'rax','eax':'rax','ax':'rax','al':'rax','ah':'rax',
       'rbx':'rbx','ebx':'rbx','bx':'rbx','bl':'rbx','bh':'rbx',
       'rcx':'rcx','ecx':'rcx','cx':'rcx','cl':'rcx','ch':'rcx',
       'rdx':'rdx','edx':'rdx','dx':'rdx','dl':'rdx','dh':'rdx',
       'rsi':'rsi','esi':'rsi','si':'rsi','sil':'rsi',
       'rdi':'rdi','edi':'rdi','di':'rdi','dil':'rdi',
       'rbp':'rbp','ebp':'rbp','bp':'rbp','bpl':'rbp',
       'rsp':'rsp','esp':'rsp','sp':'rsp','spl':'rsp'}
for _i in range(8,16):
    for _s,_p in [('',''),('d',''),('w',''),('b','')]:
        REG64[f'r{_i}{_s}']=f'r{_i}'
REG_TOKEN=re.compile(r'\b(r(?:1[0-5]|[89])[dwb]?|rax|eax|ax|al|ah|rbx|ebx|bx|bl|bh|rcx|ecx|cx|cl|ch|rdx|edx|dx|dl|dh|rsi|esi|si|sil|rdi|edi|di|dil|rbp|ebp|bp|bpl|rsp|esp|sp|spl)\b')
REGS=['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp']+[f'r{i}' for i in range(8,16)]
WRITE_MNEMONICS={'mov','movabs','or','and','xor','shl','shr','sar','lea','add','sub',
                 'cmove','cmovne','cmovb','cmovae','cmovo','cmovno','cmovs','cmovns',
                 'cmova','cmovbe','cmovg','cmovge','cmovl','cmovle','xchg','not','neg','inc','dec'}
R14_MENTIONS=[0x5cadeb6,0x5cadeba,0x5cadfa6,0x5cae051,0x5cae054,0x5cae067,0x5cae300]
R12_WRITES=[0x5cadd99,0x5cadf4b,0x5cadf4f,0x5cadf56,0x5cadf62,0x5cadf70,0x5cadf7d,
            0x5cadf80,0x5cadf83,0x5cadfdc,0x5cae036,0x5cae07b,0x5cae09f,0x5cae13b,
            0x5cae13e,0x5cae142,0x5cae146,0x5cae149,0x5cae14c,0x5cae14f,0x5cae1c0,
            0x5cae223,0x5cae227,0x5cae22a,0x5cae22d,0x5cae230,0x5cae233,0x5cae236,
            0x5cae239,0x5cae2af,0x5cae2f0,0x5cae315,0x5cae31f,0x5cae324,0x5cae35b]
R15_WRITES=[0x5cadeba,0x5cadebd,0x5cadf91,0x5cadf94,0x5cadfa2,0x5cadfcc,0x5cae033,0x5cae0ba]
R13_WRITES=[0x5cadd6d,0x5caddd8,0x5cae380,0x5cae38a,0x5cae393]
RDI_MENTIONS_AFTER_INTAKE=[0x5cae054,0x5cae057,0x5cae244,0x5cae251,0x5cae26c,0x5cae2c2,0x5cae2c7,0x5cae2f3]
RAX_DEAD_RANGES=[(0x5cae157,0x5cae165,True),(0x5cae23c,0x5cae278,False),(0x5cae2f3,0x5cae2fd,False)]


def parse_text(asm):
    """Parse an objdump export into {address: (mnemonic, operands)}."""
    out={}
    for line in asm.splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)(.*)$',line)
        if not m:
            continue
        addr=int(m[1],16);rest=m[3].strip()
        if addr in out and not rest:
            continue
        if not rest:
            continue
        parts=rest.split(None,1)
        out[addr]=(parts[0],parts[1] if len(parts)>1 else '')
    return out


def reg_tokens(operands):
    return {REG64[t] for t in REG_TOKEN.findall(operands)}


def dest_reg(mnemonic,operands):
    if mnemonic not in WRITE_MNEMONICS or not operands:
        return None
    first=operands.split(',')[0].strip()
    toks=REG_TOKEN.findall(first)
    if len(toks)==1 and first==toks[0]:
        return REG64[toks[0]]
    return None


def native_censuses(ins):
    def mentions(reg,lo,hi,skip=()):
        return sorted(a for a,(mn,ops) in ins.items()
                      if lo<=a<hi and mn not in skip and reg in reg_tokens(ops))
    r14=mentions('r14',HELPER,0x5cae3da,skip=('push','pop'))
    if r14!=R14_MENTIONS:
        raise ValueError('xcr0 composition r14 mention census changed')
    def writes(reg):
        return sorted(a for a,(mn,ops) in ins.items() if dest_reg(mn,ops)==reg)
    r12,r15,r13=writes('r12'),writes('r15'),writes('r13')
    if r12!=R12_WRITES:
        raise ValueError('xcr0 composition r12 write census changed')
    if r15!=R15_WRITES:
        raise ValueError('xcr0 composition r15 write census changed')
    if r13!=R13_WRITES:
        raise ValueError('xcr0 composition r13 write census changed')
    rdi=mentions('rdi',0x5cae051,0x5cae300)
    if rdi!=RDI_MENTIONS_AFTER_INTAKE:
        raise ValueError('xcr0 composition rdi mention census changed')
    for lo,hi,exclusive_lo in RAX_DEAD_RANGES:
        for a,(mn,ops) in ins.items():
            if (lo<a<hi) if exclusive_lo else (lo<=a<hi):
                if 'rax' in reg_tokens(ops):
                    raise ValueError('xcr0 composition rax deadness census changed')
    return {'r14_mentions':[hex(x) for x in r14],
            'r12_writes':[hex(x) for x in r12],
            'r15_writes':[hex(x) for x in r15],
            'r13_writes':[hex(x) for x in r13],
            'rdi_mentions_after_intake':[hex(x) for x in rdi],
            'rax_dead_ranges':[[hex(lo),hex(hi)] for lo,hi,_ in RAX_DEAD_RANGES]}


def _src_taint(state,mem,operand):
    operand=operand.strip()
    toks=REG_TOKEN.findall(operand)
    if operand.startswith('QWORD PTR') or operand.startswith('DWORD PTR') or '[' in operand:
        key=re.search(r'\[(.*?)\]',operand)
        key=key.group(1) if key else operand
        if 'rip' in key:
            return False
        return mem.get(key,False)
    if len(toks)==1 and operand==toks[0]:
        return state[REG64[toks[0]]]
    return False


def _transfer(state,mem,mn,ops):
    state=dict(state);mem=dict(mem)
    if mn=='cpuid':
        for r in ('rax','rbx','rcx','rdx'):
            state[r]=False
        return state,mem
    if mn=='call':
        # The pinned leaf returns XCR0 in RAX; caller-saved registers other
        # than the callee-saved set are conservatively tainted.
        state['rax']=True
        for r in ('rcx','rdx','rsi','rdi','r8','r9','r10','r11'):
            state[r]=True
        return state,mem
    if mn.startswith('set'):
        return state,mem
    if mn=='xchg':
        parts=[p.strip() for p in ops.split(',')]
        if len(parts)==2:
            ta=_src_taint(state,mem,parts[0]);tb=_src_taint(state,mem,parts[1])
            da,db=dest_reg('mov',parts[0]),dest_reg('mov',parts[1])
            if da: state[da]=tb
            if db: state[db]=ta
        return state,mem
    dest=dest_reg(mn,ops)
    if dest is None:
        if mn=='mov' and ops:
            parts=[p.strip() for p in ops.split(',',1)]
            if len(parts)==2 and '[' in parts[0]:
                key=re.search(r'\[(.*?)\]',parts[0])
                if key and 'rip' not in key.group(1):
                    mem[key.group(1)]=mem.get(key.group(1),False) or _src_taint(state,mem,parts[1])
        return state,mem
    src=ops.split(',',1)[1] if ',' in ops else ''
    if mn=='mov' or mn=='movabs':
        state[dest]=_src_taint(state,mem,src)
    elif mn.startswith('cmov'):
        state[dest]=state[dest] or _src_taint(state,mem,src)
    elif mn in ('not','neg'):
        pass
    elif mn in ('inc','dec'):
        pass
    else:
        state[dest]=state[dest] or _src_taint(state,mem,src)
        # lea/shift-by-register/index terms: any register named in the
        # source is a value input.
        for t in reg_tokens(src):
            state[dest]=state[dest] or state[t]
    return state,mem


def value_taint(ins):
    """Forward may-taint fixpoint over the helper's blocks. Taint marks
    'may carry XCR0 value bits'; it enters only at the leaf call result.
    Flag-mediated selection is not value flow (see LIMITS)."""
    addrs=sorted(ins)
    index={a:i for i,a in enumerate(addrs)}
    def branch_target(a,mn,ops):
        m=re.match(r'^([0-9a-f]+)\b',ops)
        return int(m.group(1),16) if m else None
    leaders={addrs[0]}
    edges={}
    for i,a in enumerate(addrs):
        mn,ops=ins[a]
        nxt=addrs[i+1] if i+1<len(addrs) else None
        if mn=='ret':
            edges[a]=[]
        elif mn=='jmp':
            t=branch_target(a,mn,ops);edges[a]=[t] if t is not None else []
            if t is not None: leaders.add(t)
        elif mn.startswith('j') or mn.startswith('loop'):
            t=branch_target(a,mn,ops)
            edges[a]=[x for x in (t,nxt) if x is not None]
            if t is not None: leaders.add(t)
            if nxt is not None: leaders.add(nxt)
        else:
            edges[a]=[nxt] if nxt is not None else []
    blocks=sorted(leaders)
    entry={b:({r:False for r in REGS},{}) for b in blocks}
    changed=True
    while changed:
        changed=False
        for b in blocks:
            state,mem=entry[b]
            a=b
            while True:
                mn,ops=ins[a]
                state,mem=_transfer(state,mem,mn,ops)
                nxts=edges[a]
                # Block ends when the next address starts a new block or
                # this instruction is a branch/ret.
                i=index[a]
                nxt=addrs[i+1] if i+1<len(addrs) else None
                if mn=='ret' or mn=='jmp' or mn.startswith('j'):
                    for t in nxts:
                        if t in entry:
                            es,em=entry[t]
                            ns={r:es[r] or state[r] for r in REGS}
                            nm=dict(em)
                            for k,v in mem.items():
                                nm[k]=nm.get(k,False) or v
                            if ns!=es or nm!=em:
                                entry[t]=(ns,nm);changed=True
                    break
                if nxt is None or nxt in leaders:
                    if nxt is not None and nxt in entry:
                        es,em=entry[nxt]
                        ns={r:es[r] or state[r] for r in REGS}
                        nm=dict(em)
                        for k,v in mem.items():
                            nm[k]=nm.get(k,False) or v
                        if ns!=es or nm!=em:
                            entry[nxt]=(ns,nm);changed=True
                    break
                a=nxt
    return entry


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('expected pinned node115')
    report=analyze(data);output.mkdir(parents=True,exist_ok=True);lines=[]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        native=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        for role,(a,b,_) in OWNERS.items():
            rows=[l for l in native.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(rows)!=1:
                raise ValueError('native xcr0 composition FDE disagreement')
            lines.extend(rows)
        asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',
                                     f'--start-address={HELPER:#x}',
                                     f'--stop-address={OWNERS["refresh_helper"][1]:#x}',
                                     str(snapshot)],text=True)
        a,b,_=OWNERS['refresh_helper']
        ins_bytes=decode_export(asm,a,b,read(data,a,b-a)[1])
        required={va for va,_,_ in PINS}
        if not required<=set(ins_bytes):
            raise ValueError('xcr0 composition pin site not native instruction start')
        ins=parse_text(asm)
        if set(ins)!=set(ins_bytes):
            raise ValueError('xcr0 composition text decode disagreement')
        report['censuses']=native_censuses(ins)
        entry=value_taint(ins)
        suffix_state=entry[SUFFIX][0]
        if suffix_state['r12'] or suffix_state['r13'] or suffix_state['r15'] or suffix_state['rdx']:
            raise ValueError('xcr0 composition value taint reached a composed word')
        tainted_blocks={'r12':[hex(x) for x in sorted(entry) if entry[x][0]['r12']],
                        'r15':[hex(x) for x in sorted(entry) if entry[x][0]['r15']]}
        if tainted_blocks['r12'] or tainted_blocks['r15']:
            raise ValueError('xcr0 composition value taint reached a composed word')
        gate_state=entry[0x5cae067][0]
        if not gate_state['r14']:
            raise ValueError('xcr0 composition taint sanity failed at the mask field')
        report['value_taint']={
            'method':'forward may-taint over decoded blocks; taint enters only as the leaf call result in rax and the conservative caller-saved set; cpuid outputs and immediates are untainted; flag-mediated selection propagates selected values only',
            'suffix_entry':{r:suffix_state[r] for r in REGS},
            'r12_tainted_blocks':tainted_blocks['r12'],
            'r15_tainted_blocks':tainted_blocks['r15'],
            'mask_field_block_r14_tainted':True}
        (output/'helper.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/xcr0-composition115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
