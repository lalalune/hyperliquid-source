#!/usr/bin/env python3
"""Recover the selected node 94 multisignature snapshot read/write path.

Inputs are authenticated ELF bytes, never executed. The instruction reader only
accepts the explicitly pinned x86-64 encodings below; it is not a disassembler.
The shared repository ELF and CIE/FDE parsers provide all section and unwind data.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

TOOL_DIR = Path(__file__).resolve().parent
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))
from elf_index import unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Selected FDEs only: analyst labels describe the bounded use, not recovered symbols.
# The extent and complete-body hash are admission checks, not function equivalence.
FUNCTIONS = (
    (0x27b3ab0, 0x27b3bc0, 'exchange_field_writer', '4b06750fdac5735fd855adac168dae629ef761dcdbc3f739435eb56227f78930'),
    (0x26ce210, 0x26ce2ee, 'tracker_compact_writer', '1dc1cdba048b7650726a04bc99a88eaa9bcfb67b8cc5b80a96b8d77763cbdfc8'),
    (0x25dfa30, 0x25dfaf9, 'compact_rows_adapter', 'ef0f5f68100d92ec2d3473349f94101e4acfa05d0dc9a9b9ae2ce82f5cc48952'),
    (0x256df50, 0x256e240, 'tree_row_collector', 'b5e933e5ceda2d705dcdb7e81ac6b0adc36c2422febe788bb6432d80a07c58ca'),
    (0x1e1eb10, 0x1e1ed9b, 'compact_rows_writer', 'b7cfcbd36108e7e535ea44a7e4f4c2ec7d48e0616344258984da2ed349942183'),
    (0x1dde0d0, 0x1dde625, 'compact_row_writer', '680c3d3c6b896672dff669edc57aa209608458c65f9a9799491a5c4e904e8eb9'),
    (0x1e0d0a0, 0x1e0d205, 'key20_writer', 'a202a759a0a5e43cfc7b1a4a6733a47b15471f87c5f2da3f3b2822d700289361'),
    (0x26cdbc0, 0x26cdd03, 'signers_compact_writer', '5b2a2194a940b4db191cfd5a90e0a2826f563d6b78d122f11f59b42573d1f8a8'),
    (0x1e15810, 0x1e15cae, 'authorized_users_writer', 'afe60cb68ae8ed33a87bf5d9f6a0bb54889fbf846bad48017255673bfcd33d72'),
    (0x1716c90, 0x1718080, 'tracker_compact_reader', '6acf6f595377dfb70c0eec43e5c50b050ccc2841f2d2e819ce4fb35765ae3e5c'),
    (0x1901890, 0x1902029, 'compact_rows_reader', 'b50575a29361128024ddb7ac2693b2234a4f27d86509d93ad7b92a016b98aa0b'),
    (0x263c0f0, 0x263c5d0, 'compact_map_reader', '5f366633d1ea1da5647eac07e3fa67953cc0f2b3282afba5336692c872b5d0df'),
    (0x266f210, 0x266f506, 'compact_row_array_reader', '2e4cbfe195e6b071fbdba0a871b908f237580a5f06f076a870182c85ee7fff8f'),
    (0x170f470, 0x171036c, 'compact_row_reader', 'c8cc768e8c6a237992bc1ec260d68039fbfc058c5af620d5f698948b3c2e493b'),
    (0x18325a0, 0x1833fe6, 'signers_compact_reader', '64ab88256cd2ffff13e80bd585bbd0138deca44fd6fc94ddad7a6a652492b3d0'),
    (0x26bfe00, 0x26bfe95, 'signer_field_compact_classifier', '3882d7c5823ad972daa185bd1c89183f4a0eee03e31a7604379093cab38c8dd7'),
    (0x26bfea0, 0x26bff35, 'signer_field_json_classifier', '77316795c0c315594f0dd647b7a4dbf4f5ec682e9a20707a85ea6ff12998b246'),
    (0x1bee850, 0x1bef0b5, 'tracker_json_reader', 'f8ea4b36bab796e02053315ba1d842f7be54aa38176e5ba561c8e3de577113d5'),
    (0x261ff40, 0x26207ff, 'json_rows_reader', '1726bf73495fb0b417973cff85cedf28bf621e01d02a0f22267a77ca86bf70c9'),
    (0x1b748a0, 0x1b74957, 'json_signer_value_adapter', '2ca8422e05ba74b2634fcead5dc87a0ca36d13b7dc10aab0049d2dc515b274bc'),
    (0x1c0f280, 0x1c0ff93, 'signers_json_reader', '5573b126a250c76ec7911461791f84abb70415d754b575ca57e9e649b0d17364'),
    (0x26cdfb0, 0x26ce20b, 'tracker_json_writer', '376af76ffa865fddfe0dcef6f033c9cdd49796b4c691c13fc55c77259c8358d3'),
    (0x25df550, 0x25df616, 'json_rows_adapter', '3d3cdbc55b6775d3416366d54d33f162b0bcdcfd5261ec1ecd051562806df959'),
    (0x291b5c0, 0x291bc62, 'json_rows_writer', '8717365ac0acaf15c17e8299c1fa08f9ca51f39f9dc29e2c91fd4d4f01fb1ac2'),
    (0x26cdd10, 0x26cdfab, 'signers_json_writer', '0dae5354a25ee65a47a89093ad78b87ed35ce119276ef43e6b664d539de62abd'),
    (0x25ac0d0, 0x25ac362, 'compact_unsigned_writer', 'b46f6ef6ae1413ce43646a2b4066f9caf0afa6a6eaeed1c36b3abf8a10fa56c2'),
    (0x25ac580, 0x25ac70d, 'compact_unsigned16_writer', '480f0610e8d209ee7e3b320bcf963ebaa38a6d9bcccbeee00c9932e6f1560918'),
    (0x25ac7b0, 0x25ac93b, 'compact_unsigned32_writer', 'd80152d26196c1e4f564ae1e604f175accd09fcde7ad99650d87922fbd0dcf1d'),
    (0x25ac9e0, 0x25acb74, 'compact_unsigned64_writer', '498e55a96dd64edc78aa91384917f4fabfd4a8b6ac05f0fbde5a3f0fb40a0f07'),
    (0x2860580, 0x2860859, 'row_map_insert', '284c33f54728e5e85f077b19610eab87d8fc21dcc112039e764c2870168c3969'),
)

# Selected, manually qualified direct-call sites. Common callees are contextual;
# they are not counted as newly analyzed FDEs merely because they are targets.
CALLS = (
    (0x27b3ae3, 0x25aa7f0, 'exchange field name'),
    (0x27b3b04, 0x25a8f80, 'exchange tracker named header'),
    (0x27b3b33, 0x25a9bd0, 'exchange tracker positional header'),
    (0x27b3b58, 0x25aa7f0, 'exchange tracker field name'),
    (0x27b3b6c, 0x25dfa30, 'exchange field to rows'),
    (0x26ce23f, 0x25a8f80, 'tracker named header'),
    (0x26ce26b, 0x25a9bd0, 'tracker positional header'),
    (0x26ce290, 0x25aa7f0, 'tracker field name'),
    (0x26ce2a4, 0x25dfa30, 'tracker to rows'),
    (0x25dfa9a, 0x256df50, 'collect tree entries'),
    (0x25dfaa8, 0x1e1eb10, 'write collected entries'),
    (0x1e1eb77, 0x25a9bd0, 'row collection array header'),
    (0x1e1ebcf, 0x1dde0d0, 'first row'),
    (0x1e1ecfe, 0x1dde0d0, 'remaining rows'),
    (0x1dde13a, 0x25a9bd0, 'pair array header'),
    (0x1dde196, 0x1e0d0a0, 'pair key'),
    (0x1dde265, 0x26cdbc0, 'pair signer record'),
    (0x1e0d1a4, 0x25aa7f0, 'key text'),
    (0x26cdbf3, 0x25a8f80, 'signer named header'),
    (0x26cdc25, 0x25a9bd0, 'signer positional header'),
    (0x26cdc4b, 0x25aa7f0, 'authorized field name'),
    (0x26cdc61, 0x1e15810, 'authorized collection'),
    (0x26cdc8c, 0x25aa7f0, 'threshold field name'),
    (0x26cdca2, 0x25ac0d0, 'threshold unsigned writer'),
    (0x1e15853, 0x25a9bd0, 'authorized collection header'),
    (0x1e15af7, 0x25aa7f0, 'authorized address text'),
    (0x25ac13d, 0x25ac580, 'unsigned16 writer'),
    (0x25ac16a, 0x25ac7b0, 'unsigned32 writer'),
    (0x25ac18f, 0x25ac9e0, 'unsigned64 writer'),
    (0x1717750, 0x1901890, 'tracker map value'),
    (0x171799d, 0x1901890, 'tracker sequence value'),
    (0x1901c66, 0x263c0f0, 'native map route'),
    (0x1901daa, 0x266f210, 'array-of-pairs route'),
    (0x263c17a, 0x1699080, 'native map user key decoder'),
    (0x263c1ff, 0x18325a0, 'map signer record'),
    (0x266f27e, 0x170f470, 'array pair'),
    (0x170fa1c, 0x190f5b0, 'pair key decoder'),
    (0x170fb7e, 0x18325a0, 'pair signer record'),
    (0x1832cd1, 0x17932f0, 'sequence authorized collection reader'),
    (0x1832dc4, 0x1684530, 'sequence threshold reader'),
    (0x1833a9c, 0x26bfe00, 'compact signer field classifier'),
    (0x1833c39, 0x1684530, 'map threshold reader'),
    (0x1833ce9, 0x17932f0, 'map authorized collection reader'),
    (0x263c363, 0x2860580, 'native map insertion'),
    (0x266f354, 0x2860580, 'array map insertion'),
    (0x1beeb2a, 0x261ff40, 'JSON tracker map value'),
    (0x1beecc9, 0x261ff40, 'JSON tracker sequence value'),
    (0x26201b4, 0x1b748a0, 'JSON row value adapter'),
    (0x1b74931, 0x1c0f280, 'JSON signer record'),
    (0x1c0f44e, 0x26bfea0, 'JSON signer field classifier'),
    (0x1c0f5b0, 0x1be3a70, 'JSON authorized collection reader'),
    (0x1c0f643, 0x1b2fae0, 'JSON threshold reader'),
    (0x262026b, 0x2860580, 'JSON row insertion'),
    (0x26ce056, 0x25df550, 'JSON tracker rows'),
    (0x25df5b7, 0x256df50, 'JSON collect tree entries'),
    (0x25df5c2, 0x291b5c0, 'JSON rows writer'),
    (0x291b82e, 0x27e2690, 'JSON key formatter'),
    (0x291b8ed, 0x26cdd10, 'JSON signer record'),
    (0x26cddba, 0x2924720, 'JSON authorized collection'),
    (0x26cdde5, 0x2958170, 'JSON threshold field'),
)

# (site, expected destination, interpretation when the conditional jump is taken)
BRANCHES = (
    (0x26ce232, 0x26ce260, 'tracker mode zero selects positional header'),
    (0x26ce24c, 0x26ce27a, 'named header succeeds'),
    (0x26ce278, 0x26ce24e, 'positional header fails'),
    (0x26ce27f, 0x26ce29b, 'mode other than one skips field name'),
    (0x26ce299, 0x26ce2b8, 'field-name write fails'),
    (0x26ce2b1, 0x26ce2c6, 'rows write fails'),
    (0x27b3ad2, 0x27b3b28, 'mode zero skips exchange field name'),
    (0x27b3aec, 0x27b3b80, 'exchange field-name write fails'),
    (0x27b3b11, 0x27b3b42, 'named tracker header succeeds'),
    (0x27b3b40, 0x27b3b13, 'positional tracker header fails'),
    (0x27b3b47, 0x27b3b63, 'non-one mode skips inner name'),
    (0x27b3b61, 0x27b3b8d, 'inner field-name write fails'),
    (0x1e1eb85, 0x1e1ec3e, 'rows header fails'),
    (0x1e1ed0b, 0x1e1ebf0, 'row write fails'),
    (0x1dde109, 0x1dde127, 'pair writer emits header when mode byte is not two'),
    (0x1dde148, 0x1dde45f, 'pair header fails'),
    (0x1dde1a4, 0x1dde433, 'key write fails'),
    (0x1dde26f, 0x1dde532, 'signer record write fails'),
    (0x26cdbe4, 0x26cdc18, 'signer mode zero selects positional header'),
    (0x26cdc3a, 0x26cdc56, 'non-one mode skips authorized field name'),
    (0x26cdc54, 0x26cdcb7, 'authorized field-name write fails'),
    (0x26cdc70, 0x26cdcc6, 'authorized collection write fails'),
    (0x26cdc7b, 0x26cdc97, 'non-one mode skips threshold name'),
    (0x26cdc95, 0x26cdce7, 'threshold field-name write fails'),
    (0x1717052, 0x17177c7, 'empty tracker map reaches missing field'),
    (0x17172fc, 0x1717334, 'tracker name length differs'),
    (0x17176fe, 0x1717734, 'tracker field tag zero'),
    (0x1717742, 0x1717e6d, 'recognized tracker field already seen'),
    (0x171798a, 0x1717ac1, 'tracker sequence has no first element'),
    (0x17179cc, 0x1717a83, 'tracker sequence count differs from one'),
    (0x1901c27, 0x1901d68, 'short array markers use row array route'),
    (0x1901d6b, 0x1901eaf, 'markers beyond short arrays take another route'),
    (0x263c371, 0x263c3b1, 'map insertion reports an existing value'),
    (0x266f288, 0x266f396, 'row decoder reports failure'),
    (0x266f362, 0x266f3b1, 'row insertion reports an existing value'),
    (0x28605a8, 0x2860696, 'empty tree takes insertion path'),
    (0x2860628, 0x28605f0, 'positive comparison continues within node'),
    (0x286062f, 0x2860662, 'equal key selects replacement result'),
    (0x170f9bb, 0x170feeb, 'pair sequence lacks first value'),
    (0x170fb59, 0x170ff6e, 'pair sequence lacks second value'),
    (0x170fdfc, 0x170fe79, 'pair sequence count differs from two'),
    (0x1832cbe, 0x1832f1d, 'signer sequence lacks first value'),
    (0x1832d07, 0x1832db9, 'signer sequence count differs from one'),
    (0x1832e1f, 0x1832ecf, 'signer sequence count differs from two'),
    (0x1833383, 0x18329aa, 'signer map lacks authorized field'),
    (0x18333b5, 0x1832aad, 'signer map has threshold field'),
    (0x1833c2b, 0x1833f09, 'threshold field already seen'),
    (0x1833cd6, 0x1833e93, 'authorized field already seen'),
    (0x1bee9fb, 0x1beea31, 'JSON tracker name length differs'),
    (0x1beea2b, 0x1beeab9, 'JSON tracker name comparison matches'),
    (0x1beeabf, 0x1beef67, 'JSON tracker field already seen'),
    (0x1c0f465, 0x1c0f4f4, 'JSON authorized field tag'),
    (0x1c0f473, 0x1c0f54b, 'JSON field tag is unknown'),
    (0x1c0f482, 0x1c0fd76, 'JSON threshold field already seen'),
    (0x1c0f4fc, 0x1c0fdc6, 'JSON authorized field already seen'),
    (0x2620275, 0x2620180, 'JSON row insertion reports no previous value'),
)

# Short instruction windows, including several established shared serializer
# primitives. These pins support the local data flow without claiming the shared
# helper bodies as new functions. Masks are empty and all bytes are checked.
WINDOWS = (
    (0x25a8f99, '83fa100fb6c0bd800000000f43e8', 'fixmap base and size cutoff'),
    (0x25a9be9, '83fa100fb6c0bd900000000f43e8', 'fixarray base and size cutoff'),
    (0x25aa806, '83fa20731440b5a0', 'fixstr cutoff and base'),
    (0x25aa81f, '81fa00010000731440b5d9', 'str8 cutoff and marker'),
    (0x25acc49, '4080e61f4080cea0', 'fixstr marker composition'),
    (0x25acc58, '4080e60f4080ce80', 'fixmap marker composition'),
    (0x25acc63, '4080e60f4080ce90', 'fixarray marker composition'),
    (0x17172f6, '48837c245019', 'tracker name length comparison'),
    (0x171730b, 'f30f6f08660f74c8f30f6f4009', 'tracker two overlapping 16-byte comparisons'),
    (0x1717320, '660f74d0660fdbd1660fd7c23dffff0000', 'tracker comparison aggregation'),
    (0x1bee9f5, '48837c241019', 'JSON tracker name length comparison'),
    (0x1beea05, 'f30f6f08660f74c8f30f6f4009', 'JSON overlapping tracker comparisons'),
    (0x1beea1a, '660f74d0660fdbd1660fd7c23dffff0000', 'JSON comparison aggregation'),
    (0x17179c9, '83fd01', 'tracker sequence arity'),
    (0x170f9f3, '48c784249801000014000000', 'pair key input capacity'),
    (0x170fa17, 'b901000000', 'pair key decoder mode'),
    (0x263c161, 'b904000000', 'native map key type name length'),
    (0x170fdf9, '83fd02757b', 'pair arity check'),
    (0x1832e1c, '83fd020f85aa000000', 'signer sequence arity check'),
    (0x1833c14, '83f802745083f8010f85b1000000', 'compact signer field tags'),
    (0x26bfe03, '4883c2fe4883fa0e', 'classifier indexes lengths two through sixteen'),
    (0x26bfe1d, '66813e6175', 'short authorized alias'),
    (0x26bfe26, '48b9617574686f72697a', 'canonical authorized first bytes'),
    (0x26bfe33, '48ba7a65645573657273', 'canonical authorized overlapping bytes'),
    (0x26bfe48, '48b97468726573686f6c', 'threshold first bytes'),
    (0x26bfe55, '0fb656084883f264', 'threshold final byte'),
    (0x26bfe77, '660fd7c881f9ffff0000', 'snake-case comparison mask'),
    (0x26bfe83, 'b102884801c60009c3', 'compact unknown tag'),
    (0x26bfe8c, '31c9884801c60009c3', 'compact authorized tag'),
    (0x26bfe62, 'b101884801c60009c3', 'compact threshold tag'),
    (0x26bff23, 'b102884801c60000c3', 'JSON unknown tag'),
    (0x26bff2c, '31c9884801c60000c3', 'JSON authorized tag'),
    (0x26bff02, 'b101884801c60000c3', 'JSON threshold tag'),
    (0x1e0d18b, 'be2a000000b9140000004531c0', 'key formatter capacity, width and mode'),
    (0x1e15adb, 'be2a000000b9140000004c89ff4531c0', 'authorized formatter capacity, width and mode'),
    (0x1dde295, '498b4c2408c6040192', 'direct two-element array marker'),
    (0x26ce23a, 'ba01000000', 'named tracker field count'),
    (0x26ce266, 'ba01000000', 'positional tracker field count'),
    (0x27b3aff, 'ba01000000', 'exchange named tracker field count'),
    (0x27b3b2e, 'ba01000000', 'exchange positional tracker field count'),
    (0x26cdbee, 'ba02000000', 'named signer field count'),
    (0x26cdc20, 'ba02000000', 'positional signer field count'),
    (0x26cdc72, '4d8b7f18', 'load threshold qword from signer input'),
    (0x1dde135, 'ba02000000', 'row pair field count'),
    (0x291b604, '42c604385b', 'JSON row-array opening byte'),
    (0x291b777, '42c604385b', 'JSON pair opening byte'),
    (0x291b812, 'be2a000000b914000000', 'JSON key capacity and width'),
    (0x291b9b7, '42c604385d', 'JSON pair closing byte'),
    (0x291bb15, '42c604385d', 'JSON row-array closing byte'),
    (0x2860600, 'ba140000004c89e7', 'key comparison length and argument'),
    (0x2860610, '4885c00f98c10f9fc028c8', 'key comparison sign normalization'),
    (0x2860662, '410f1007410f104f10', 'load previous value on equal key'),
    (0x286068c, 'b801000000', 'equal-key result tag'),
    (0x28607e4, '31c0488907', 'inserted-key result tag'),
    (0x1e1ecc3, '49c1e6044d01f5', 'row-pointer stride'),
    (0x266f446, 'bf0d000000', 'duplicate diagnostic length'),
    (0x266f456, '48b963617465206b6579', 'duplicate diagnostic trailing immediate'),
    (0x266f464, '48b96475706c69636174', 'duplicate diagnostic leading immediate'),
    (0x263c506, 'bf0d000000', 'map duplicate diagnostic length'),
    (0x263c51a, '48b963617465206b6579', 'map duplicate diagnostic trailing immediate'),
    (0x263c528, '48b96475706c69636174', 'map duplicate diagnostic leading immediate'),
    (0x2620285, 'bf0d000000', 'JSON duplicate diagnostic length'),
    (0x2620299, '48b963617465206b6579', 'JSON duplicate diagnostic trailing immediate'),
    (0x26202a7, '48b96475706c69636174', 'JSON duplicate diagnostic leading immediate'),
    (0x25ac0e0, '4881fa00010000', 'unsigned 8-bit upper bound'),
    (0x25ac100, '84d2', 'positive fixint high-bit test'),
    (0x25ac12f, '4881fa00000100', 'unsigned 16-bit upper bound'),
    (0x25ac15f, '48c1e820', 'unsigned 32-bit upper bound'),
    (0x25ac228, 'c60430cc', 'unsigned8 marker store'),
    (0x25ac5a7, 'c60401cd', 'unsigned16 marker store'),
    (0x25ac7d7, 'c60401ce', 'unsigned32 marker store'),
    (0x25aca08, 'c60401cf', 'unsigned64 marker store'),
    (0x25ac639, '66c1c608488b4f0866893401', 'unsigned16 big-endian store'),
    (0x25ac869, '0fce488b470842893408', 'unsigned32 big-endian store'),
    (0x25aca9c, '480fce488b47084a893408', 'unsigned64 big-endian store'),
)

# RIP-relative pointer references and explicit immediate lengths at write sites.
FIELD_REFS = (
    (0x27b3ad4, 0x27b3adb, 'exchange_field'),
    (0x27b3b49, 0x27b3b50, 'tracker_field_exchange'),
    (0x26ce281, 0x26ce288, 'tracker_field'),
    (0x26cdc3c, 0x26cdc43, 'authorized_canonical'),
    (0x26cdc7d, 0x26cdc84, 'threshold'),
    (0x26ce004, 0x26ce00e, 'tracker_field_json'),
    (0x26cdd65, 0x26cdd71, 'authorized_canonical_json'),
    (0x26cddd1, 0x26cdddd, 'threshold_json'),
)

# Field names and diagnostic-template references on selected failure paths.
# Length immediates are checked as complete fixed instruction encodings.
FIELD_DIAGNOSTICS = (
    ('compact tracker missing', 0x17177c7, 0x17177d6, '48c78424f000000019000000', 0x17177fa, '488d35', 'tracker_field', 'missing'),
    ('compact tracker duplicate', 0x1717e6d, 0x1717e78, '48c744240819000000', 0x1717e95, '488d35', 'tracker_field', 'duplicate'),
    ('compact signer authorized missing', 0x18329aa, 0x18329b9, '48c78424280100000f000000', 0x18329ea, '488d35', 'authorized_canonical', 'missing'),
    ('compact signer threshold missing', 0x1832a45, 0x1832a54, '48c784242801000009000000', 0x1832a7f, '488d35', 'threshold', 'missing'),
    ('compact signer authorized duplicate', 0x1833eb1, 0x1833ec0, '48c78424a80000000f000000', 0x1833eee, '488d35', 'authorized_canonical', 'duplicate'),
    ('compact signer threshold duplicate', 0x1833f27, 0x1833f36, '48c78424a800000009000000', 0x1833f64, '488d35', 'threshold', 'duplicate'),
    ('JSON tracker duplicate', 0x1beef67, 0x1beef73, '48c744247819000000', 0x1beef91, '488d3d', 'tracker_field', 'duplicate'),
    ('JSON signer authorized duplicate', 0x1c0fdd4, 0x1c0fde0, '48c74424100f000000', 0x1c0fe02, '488d3d', 'authorized_canonical', 'duplicate'),
    ('JSON signer threshold duplicate', 0x1c0fd84, 0x1c0fd90, '48c744241009000000', 0x1c0fdb2, '488d3d', 'threshold', 'duplicate'),
)


def fail(message):
    raise ValueError(message)


def check_hash(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        fail('node 94 SHA-256 mismatch')
    return digest


def va_offset(secs, va, size, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size < 0:
        fail('invalid address or size')
    if va + size >= 1 << 64:
        fail('address range overflows')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + size <= s['address'] + s['size'] and
               (size != 0 or va < s['address'] + s['size'])]
    if len(matches) != 1:
        fail('address is not in one file-backed section')
    s = matches[0]
    return s['offset'] + va - s['address']


def va_bytes(data, secs, va, size, executable=False):
    off = va_offset(secs, va, size, executable)
    result = bytes(data[off:off + size])
    if len(result) != size:
        fail('file range is truncated')
    return result


def expect(data, secs, site, expected, executable=True):
    wanted = bytes.fromhex(expected)
    actual = va_bytes(data, secs, site, len(wanted), executable)
    if actual != wanted:
        fail(f'instruction pattern mismatch at {site:#x}')
    return actual


def rip_ref(data, secs, site, prefix):
    prefix = bytes.fromhex(prefix)
    raw = va_bytes(data, secs, site, len(prefix) + 4, True)
    if not raw.startswith(prefix):
        fail(f'RIP-relative opcode mismatch at {site:#x}')
    target = site + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]
    va_offset(secs, target, 1)
    return target, raw


def direct_call(data, secs, site):
    raw = va_bytes(data, secs, site, 5, True)
    if raw[0] != 0xe8:
        fail(f'direct-call opcode mismatch at {site:#x}')
    target = site + 5 + struct.unpack_from('<i', raw, 1)[0]
    va_offset(secs, target, 1, True)
    return target, raw


def conditional_branch(data, secs, site):
    head = va_bytes(data, secs, site, 2, True)
    if 0x70 <= head[0] <= 0x7f:
        raw = head
        disp = struct.unpack_from('<b', raw, 1)[0]
        code = head[0] & 15
    elif head[0] == 0x0f and 0x80 <= head[1] <= 0x8f:
        raw = va_bytes(data, secs, site, 6, True)
        disp = struct.unpack_from('<i', raw, 2)[0]
        code = head[1] & 15
    else:
        fail(f'unsupported conditional branch at {site:#x}')
    target = site + len(raw) + disp
    va_offset(secs, target, 1, True)
    return target, raw, code


def relocation(data, secs, slot):
    matches = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(matches) != 1 or matches[0]['size'] % 24:
        fail('invalid relocation section')
    s = matches[0]
    rows = []
    for pos in range(s['offset'], s['offset'] + s['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', data, pos)
        if address == slot:
            rows.append((address, info, addend))
    if len(rows) != 1 or rows[0][1] != 8:
        fail('expected one symbol-zero relative relocation')
    va_offset(secs, rows[0][2], 1, True)
    return rows[0]


def imported_symbol(data, secs, slot):
    """Resolve a GLOB_DAT slot via file-backed ELF relocation and dynsym bytes."""
    rela = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    syms = [s for s in secs if s['name'] == '.dynsym' and s['type'] == 11]
    strs = [s for s in secs if s['name'] == '.dynstr' and s['type'] == 3]
    if len(rela) != 1 or len(syms) != 1 or len(strs) != 1:
        fail('missing or duplicate dynamic symbol sections')
    if rela[0]['size'] % 24 or syms[0]['size'] % 24:
        fail('malformed dynamic record sizes')
    matches = [struct.unpack_from('<QQq', data, pos)
               for pos in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24)
               if struct.unpack_from('<Q', data, pos)[0] == slot]
    if len(matches) != 1:
        fail('dynamic slot is not unique')
    _, info, addend = matches[0]
    index, kind = info >> 32, info & 0xffffffff
    if kind != 6 or index == 0 or index >= syms[0]['size'] // 24 or addend != 0:
        fail('unexpected dynamic relocation')
    name_offset, st_info, other, shndx, value, size = struct.unpack_from(
        '<IBBHQQ', data, syms[0]['offset'] + index * 24)
    if name_offset >= strs[0]['size'] or shndx != 0 or value != 0:
        fail('unexpected dynamic symbol record')
    begin = strs[0]['offset'] + name_offset
    end = data.find(b'\0', begin, strs[0]['offset'] + strs[0]['size'])
    if end < 0:
        fail('unterminated dynamic symbol')
    name = bytes(data[begin:end]).decode('ascii')
    return {'slot_va': hex(slot), 'relocation_type': kind, 'symbol_index': index,
            'symbol_name': name, 'symbol_info': st_info, 'symbol_other': other,
            'symbol_section_index': shndx, 'symbol_value': value, 'symbol_size': size}


def field_classifier(data, secs, start):
    """Read both fixed-length signer classifiers, including their jump tables."""
    delta = start - 0x26bfe00
    if delta not in (0, 0xa0):
        fail('unsupported classifier')
    range_insn = expect(data, secs, start + 3, '4883c2fe4883fa0e')
    first_length = -struct.unpack_from('<b', range_insn, 3)[0]
    table_count = range_insn[-1] + 1
    table, _ = rip_ref(data, secs, start + 0x0d, '488d0d')
    table_data = va_bytes(data, secs, table, table_count * 4)
    targets = [table + n for n in struct.unpack(f'<{table_count}i', table_data)]
    route = {2: start + 0x1d, 9: start + 0x48, 15: start + 0x26, 16: start + 0x6b}
    for length, target in enumerate(targets, first_length):
        if target != route.get(length, start + 0x83):
            fail('signer length table target mismatch')
    short = expect(data, secs, start + 0x1d, '66813e6175')[3:]
    a = expect(data, secs, start + 0x26, '48b9617574686f72697a')[2:]
    b = expect(data, secs, start + 0x33, '48ba7a65645573657273')[2:]
    if a[7:] != b[:1]:
        fail('authorized name overlap mismatch')
    camel = a + b[1:]
    t1 = expect(data, secs, start + 0x48, '48b97468726573686f6c')[2:]
    t2 = expect(data, secs, start + 0x55, '0fb656084883f264')[-1:]
    threshold = t1 + t2
    snake_va, _ = rip_ref(data, secs, start + 0x6f, '660f7405')
    snake = va_bytes(data, secs, snake_va, 16)
    expect(data, secs, start + 0x77, '660fd7c881f9ffff0000')
    if (short, camel, snake, threshold) != (b'au', b'authorizedUsers', b'authorized_users', b'threshold'):
        fail('unexpected field spellings')
    return {'start': start, 'table': table, 'first_length': first_length,
            'table_targets': targets, 'snake_va': snake_va,
            'authorized': (short, camel, snake), 'threshold': threshold}


def classify_signer(classifier, name):
    if not isinstance(name, bytes):
        raise TypeError('field name must be bytes')
    if name in classifier['authorized']:
        return 0
    if name == classifier['threshold']:
        return 1
    return 2


def tracker_name(data, secs):
    length_insn = expect(data, secs, 0x17172f6, '48837c245019')
    length = length_insn[-1]
    first, _ = rip_ref(data, secs, 0x1717303, 'f30f6f05')
    second, _ = rip_ref(data, secs, 0x1717318, 'f30f6f15')
    part1, part2 = va_bytes(data, secs, first, 16), va_bytes(data, secs, second, 16)
    if second - first != 9 or part1[9:] != part2[:7]:
        fail('tracker comparison overlap mismatch')
    name = part1 + part2[7:]
    if len(name) != length:
        fail('tracker name length mismatch')
    return name, first, second


def classify_tracker(name, needle):
    if not isinstance(name, bytes):
        raise TypeError('field name must be bytes')
    return 0 if len(name) == len(needle) and name[:16] == needle[:16] and name[9:25] == needle[9:25] else 1


def collect_fields(data, secs):
    found = {}
    evidence = []
    for ref, length_site, label in FIELD_REFS:
        target, raw = rip_ref(data, secs, ref, '488d35')
        imm = va_bytes(data, secs, length_site, 5, True)
        if imm[0] != 0xba:
            fail('field length setup mismatch')
        length = struct.unpack_from('<I', imm, 1)[0]
        value = va_bytes(data, secs, target, length)
        try:
            string = value.decode('ascii')
        except UnicodeDecodeError as exc:
            raise ValueError('non-ASCII field name') from exc
        found[label] = value
        evidence.append({'role': label, 'ref_va': hex(ref), 'ref_bytes': raw.hex(),
                         'length_va': hex(length_site), 'length_bytes': imm.hex(),
                         'value_va': hex(target), 'length': length, 'value': string})
    if (found['tracker_field'] != found['tracker_field_exchange'] or
            found['tracker_field'] != found['tracker_field_json'] or
            found['authorized_canonical'] != found['authorized_canonical_json'] or
            found['threshold'] != found['threshold_json']):
        fail('writer copies disagree')
    return found, evidence


def collect_field_diagnostics(data, secs, fields):
    """Resolve selected error-field names and the length-prefixed template heads."""
    records = []
    prefixes = {'missing': b'missing field `', 'duplicate': b'duplicate field `'}
    for role, name_ref, length_site, pattern, template_ref, opcode, label, kind in FIELD_DIAGNOSTICS:
        owner_for(name_ref)
        name_va, name_insn = rip_ref(data, secs, name_ref, '488d05')
        length_insn = expect(data, secs, length_site, pattern)
        length = struct.unpack_from('<I', length_insn, len(length_insn) - 4)[0]
        name = va_bytes(data, secs, name_va, length)
        if name != fields[label]:
            fail('diagnostic field mismatch')
        template_va, template_insn = rip_ref(data, secs, template_ref, opcode)
        prefix = prefixes[kind]
        raw = va_bytes(data, secs, template_va, len(prefix) + 1)
        if raw != bytes([len(prefix)]) + prefix:
            fail('diagnostic template mismatch')
        records.append({'role': role, 'field_ref_va': hex(name_ref), 'field_ref_bytes': name_insn.hex(),
                        'field_va': hex(name_va), 'field': name.decode('ascii'),
                        'length_va': hex(length_site), 'length_bytes': length_insn.hex(), 'length': length,
                        'template_ref_va': hex(template_ref), 'template_ref_bytes': template_insn.hex(),
                        'template_va': hex(template_va), 'template_prefix_hex': raw.hex(),
                        'template_prefix': raw[1:].decode('ascii')})
    return records


def native_map_key_label(data, secs):
    """Recover the type-name slice passed to the selected map key decoder."""
    reference, raw = rip_ref(data, secs, 0x263c173, '488d15')
    length_raw = expect(data, secs, 0x263c161, 'b904000000')
    length = struct.unpack_from('<I', length_raw, 1)[0]
    value = va_bytes(data, secs, reference, length)
    if value != b'User':
        fail('native-map key label mismatch')
    return {'reference_va': hex(0x263c173), 'reference_bytes': raw.hex(),
            'value_va': hex(reference), 'length_va': hex(0x263c161),
            'length_bytes': length_raw.hex(), 'length': length, 'label': value.decode('ascii')}


def marker_parameters(data, secs):
    # Only the small container/string cases used by the fixtures are modeled.
    map_or = expect(data, secs, 0x25acc58, '4080e60f4080ce80')
    array_or = expect(data, secs, 0x25acc63, '4080e60f4080ce90')
    str_or = expect(data, secs, 0x25acc49, '4080e61f4080cea0')
    short_cut = expect(data, secs, 0x25aa806, '83fa20731440b5a0')[2]
    str8 = expect(data, secs, 0x25aa81f, '81fa00010000731440b5d9')[-1]
    compact = expect(data, secs, 0x25ac0e0, '4881fa00010000')
    wide = expect(data, secs, 0x25ac12f, '4881fa00000100')
    expect(data, secs, 0x25ac100, '84d2')
    shift = expect(data, secs, 0x25ac15f, '48c1e820')[-1]
    markers = [expect(data, secs, site, opcode)[-1] for site, opcode in (
        (0x25ac228, 'c60430cc'), (0x25ac5a7, 'c60401cd'),
        (0x25ac7d7, 'c60401ce'), (0x25aca08, 'c60401cf'))]
    expect(data, secs, 0x25ac639, '66c1c608488b4f0866893401')
    expect(data, secs, 0x25ac869, '0fce488b470842893408')
    expect(data, secs, 0x25aca9c, '480fce488b47084a893408')
    key_width = struct.unpack_from('<I', expect(data, secs, 0x1e0d190, 'b914000000'), 1)[0]
    tracker_arity = expect(data, secs, 0x17179c9, '83fd01')[-1]
    row_arity = expect(data, secs, 0x170fdf9, '83fd02')[-1]
    signer_arity = expect(data, secs, 0x1832e1c, '83fd02')[-1]
    for site, arity in ((0x26ce23a, tracker_arity), (0x26ce266, tracker_arity),
                        (0x27b3aff, tracker_arity), (0x27b3b2e, tracker_arity),
                        (0x26cdbee, signer_arity), (0x26cdc20, signer_arity),
                        (0x1dde135, row_arity)):
        raw = va_bytes(data, secs, site, 5, True)
        if raw[0] != 0xba or struct.unpack_from('<I', raw, 1)[0] != arity:
            fail('writer and reader arities differ')
    return {'map_base': map_or[-1], 'array_base': array_or[-1], 'str_base': str_or[-1],
            'container_mask': map_or[3], 'short_str_cutoff': short_cut, 'str8': str8,
            'uint8_limit': struct.unpack_from('<I', compact, 3)[0],
            'uint16_limit': struct.unpack_from('<I', wide, 3)[0],
            'uint32_limit': 1 << shift, 'uint_markers': markers, 'key_width': key_width,
            'tracker_arity': tracker_arity, 'row_arity': row_arity, 'signer_arity': signer_arity}


def encode_uint(value, p):
    if type(value) is not int or value < 0 or value >= 1 << 64:
        raise ValueError('unsigned input is outside 64 bits')
    if value < (p['uint8_limit'] >> 1):
        return bytes([value])
    if value < p['uint8_limit']:
        return bytes([p['uint_markers'][0], value])
    if value < p['uint16_limit']:
        return bytes([p['uint_markers'][1]]) + value.to_bytes(2, 'big')
    if value < p['uint32_limit']:
        return bytes([p['uint_markers'][2]]) + value.to_bytes(4, 'big')
    return bytes([p['uint_markers'][3]]) + value.to_bytes(8, 'big')


def encode_small_str(value, p):
    if not isinstance(value, bytes) or len(value) >= p['uint8_limit']:
        raise ValueError('modeled string is outside the short/str8 domain')
    if len(value) < p['short_str_cutoff']:
        return bytes([p['str_base'] | len(value)]) + value
    return bytes([p['str8'], len(value)]) + value


def container_header(kind, count, p):
    if type(count) is not int or not 0 <= count <= p['container_mask']:
        raise ValueError('modeled container is outside the fix-container domain')
    return bytes([p[kind + '_base'] | count])


def snapshot_example(named, rows, fields, p):
    """Conditional static model for successful writes, mode bytes b=0/1,c=0.

    `rows` is an already ordered, unique collection; no sorting is simulated.
    Each key and each authorized member is exactly 20 bytes.
    """
    if type(named) is not bool:
        raise ValueError('named mode must be a boolean')
    kind = 'map' if named else 'array'
    out = bytearray(container_header(kind, p['tracker_arity'], p))
    if named:
        out += encode_small_str(fields['tracker_field'], p)
    out += container_header('array', len(rows), p)
    for key, authorized, threshold in rows:
        if not isinstance(key, bytes) or len(key) != p['key_width']:
            raise ValueError('key must have 20 bytes')
        out += container_header('array', p['row_arity'], p)
        out += encode_small_str(b'0x' + key.hex().encode('ascii'), p)
        out += container_header(kind, p['signer_arity'], p)
        if named:
            out += encode_small_str(fields['authorized_canonical'], p)
        out += container_header('array', len(authorized), p)
        for member in authorized:
            if not isinstance(member, bytes) or len(member) != p['key_width']:
                raise ValueError('authorized address must have 20 bytes')
            out += encode_small_str(b'0x' + member.hex().encode('ascii'), p)
        if named:
            out += encode_small_str(fields['threshold'], p)
        out += encode_uint(threshold, p)
    return bytes(out)


def assess_map(keys, classifier, names):
    """Only the field-presence decision after successful child/unknown reads."""
    seen = set()
    for key in keys:
        tag = classify_signer(classifier, key)
        if tag in (0, 1):
            if tag in seen:
                return 'duplicate ' + names[tag].decode('ascii')
            seen.add(tag)
    for tag in (0, 1):
        if tag not in seen:
            return 'missing ' + names[tag].decode('ascii')
    return 'fields present'


def duplicate_diagnostic(data, secs, length_site, tail_site, head_site):
    length = struct.unpack_from('<I', expect(data, secs, length_site, 'bf0d000000'), 1)[0]
    tail = va_bytes(data, secs, tail_site, 10, True)
    head = va_bytes(data, secs, head_site, 10, True)
    if tail[:2] != b'\x48\xb9' or head[:2] != b'\x48\xb9' or head[7:] != tail[2:5]:
        fail('duplicate diagnostic immediate overlap mismatch')
    text = head[2:] + tail[5:]
    if len(text) != length or text != b'duplicate key':
        fail('duplicate diagnostic mismatch')
    return text.decode('ascii')


def extent_records(data, secs, header):
    _, fdes = eh_frame_records(data, secs)
    index = {row['start']: row for row in header}
    by_start = {}
    for record in fdes:
        by_start.setdefault(record['start'], []).append(record)
    result = []
    for start, end, role, expected_hash in FUNCTIONS:
        matches = by_start.get(start, [])
        if len(matches) != 1 or matches[0]['end'] != end:
            fail(f'FDE mismatch at {start:#x}')
        entry = index.get(start)
        if entry is None or entry['fde'] != matches[0]['fde']:
            fail(f'unwind header mismatch at {start:#x}')
        actual = matches[0]
        actual_start, actual_end = actual['start'], actual['end']
        off = va_offset(secs, actual_start, actual_end - actual_start, True)
        digest = hashlib.sha256(data[off:off + actual_end - actual_start]).hexdigest()
        if digest != expected_hash:
            fail(f'selected FDE body mismatch at {start:#x}')
        result.append({'role': role, 'start_va': hex(actual_start), 'end_va_exclusive': hex(actual_end),
                       'file_offset': hex(off), 'byte_count': actual_end - actual_start,
                       'fde_va': hex(actual['fde']), 'cie_va': hex(actual['cie']),
                       'unwind_index': entry['index'], 'body_sha256': digest})
    return result


def owner_for(site):
    owners = [(a, b, role) for a, b, role, _ in FUNCTIONS if a <= site < b]
    if len(owners) != 1:
        fail(f'selected site has no unique owner: {site:#x}')
    return owners[0]


def analyze(data, authenticate=True):
    if authenticate:
        check_hash(data)
    secs, header = unwind_index(data)
    functions = extent_records(data, secs, header)
    windows = []
    for va, pattern, role in WINDOWS:
        raw = expect(data, secs, va, pattern)
        windows.append({'role': role, 'va': hex(va), 'file_offset': hex(va_offset(secs, va, len(raw), True)),
                        'bytes': raw.hex()})
    calls = []
    for site, wanted, role in CALLS:
        owner_for(site)
        target, raw = direct_call(data, secs, site)
        if target != wanted:
            fail(f'call target mismatch at {site:#x}')
        calls.append({'site_va': hex(site), 'owner_va': hex(owner_for(site)[0]), 'target_va': hex(target),
                      'bytes': raw.hex(), 'role': role})
    branches = []
    for site, wanted, meaning in BRANCHES:
        owner_for(site)
        target, raw, condition = conditional_branch(data, secs, site)
        if target != wanted or not owner_for(site)[0] <= target < owner_for(site)[1]:
            fail(f'branch target mismatch at {site:#x}')
        branches.append({'site_va': hex(site), 'owner_va': hex(owner_for(site)[0]),
                         'target_va': hex(target), 'fallthrough_va': hex(site + len(raw)),
                         'condition_code': condition, 'bytes': raw.hex(), 'taken_interpretation': meaning})
    fields, field_records = collect_fields(data, secs)
    field_diagnostics = collect_field_diagnostics(data, secs, fields)
    key_label = native_map_key_label(data, secs)
    name, first, second = tracker_name(data, secs)
    if name != fields['tracker_field']:
        fail('tracker reader and writer names disagree')
    json_first, _ = rip_ref(data, secs, 0x1bee9fd, 'f30f6f05')
    json_second, _ = rip_ref(data, secs, 0x1beea12, 'f30f6f15')
    if (json_first, json_second) != (first, second):
        fail('tracker JSON and compact names disagree')
    compact = field_classifier(data, secs, 0x26bfe00)
    json_classifier = field_classifier(data, secs, 0x26bfea0)
    if compact['authorized'] != json_classifier['authorized'] or compact['threshold'] != json_classifier['threshold']:
        fail('field classifier copies disagree')
    if fields['authorized_canonical'] != compact['authorized'][1] or fields['threshold'] != compact['threshold']:
        fail('reader and writer names disagree')
    for site in (0x1e0d198, 0x1e15aeb, 0x1e15b32):
        slot, _ = rip_ref(data, secs, site, 'ff15')
        if slot != 0x5773120:
            fail('formatter slot mismatch')
    _, _, target = relocation(data, secs, 0x5773120)
    if target != 0x29ed380:
        fail('formatter relocation mismatch')
    compare_slot, _ = rip_ref(data, secs, 0x2860608, 'ff15')
    compare_import = imported_symbol(data, secs, compare_slot)
    if compare_import['symbol_name'] != 'memcmp':
        fail('key comparator import mismatch')
    p = marker_parameters(data, secs)
    compare_width = struct.unpack_from('<I', expect(data, secs, 0x2860600, 'ba140000004c89e7'), 1)[0]
    equal_tag = struct.unpack_from('<I', expect(data, secs, 0x286068c, 'b801000000'), 1)[0]
    if compare_width != p['key_width'] or equal_tag != 1:
        fail('duplicate-key comparison contract mismatch')
    diagnostics = [duplicate_diagnostic(data, secs, *sites) for sites in (
        (0x266f446, 0x266f456, 0x266f464),
        (0x263c506, 0x263c51a, 0x263c528),
        (0x2620285, 0x2620299, 0x26202a7))]
    if len(set(diagnostics)) != 1:
        fail('duplicate diagnostic copies disagree')
    named = (fields['authorized_canonical'], fields['threshold'])
    short, camel, snake = compact['authorized']
    threshold = compact['threshold']
    map_inputs = ((), (short,), (threshold,), (short, threshold),
                  (snake, threshold), (camel, threshold),
                  (b'unknown', camel, threshold), (short, camel, threshold),
                  (snake, short, threshold), (camel, threshold, threshold))
    map_cases = [{'keys': [x.decode('ascii') for x in keys],
                  'outcome': assess_map(keys, compact, named)} for keys in map_inputs]
    values = sorted(set([0, (p['uint8_limit'] >> 1) - 1, p['uint8_limit'] >> 1,
                         p['uint8_limit'] - 1, p['uint8_limit'], p['uint16_limit'] - 1,
                         p['uint16_limit'], p['uint32_limit'] - 1, p['uint32_limit'], (1 << 64) - 1]))
    unsigned_cases = [{'value': n, 'hex': encode_uint(n, p).hex()} for n in values]
    key = bytes(range(p['key_width']))
    member = bytes(range(p['key_width'], p['key_width'] * 2))
    examples = {'empty_named': snapshot_example(True, [], fields, p).hex(),
                'empty_positional': snapshot_example(False, [], fields, p).hex(),
                'one_named': snapshot_example(True, [(key, [member], 1)], fields, p).hex(),
                'one_positional': snapshot_example(False, [(key, [member], 1)], fields, p).hex()}
    records = {'input': {'artifact': 'artifacts/node/94/hl-node', 'sha256': SHA256,
                         'coordinate_system': 'unrelocated ELF virtual addresses'},
               'functions': functions, 'calls': calls, 'branches': branches, 'windows': windows,
               'field_references': field_records, 'field_diagnostics': field_diagnostics,
               'native_map_key_label': key_label,
               'tracker_classifier': {'length': len(name), 'name': name.decode('ascii'),
                                      'first_chunk_va': hex(first), 'second_chunk_va': hex(second),
                                      'json_first_load_va': hex(0x1bee9fd),
                                      'json_second_load_va': hex(0x1beea12),
                                      'first_chunk_hex': va_bytes(data, secs, first, 16).hex(),
                                      'second_chunk_hex': va_bytes(data, secs, second, 16).hex(),
                                      'first_load_bytes': rip_ref(data, secs, 0x1717303, 'f30f6f05')[1].hex(),
                                      'second_load_bytes': rip_ref(data, secs, 0x1717318, 'f30f6f15')[1].hex()},
               'signer_classifiers': [{'start_va': hex(c['start']), 'table_va': hex(c['table']),
                                       'first_length': c['first_length'],
                                       'table_bytes': va_bytes(data, secs, c['table'], len(c['table_targets']) * 4).hex(),
                                       'targets': [hex(x) for x in c['table_targets']],
                                       'snake_literal_va': hex(c['snake_va']),
                                       'authorized_spellings': [x.decode('ascii') for x in c['authorized']],
                                       'threshold_spelling': c['threshold'].decode('ascii')}
                                      for c in (compact, json_classifier)],
               'hex_formatter_relocation': {'slot_va': hex(0x5773120), 'target_va': hex(target),
                                             'relocation_type': 8, 'symbol_index': 0},
               'duplicate_diagnostics': diagnostics,
               'key_comparator_import': compare_import,
               'key_comparison': {'width': compare_width, 'equal_result_tag': equal_tag,
                                  'comparison_call_va': hex(0x2860608),
                                  'equal_branch_va': hex(0x286062f),
                                  'result_store_va': hex(0x28607e6)},
               'marker_parameters': p,
               'limitations': ['selected instruction patterns, not a complete disassembly or CFG',
                               'FDEs are unwind ranges, not proof of all source function boundaries',
                               'fixtures are static models conditional on successful helpers and mode bytes',
                               'no target execution, database, cross-release or complete grammar claim']}
    fixtures = {'kind': 'synthetic static models, not captured output',
                'conditions': 'successful helpers; serializer mode b is 0 or 1, mode c is 0; supplied rows already ordered and unique',
                'synthetic_key': key.hex(), 'synthetic_authorized_member': member.hex(),
                'synthetic_threshold': 1, 'messagepack_hex': examples,
                'unsigned_boundary_cases': unsigned_cases, 'field_presence_cases': map_cases,
                'sequence_counts_after_successful_children': {
                    role: [{'count': count, 'outcome': ('missing first' if count == 0 else
                                                        'missing second' if count < arity else
                                                        'join' if count == arity else 'extra element')}
                           for count in range(arity + 2)]
                    for role, arity in (('tracker', p['tracker_arity']), ('row', p['row_arity']),
                                        ('signers', p['signer_arity']))}}
    return records, fixtures


def write_tsv(path, fieldnames, rows):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames, delimiter='\t', lineterminator='\n', extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def generate(out):
    with TARGET.open('rb') as binary, mmap.mmap(binary.fileno(), 0, access=mmap.ACCESS_READ) as data:
        records, fixtures = analyze(data)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(records, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    (out / 'fixtures.json').write_text(json.dumps(fixtures, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    write_tsv(out / 'functions.tsv', ['role', 'start_va', 'end_va_exclusive', 'file_offset', 'byte_count',
                                       'fde_va', 'cie_va', 'unwind_index', 'body_sha256'], records['functions'])
    write_tsv(out / 'calls.tsv', ['site_va', 'owner_va', 'target_va', 'bytes', 'role'], records['calls'])
    write_tsv(out / 'branches.tsv', ['site_va', 'owner_va', 'target_va', 'fallthrough_va', 'condition_code',
                                      'bytes', 'taken_interpretation'], records['branches'])
    rows = []
    c = records['signer_classifiers'][0]
    for length, dest in enumerate(c['targets'], c['first_length']):
        rows.append({'length': length, 'target_va': dest,
                     'recognized_names': ','.join(n for n in c['authorized_spellings'] + [c['threshold_spelling']]
                                                  if len(n) == length)})
    write_tsv(out / 'field-lengths.tsv', ['length', 'target_va', 'recognized_names'], rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(args.out)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        print(f'multisig_snapshot94: {exc}', file=sys.stderr)
        raise SystemExit(1)
