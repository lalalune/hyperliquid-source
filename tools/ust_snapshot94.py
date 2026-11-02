"""Extract a bounded locus.ust writer and candidate readers from node #94.

Only static file bytes are read.  The small models at the end are conditional
on the recorded instruction paths and on the separately studied common codecs.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are selected FDE starts and expected authenticated body hashes, not a
# function census.  The end and record addresses are read from .eh_frame.
FUNCTIONS = (
    ('map adapter', 0x20296f0, 0x20297db, 'b7bec97077dfc167d033f311f393cbe23205c27062a1477e49a6911641b058be'),
    ('entry collector', 0x256dd10, 0x256df46, '3b864bb9d501bfdd141a20ec6a67a71c63c151a1e18592328de88b68a54a8177'),
    ('key sort', 0x1fe87b0, 0x1fe8fc5, '3db1e71ff37a7adddd3d21261efa7deb3953707af88e89cc63221f48a65cd067'),
    ('sequence writer', 0x1e4a430, 0x1e4a6bb, '5f7e8938b4805d9bd674649fa907a490f507f99e5843c0b13b1b6991baebe5c9'),
    ('entry pair writer', 0x1dd8490, 0x1dd8a2c, '4bf36f4cb0f51edf42ab3bbd7160c74132fc55339943f41694b935e43551dda2'),
    ('key text adapter', 0x1e0d0a0, 0x1e0d205, 'a202a759a0a5e43cfc7b1a4a6733a47b15471f87c5f2da3f3b2822d700289361'),
    ('value writer', 0x275ce60, 0x275d36c, '6d08b6b7e098d6e9f4e1d586579e56ff3e997c5b5c872eeec6d66664db764646'),
    ('a field adapter', 0x27b18c0, 0x27b191c, '8c92310f6bcf583a88dadc6a1f6227d3cebba10539ba31e545f625124db17909'),
    ('a variant writer', 0x28e7990, 0x28e7a0f, 'e6c16007d9cdea839c876572c8ddc698ad27e640f5deef1dff2ca48228a0775c'),
    ('t string adapter', 0x1dfca40, 0x1dfcb91, '53404c658c477544f6921af8516b6d915760d0a5231b3e23a60fc690e656da20'),
    ('compact collection reader', 0x19a14e0, 0x19a1d5d, 'b317e28e827671bec7bf31f4a2893e08de58c506045be93d32ff04eb2293e5da'),
    ('compact map-entry loop', 0x26351d0, 0x263572e, '62db2ef7d84e22acd8c2953572b3a8efa6f32c469a90177afce4b08db9ae4386'),
    ('compact pair-sequence loop', 0x2661ac0, 0x2661e1a, '6555d029dfabf51c2175bc3e7f502d55d749b310b3ee8990a4fa6f9b036668a5'),
    ('compact pair reader', 0x18e0050, 0x18e1126, 'c1ef593968ab95c90a49b89d3b9b712e09d4b8b08ef0a97a370f90b46a517804'),
    ('compact user-key adapter', 0x1699080, 0x1699478, '95e1f8862d3ce2abd74e535737e04764dac6b9c1949953325bcee882aa71cd07'),
    ('compact value reader', 0x1956bf0, 0x1958628, '9c55be8d59a640f61d771c1d84cd2057768766ef957546dee667955141d7bd4c'),
    ('compact field classifier', 0x26bf820, 0x26bf8b2, '509a01974cc65512a2d2a6563e77eaa572adf38861614c99ae8f4dac2ea1dd0a'),
    ('map insertion helper', 0x27c8cf0, 0x27c8f50, 'afb9514fc24f0198d80bdcbbc3cc726badaddefb4eb475115e664a472567fdcd'),
    ('JSON-shaped entry loop', 0x259d4e0, 0x259de6e, 'e87c345880a3ec5fb51ad1cd952f9ffd2d0f71e35cedb1eae54469a6e1cf855f'),
    ('JSON-shaped value adapter', 0x1b710d0, 0x1b71183, 'b379c0217fb9eec5ef7ec37008153d79e4cd7cec4b844ff93759d7a873469ee4'),
    ('JSON-shaped value reader', 0x1d1c2f0, 0x1d1d2a3, '8297be6f042bd24887f37117b5b1fe66f98c2f2f2912504b4024f01437895907'),
    ('JSON-shaped field classifier', 0x26bf8c0, 0x26bf952, 'ab7e46f08c70dd4e08e7080486a8dc891701015828c2bc58c3c0ba8d5a842886'),
)

# Exact windows establish instruction shapes and dataflow; branch displacements
# and calls are additionally decoded below.  The two caller windows are
# contextual call-site evidence, not an analysis of their enclosing function.
PINS = (
    ('context locus header', 0x275abf1, '41807f0b00744c488d356746c9fdba050000004c89ffe8e4fbe4ff4883f802752641807f0b00742b4889e74c89feba10000000e857e3e4ff488b04244883f802742b488b5424084983c4fc4c89e1e9550b00004889e74c89feba10000000e87cefe4ff488b04244883f80275d5'),
    ('context ust', 0x275ad72, '41807f0b01751e488d35fd43c9fdba030000004c89ffe863fae4ff4883f8020f85a1feffff498db6400700004889e74c89fae847e98cff'),
    ('adapter iterator and calls', 0x20296ff, '488b06488b4e08488d4c0801660f6f00660fd7d0f7d2668954245048894424384883c010488944244048894c2448488b46184889442458488d7c2420488d742438e8cb4554004c8b7c2428488b7424304889e24c89ffe856f0fbfff30f6f442420660f7f0424488b44243048894424104889e24889df4c89f6e8b30ce2ff'),
    ('collector count and allocation', 0x256dd1e, '488b46204885c00f848a000000440fb766184c8b2e664585e4752e488b4e080f1f00660f6f0166440fd7e04981c580faffff4883c1104181fcffff000074e341f7d448894e084c892e418d6c24ff4421e566896e184c8d70ff4c8976204883f805bb04000000480f43d84989df49c1e704'),
    ('collector first pair', 0x256dded, 'f3410fbccc48f7d9486bc9584a8d14294883c2a8498d4c0dc048891048894808'),
    ('collector next pairs', 0x256de45, '8d4dfff30fbcd521e948f7da486bd25849ffce4a8d342a4883c6a84c01ea4883c2c04c89ff48c1e70448893438488954380849ffc74c897c2410'),
    ('small sort bounds', 0x1fe87cc, '4883fe1548897c24080f83f90000004883fd020f82a6060000'),
    ('small sort comparison', 0x1fe8831, '4a8b1c2b4a8b7c2810ba140000004889deff15405c780385c079c6'),
    ('larger sort threshold and allocation', 0x1fe88d4, '4989ef49c1e7044c89ffff15f45678034885c00f84100600004989c64881fdd007000077314889df4889ee4c89f2e879b500003c010f856e050000'),
    ('large sort helper', 0x1fe8987, '488d7c2468488db42480000000e8372d5300'),
    ('sequence setup and header', 0x1e4a449, '4c8b6a084c8b72104c89f048c1e8200f94c1807e0c00410f95c44120cc741831ed4d85f6400f95c54c89eb490f44dec1e5044c01edeb0c4c89ed4885c00f85f6000000488d7c24404c89fe4489f2e834f77500488b4424404883f8020f85b3000000'),
    ('sequence pair loop', 0x1e4a5e3, '49c1e6044d01f54c39ed744b4c8d7424404c8d7c241048b80000000000000080488d5804660f1f840000000000488b5500488b4d084c89f74c89fee86ddef8ff488b4424404839d80f85dffeffff4883c5104c39ed75d6'),
    ('pair mode and header', 0x1dd84b4, '488b364889f048f7d8711a48895c24284d8b7c242841807f0c02751c4c896c244831c0eb4241807c241c020f859f00000031c0e9ba0000004889d3488d7c24104c89feba02000000e8cf167d00'),
    ('pair key call and result', 0x1dd854b, '488d7c2410488d742478e8464b0300498d5e0448395c24100f85c2000000'),
    ('pair value call and result', 0x1dd8813, '488d7c2410488b7424484c89eae83b46980048395c2410488b7c24280f85e6000000'),
    ('key formatter arguments', 0x1e0d174, '0f57c00f1144243a0f294424300f29442420488d7c2420be2a000000b9140000004531c0ff15825f96034c89f74889c6e847d67900'),
    ('shared signed small-integer path', 0x25aaf50, '4883fadf763a488b1e4c8b33488b73104939f60f84e10200004939f60f84cf030000488b4b0888143148ff4310c64008e088500948c70002000000'),
    ('shared unsigned small-integer path', 0x25ac0e0, '4881fa0001000073464c8b36498b76104939360f84bd000000498b06498b761084d20f88130100004839f00f84d9010000498b460888143049ff4610c643080088530948c70302000000'),
    ('value loads and field count', 0x275ce79, '488b1e4c8b6e084c8b6610488b6e18bf3bf90a00ff15fd19010385c00f84c404000031c94d85ed0f95c14883fb0183d9ff4983fc0183d9ff48896c24484883fd0183d9ff418b6e3031e8418b56348954243c09d0418b763831d28974243809f00f95c201ca498b462048894424504883f80183daff498b4628410fb64e3d894c243401ca48894424404883f80183daff410fb6463c8844240f3c0183daff'),
    ('time default comparison', 0x275d0ae, '49bc000000000000008031c50b6c243c0b6c2438488b5c2450745a41807f0b01751e488d35421fc9fdba010000004c89ffe80cd7e4ff4883f8020f859f010000'),
    ('f branch and marker', 0x275d16c, '807c243400745b41807f0b00741e488d35ee1fc9fdba010000004c89ffe862d6e4ff4883f8020f85eb000000498b1f488b2b4c8b6b104c39ed0f842a0100008b4424340cc20fb6f8e867fae4ff4c39ed0f8475010000488b4b084288042948ff4310'),
    ('a branch', 0x275d218, '807c240f0074204983c63c488d7c24184c89fe4c89f2e88d460500498d4424044839442418757e4983c404'),
    ('a field adapter', 0x27b18c0, '41574156534989d64889f3807e0b007420488d3598d8c3fdba010000004989ff4889dfe8088fdfff4c89ff4883f80275104c89f64889da5b415e415fe98f60130048b9000000000000008048890f48894708488957105b415e415fc3'),
    ('variant table dispatch', 0x28e7990, '415653504889d04889fb49be04000000000000800fb60e488d1572e0b0fd48630c8a4801d1ffe1'),
    ('time format sequence', 0x1dfca8b, '488b024c8b38488d7424204c89ffff15c12a970384c00f8591000000488b7c2420488b442428be54000000ff502084c0757b4983c704488d7424204c89ffff15992a970384c075654c8b7c24084c8b642410488b542418'),
    ('time string result', 0x1dfcae2, '4c89f74c89e6e803dd7a0048b900000000000000804883f802750e'),
    ('context reader dispatch', 0x173a49a, '0fb68424400300003c090f85900c00000fb6842441030000488d0d8716b7fe486304814801c8ffe0'),
    ('context reader tag four', 0x173a6fc, '4883bc2480010000000f856c140000410fb65624488dbc24b00900004c89f6e8c06d2600'),
    ('collection calls entry loop', 0x19a18a1, '4989ff4989f64889b42490000000899c2498000000488d7c2460488db42490000000e80839c900488b4424600f104424680f298424a00000000f104424780f298424b00000004885c00f8403020000'),
    ('collection calls pair-sequence loop', 0x19a1a4e, '4989ff4989f64889b42490000000899c2498000000488d7c2460488db42490000000e84b00cc00'),
    ('pair-sequence loop reads next pair', 0x2661b30, '4183fdff0f840d02000045896e084c89e74c89fe31d2e805e527ff0fb684249d0000003c020f840d020000'),
    ('pair-sequence insert and duplicate error', 0x2661cac, '4c89e7488d742410488d9424a00000004889d9e82c70160041ffcd80bc2485000000020f845bfeffffbf0d000000ff15f8c210034885c00f840801000048b963617465206b65794889480548b96475706c69636174488908'),
    ('pair reader empty and key', 0x18e05d0, '48897c246885ed0f841c0600000f57c00f29842430010000c78424400100000000000048c784243002000000000000488d842430010000488984243802000048c784244002000014000000488dbc24e0000000488d9424300200004889b42448010000b901000000e873ef0200'),
    ('pair reader second value', 0x18e076e, '83fd010f84070500000f298424b0020000448854240e44884c240f488dbc24e00000004c89c631d2e8556407000fb684241d0100003c020f8598000000'),
    ('pair reader length check', 0x18e0ad4, '83fd020f859c000000'),
    ('pair reader extra-element result', 0x18e0b79, 'c644247004c744247402000000b002'),
    ('pair reader zero-length diagnostic', 0x18e0bf9, '488d0d8857da03488d7c2410488d54240d31f6e983000000'),
    ('pair reader one-length diagnostic', 0x18e0c7e, '488d0d0357da03488d7c2410488d54240dbe01000000e8d731e2ff'),
    ('entry loop and user key', 0x2635250, '85db0f8448010000ffcb488b8424a8000000895808b904000000488d7c2438488bb424a0000000488d15a24dbdfde8fd3d06ff807c2438090fb64424448844240f0f854a030000'),
    ('entry value and error test', 0x26352f6, '488d7c2438488bb424a000000031d2e8e61832ff0fb64424753c020f840c030000'),
    ('user-key adapter twenty-byte buffer', 0x1699088, '4889fb4883f90a752148b85f457874537472754833020fb74a084881f1637400004809c10f840c0100000f57c00f29442420c74424300000000048c744244000000000488d442420488944244848c744245014000000488d7c2460488d542440b901000000e8be642700'),
    ('user-key decoder result tag', 0x16990f2, '0fb64424603c0975448b4c24208b5424'),
    ('compact insert and duplicate error', 0x26354ef, '488d7c2438488db424b0000000488d542424488d8c24a0010000e8e2371900807c2475020f8437fdffffbf0d000000ff15b48a13034885c00f84d501000048b963617465206b65794889480548b96475706c69636174488908'),
    ('insertion key equality', 0x27c8d68, 'f3450fbcda4901c34921f349f7db4d6bdb58f3410f6f1c24f3420f6f6419a8660f74e366410f6e5c241066420f6e6c19b8660f74eb660fdbec660fd7ed81fdffff00007454'),
    ('insertion existing value exchange', 0x27c8e01, '4c01d90f1041c00f1049d00f1051e00f1059f00f115b300f1153200f114b100f1103410f1007410f104f10410f105720410f105f300f1141c00f1149d00f1151e00f1159f0e9bd000000'),
    ('insertion absent sentinel', 0x27c8ef0, '0f115c01d80f115401c80f114c01b80f114401a8c6433d02'),
    ('compact field classifier call', 0x1957ec8, '488b742410488b542418488d7c2470e84479d6004989eee92d020000'),
    ('compact field dispatch', 0x1958111, '0fb64424703c090f85a60300000fb6442471488d0d8e4ba0fe486304814801c8ffe0'),
    ('compact missing numeric defaults', 0x1957a9f, '31c0f68424e000000001488b8c24b0000000480f44c848898c24b0000000f68424e800000001488b8c24a8000000480f44c848898c24a8000000f68424f000000001488b8c2490000000480f44c848898c2490000000f68424f800000001488b8c24a0000000480f44c848898c24a0000000f6842408010000014c8bbc24300100004c0f44f84180e401f684240001000001'),
    ('compact output layout', 0x1957110, '488b8424b0000000488903488b8424a800000048894308488b84249000000048894310488b8424a0000000488943184c897b204c896b28488b842410010000488943308b84241801000089433888533c4488633d'),
    ('JSON field classifier call', 0x1d1c4f6, '488b5424284c89ffe8bd339a00807c2430010f843f0900000fb6442431488d0d42ab69fe486304814801c8ffe0'),
    ('JSON context entry loop', 0x1bf0699, '4883fe3a0f850f2e00004885c00f840933000049894628488dbc24e00200004c89f6e820ce9a00488b9424e0'),
    ('JSON entry value adapter', 0x259d74c, '488dbc24b80000004c89e6e874395dff0fb68424f50000003c020f840b020000'),
    ('JSON adapter value call', 0x1b7114b, '4983f83a751a4885c07420488946284889dfe88eb11a004889d84883c420'),
    ('JSON insert and duplicate error', 0x259d861, '488d7c2410488db42440010000488d942488010000488d8c24f0010000e86db42200807c244d020f8492feffffbf0d000000ff153f071d034885c00f842f05000048b963617465206b65794889480548b96475706c69636174488908'),
    ('JSON map defaults', 0x1d1cc8c, '4489ed4531e4f644247001488b442448490f44c44889442448f6442478014c8b7c24504d0f44fcf6842480000000014c8b6c24584d0f44ec8b44244485c0751fbf3bf90a00ff15b91ba50385c00f844005000048c78424a8000000000000004c896c2458894424444c897c2450f6842488000000014c8bbc24c00000004d0f44fc8064240f01f684249000000001488b442468490f44c448894424684080fd05400fb6ed410f44ecf684249800000001488b442410490f44c44889442410'),
)

# Roles are analyst labels; every target is decoded and checked against the
# bytes, including shared helpers, whose internals are not selected functions.
CALLS = (
    ('context locus name', 0x275ac07, 0x25aa7f0),
    ('context locus map header', 0x275ac24, 0x25a8f80),
    ('context locus array header', 0x275ac4f, 0x25a9bd0),
    ('context to adapter', 0x275ada4, 0x20296f0),
    ('collect pairs', 0x2029740, 0x256dd10),
    ('sort pairs', 0x2029755, 0x1fe87b0),
    ('medium sort helper', 0x1fe8902, 0x1ff3e80),
    ('large sort helper', 0x1fe8994, 0x251b6d0),
    ('write sequence', 0x2029778, 0x1e4a430),
    ('sequence header', 0x1e4a497, 0x25a9bd0),
    ('first pair', 0x1e4a4ef, 0x1dd8490),
    ('subsequent pair', 0x1e4a61e, 0x1dd8490),
    ('pair header', 0x1dd84fc, 0x25a9bd0),
    ('pair key', 0x1dd8555, 0x1e0d0a0),
    ('pair value', 0x1dd8820, 0x275ce60),
    ('key string', 0x1e0d1a4, 0x25aa7f0),
    ('value named header', 0x275cf26, 0x25a8f80),
    ('value positional header', 0x275cf62, 0x25a9bd0),
    ('time value', 0x275d10e, 0x1dfca40),
    ('boolean marker', 0x275d1b4, 0x25acc20),
    ('a adapter', 0x275d22e, 0x27b18c0),
    ('a variant tail', 0x27b18fc, 0x28e7990),
    ('time string', 0x1dfcae8, 0x25aa7f0),
    ('context tag four to collection', 0x173a71b, 0x19a14e0),
    ('collection to entry loop', 0x19a18c3, 0x26351d0),
    ('collection to pair-sequence loop', 0x19a1a70, 0x2661ac0),
    ('pair-sequence to pair reader', 0x2661b46, 0x18e0050),
    ('pair-sequence insert entry', 0x2661cbf, 0x27c8cf0),
    ('pair reader key decoder', 0x18e0638, 0x190f5b0),
    ('pair reader value decoder', 0x18e0796, 0x1956bf0),
    ('pair reader missing item diagnostic', 0x18e0c94, 0x1703e70),
    ('entry key reader', 0x263527e, 0x1699080),
    ('user-key generic decoder', 0x16990ed, 0x190f5b0),
    ('entry value reader', 0x2635305, 0x1956bf0),
    ('compact insert entry', 0x2635509, 0x27c8cf0),
    ('compact field classifier', 0x1957ed7, 0x26bf820),
    ('compact unknown value helper', 0x19581cc, 0x19682d0),
    ('JSON context to entry loop', 0x1bf06bb, 0x259d4e0),
    ('JSON entry to adapter', 0x259d757, 0x1b710d0),
    ('JSON adapter to value reader', 0x1b7115d, 0x1d1c2f0),
    ('JSON insert entry', 0x259d87e, 0x27c8cf0),
    ('JSON field classifier', 0x1d1c4fe, 0x26bf8c0),
    ('JSON unknown value helper', 0x1d1c959, 0x1b2dd60),
)

# The guard is the conditional jump immediately after the corresponding test.
# Name and value call sites are decoded from the value FDE; the a name is in
# its small tail adapter.  Offsets are checked against load instructions below.
FIELD_SPECS = (
    ('ln', 0x275ce79, '488b1e', False, 'u64 nonzero', 0x275cf75, 0x275cf7e, 0x275cfa7, 0x25ac0d0),
    ('R',  0x275ce7c, '4c8b6e', True, 'u64 nonzero', 0x275cfbe, 0x275cfc7, 0x275cff0, 0x25ac0d0),
    ('C',  0x275ce80, '4c8b66', True, 'i64 nonzero', 0x275d007, 0x275d010, 0x275d039, 0x25aaf40),
    ('P',  0x275ce84, '488b6e', True, 'i64 nonzero', 0x275d053, 0x275d05c, 0x275d087, 0x25aaf40),
    ('t',  0x275cebd, '418b6e', True, 'three dwords differ from returned default, zero, zero', 0x275d0c7, 0x275d0d0, 0x275d10e, 0x1dfca40),
    ('no', 0x275cede, '498b46', True, 'u64 nonzero', 0x275d126, 0x275d12f, 0x275d158, 0x25ac0d0),
    ('f',  0x275cef2, '410fb64e', True, 'byte nonzero; count adds raw byte', 0x275d171, 0x275d17a, 0x275d1b4, 0x25acc20),
    ('r',  0x275ceee, '498b46', True, 'u64 nonzero', 0x275d1d4, 0x275d1dd, 0x275d208, 0x25ac0d0),
    ('a',  0x275cf09, '410fb646', True, 'byte nonzero', 0x275d21d, 0x27b18d1, 0x275d22e, 0x27b18c0),
)

BRANCHES = (
    ('sort large count', 0x1fe87d5), ('sort count below two', 0x1fe87df),
    ('sort first comparison nonnegative', 0x1fe884a),
    ('larger sort allocation failure', 0x1fe88e7), ('sort count above medium', 0x1fe88f7),
    ('medium sort helper alternate result', 0x1fe8909),
    ('sequence header failure', 0x1e4a4a5), ('sequence empty', 0x1e4a5ed),
    ('pair failure stops sequence', 0x1e4a62b), ('sequence next pair', 0x1e4a638),
    ('pair header failure', 0x1dd850a), ('pair key failure', 0x1dd8563),
    ('pair value failure', 0x1dd882f),
    ('initial default helper failure', 0x275ce95),
    ('named or positional header', 0x275cf1c), ('named header success', 0x275cf34),
    ('positional header failure', 0x275cf70),
    ('ln name failure', 0x275cf96), ('ln value failure', 0x275cfb5),
    ('R name failure', 0x275cfdf), ('R value failure', 0x275cffe),
    ('C name failure', 0x275d028), ('C value failure', 0x275d047),
    ('P name failure', 0x275d074), ('P value failure', 0x275d095),
    ('default helper failure', 0x275d0a8), ('t name failure', 0x275d0e8),
    ('t value failure', 0x275d11d), ('no name failure', 0x275d147),
    ('no value failure', 0x275d166), ('f name failure', 0x275d192),
    ('r name failure', 0x275d1f5), ('r value failure', 0x275d216),
    ('a value failure', 0x275d23d), ('a name failure', 0x27b18ef),
    ('compact new key continues', 0x2635513), ('JSON new key continues', 0x259d888),
    ('insertion existing key matches', 0x27c8dab),
    ('user-key takes ordinary path', 0x169908f), ('user-key decode error', 0x16990f9),
    ('time first format failure', 0x1dfcaa1), ('time separator failure', 0x1dfcabb),
    ('time second format failure', 0x1dfcad1), ('time string output failure', 0x1dfcafb),
    ('pair-sequence exhausted', 0x2661b34), ('pair reader failure', 0x2661b55),
    ('pair-sequence new key continues', 0x2661ccf),
    ('empty pair', 0x18e05d7), ('pair key failure', 0x18e075d),
    ('one-item pair', 0x18e0771), ('pair value success', 0x18e07a5),
    ('pair count not two', 0x18e0ad7),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked_digest(data):
    if sha(data) != DIGEST:
        raise ValueError('node #94 digest mismatch')


def va_offset(secs, address, size):
    if address < 0 or size <= 0:
        raise ValueError('invalid address or size')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] <= address and address + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('unmapped, non-file-backed or ambiguous VA')
    s = matches[0]
    return s['offset'] + address - s['address']


def va_bytes(data, secs, address, size):
    off = va_offset(secs, address, size)
    if off < 0 or size > len(data) - off:
        raise ValueError('file-backed range exceeds the input')
    return data[off:off + size]


def expect(data, secs, address, expected):
    want = bytes.fromhex(expected)
    got = va_bytes(data, secs, address, len(want))
    if got != want:
        raise ValueError(f'instruction bytes changed at {address:#x}')
    return got


def field_displacement(data, secs, site, prefix, has_disp8):
    code = expect(data, secs, site, prefix)
    if not has_disp8:
        return 0
    return va_bytes(data, secs, site + len(code), 1)[0]


def relative_target(data, secs, site):
    insn = va_bytes(data, secs, site, 5)
    if insn[0] not in (0xe8, 0xe9):
        raise ValueError('expected rel32 call or tail jump')
    return site + 5 + struct.unpack_from('<i', insn, 1)[0]


def branch(data, secs, site):
    pair = va_bytes(data, secs, site, 2)
    if 0x70 <= pair[0] <= 0x7f:
        code = pair
        target = site + 2 + struct.unpack('b', pair[1:])[0]
    elif pair[0] == 0x0f and 0x80 <= pair[1] <= 0x8f:
        code = va_bytes(data, secs, site, 6)
        target = site + 6 + struct.unpack_from('<i', code, 2)[0]
    else:
        raise ValueError('expected conditional branch')
    return {'site': hex(site), 'bytes': code.hex(), 'target': hex(target)}


def rip_target(data, secs, site, prefix):
    code = va_bytes(data, secs, site, 7)
    if code[:3] != prefix:
        raise ValueError('unexpected RIP-relative instruction')
    return site + 7 + struct.unpack_from('<i', code, 3)[0]


def read_name(data, secs, site):
    address = rip_target(data, secs, site, b'\x48\x8d\x35')
    length_code = va_bytes(data, secs, site + 7, 5)
    if length_code[0] != 0xba:
        raise ValueError('name length setup changed')
    length = struct.unpack_from('<I', length_code, 1)[0]
    if not 0 < length <= 32:
        raise ValueError('invalid selected field-name length')
    name = va_bytes(data, secs, address, length).decode('ascii')
    return {'name': name, 'data_va': hex(address), 'length': length,
            'lea_va': hex(site), 'bytes': va_bytes(data, secs, address, length).hex()}


def relocations(data, secs, slots):
    by_name = {}
    for s in secs:
        if s['name'] in by_name:
            raise ValueError('duplicate section name')
        by_name[s['name']] = s
    rela, dynsym, dynstr = (by_name[n] for n in ('.rela.dyn', '.dynsym', '.dynstr'))
    if any(x['type'] == 8 for x in (rela, dynsym, dynstr)) or rela['size'] % 24:
        raise ValueError('invalid relocation or symbol section')
    found = {}
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in slots:
            continue
        if slot in found:
            raise ValueError('duplicate selected relocation')
        kind, symbol = info & 0xffffffff, info >> 32
        row = {'slot': hex(slot), 'type': kind, 'addend': hex(addend), 'symbol_index': symbol}
        if symbol:
            if (symbol + 1) * 24 > dynsym['size']:
                raise ValueError('symbol index outside section')
            nameoff = struct.unpack_from('<I', data, dynsym['offset'] + symbol * 24)[0]
            if nameoff >= dynstr['size']:
                raise ValueError('symbol name outside string table')
            start = dynstr['offset'] + nameoff
            end = data.find(b'\0', start, dynstr['offset'] + dynstr['size'])
            if end < 0:
                raise ValueError('unterminated dynamic symbol')
            row['symbol'] = data[start:end].decode('ascii')
        found[slot] = row
    if set(found) != set(slots):
        raise ValueError('missing selected relocation')
    return [found[x] for x in sorted(slots)]


def indirect_slot(data, secs, site):
    code = va_bytes(data, secs, site, 6)
    if code[:2] != b'\xff\x15':
        raise ValueError('expected RIP-relative indirect call')
    return site + 6 + struct.unpack_from('<i', code, 2)[0]


def variant_table(data, secs):
    table = rip_target(data, secs, 0x28e79a7, b'\x48\x8d\x15')
    arms = {0x28e79b7, 0x28e79c0, 0x28e79c9, 0x28e79d2, 0x28e79db}
    # The candidate reader uses the next discriminant as its absent sentinel.
    # Read that immediate from its compared instruction, not a table census.
    absent_guard = expect(data, secs, 0x195839b, '80bc249c00000005')
    count = absent_guard[-1]
    if count != len(arms):
        raise ValueError('variant domain and selected arms disagree')
    rows = []
    for index in range(count):
        entry = va_bytes(data, secs, table + 4 * index, 4)
        target = table + struct.unpack('<i', entry)[0]
        if target not in arms:
            raise ValueError('variant table target outside selected arms')
        text = rip_target(data, secs, target, b'\x48\x8d\x35')
        label = va_bytes(data, secs, text, 1).decode('ascii')
        rows.append({'index': index, 'entry_va': hex(table + 4 * index),
                     'entry_bytes': entry.hex(), 'target': hex(target),
                     'label_va': hex(text), 'label': label})
    if len({x['target'] for x in rows}) != len(arms) or ''.join(x['label'] for x in rows) != 'eidup':
        raise ValueError('variant labels or table changed')
    return rows


def classifier_table(data, secs, start, fields):
    """Decode both fixed-name classifiers' length tests and relative tables."""
    if start == 0x26bf820:
        lea, key1, key2, miss, first_byte = 0x26bf851, 0x26bf82f, 0x26bf836, 0x26bf83d, 9
    elif start == 0x26bf8c0:
        lea, key1, key2, miss, first_byte = 0x26bf8f1, 0x26bf8cf, 0x26bf8d6, 0x26bf8dd, 0
    else:
        raise ValueError('unknown classifier')
    table = rip_target(data, secs, lea, b'\x48\x8d\x15')
    # Both FDEs dispatch a single byte after subtracting 0x43 and comparing
    # the result with 0x31.  These are instruction operands, not string lists.
    bound = expect(data, secs, lea - 8, '83c1bd83f93177ec')
    first = (-struct.unpack('b', bound[2:3])[0]) & 0xff
    count = bound[5] + 1
    rows = []
    for i in range(count):
        raw = va_bytes(data, secs, table + 4 * i, 4)
        target = table + struct.unpack('<i', raw)[0]
        if not start <= target < start + 0x92:
            raise ValueError('classifier table target outside selected FDE')
        code = va_bytes(data, secs, target, 9)
        if code[0] != 0xb1 or code[2:] != bytes((0x88, 0x48, 0x01, 0xc6, 0x00, first_byte, 0xc3)):
            raise ValueError('classifier arm changed')
        rows.append({'byte': first + i, 'entry_va': hex(table + 4 * i),
                     'entry_bytes': raw.hex(), 'target': hex(target), 'tag': code[1]})
    two = []
    for site in (key1, key2):
        code = va_bytes(data, secs, site, 5)
        if code[:3] != b'\x66\x81\x3e':
            raise ValueError('two-byte classifier compare changed')
        key = code[3:5]
        br = branch(data, secs, site + 5)
        target = int(br['target'], 16)
        code = va_bytes(data, secs, target, 9)
        if code[:2] == b'\x31\xc9':
            tag = 0
        elif code[0] == 0xb1:
            tag = code[1]
        else:
            raise ValueError('two-byte classifier target changed')
        if code[2:] != bytes((0x88, 0x48, 0x01, 0xc6, 0x00, first_byte, 0xc3)):
            raise ValueError('two-byte classifier result changed')
        two.append({'key': key.decode('ascii'), 'compare_va': hex(site), 'branch': br, 'tag': tag})
    if va_bytes(data, secs, miss, 2) != b'\xb1\x09':
        raise ValueError('unknown-name tag changed')
    single = {chr(x['byte']): x['tag'] for x in rows if x['tag'] != 9}
    combined = dict(single)
    combined.update({x['key']: x['tag'] for x in two})
    expected = {x['name']['name']: x['ordinal'] for x in fields}
    if combined != expected:
        raise ValueError('writer fields and classifier tags disagree')
    return {'start': hex(start), 'table_va': hex(table), 'first_byte': first,
            'count': count, 'unknown_tag': 9, 'result_kind': first_byte,
            'entries': rows, 'two_byte_keys': two}


def classify(key, table):
    if len(key) == 1:
        index = key[0] - table['first_byte']
        return table['entries'][index]['tag'] if 0 <= index < table['count'] else table['unknown_tag']
    if len(key) == 2:
        for row in table['two_byte_keys']:
            if key == row['key'].encode('ascii'):
                return row['tag']
    return table['unknown_tag']


def pair_length_route(count, required):
    """Sequence-size decision after preceding selected children succeed."""
    if not 0 <= count <= 0xffffffff or required != 2:
        raise ValueError('outside the selected pair-length model')
    if count == 0:
        return 'missing first element'
    if count == 1:
        return 'missing second element after key'
    if count == required:
        return 'pair after key and value'
    return 'extra-element result after key and value'


def reader_dispatch(data, secs, lea_site, guard_sizes, bounds, fields):
    """Read the nine tagged arms and their duplicate-name destinations."""
    table = rip_target(data, secs, lea_site, b'\x48\x8d\x0d')
    rows = []
    for index in range(len(fields) + 1):
        entry = va_bytes(data, secs, table + 4 * index, 4)
        target = table + struct.unpack('<i', entry)[0]
        if not bounds[0] <= target < bounds[1]:
            raise ValueError('reader dispatch target outside selected FDE')
        row = {'tag': index, 'entry_va': hex(table + 4 * index),
               'entry_bytes': entry.hex(), 'target': hex(target)}
        if index < len(fields):
            guard = va_bytes(data, secs, target, guard_sizes[index])
            failure = branch(data, secs, target + len(guard))
            destination = int(failure['target'], 16)
            if not bounds[0] <= destination < bounds[1]:
                raise ValueError('duplicate branch outside selected FDE')
            name_va = rip_target(data, secs, destination, b'\x48\x8d\x05')
            name = fields[index]['name']['name']
            if va_bytes(data, secs, name_va, len(name)) != name.encode('ascii'):
                raise ValueError('duplicate diagnostic name disagrees with writer')
            row.update({'name': name, 'guard_bytes': guard.hex(), 'duplicate_branch': failure,
                        'duplicate_name_va': hex(name_va)})
        else:
            row['name'] = 'unknown'
        rows.append(row)
    return {'table_va': hex(table), 'entries': rows}


def duplicate_key_message(data, secs, tail_site, front_site):
    """Reconstruct two overlapping immediate stores into a 13-byte buffer."""
    tail = va_bytes(data, secs, tail_site, 14)
    front = va_bytes(data, secs, front_site, 13)
    if (tail[:2] != b'\x48\xb9' or tail[10:] != b'\x48\x89\x48\x05' or
            front[:2] != b'\x48\xb9' or front[10:] != b'\x48\x89\x08'):
        raise ValueError('duplicate diagnostic store changed')
    if front[7:10] != tail[2:5]:
        raise ValueError('duplicate diagnostic overlap changed')
    text = bytes(front[2:10] + tail[5:10])
    if text != b'duplicate key':
        raise ValueError('duplicate diagnostic message changed')
    return {'message': text.decode('ascii'), 'length': len(text),
            'tail_store_va': hex(tail_site), 'front_store_va': hex(front_site),
            'tail_bytes': tail.hex(), 'front_bytes': front.hex()}


def presence(row):
    """Presence model for valid bool/variant bytes; it does not run node code."""
    f, a = row.get('f', 0), row.get('a', 0)
    if f not in (0, 1) or a not in range(5):
        raise ValueError('outside selected boolean or variant domain')
    return [name for name, value in (
        ('ln', row.get('ln', 0)), ('R', row.get('R', 0)),
        ('C', row.get('C', 0)), ('P', row.get('P', 0)),
        ('t', row.get('t_diff', False)), ('no', row.get('no', 0)),
        ('f', f), ('r', row.get('r', 0)), ('a', a)) if value]


def model_row(row, named, markers, variants):
    """Small-value static model; excludes nondefault t and all native execution."""
    if named not in (0, 1) or row.get('t_diff', False):
        raise ValueError('outside selected example mode')
    keys = presence(row)
    data = bytearray([(markers['map'] if named else markers['array']) | len(keys)])
    for key in keys:
        if named:
            b = key.encode('ascii')
            data.append(markers['string'] | len(b))
            data.extend(b)
        value = row[key]
        if key in ('ln', 'R', 'no', 'r'):
            if not 0 <= value <= markers['unsigned_small_max']:
                raise ValueError('unsigned example outside fixint range')
            data.append(value)
        elif key in ('C', 'P'):
            if not markers['negative_small_min'] <= value <= 0:
                raise ValueError('signed example outside negative fixint range')
            data.append(value & 255)
        elif key == 'f':
            data.append(markers['false'] | value)
        elif key == 'a':
            text = variants[value]['label'].encode('ascii')
            data.append(markers['string'] | len(text))
            data.extend(text)
        else:
            raise ValueError('unsupported example field')
    return bytes(data)


def insertion_order(keys, threshold):
    """Model the selected insertion-sort branch, not the larger sort paths."""
    if len(keys) >= threshold or any(len(k) != 20 for k in keys):
        raise ValueError('outside selected key-sort domain')
    result = list(keys)
    for i in range(len(result) - 2, -1, -1):
        value = result[i]
        j = i + 1
        while j < len(result) and result[j] < value:
            result[j - 1] = result[j]
            j += 1
        result[j - 1] = value
    return result


def sort_path(count, small_limit, medium_limit):
    """Choose the observed initial branch; helper outcomes are not modeled."""
    if not 0 <= count <= 0xffffffffffffffff // 16 or (small_limit, medium_limit) != (21, 2000):
        raise ValueError('outside the selected sort branch model')
    if count < 2:
        return 'return before comparison'
    if count < small_limit:
        return 'local comparison loop'
    if count <= medium_limit:
        return 'allocation then medium helper'
    return 'allocation then large helper'


def model_container(items, named, markers, variants, alphabet, prefix, threshold):
    """Model short successful pair-array output, with distinct 20-byte keys."""
    if len(items) >= 16 or len(alphabet) != 16 or len(prefix) != 2:
        raise ValueError('outside selected container example domain')
    mapping = {key: value for key, value in items}
    if len(mapping) != len(items):
        raise ValueError('duplicate synthetic keys are outside the selected map domain')
    keys = insertion_order([key for key, _ in items], threshold)
    output = bytearray((markers['array'] | len(keys),))
    for key in keys:
        text = bytearray(prefix)
        for byte in key:
            text.extend((alphabet[byte >> 4], alphabet[byte & 15]))
        output.extend((markers['array'] | 2, markers['string8'], len(text)))
        output.extend(text)
        output.extend(model_row(mapping[key], named, markers, variants))
    return bytes(output)


def analyze(data):
    checked_digest(data)
    secs, index = unwind_index(data)
    cies, fdes = eh_frame_records(data, secs)
    index_by_start = {}
    for row in index:
        index_by_start.setdefault(row['start'], []).append(row)
    fdes_by_start = {}
    for row in fdes:
        fdes_by_start.setdefault(row['start'], []).append(row)
    functions = []
    bodies = []
    for role, start, expected_end, expected_hash in FUNCTIONS:
        found = fdes_by_start.get(start, [])
        indexed = index_by_start.get(start, [])
        if len(found) != 1 or len(indexed) != 1:
            raise ValueError('selected FDE is absent or ambiguous')
        fde = found[0]
        if fde['end'] != expected_end or indexed[0]['fde'] != fde['fde'] or fde['cie'] not in cies:
            raise ValueError('selected FDE and index disagree')
        body = va_bytes(data, secs, start, fde['end'] - start)
        if sha(body) != expected_hash:
            raise ValueError('selected function body changed')
        file_off = va_offset(secs, start, len(body))
        functions.append({'role': role, 'start': hex(start), 'end_exclusive': hex(fde['end']),
                          'fde': hex(fde['fde']), 'cie': hex(fde['cie']), 'size': len(body),
                          'file_offset': hex(file_off), 'sha256': sha(body)})
        bodies.append({'role': role, 'start': hex(start), 'bytes': body.hex()})
    windows = []
    for role, address, hexdump in PINS:
        raw = expect(data, secs, address, hexdump)
        windows.append({'role': role, 'va': hex(address), 'file_offset': hex(va_offset(secs, address, len(raw))),
                        'bytes': raw.hex()})
    calls = []
    for role, site, wanted in CALLS:
        target = relative_target(data, secs, site)
        if target != wanted:
            raise ValueError('selected call target changed')
        calls.append({'role': role, 'site': hex(site), 'bytes': va_bytes(data, secs, site, 5).hex(),
                      'target': hex(target)})
    branches = []
    for role, site in BRANCHES:
        rec = branch(data, secs, site)
        rec['role'] = role
        owner = next((f for f in functions if int(f['start'], 16) <= site < int(f['end_exclusive'], 16)), None)
        if owner is None or not int(owner['start'], 16) <= int(rec['target'], 16) < int(owner['end_exclusive'], 16):
            raise ValueError('selected branch target outside its FDE')
        branches.append(rec)
    names = [read_name(data, secs, 0x275abf8), read_name(data, secs, 0x275ad79)]
    if [x['name'] for x in names] != ['locus', 'ust']:
        raise ValueError('context field names changed')
    fields = []
    for expected, load_site, load_prefix, has_disp8, condition, guard, name_site, value_site, target in FIELD_SPECS:
        name = read_name(data, secs, name_site)
        if name['name'] != expected or relative_target(data, secs, value_site) != target:
            raise ValueError('field name or value call changed')
        offset = field_displacement(data, secs, load_site, load_prefix, has_disp8)
        skip = branch(data, secs, guard)
        if not 0x275ce60 <= int(skip['target'], 16) < 0x275d36c:
            raise ValueError('field guard leaves value FDE')
        fields.append({'ordinal': len(fields), 'name': name, 'value_offset': hex(offset),
                       'offset_load_site': hex(load_site),
                       'presence_rule': condition, 'skip_branch': skip,
                       'value_site': hex(value_site), 'value_target': hex(target)})
    variants = variant_table(data, secs)
    classifiers = [classifier_table(data, secs, start, fields) for start in (0x26bf820, 0x26bf8c0)]
    for a in range(256):
        if classify(bytes((a,)), classifiers[0]) != classify(bytes((a,)), classifiers[1]):
            raise ValueError('field classifier copies disagree')
    readers = {
        'compact': reader_dispatch(data, secs, 0x1958123, (9, 9, 9, 9, 5, 9, 4, 9, 8),
                                   (0x1956bf0, 0x1958628), fields),
        'json_shaped': reader_dispatch(data, secs, 0x1d1c513, (9, 6, 6, 9, 5, 9, 5, 9, 4),
                                       (0x1d1c2f0, 0x1d1d2a3), fields),
    }
    duplicate_messages = {
        'compact': duplicate_key_message(data, secs, 0x263552d, 0x263553b),
        'compact_pairs': duplicate_key_message(data, secs, 0x2661ce9, 0x2661cf7),
        'json_shaped': duplicate_key_message(data, secs, 0x259d8a2, 0x259d8b0),
    }
    length_insn = expect(data, secs, 0x18e0ad4, '83fd02')
    pair_length = length_insn[2]
    context_table = rip_target(data, secs, 0x173a4b2, b'\x48\x8d\x0d')
    tag_four_entry = va_bytes(data, secs, context_table + 4 * 4, 4)
    tag_four_target = context_table + struct.unpack('<i', tag_four_entry)[0]
    if tag_four_target != 0x173a6fc:
        raise ValueError('context tag-four dispatch changed')
    user_key = va_bytes(data, secs, rip_target(data, secs, 0x2635277, b'\x48\x8d\x15'), 4)
    if user_key != b'User':
        raise ValueError('entry key type label changed')
    indirect_sites = (0x1fe8842, 0x1fe8882, 0x1fe88c5, 0x1e0d198, 0x275ce8d, 0x275d0a0,
                      0x1dfca99, 0x1dfcac9)
    expected_slots = (0x576e488, 0x576e488, 0x576e488, 0x5773120, 0x576e890, 0x576e890,
                      0x576f560, 0x576f568)
    slots = [indirect_slot(data, secs, s) for s in indirect_sites]
    if tuple(slots) != expected_slots:
        raise ValueError('indirect call slot changed')
    relocs = relocations(data, secs, set(slots))
    by_slot = {r['slot']: r for r in relocs}
    if (by_slot[hex(slots[0])].get('symbol') != 'memcmp' or by_slot[hex(slots[0])]['type'] != 6 or
            by_slot[hex(slots[3])]['type'] != 8 or by_slot[hex(slots[3])]['addend'] != hex(0x29ed380) or
            by_slot[hex(slots[4])]['type'] != 8 or by_slot[hex(slots[4])]['addend'] != hex(0x151f6f0) or
            by_slot[hex(slots[6])]['type'] != 8 or by_slot[hex(slots[6])]['addend'] != hex(0x151f240) or
            by_slot[hex(slots[7])]['type'] != 8 or by_slot[hex(slots[7])]['addend'] != hex(0x15204a0)):
        raise ValueError('selected relocation target changed')
    markers = {}
    for role, site, pattern, at in (
        ('map', 0x25a8f9f, 'bd80000000', 1),
        ('array', 0x25a9bef, 'bd90000000', 1),
        ('string', 0x25aa80b, '40b5a0', 2),
        ('string8', 0x25aa827, '40b5d9', 2),
        ('false', 0x275d1af, '0cc2', 1),
    ):
        code = expect(data, secs, site, pattern)
        markers[role] = code[at]
    signed_cmp = expect(data, secs, 0x25aaf50, '4883fadf')
    unsigned_cmp = expect(data, secs, 0x25ac0e0, '4881fa00010000')
    markers['negative_small_min'] = struct.unpack('b', signed_cmp[3:4])[0] + 1
    markers['unsigned_small_max'] = struct.unpack_from('<I', unsigned_cmp, 3)[0] // 2 - 1
    # These shared codec bodies are prior work; this packet binds the calls and
    # the relevant marker bytes, not their complete semantics.
    threshold_code = expect(data, secs, 0x1fe87cc, '4883fe15')
    threshold = threshold_code[3]
    medium_code = expect(data, secs, 0x1fe88f0, '4881fdd0070000')
    medium_threshold = struct.unpack_from('<I', medium_code, 3)[0]
    expect(data, secs, 0x1e0d18b, 'be2a000000b9140000004531c0')
    key_chars, key_bytes = struct.unpack('<I', va_bytes(data, secs, 0x1e0d18c, 4))[0], struct.unpack('<I', va_bytes(data, secs, 0x1e0d191, 4))[0]
    default_input = struct.unpack('<I', va_bytes(data, secs, 0x275ce89, 4))[0]
    # The address formatter was established in the prefixed-hex packet.  Bind
    # just its shared prefix and table bytes here for conditional examples.
    prefix_insn = expect(data, secs, 0x29ed392, '66c7073078')
    alphabet = va_bytes(data, secs, 0x208620, 16)
    if alphabet != b'0123456789abcdef':
        raise ValueError('shared hexadecimal alphabet changed')
    records = {'target': {'artifact': 'artifacts/node/94/hl-node', 'sha256': DIGEST},
               'coordinate': 'linked ELF virtual addresses; FDE ends exclusive',
               'functions': functions, 'windows': windows, 'calls': calls, 'branches': branches,
               'context_names': names, 'fields': fields, 'variants': variants,
               'reader_classifiers': classifiers, 'reader_dispatch': readers,
               'duplicate_key_messages': duplicate_messages,
               'pair_required_length': pair_length,
               'context_tag_four': {'table_va': hex(context_table), 'entry_bytes': tag_four_entry.hex(),
                                    'target': hex(tag_four_target)},
               'entry_key_type_label': user_key.decode('ascii'),
               'indirect_calls': [{'site': hex(a), 'slot': hex(b)} for a, b in zip(indirect_sites, slots)],
               'relocations': relocs, 'markers': {k: hex(v) for k, v in markers.items()},
               'key_formatter': {'capacity': key_chars, 'input_bytes': key_bytes, 'mode': 0},
               'shared_key_text': {'prefix': bytes(prefix_insn[-2:]).decode('ascii'),
                                   'alphabet': bytes(alphabet).decode('ascii')},
               'small_sort_exclusive_upper_bound': threshold, 'medium_sort_inclusive_upper_bound': medium_threshold,
               'default_helper_input': default_input,
               'limits': ['FDE extents are unwind ranges, not complete CFG proofs',
                          'sort semantics are bounded to counts below the recorded threshold',
                          'writer-to-reader context identity is an inference from matching tags and layouts',
                          'shared helper semantics use prior evidence',
                          'models are static and conditional, not executed node results']}
    return records, bodies, markers, variants


def render_tsv(header, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue()


def write_output(out, data):
    records, bodies, markers, variants = analyze(data)
    names = [x['name']['name'] for x in records['fields']]
    field_rows = [(x['ordinal'], x['name']['name'], x['value_offset'], x['offset_load_site'], x['presence_rule'],
                   x['name']['lea_va'], x['name']['data_va'], x['skip_branch']['site'],
                   x['skip_branch']['target'], x['value_site'], x['value_target']) for x in records['fields']]
    decision_rows = []
    for mask in range(1 << len(names)):
        row = {('t_diff' if n == 't' else n): int(bool(mask & (1 << i))) for i, n in enumerate(names)}
        selected = presence(row)
        decision_rows.append((hex(mask), len(selected), ','.join(selected)))
    examples = [
        ('default', {}, 1), ('default_positional', {}, 0),
        ('ln_one', {'ln': 1}, 1), ('ln_one_positional', {'ln': 1}, 0),
        ('signed_boolean_variant', {'C': -1, 'f': 1, 'a': 2}, 1),
        ('enum_i', {'a': 1}, 1), ('enum_d', {'a': 2}, 1),
        ('enum_u', {'a': 3}, 1), ('enum_p', {'a': 4}, 1),
    ]
    example_rows = [(label, mode, ','.join(presence(row)), model_row(row, mode, markers, variants).hex())
                    for label, row, mode in examples]
    prefix = records['shared_key_text']['prefix'].encode('ascii')
    alphabet = records['shared_key_text']['alphabet'].encode('ascii')
    low = bytes(19) + b'\x01'
    middle = b'\x80' + bytes(19)
    high = bytes((255,)) * 20
    container_cases = [
        ('empty', []),
        ('one', [(low, {})]),
        ('three_reverse', [(high, {'f': 1}), (middle, {'ln': 1}), (low, {'C': -1, 'a': 2})]),
    ]
    container_rows = []
    for label, items in container_cases:
        raw = model_container(items, 1, markers, variants, alphabet, prefix,
                              records['small_sort_exclusive_upper_bound'])
        container_rows.append((label, ','.join(key.hex() for key, _ in items), raw.hex()))
    compact, json_shape = records['reader_classifiers']
    name_inputs = [bytes((i,)) for i in range(256)] + [b'', b'ln', b'no', b'lN', b'nO', b'lnx', b'no\0']
    name_rows = [(len(key), key.hex(), classify(key, compact), classify(key, json_shape)) for key in name_inputs]
    read_rows = []
    for kind in ('compact', 'json_shaped'):
        for row in records['reader_dispatch'][kind]['entries']:
            br = row.get('duplicate_branch', {})
            read_rows.append((kind, row['tag'], row['name'], row['target'], br.get('site', ''),
                              br.get('target', ''), row.get('duplicate_name_va', '')))
    length_rows = [(count, pair_length_route(count, records['pair_required_length']))
                   for count in (0, 1, 2, 3, 15, 16, 0xffffffff)]
    sort_rows = [(count, sort_path(count, records['small_sort_exclusive_upper_bound'],
                                   records['medium_sort_inclusive_upper_bound']))
                 for count in (0, 1, 2, 19, 20, 21, 22, 1999, 2000, 2001)]
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(json.dumps(records, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (out / 'bodies.json').write_text(json.dumps(bodies, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (out / 'fields.tsv').write_text(render_tsv(('ordinal', 'name', 'value_offset', 'offset_load_site', 'presence_rule', 'name_lea',
                                                'name_data', 'skip_site', 'skip_target', 'value_call', 'value_target'), field_rows), encoding='utf-8')
    (out / 'presence.tsv').write_text(render_tsv(('mask', 'field_count', 'selected_fields'), decision_rows), encoding='utf-8')
    (out / 'examples.tsv').write_text(render_tsv(('case', 'named_mode', 'selected_fields', 'modeled_hex'), example_rows), encoding='utf-8')
    (out / 'container-examples.tsv').write_text(render_tsv(('case', 'input_keys', 'modeled_hex'), container_rows), encoding='utf-8')
    (out / 'name-cases.tsv').write_text(render_tsv(('length', 'input_hex', 'compact_tag', 'json_tag'), name_rows), encoding='utf-8')
    (out / 'reader-decisions.tsv').write_text(render_tsv(('reader', 'tag', 'name', 'case_target', 'duplicate_site',
                                                          'duplicate_target', 'diagnostic_name'), read_rows), encoding='utf-8')
    (out / 'pair-lengths.tsv').write_text(render_tsv(('count', 'route_if_prior_children_succeed'),
                                                     length_rows), encoding='utf-8')
    (out / 'sort-paths.tsv').write_text(render_tsv(('count', 'initial_path_if_allocation_succeeds'),
                                                   sort_rows), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    write_output(args.out, BINARY.read_bytes())


if __name__ == '__main__':
    main()
