#!/usr/bin/env python3
"""MIT. Bounded node115 static evidence; never execute/evaluate the captured code.

Only stdlib is imported. validate_inner deliberately omits whole-target/body SHA
admission so focused tests can corrupt real operands, data, CFI and relocations.
Its rejections are evidence-integrity controls, not source/native equivalence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
BODY_START, BODY_END = 0x447c620, 0x447c7c4
BODIES = {64381728: {'cie_raw': '1400000000000000017a5200017810011b0c070890010000',
            'cie_va': 13266648,
            'end': 64381806,
            'fde_raw': '1000000038931b000c61f0024e00000000000000',
            'fde_va': 15073804,
            'lsda': None,
            'role': 'operand-context',
            'sha256': '3621c428dba6bf857aea86912f83d464a01157156082d9dbbc909646684430d2'},
 64587760: {'cie_raw': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
            'cie_va': 17028612,
            'end': 64588594,
            'fde_raw': '7c000000f4ac2200f404b3024203000004db220aff410e10420e18420e20420e28420e30410e38440ea00183078c068d058e048f03860202512e0002442e0002e32e10580ea801410eb001490ea001702e0002c52e00622e00770e38410e30420e28420e20420e18420e10410e08410ea0012e005f2e004a2e00502e00000000',
            'fde_va': 19301108,
            'lsda': 3188192,
            'role': 'credited-caller',
            'sha256': '5d854b54497e96900803e5c4f62820c393a337058dde98bd6be8abcf580e7990'},
 71812640: {'cie_raw': '1400000000000000017a5200017810011b0c070890010000',
            'cie_va': 13266648,
            'end': 71813060,
            'fde_raw': '4c000000385621000c015c03a401000000410e10420e18420e20420e28420e30410e38440e800183078c068d058e048f038602035a010e38410e30420e28420e20420e18420e10410e08410e80010000',
            'fde_va': 15451404,
            'lsda': None,
            'role': 'selected-helper',
            'sha256': 'fd1c8cc52b5258565d840999760c5f23038f249d62056c20febb703c9d4d654c'},
 72244256: {'cie_raw': '1400000000000000017a5200017810011b0c070890010000',
            'cie_va': 13266648,
            'end': 72244307,
            'fde_raw': '140000004cd82100f81462033300000000440e206e0e0800',
            'fde_va': 15484704,
            'lsda': None,
            'role': 'operand-context',
            'sha256': '7d4cf8576a3cd8683dea83166332da3b6f311862d1f152c7fc47e17f4fa3d2eb'},
 74398576: {'cie_raw': '1400000000000000017a5200017810011b0c070890010000',
            'cie_va': 13266648,
            'end': 74398627,
            'fde_raw': '14000000d01e2500c4ad7f033300000000440e206e0e0800',
            'fde_va': 15699364,
            'lsda': None,
            'role': 'operand-context',
            'sha256': '9ff7edf3a2b40bf47343890c87ea6d86a934e37701cf8ec0263af8edbd2aae62'}}

ANCHORS = {64381728: '4889f0',
 64381731: '0fb60f',
 64381734: '85c9',
 64381736: '741a',
 64381738: '83f901',
 64381741: '752a',
 64381743: '488d358e3b6ffc',
 64381750: 'ba04000000',
 64381755: '4889c7',
 64381758: 'ff25dc937702',
 64381764: '488d35c93d6ffc',
 64381771: 'ba04000000',
 64381776: '4889c7',
 64381779: 'ff25c7937702',
 64381785: '488d350c70a5fc',
 64381792: 'ba0c000000',
 64381797: '4889c7',
 64381800: 'ff25b2937702',
 64587783: '488b07488b4f0848894c2460440fb6294c8b204c8b7808',
 64587811: '498bac24f00000004889e848f7d8714d',
 64587865: 'e8024e82ff837c2430010f858a000000',
 64587928: 'e843bf7b004531c9a8010f85af000000493b9424080100004d89e8',
 64587965: '490394240001000031c04839ea480f43c54829c2498b8424f800000048c1e2044801d04883c008eb22',
 64588019: '488b442438488b4c2448488d04c84883c0604989e84c8b08',
 64588051: '48ba4b598638d6c56d344889d848f7e248c1ea0b4869c2102700004889df4829c7488b71104839f70f83b0010000488b4108488d0cff48c1e105488b840818010000',
 64588138: '31c048bd00000000000000804c8d154b1d6e02410fb6cd488d7c24304c89e64889da415250e88c3c6e00',
 64588184: '4c8b7c24304939ef0f8436010000',
 64588241: '498b4424084a8d0c6d000000004c01e94c893cc8488b542408488954c80848896cc81049ffc54d896c2410',
 64588284: '488b4424600fb600410fb6',
 64588446: 'ff15446c7402',
 64588466: 'ff1558817402498b442408488d0c5b488b542428488954c8100f104424180f1104c848ffc349895c2410',
 64588508: '4939ef0f94c0',
 71812640: '55',
 71812641: '4157',
 71812643: '4156',
 71812645: '4155',
 71812647: '4154',
 71812649: '53',
 71812650: '4883ec48',
 71812654: '488b842480000000',
 71812662: '884c240a',
 71812666: '4885c0',
 71812669: '0f885c010000',
 71812675: '4d89c6',
 71812678: '4989d7',
 71812681: '4889fb',
 71812684: '4d89cd',
 71812687: '4901c5',
 71812690: '49bc0000000000000080',
 71812700: '700f',
 71812702: '4d85f6',
 71812705: '7835',
 71812707: '4d0faff5',
 71812711: '400f91c5',
 71812715: 'eb2d',
 71812717: '49c1fd3f',
 71812721: '4d31e5',
 71812724: '4901c1',
 71812727: '488d058af30002',
 71812734: '4d0f41e9',
 71812738: '31ff',
 71812740: '4889f5',
 71812743: '4889c6',
 71812746: 'ff1518880602',
 71812752: '4889ee',
 71812755: '4d85f6',
 71812758: '79cb',
 71812760: '31ed',
 71812762: '48b85d8fc2f5285c8f02',
 71812772: '4939c6',
 71812775: '0f9cc0',
 71812778: '4084e8',
 71812781: '751c',
 71812783: '4c39a678030000',
 71812790: '7513',
 71812792: '488bb42488000000',
 71812800: 'bf01000000',
 71812805: 'ff15dd870602',
 71812811: '48b89a99999999999919',
 71812821: '4939c6',
 71812824: '0f9cc0',
 71812827: '4084e8',
 71812830: '7408',
 71812832: '4c8923',
 71812835: 'e999000000',
 71812840: '4981ff0f270000',
 71812847: '7705',
 71812849: '4489f8',
 71812852: 'eb12',
 71812854: 'b8ffffffff',
 71812859: '4981ff5f5af405',
 71812866: '0f868b000000',
 71812872: '8944240c',
 71812876: '4084ed',
 71812879: '7506',
 71812881: '660f57c0',
 71812885: 'eb0d',
 71812887: 'f2490f2ac6',
 71812892: 'f20f5e057cd2fdfb',
 71812900: 'f20f11442410',
 71812906: '488d44240c',
 71812911: '4889442418',
 71812916: '488b0555b90602',
 71812923: '4889442420',
 71812928: '488d44240a',
 71812933: '4889442428',
 71812938: '488b0547b90602',
 71812945: '4889442430',
 71812950: '488d442410',
 71812955: '4889442438',
 71812960: '488b0501930602',
 71812967: '4889442440',
 71812972: '488d35aec9fcfb',
 71812979: '488d542418',
 71812984: '4889df',
 71812987: 'ff15672f0602',
 71812993: '4889d8',
 71812996: '4883c448',
 71813000: '5b',
 71813001: '415c',
 71813003: '415d',
 71813005: '415e',
 71813007: '415f',
 71813009: '5d',
 71813010: 'c3',
 71813011: '4181c7a0860100',
 71813018: 'e952ffffff',
 71813023: '488d3d6c6a35fc',
 71813030: '488d0debfd0002',
 71813037: '4c8d053cf20002',
 71813044: '488d54240b',
 71813049: 'be2b000000',
 71813054: 'ff15dc2e0602',
 72244256: '4883ec18',
 72244260: '48897c2408',
 72244265: '488b0548aeff01',
 72244272: '4889442410',
 72244277: '488b3e',
 72244280: '488b7608',
 72244284: '488d15145cf5fb',
 72244291: '488d4c2408',
 72244296: 'ff15a29aff01',
 72244302: '4883c418',
 72244306: 'c3',
 74398576: '4883ec18',
 74398580: '48897c2408',
 74398585: '488b05f0c6de01',
 74398592: '4889442410',
 74398597: '488b3e',
 74398600: '488b7608',
 74398604: '488d15c47cd4fb',
 74398611: '488d4c2408',
 74398616: 'ff1552bbde01',
 74398622: '4883c418',
 74398626: 'c3'}

DATA_PINS = {4413712: '6c312f7372632f717479732f6d6f642e7273',
 4435752: '1b4d697373696e672070726963652c206b656570696e67206f6c6420c00d2070726963652061737365743dc00d206f7261636c655f6b696e643dc0000b4356616c',
 4484690: '6c312f7372632f717479732f696d706c5f737a2e7273',
 4493601: '274173736574206f70656e20696e746572657374206578636565646564206361702061737365743dc006206b696e643dc0052c206f693dc000',
 4519774: '6c312f7372632f636c656172696e67686f7573652f636c656172696e67686f7573652e7273',
 4561312: '0000000080842e41',
 4562628: '4d61726b',
 4563220: '53706f74',
 8115052: '45787465726e616c50657270',
 8204818: '63616c6c65642060526573756c743a3a756e77726170282960206f6e20616e2060457272602076616c7565',
 105359048: '000000000000000025000000000000002002000012000000',
 105372680: '00000000000000000f000000000000000e00000010000000',
 105429488: '000000000000000012000000000000005003000001000000',
 105429512: '000000000000000016000000000000002700000001000000',
 105432472: '0000000000000000000000000000000001000000000000000000000000000000'}

RELA_PINS = {105359048: {'addend': 4519774,
             'info': 8,
             'raw': 'c8a647060000000008000000000000005ef7440000000000'},
 105372680: {'addend': 4515506,
             'info': 8,
             'raw': '08dc4706000000000800000000000000b2e6440000000000'},
 105429488: {'addend': 4413712,
             'info': 8,
             'raw': 'f0b948060000000008000000000000001059430000000000'},
 105429512: {'addend': 4484690,
             'info': 8,
             'raw': '08ba4806000000000800000000000000526e440000000000'},
 105432496: {'addend': 71093776,
             'info': 8,
             'raw': 'b0c5480600000000080000000000000010ce3c0400000000'},
 105772192: {'addend': 104193584,
             'info': 8,
             'raw': 'a0f44d0600000000080000000000000030de350600000000'},
 105772576: {'addend': 23596223,
             'info': 8,
             'raw': '20f64d06000000000800000000000000bf0c680100000000'},
 105772704: {'addend': 23596080,
             'info': 8,
             'raw': 'a0f64d06000000000800000000000000300c680100000000'},
 105772776: {'addend': 21095328,
             'info': 8,
             'raw': 'e8f64d06000000000800000000000000a0e3410100000000'},
 105772784: {'addend': 23594240,
             'info': 8,
             'raw': 'f0f64d060000000008000000000000000005680100000000'},
 105772832: {'addend': 23591536,
             'info': 8,
             'raw': '20f74d0600000000080000000000000070fa670100000000'},
 105775728: {'addend': 23628320,
             'info': 8,
             'raw': '70024e06000000000800000000000000208a680100000000'},
 105777784: {'addend': 23627584,
             'info': 8,
             'raw': '780a4e060000000008000000000000004087680100000000'},
 105778192: {'addend': 97038672,
             'info': 8,
             'raw': '100c4e0600000000080000000000000050b1c80500000000'},
 105795240: {'addend': 72502848,
             'info': 8,
             'raw': 'a84e4e06000000000800000000000000404e520400000000'},
 105798248: {'addend': 72244256,
             'info': 8,
             'raw': '685a4e06000000000800000000000000205c4e0400000000'},
 105808016: {'addend': 74398576,
             'info': 8,
             'raw': '90804e06000000000800000000000000703b6f0400000000'},
 105808024: {'addend': 64381728,
             'info': 8,
             'raw': '98804e060000000008000000000000002063d60300000000'}}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    require(len(data) == TARGET_SIZE and digest(data) == TARGET_SHA256,
            'node115 identity mismatch')


class Image:
    """File-backed VA reads require agreeing unique PT_LOAD and section mappings."""
    def __init__(self, data):
        self.data = data
        require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01', 'ELF class/endian')
        require(struct.unpack_from('<HHI', data, 16) == (3, 62, 1), 'ELF type/machine')
        po, so = struct.unpack_from('<QQ', data, 32)
        eh, pe, pn, se, sn, st = struct.unpack_from('<HHHHHH', data, 52)
        require(eh == 64 and pe == 56 and se == 64 and 0 < st < sn, 'ELF header sizes')
        require(po + pe * pn <= len(data) and so + se * sn <= len(data), 'ELF tables')
        self.ph = [struct.unpack_from('<IIQQQQQQ', data, po + i * pe) for i in range(pn)]
        self.sh = [struct.unpack_from('<IIQQQQIIQQ', data, so + i * se) for i in range(sn)]
        for p in self.ph:
            if p[0] == 1:
                require(p[5] <= p[6] and p[2] + p[5] <= len(data), 'PT_LOAD file extent')
        for s in self.sh:
            if s[1] != 8:
                require(s[4] + s[5] <= len(data), 'section file extent')
        names = self.sh[st]
        require(names[1] == 3, 'section-name table')
        names = bytes(data[names[4]:names[4] + names[5]])
        self.sections = {}
        for s in self.sh:
            require(s[0] < len(names), 'section-name offset')
            end = names.find(b'\0', s[0])
            require(end >= s[0], 'section-name terminator')
            name = names[s[0]:end].decode('ascii')
            require(name not in self.sections, 'duplicate section name')
            self.sections[name] = s

    def read(self, address, size):
        require(address >= 0 and size > 0, 'invalid VA span')
        p = [p for p in self.ph if p[0] == 1 and
             p[3] <= address and address + size <= p[3] + p[5]]
        s = [s for s in self.sh if s[1] != 8 and s[3] <= address and
             address + size <= s[3] + s[5]]
        require(len(p) == len(s) == 1, 'nonunique or missing PT_LOAD/section mapping')
        po = p[0][2] + address - p[0][3]
        so = s[0][4] + address - s[0][3]
        require(po == so, 'PT_LOAD/section offset disagreement')
        result = bytes(self.data[po:po + size])
        require(len(result) == size, 'short mapped read')
        return result

    def frame_index(self):
        s = self.sections['.eh_frame_hdr']
        b = self.read(s[3], s[5])
        require(b[:4] == bytes([1, 0x1b, 3, 0x3b]), 'unwind-header encodings')
        count = struct.unpack_from('<I', b, 8)[0]
        require(12 + count * 8 == len(b), 'unwind-header table extent')
        result = {}
        for i in range(count):
            start, fde = struct.unpack_from('<ii', b, 12 + i * 8)
            start += s[3]
            require(start not in result, 'duplicate FDE start')
            result[start] = s[3] + fde
        return result

    def relocations(self):
        s = self.sections['.rela.dyn']
        require(s[9] == 24 and s[5] % 24 == 0, 'RELA shape')
        b = self.read(s[3], s[5])
        return [(a, info, add, b[i:i + 24]) for i in range(0, len(b), 24)
                for a, info, add in [struct.unpack_from('<QQq', b, i)]]


def validate_inner(data):
    image = Image(data)
    for address, expected in ANCHORS.items():
        require(image.read(address, len(expected) // 2).hex() == expected,
                f'native operand/instruction anchor {address:#x}')
    for address, expected in DATA_PINS.items():
        require(image.read(address, len(expected) // 2).hex() == expected,
                f'data anchor {address:#x}')
    frames = image.frame_index()
    for start, spec in BODIES.items():
        require(frames.get(start) == spec['fde_va'], f'FDE-header binding {start:#x}')
        for kind in ('fde', 'cie'):
            wanted = spec[kind + '_raw']
            require(image.read(spec[kind + '_va'], len(wanted) // 2).hex() == wanted,
                    f'full {kind.upper()} raw bytes {start:#x}')
        f = spec['fde_va']
        b = bytes.fromhex(spec['fde_raw'])
        require(f + 8 + struct.unpack_from('<i', b, 8)[0] == start and
                start + struct.unpack_from('<I', b, 12)[0] == spec['end'], 'FDE range')
        require(f + 4 - struct.unpack_from('<I', b, 4)[0] == spec['cie_va'], 'CIE link')
    relas = image.relocations()
    for slot, expected in RELA_PINS.items():
        hits = [r for r in relas if slot < r[0] + 8 and r[0] < slot + 8]
        require(len(hits) == 1 and hits[0][0] == slot, f'RELA overlap {slot:#x}')
        _, info, addend, raw = hits[0]
        require(info == expected['info'] == 8 and addend == expected['addend'] and
                raw.hex() == expected['raw'], f'RELATIVE symbol/type/addend {slot:#x}')
        require(image.read(slot, 8) == bytes(8), f'pre-relocation slot bytes {slot:#x}')
    return {'instruction_anchors': len(ANCHORS), 'data_anchors': len(DATA_PINS),
            'relocations': len(RELA_PINS), 'full_fdes': len(BODIES)}


def decode_export(output, image, start, end):
    rows, position = [], start
    for line in output.decode('utf-8').splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.*)$', line)
        if not match:
            continue
        address = int(match[1], 16)
        code = bytes.fromhex(match[2])
        require(address == position and code == image.read(address, len(code)),
                'GNU/raw byte partition disagreement')
        require(match[3].strip(), 'unexpected GNU instruction continuation')
        require(address + len(code) <= end, 'GNU row outside full FDE')
        rows.append({'va': hex(address), 'raw': code.hex()})
        position += len(code)
    require(rows and position == end, 'incomplete GNU full-body export')
    return rows


def collect(data, output, objdump=None):
    authenticate(data)  # must precede output creation, snapshot creation and any native tool
    facts = validate_inner(data)
    image = Image(data)
    for start, spec in BODIES.items():
        require(digest(image.read(start, spec['end'] - start)) == spec['sha256'], 'full body digest')
    output = Path(output)
    require(not output.exists(), 'output must be fresh')
    resolved = shutil.which(objdump or 'objdump')
    require(resolved is not None, 'installed GNU objdump required')
    tool = Path(resolved).resolve()
    require(tool.is_file(), 'objdump executable path')
    tool_sha = digest(tool.read_bytes())
    output.mkdir(parents=True)
    (output / 'native').mkdir()
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'LANG': 'C',
           'DEBUGINFOD_URLS': ''}
    commands = []

    def run(label, argv, cwd):
        try:
            result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=60)
        except OSError as exc:
            (output / 'launch-error.txt').write_text(repr(exc) + '\n')
            raise
        except subprocess.TimeoutExpired as exc:
            (output / 'timeout.stdout').write_bytes(exc.stdout or b'')
            (output / 'timeout.stderr').write_bytes(exc.stderr or b'')
            raise
        stdout_name = 'objdump-version.txt' if label == 'version' else f'native/{int(label, 16):x}.objdump.txt'
        stderr_name = 'objdump-version.stderr' if label == 'version' else f'native/{int(label, 16):x}.stderr'
        (output / stdout_name).write_bytes(result.stdout)
        (output / stderr_name).write_bytes(result.stderr)
        commands.append({'label': label, 'argv': ['objdump', *argv[1:]],
                         'stdout_file': stdout_name, 'stderr_file': stderr_name,
                         'exit_code': result.returncode, 'stdout_sha256': digest(result.stdout),
                         'stderr_sha256': digest(result.stderr)})
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        require(result.returncode == 0 and not result.stderr, 'GNU tool failure/nonempty stderr')
        return result.stdout

    version = run('version', [str(tool), '--version'], output)
    require(b'GNU objdump' in version, 'GNU objdump required')
    records = []
    with tempfile.TemporaryDirectory(prefix='node115-cap-static-') as tmp:
        native = Path(tmp) / 'authenticated-node115'
        native.write_bytes(data)
        native.chmod(0o400)
        require(digest(native.read_bytes()) == TARGET_SHA256, 'private snapshot identity')
        for start, spec in sorted(BODIES.items()):
            end = spec['end']
            argv = [str(tool), '-d', '-w', '-M', 'intel', '--insn-width=16',
                    f'--start-address={start:#x}', f'--stop-address={end:#x}', native.name]
            raw = run(hex(start), argv, tmp)
            rows = decode_export(raw, image, start, end)
            name = f'native/{start:x}.objdump.txt'
            calls = []
            for row in rows:
                pc, code = int(row['va'], 16), bytes.fromhex(row['raw'])
                if len(code) == 5 and code[0] == 0xe8:
                    calls.append({'pc': row['va'], 'kind': 'direct',
                                  'target': hex(pc + 5 + struct.unpack_from('<i', code, 1)[0])})
                elif len(code) == 6 and code[:2] in (b'\xff\x15', b'\xff\x25'):
                    slot = pc + 6 + struct.unpack_from('<i', code, 2)[0]
                    require(slot in RELA_PINS, 'unbound selected RIP call/jump slot')
                    calls.append({'pc': row['va'], 'kind': 'rip-slot', 'slot': hex(slot),
                                  'target': hex(RELA_PINS[slot]['addend'])})
            records.append({'start': hex(start), **spec, 'instructions': len(rows),
                            'rows': rows, 'calls': calls, 'export': name,
                            'export_sha256': digest(raw)})
        require(digest(native.read_bytes()) == TARGET_SHA256, 'final private snapshot identity')
    require(digest(tool.read_bytes()) == tool_sha, 'objdump changed during collection')
    result = {'target_sha256': TARGET_SHA256, 'target_bytes': TARGET_SIZE, 'facts': facts,
              'tool_sha256': tool_sha, 'tool_version': version.decode().splitlines()[0],
              'bodies': records, 'data': {hex(k): v for k, v in DATA_PINS.items()},
              'relocations': {hex(k): v for k, v in RELA_PINS.items()},
              'limits': ['Static decoding/data only, no captured execution/evaluation.',
                         'Caller and shared formatting context are credited prior evidence.',
                         'Raw CFI bound; unwind not evaluated; caller LSDA address only.',
                         'All source behavior, callback effects and rendering claims are separate.']}
    (output / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    return result



def compare_packet(output, expected=None):
    """Exact semantic/native replay, with narrowly declared tool-provenance exceptions.

    No instruction text, raw bytes, CFI/data/RELA, native command or native
    stdout/stderr hash is masked. Different GNU versions may still fail the
    exact raw-export comparison; this is not a cross-disassembler equivalence.
    """
    output, expected = Path(output), PACKET if expected is None else Path(expected)
    native_names = {f'native/{start:x}.{suffix}' for start in BODIES
                    for suffix in ('objdump.txt', 'stderr')}
    wanted = native_names | {'records.json', 'commands.json',
                             'objdump-version.txt', 'objdump-version.stderr'}
    actual = {str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()}
    require(actual == wanted, 'generated artifact set mismatch')
    for name in wanted:
        require((expected / name).is_file(), 'missing committed artifact: ' + name)
    for name in native_names:
        require((output / name).read_bytes() == (expected / name).read_bytes(),
                'native artifact mismatch: ' + name)

    def load(path):
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, 'duplicate JSON key')
                result[key] = value
            return result
        return json.loads(path.read_text(), object_pairs_hook=unique)

    actual_record, expected_record = load(output / 'records.json'), load(expected / 'records.json')
    provenance = {}
    for key in ('tool_sha256', 'tool_version'):
        require(key in actual_record and key in expected_record, 'missing tool provenance')
        provenance[key] = {'actual': actual_record.pop(key), 'committed': expected_record.pop(key)}
    require(actual_record == expected_record, 'native/data/CFI/RELA record mismatch')
    actual_commands, expected_commands = load(output / 'commands.json'), load(expected / 'commands.json')
    require(len(actual_commands) == len(expected_commands) == 1 + len(BODIES), 'command count')
    for sequence in (actual_commands, expected_commands):
        require(sequence[0].get('label') == 'version' and
                sequence[0].get('argv') == ['objdump', '--version'] and
                sequence[0].get('stdout_file') == 'objdump-version.txt' and
                sequence[0].get('stderr_file') == 'objdump-version.stderr', 'version command identity')
        for key in ('stdout_sha256', 'stderr_sha256'):
            require(key in sequence[0], 'missing version command stream hash')
            sequence[0].pop(key)
    require(actual_commands == expected_commands, 'native command/provenance structure mismatch')
    # Version streams remain complete run artifacts and are individually tied
    # to their original command records, even though their bytes are not compared.
    for directory in (output, expected):
        command = load(directory / 'commands.json')[0]
        for stream in ('stdout', 'stderr'):
            require(digest((directory / command[stream + '_file']).read_bytes()) ==
                    command[stream + '_sha256'], 'version stream identity')
    return {'exact_native_files': len(native_names), 'semantic_records_equal': True,
            'provenance_exceptions': ['records.tool_sha256', 'records.tool_version',
                                     'version-command stdout/stderr hashes and their raw version streams'],
            'tool_provenance': provenance}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='fresh output directory')
    parser.add_argument('--objdump', help='installed GNU objdump path')
    parser.add_argument('--check', action='store_true', help='compare generated artifacts to this packet')
    args = parser.parse_args()
    result = collect((ROOT / 'artifacts/node/115/hl-node').read_bytes(), args.output, args.objdump)
    comparison = compare_packet(args.output) if args.check else None
    print(json.dumps({'bodies': len(result['bodies']), 'facts': result['facts'],
                      'comparison': comparison}, sort_keys=True))


if __name__ == '__main__':
    main()
