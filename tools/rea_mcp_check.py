#!/usr/bin/env python3
"""Check the repo-local stdio MCP handshake; launches only an owned REA server."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from artifacts import ROOT
from mcp_stdio import JsonLineReader

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--require-ghidra', action='store_true')
p.add_argument('--native-smoke', action='store_true')
args = p.parse_args()
expected = json.loads((ROOT / 'config/rea.json').read_text())['version']
work = ROOT / 'work/rea-smoke'
work.mkdir(parents=True, exist_ok=True)
with (work / 'mcp-stderr.log').open('wb') as diagnostics:
    launch = [sys.executable, str(ROOT / 'tools/rea.py')]
    if args.native_smoke:
        launch += ['--profile', 'native-smoke']
    launch += ['mcp']
    child = subprocess.Popen(launch, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=diagnostics, cwd=ROOT)
    reader = JsonLineReader(child.stdout)

    def send(value):
        child.stdin.write((json.dumps(value) + '\n').encode())
        child.stdin.flush()

    def receive(request_id, timeout=60):
        return reader.receive(request_id, timeout)

    opened = False
    try:
        send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{
            'protocolVersion':'2025-06-18','capabilities':{},
            'clientInfo':{'name':'hyperliquid-source-smoke','version':'1'}}})
        init = receive(1)
        send({'jsonrpc':'2.0','method':'notifications/initialized'})
        send({'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'binary_session','arguments':{}}})
        call = receive(2)
        if call.get('isError'):
            raise RuntimeError('binary_session failed')
        state = call.get('structuredContent')
        if state is None:
            state = json.loads(next(c['text'] for c in call['content'] if c['type'] == 'text'))
        state = state['result']
        identity = state['server_identity']
        ghidra = next(c for c in state['analysis_provider_candidates'] if c['provider']['id'] == 'ghidra')
        if identity['package']['version'] != expected or state['open']:
            raise RuntimeError('Unexpected REA server version or active target')
        if args.require_ghidra and ghidra['availability']['status'] != 'available':
            raise RuntimeError('Ghidra is unavailable in the project-local MCP server')
        report = {'protocol': init['protocolVersion'], 'package_version': identity['package']['version'],
                  'catalog': identity['catalog'], 'ghidra': ghidra['availability'],
                  'target_open': state['open'], 'captured_binaries_executed': False}
        if args.native_smoke:
            from rea import target
            target_info = target('visor')
            send({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'open_binary','arguments':{
                'path':target_info['path'], 'provider_id':'ghidra'}}})
            opened_result = receive(3)
            if opened_result.get('isError'):
                raise RuntimeError('Native smoke could not open the visor')
            opened = True
            from elf_index import entry_file_offset
            entry_offset = entry_file_offset(Path(target_info['path']).read_bytes())
            send({'jsonrpc':'2.0','id':4,'method':'tools/call','params':{
                'name':'procedure_pseudo_code','arguments':{'procedure':f'file-offset:{entry_offset:#x}'}}})
            native = receive(4, timeout=420)
            (work / 'visor-native-call.json').write_text(json.dumps(native, indent=2) + '\n')
            if native.get('isError'):
                raise RuntimeError('Native smoke failed; inspect work/rea-smoke/visor-native-call.json')
            record = native.get('structuredContent')
            if record is None:
                record = json.loads(next(c['text'] for c in native['content'] if c['type'] == 'text'))
            if record['subject']['digest']['sha256'] != target_info['sha256']:
                raise RuntimeError('Native evidence belongs to a different artifact')
            if not isinstance(record['normalized_result'], str) or not record['normalized_result'].strip():
                raise RuntimeError('No visor entrypoint pseudocode returned')
            (work / 'visor-native-evidence.json').write_text(json.dumps(record, indent=2) + '\n')
            report['entry_file_offset'] = hex(entry_offset)
            report['native_evidence_id'] = record['evidence_id']
            report['native_profile'] = 'native-smoke (reduced analysis)'
        (work / 'mcp-handshake.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f"REA {expected} stdio MCP handshake passed; Ghidra {ghidra['availability']['status']}.")
    finally:
        cleanup_error = None
        if opened and child.poll() is None:
            try:
                send({'jsonrpc':'2.0','id':5,'method':'tools/call','params':{'name':'close_binary','arguments':{}}})
                close_result = receive(5, timeout=30)
                if close_result.get('isError'):
                    raise RuntimeError('Native session cleanup failed')
            except Exception as error:
                cleanup_error = error
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)
        reader.join()
        child.stdout.close()
        child.stdin.close()
        if cleanup_error is not None:
            raise cleanup_error
