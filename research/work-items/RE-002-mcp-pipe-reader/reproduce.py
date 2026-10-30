"""Run the unchanged baseline receive path against a real owned child pipe."""
import ast
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

root = Path(__file__).resolve().parents[3]
import shutil
git = shutil.which('git')
if git is None:
    raise SystemExit('git is required for the original-source comparison')
base = '1f8c67c63ca4794c9689235471c60297f8a5c985'
source = subprocess.check_output([git, '-C', str(root), 'show', base + ':tools/rea_mcp_check.py']).decode()
tree = ast.parse(source)
block = next(n for n in tree.body if isinstance(n, ast.With))
nodes = []
for n in block.body:
    if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ('selector','buffer') for t in n.targets):
        nodes.append(n)
    elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute) and isinstance(n.value.func.value, ast.Name) and n.value.func.value.id == 'selector':
        nodes.append(n)
    elif isinstance(n, ast.FunctionDef) and n.name == 'receive':
        nodes.append(n)
assert len(nodes) == 4
print('baseline commit:', base)
for mode in ('baseline', 'fixed'):
    child = subprocess.Popen([sys.executable, '-c', "print('{\"id\":1,\"result\":42}',flush=True)"], stdout=subprocess.PIPE)
    scope = dict(child=child, selectors=selectors, time=time, os=os, json=json)
    reader = None
    try:
        if mode == 'baseline':
            exec(compile(ast.Module(body=nodes, type_ignores=[]), '<unchanged baseline receive>', 'exec'), scope)
            receive = scope['receive']
        else:
            sys.path.insert(0, str(root / 'tools'))
            from mcp_stdio import JsonLineReader
            reader = JsonLineReader(child.stdout)
            receive = reader.receive
        result = receive(1, 5)
        print(mode, 'result:', result)
        assert result == 42
    except OSError as error:
        print(mode, type(error).__name__, str(error))
        if mode != 'baseline':
            raise
    finally:
        if 'selector' in scope:
            scope['selector'].close()
        child.wait(timeout=10)
        if reader:
            reader.join()
            assert not reader.thread.is_alive()
        child.stdout.close()
print('captured target execution: false; REA/Ghidra handshake: not tested')
