PYTHON ?= python3
.PHONY: setup pull fetch verify test reproduce doctor index fde-index target-cpu-features catalogue catalogue-check provenance rea-install rea-doctor rea-mcp rea-smoke rea-mcp-check rea-native-smoke
setup:
	./scripts/setup.sh
pull:
	git submodule update --init --recursive
	git lfs pull
	git -C references/can1357-hl lfs pull
fetch:
	$(PYTHON) tools/artifacts.py fetch
verify:
	$(PYTHON) tools/artifacts.py verify
	$(PYTHON) tools/verify_imports.py
test:
	$(PYTHON) -m unittest discover -s tests -v
provenance:
	$(PYTHON) tools/build_provenance.py
reproduce:
	$(PYTHON) tools/reproduce.py
doctor:
	$(PYTHON) tools/doctor.py
index:
	$(PYTHON) tools/elf_index.py --release 94
	$(PYTHON) tools/elf_index.py --release 115
fde-index:
	$(PYTHON) tools/fde_extents.py --release 94
	$(PYTHON) tools/fde_extents.py --release 115
target-cpu-features:
	$(PYTHON) tools/target_cpu_features.py --release 94 --out work/target-cpu-features/94
	$(PYTHON) tools/target_cpu_features.py --release 115 --out work/target-cpu-features/115
	$(PYTHON) tools/target_cpu_features.py --release visor --out work/target-cpu-features/visor
visor-index:
	$(PYTHON) tools/elf_index.py --release visor
catalogue:
	$(PYTHON) tools/catalogue.py
catalogue-check:
	$(PYTHON) tools/catalogue.py --check
rea-install:
	$(PYTHON) tools/rea.py install
rea-doctor:
	$(PYTHON) tools/rea.py doctor --provider ghidra --target artifacts/visor/captured/hl-visor --format json
rea-mcp:
	$(PYTHON) tools/rea.py mcp
rea-smoke:
	$(PYTHON) tools/rea_smoke.py
rea-mcp-check:
	$(PYTHON) tools/rea_mcp_check.py --require-ghidra
rea-native-smoke:
	$(PYTHON) tools/rea_mcp_check.py --require-ghidra --native-smoke
