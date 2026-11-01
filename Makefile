PYTHON ?= python3
.PHONY: setup pull fetch verify test reproduce doctor index fde-index visor-index catalogue catalogue-check provenance rea-install rea-doctor rea-mcp rea-smoke rea-mcp-check rea-native-smoke alias-rust drift drift-verify
setup:
	./scripts/setup.sh
pull:
	git lfs install --local
	git submodule update --init --recursive
	git -C references/can1357-hl lfs install --local
	git lfs pull
	git -C references/can1357-hl lfs pull
fetch:
	$(PYTHON) tools/artifacts.py fetch
verify:
	$(PYTHON) tools/artifacts.py verify
	$(PYTHON) tools/verify_imports.py
	$(PYTHON) tools/verify_packets.py
test:
	$(PYTHON) tools/run_tests.py
alias-rust:
	$(PYTHON) tools/short_string_alias_rust.py --controls
.PHONY: kind5-rust
kind5-rust:
	$(PYTHON) tools/kind5_reader_rust.py --controls
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
drift:
	$(PYTHON) tools/release_drift.py --output-dir work/drift
drift-verify:
	$(PYTHON) -I -B research/work-items/RE-014-release-drift/verify.py
