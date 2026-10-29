# Changelog

## 2.0.0-beta.1 — 2026-10-29

- Introduced function-scoped decompilation files for auditable evidence and source comparisons.
- Added per-function *heuristic* scores, decoded-instruction fingerprints, and explicit address-level evidence.
- Added Ghidra-recorded call references with target-resolution caveats.
- Added undecoded executable memory ranges: gaps in **Ghidra's disassembly**, not necessarily hidden executable code.
- Added multiple focused address ranges in a single run.
- Added a `manifest.json` with size and SHA-256 for exported artifacts.
- Added `varkai_navigator.py` offline HTML/Markdown/Graphviz generator with optional export comparison.
- Kept the original CSV leading columns.
- Marked Java script **beta** pending a real Ghidra run.

## 1.0 — initial merger

- Merged static Ghidra export, initialized-memory export and focused binary extraction into one Ghidra script.
