# Varkai Master Exporter v2.0.0-beta.1

A **read-only static-analysis evidence collection pipeline** for Ghidra, paired with a fully offline Python investigation navigator. Built for repeatable malware reverse engineering, binary triage, and auditable AI-assisted research.

> **Beta release:** `VarkaiMasterExporter.java` passed standalone Java **syntax parsing**, and its API calls were compared against Ghidra's documented API. It has **not** been compiled or integration-tested in a running Ghidra installation. `varkai_navigator.py` was executed against both synthetic v2 test data and an older, real Ghidra export, and tests passed. Do not label this as a fully verified Ghidra release until the Ghidra smoke test succeeds.

## Why this exists

A large Ghidra decompilation can be difficult to audit: a useful observation needs a function, an instruction address, a reference, and the underlying bytes. This toolkit exports those artifacts and creates a prioritized **hypothesis queue**, without presenting heuristic indicators as proven malware behavior.

## Install and run

1. Unzip the toolkit. Copy **only** `VarkaiMasterExporter.java` into your configured Ghidra script directory (or add its folder in **Window → Script Manager**). The filename must match the public Java class name.
2. Open the *analyzed program* in Ghidra's CodeBrowser and let auto-analysis finish. In Script Manager, refresh and run **VarkaiMasterExporter.java**.
3. Select one of the five export modes, then select an output parent directory. The script creates a **new timestamped folder** for each run.
4. If the mode requests focused bytes, enter an address/decimal-length pair or multiple semicolon-separated pairs, e.g. `140384B70:64;1400FFA5A:128`. `0x` prefix is supported.
5. A completed run has `manifest.json`, `export_summary.txt`, and **no** `EXPORT_INCOMPLETE.txt` marker. Memory read errors and incomplete decompilations can still occur; see their logs.
6. **Offline navigator:** With Python 3.10 or newer (no third-party packages), run:

```bash
python varkai_navigator.py "PATH_TO_EXPORTED_FOLDER"
```

It creates `varkai_reports/investigation_dashboard.html`, `evidence_pack.md`, and `priority_call_graph.dot`. Open the HTML locally in your browser. It requires **no network access**.

**Optional:** compare two separate exports of the same program:

```bash
python varkai_navigator.py "NEW_EXPORT" --compare "OLD_EXPORT" --top 40
```

The comparison uses entry addresses and indexed-instruction SHA-256 fingerprints; **rebasing, changed analysis, and missing fingerprints can affect the comparison**. It is not a proof of semantic equivalence or a mechanism for reusing stale decompilation.

## Export profiles

| Profile | Results |
|---|---|
| Complete: static analysis + raw memory | Most comprehensive; static analysis, raw initialized bytes, triage, manifest |
| Complete + focused binary region | Same plus *one or several* chosen range `.bin` files with SHA-256 |
| Static analysis only | Decompiled code, indexed assembly/bytes, references, features, call edges, triage |
| All initialized memory only | Raw initialized memory CSV + block map, integrity manifest |
| Focused region(s): hex CSV + binary | Chosen range(s) and manifest; no whole-program decompilation |

## Core output files

| File or directory | Interpretation |
|---|---|
| `ALL_FUNCTIONS_DECOMPILED.c` | Decompiled C concatenated; **not** buildable C |
| `decompiled_functions/<entry>.c` | Individual C outputs to assist targeted review/diffs |
| `functions.csv` | Function signatures, entries, thunk/external status and body address counts |
| `all_disassembly.csv` | All Ghidra-decoded instructions, including outside functions; **machine_bytes** included |
| `all_code_references.csv` | All exported Ghidra references from indexed code and defined data |
| `call_edges.csv` | Ghidra **call-type references**, with site and resolved callee (where available) |
| `indicator_evidence.csv` | Each observed computed flow, trap opcode, GS access, syscall opcode, or matched API name; contains precise addresses |
| `function_features.csv` | Triage counts, scores, instruction fingerprints and selected address evidence |
| `undecoded_executable_ranges.csv` | Initialized executable bytes that Ghidra has not decoded as instructions; **may be padding or data**, not necessarily hidden code |
| `TRIAGE_REPORT.md` | Top 40 static triage candidates with methodological caveats |
| `defined_strings.csv` | Only Ghidra-defined strings, **not** all potential runtime strings |
| `all_symbols.csv`, `all_code_comments.csv` | Symbol and annotation context |
| `memory_bytes.csv`, `memory_blocks.csv`, `read_errors.csv` | Initialized memory hex dump, block metadata and read failures (when requested) |
| `focused_*.bin` and matching CSV/manifest | Selected Ghidra-memory bytes; not necessarily original file bytes |
| `decompile_errors.csv` | Individual decompilation failures/timeouts |
| `manifest.json` | SHA-256 and file size of every export artifact written before it; does not include itself |
| `EXPORT_INCOMPLETE.txt` | **If present, the export was interrupted or failed** |

The original v1 CSV leading columns remain intact, so most existing CSV consumers can continue to operate.

## Heuristic scoring (NOT classification)

Functions are prioritized by counts of **computed control flows, trap opcodes, GS accesses, syscall opcodes, named Windows API references, incoming call references, and size**. Contributions are capped per signal to avoid simply rewarding huge functions. Every feature is an observed static property; name-only API signals are marked `name_match_only`.

Do **not** equate a high score with malware, code execution, injection, debugger detection, persistence, or credential theft. Ghidra references can be inaccurate under obfuscation. The tool does not emulate, execute, or validate paths. The evidence bundle is a queue of claims **to investigate**, not a ready-to-publish malware report.

## Known limitations and privacy

- Memory bytes are from Ghidra's **current program memory** and can reflect loader relocations, mapped sections, and patches. Focused `.bin` SHA-256 is a hash of **that extracted region**, not of the original executable.
- A decoded instruction is not necessarily executable at runtime; a referenced function is not necessarily reached.
- The export does not resolve indirect calls automatically and does not decrypt/execute embedded payloads.
- The whole-memory CSV can become **very large**. Use `Static analysis only` or targeted ranges when you want smaller outputs.
- Some outputs may contain reconstructed malware code, secrets, private paths, or sensitive text. Keep *raw exports private* and publish only material you have reviewed. The program's original local source path is deliberately omitted from `program_metadata.txt`.
- The offline dashboard uses only local files, has no analytics and requires no external libraries.
- A successful process run still may have `decompile_errors.csv` or `read_errors.csv`; check these before claiming coverage.
- API status: verified against published Ghidra Java API documentation for Ghidra 12-era interfaces; **live Ghidra integration remains unverified**.

## First integration smoke test in Ghidra

1. Run **Static analysis only** on a known, benign 64-bit executable with a few functions.
2. Confirm `manifest.json` exists and `EXPORT_INCOMPLETE.txt` does **not**.
3. Confirm `functions.csv`, `all_disassembly.csv`, `indicator_evidence.csv`, `function_features.csv`, and `TRIAGE_REPORT.md` contain rows.
4. Run `python varkai_navigator.py "OUTPUT_FOLDER"`, view the HTML, and ensure zero SHA-256 errors.
5. Re-run with **Focused region(s)** on a known initialized `.text` location. Confirm the `.bin` length equals the chosen decimal length and its SHA-256 matches the region manifest.
6. Run **Complete** on an authorized analysis sample; inspect memory read/decompile error logs and the manifest; monitor disk use.
7. If Script Manager reports errors, copy the **exact compiler message and line number** to fix any version-specific API incompatibilities.

## Repository publication

Publish the script, navigator, documentation, license and tests **without committing the real exported malware bytes**. CI runs the Python-side tests. Do not claim the Ghidra Java exporter is integration-tested until step 1–6 above pass.

Ghidra API references:
- [GhidraScript](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html)
- [Memory](https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html)
- [FunctionManager](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html)
- [Instruction](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html)
- [ReferenceManager](https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/ReferenceManager.html)
