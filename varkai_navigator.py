#!/usr/bin/env python3
"""Varkai Navigator 2.0 — offline evidence browser for Varkai Master Exporter.
Python 3.10+, stdlib only. Reads static exports; never runs the analyzed program.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import html
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

TOP_DEFAULT = 40
CSV_LIMIT = 4000


def read_csv(path: Path):
    if not path.is_file():
        return []
    with path.open('r', newline='', encoding='utf-8-sig', errors='replace') as f:
        return list(csv.DictReader(f))


def num(value: Any) -> int:
    try:
        return int(value or 0)
    except (ValueError, TypeError):
        return 0


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for part in iter(lambda: f.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def verify_manifest(root: Path) -> list[str]:
    path = root / 'manifest.json'
    if not path.is_file():
        return ['Integrity manifest absent (legacy export or incomplete export).']
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        return [f'Invalid manifest: {exc}']
    warnings = []
    for entry in data.get('artifacts', []):
        rel = Path(entry.get('path', ''))
        if rel.is_absolute() or '..' in rel.parts:
            warnings.append(f'Rejected unsafe manifest path: {rel}')
            continue
        file = root / rel
        if not file.is_file():
            warnings.append(f'Missing artifact: {rel}')
        elif file.stat().st_size != entry.get('bytes'):
            warnings.append(f'Size mismatch: {rel}')
        elif digest(file).lower() != str(entry.get('sha256', '')).lower():
            warnings.append(f'SHA-256 mismatch: {rel}')
    if (root / 'EXPORT_INCOMPLETE.txt').exists():
        warnings.append('EXPORT_INCOMPLETE.txt exists; this export is partial.')
    return warnings


def load_legacy(root: Path) -> list[dict]:
    """Legacy export fallback — derived heuristics from function + instruction CSVs."""
    rows = read_csv(root / 'functions.csv')
    if not rows:
        raise FileNotFoundError('Missing function_features.csv and functions.csv')
    funcs = {}
    for row in rows:
        entry = row.get('entry', '')
        if not entry:
            continue
        funcs[row.get('name', '')] = {
            'entry': entry,
            'name': row.get('name', ''),
            'score': 0, 'instructions': 0, 'indirect_flows': 0,
            'trap_opcodes': 0, 'gs_accesses': 0, 'syscall_opcodes': 0,
            'inbound_call_refs': 0, 'outgoing_call_refs': 0, 'named_api_hits': 0,
            'api_tags': '', 'evidence_samples': '', 'instruction_fingerprint_sha256': '',
        }
    evidence = defaultdict(list)
    # Streaming prevents holding hundreds of thousands of instruction rows in memory.
    path = root / 'all_disassembly.csv'
    if path.is_file():
        with path.open('r', newline='', encoding='utf-8-sig', errors='replace') as fh:
            for item in csv.DictReader(fh):
                f = funcs.get(item.get('function', ''))
                if f is None:
                    continue
                f['instructions'] += 1
                asm = item.get('instruction', '').upper()
                opcode = asm.split(' ')[0] if asm else ''
                flags = []
                if opcode in ('UD2', 'INT3', 'HLT'):
                    f['trap_opcodes'] += 1; flags.append('trap')
                if opcode in ('SYSCALL', 'SYSENTER'):
                    f['syscall_opcodes'] += 1; flags.append('syscall')
                if 'GS:[' in asm or 'GS:' in asm:
                    f['gs_accesses'] += 1; flags.append('GS')
                # Do NOT automatically call every JMP/CALL indirect: requires operand/type interpretation.
                if flags and len(evidence[f['entry']]) < 16:
                    evidence[f['entry']].append(item.get('virtual_address', '') + ':' + '/'.join(flags))
    for f in funcs.values():
        f['score'] = min(12, f['trap_opcodes'] * 2) + min(12, f['gs_accesses'] * 4) + min(15, f['syscall_opcodes'] * 5)
        f['evidence_samples'] = ' ; '.join(evidence[f['entry']])
    return list(funcs.values())


def load_edges(root: Path) -> list[dict]:
    """Prefer explicit v2 edges; approximate direct call references for legacy exports."""
    newer = root / 'call_edges.csv'
    if newer.is_file():
        return read_csv(newer)
    fns = read_csv(root / 'functions.csv')
    byname = {row.get('name', ''): row for row in fns if row.get('name')}
    byaddr = {row.get('entry', '').lower(): row for row in fns if row.get('entry')}
    edges = []
    old = root / 'all_code_references.csv'
    if not old.is_file():
        return edges
    with old.open('r', newline='', encoding='utf-8-sig', errors='replace') as fh:
        for ref in csv.DictReader(fh):
            if 'CALL' not in ref.get('reference_type', '').upper():
                continue
            src = byname.get(ref.get('function', ''), {})
            dst = byaddr.get(ref.get('to', '').lower(), {})
            edges.append({
                'caller_entry': src.get('entry', ''),
                'caller_name': src.get('name', ''),
                'site_address': ref.get('from', ''),
                'target_address': ref.get('to', ''),
                'callee_entry': dst.get('entry', ''),
                'callee_name': dst.get('name', ref.get('external_target_name', '')),
                'reference_type': ref.get('reference_type', ''),
                'warning': 'Legacy reference reconstruction; unresolved targets possible'
            })
    return edges


def load_features(root: Path) -> tuple[list[dict], bool]:
    path = root / 'function_features.csv'
    if not path.exists():
        return load_legacy(root), True
    return read_csv(path), False


def clean(text: Any) -> str:
    return html.escape(str(text or ''), quote=True)


def markdown_safe(value: Any) -> str:
    return str(value or '').replace('|', '\\|').replace('`', "'").replace('\n', ' ')


def feature_rows(rows: list[dict]):
    return sorted(rows, key=lambda r: (-num(r.get('score')), r.get('entry', '')))


def build_graph(edges: list[dict], top: list[dict]) -> str:
    names = {r.get('entry', ''): r.get('name', '') for r in top}
    out = ['digraph VarkaiEvidence {', '  graph [rankdir=LR, fontname="monospace"];',
           '  node [shape=box, fontname="monospace", fontsize=10];']
    for entry, name in names.items():
        safe_id = 'n_' + re.sub('[^A-Za-z0-9]', '_', entry)
        label = (entry + '\\n' + name[:35]).replace('"', "'").replace('\\', '/')
        out.append(f'  {safe_id} [label="{label}"];')
    seen = set()
    for e in edges:
        src, dst = e.get('caller_entry', ''), e.get('callee_entry', '')
        if src in names and dst in names and (src, dst) not in seen:
            seen.add((src, dst))
            out.append('  n_' + re.sub('[^A-Za-z0-9]', '_', src) + ' -> n_' + re.sub('[^A-Za-z0-9]', '_', dst) + ';')
    out.append('}')
    return '\n'.join(out) + '\n'


def compare_exports(current: list[dict], previous: list[dict]) -> str:
    left = {r.get('entry', ''): r for r in previous if r.get('entry')}
    right = {r.get('entry', ''): r for r in current if r.get('entry')}
    added = sorted(set(right) - set(left))
    gone = sorted(set(left) - set(right))
    changed = []
    unknown = []
    for key in sorted(set(right) & set(left)):
        a = left[key].get('instruction_fingerprint_sha256', '')
        b = right[key].get('instruction_fingerprint_sha256', '')
        if a and b:
            if a != b:
                changed.append(key)
        else:
            unknown.append(key)
    lines = ['# Varkai export comparison', '',
             'Comparison uses virtual-address function entrypoints. Different load bases can make identical functions appear changed.',
             'A matching instruction fingerprint does **not** prove unchanged types, decompiler output, comments, or program behavior.', '',
             f'- Added entries: **{len(added)}**', f'- Removed entries: **{len(gone)}**',
             f'- Different instruction fingerprints: **{len(changed)}**',
             f'- Fingerprint unavailable in either export: **{len(unknown)}**', '']
    for title, values in [('Added', added), ('Removed', gone), ('Changed bytes/indexed instructions', changed)]:
        lines.extend(['## ' + title, ''])
        lines.extend('- `' + k + '`' for k in values[:200])
        if len(values)>200: lines.append(f'- ... plus {len(values)-200} more')
        lines.append('')
    return '\n'.join(lines)


def make_html(rows: list[dict], edges: list[dict], warnings: list[str], legacy: bool) -> str:
    sorted_rows = feature_rows(rows)
    incoming = defaultdict(list)
    outgoing = defaultdict(list)
    for e in edges:
        incoming[e.get('callee_entry', '')].append(e)
        outgoing[e.get('caller_entry', '')].append(e)
    body = []
    for f in sorted_rows:
        entry = f.get('entry', '')
        name = f.get('name', '')
        evidence = f.get('evidence_samples', '')
        sc = num(f.get('score'))
        refs = outgoing.get(entry, [])
        desc = ', '.join(f'{e.get("target_address", "?")} ({e.get("callee_name", "unresolved")})' for e in refs[:15])
        body.append(f'''<tr class="item" data-text="{clean(entry+' '+name+' '+f.get('api_tags','')+' '+evidence)}" data-score="{sc}">
<td>{sc}</td><td><code>{clean(entry)}</code></td><td>{clean(name)}</td>
<td>{num(f.get('instructions'))}</td><td>{num(f.get('indirect_flows'))}</td>
<td>{num(f.get('trap_opcodes'))}</td><td>{num(f.get('gs_accesses'))}</td>
<td>{num(f.get('named_api_hits'))}</td><td>{clean(f.get('api_tags'))}</td>
<td><details><summary>Show evidence</summary><p>{clean(evidence) or 'No sampled evidence'}</p>
<p><b>Call references:</b> {clean(desc) or 'Unavailable'}</p>
<p><b>Incoming call refs:</b> {num(f.get('inbound_call_refs'))}</p>
<p><b>Indexed-instruction fingerprint:</b> <code>{clean(f.get('instruction_fingerprint_sha256'))}</code></p>
</details></td></tr>''')
    warn = ''.join(f'<li>{clean(w)}</li>' for w in warnings) or '<li>Manifest present and all listed artifacts verified, or validation skipped.</li>'
    legacy_msg = '<p class="notice">Legacy-export fallback: only limited opcode signals could be recovered. Scores are not comparable to v2 exports.</p>' if legacy else ''
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Varkai Navigator — static evidence</title><style>
:root{color-scheme:dark;font-family:system-ui,-apple-system,sans-serif;background:#10141d;color:#e7e9f0}
body{margin:auto;max-width:1400px;padding:24px}h1{letter-spacing:-.04em}p{color:#b5bfce}
.notice{background:#242433;border-left:4px solid #cba36c;padding:12px}
input{background:#1f2530;border:1px solid #526070;color:white;padding:12px;width:min(480px,80%);border-radius:8px;margin:10px 0 18px}
table{width:100%;border-collapse:collapse;font-size:13px}th{color:#bfcce0;text-align:left;background:#202634;position:sticky;top:0}
th,td{border-bottom:1px solid #363b48;padding:10px 8px;vertical-align:top}
tr:hover{background:#1b2331}code{font-family:ui-monospace,Consolas,monospace;word-break:break-all}
summary{cursor:pointer;color:#90c3ff}details p{max-width:480px;overflow-wrap:anywhere;color:#d1d5df}
small{color:#9ea8b7}.table-wrap{overflow-x:auto}
</style></head><body><h1>Varkai Navigator</h1>
<p>Offline static-analysis investigation dashboard. <b>These are heuristic priorities, not malware verdicts or evidence of runtime execution.</b></p>
''' + legacy_msg + f'''<p><small>{len(rows)} functions indexed · {len(edges)} recorded call references</small></p>
<details><summary>Integrity / warnings</summary><ul>{warn}</ul></details>
<input id="search" placeholder="Filter by address, function, API tag, evidence..." aria-label="Search functions">
<label for="minscore">Minimum triage score:</label> <select id="minscore"><option>0</option><option>5</option><option>10</option><option>20</option><option>30</option></select>
<p id="count"></p><div class="table-wrap"><table><thead><tr>
<th>Score</th><th>Address</th><th>Function</th><th>Instructions</th><th>Indirect</th><th>Traps</th><th>GS</th><th>API hits</th><th>Tags</th><th>Evidence / calls</th>
</tr></thead><tbody>''' + '\n'.join(body) + '''</tbody></table></div>
<script>
const search=document.querySelector('#search'),minscore=document.querySelector('#minscore'),rows=[...document.querySelectorAll('tr.item')],count=document.querySelector('#count');
function apply(){let q=search.value.toLowerCase().trim(),s=+minscore.value,n=0;
for(const r of rows){let show=+r.dataset.score>=s && r.dataset.text.toLowerCase().includes(q);r.hidden=!show;if(show)n++;}
count.textContent=n+' of '+rows.length+' functions shown';}
search.addEventListener('input',apply);minscore.addEventListener('change',apply);apply();
</script></body></html>'''


def main() -> int:
    ap = argparse.ArgumentParser(description='Build offline evidence navigator for a Ghidra export (no external dependencies)')
    ap.add_argument('export', type=Path, help='Directory containing function_features.csv or legacy functions.csv')
    ap.add_argument('--output', type=Path, help='Where to write reports (default EXPORT/varkai_reports)')
    ap.add_argument('--compare', type=Path, help='Previous export folder for a non-destructive instruction fingerprint comparison')
    ap.add_argument('--top', type=int, default=TOP_DEFAULT, help='Number of top functions in evidence pack and graph')
    ap.add_argument('--skip-verify', action='store_true', help='Skip manifest SHA-256 verification (for huge dumps)')
    args = ap.parse_args()
    root = args.export.expanduser().resolve()
    if not root.is_dir():
        ap.error(f'Not a directory: {root}')
    output = (args.output or (root/'varkai_reports')).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    rows, legacy = load_features(root)
    edges = load_edges(root)
    warnings = [] if args.skip_verify else verify_manifest(root)
    if (root/'EXPORT_INCOMPLETE.txt').exists() and not any('partial' in w for w in warnings):
        warnings.append('Incomplete marker present; data may be partial.')
    ranked = feature_rows(rows)
    top = ranked[:max(1, min(args.top, 250))]
    (output/'investigation_dashboard.html').write_text(make_html(rows, edges, warnings, legacy), encoding='utf-8')
    (output/'priority_call_graph.dot').write_text(build_graph(edges, top), encoding='utf-8')
    lines = ['# Varkai prioritized evidence', '',
             '**Heuristic review queue only. No runtime or malware-behavior claims.**', '',
             f'Functions: {len(rows)}; recorded call references: {len(edges)}; legacy fallback: {legacy}', '']
    if warnings:
        lines.extend(['## Integrity / validation notes', ''])
        lines.extend('- ' + w for w in warnings)
        lines.append('')
    for i, f in enumerate(top, 1):
        e=f.get('entry', '')
        lines.extend([f'## {i}. `{markdown_safe(f.get("name"))}` — `{markdown_safe(e)}`', '',
            f'Score: **{num(f.get("score"))}** (not a probability)', '',
            'Observed evidence: ' + (markdown_safe(f.get('evidence_samples')) or 'No sampled evidence'), '',
            f'API tags (name-only): {markdown_safe(f.get("api_tags")) or "None"}', ''])
        calls = [x for x in edges if x.get('caller_entry')==e][:20]
        if calls:
            lines.append('Recorded call references (not runtime execution):')
            lines.extend(f'- `{markdown_safe(x.get("site_address"))}` → `{markdown_safe(x.get("target_address"))}` {markdown_safe(x.get("callee_name"))}' for x in calls)
            lines.append('')
        source = root/'decompiled_functions'/(re.sub(r'[^a-zA-Z0-9._-]','_',e) + '.c')
        if source.is_file():
            snippet=source.read_text(encoding='utf-8', errors='replace')[:6000]
            snippet=snippet.replace('```', '` ` `')
            lines.extend(['Decompiled-code excerpt (truncated to 6000 characters):', '', '```c', snippet, '```', ''])
    (output/'evidence_pack.md').write_text('\n'.join(lines), encoding='utf-8')
    if args.compare:
        prior, _ = load_features(args.compare.expanduser().resolve())
        (output/'export_comparison.md').write_text(compare_exports(rows, prior), encoding='utf-8')
    print(f'Created offline dashboard and evidence bundle in: {output}')
    print(f'Functions: {len(rows)}; call references: {len(edges)}; warnings: {len(warnings)}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
