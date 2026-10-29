import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / 'varkai_navigator.py'

class NavigatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        with (self.root/'function_features.csv').open('w', newline='') as fh:
            writer = csv.writer(fh)
            writer.writerow(['entry','name','score','instructions','indirect_flows','trap_opcodes',
                             'gs_accesses','named_api_hits','api_tags','evidence_samples',
                             'instruction_fingerprint_sha256','inbound_call_refs'])
            writer.writerow(['1000','<script>alert(1)</script>',21,17,2,1,0,1,'api',
                             '1004:computed_call',hashlib.sha256(b'test').hexdigest(),0])
        with (self.root/'call_edges.csv').open('w', newline='') as fh:
            writer=csv.writer(fh)
            writer.writerow(['caller_entry','caller_name','site_address','target_address','callee_entry','callee_name','reference_type'])
            writer.writerow(['1000','unsafe','1004','2000','2000','callee','UNCONDITIONAL_CALL'])
        source = self.root/'function_features.csv'
        manifest = {'artifacts':[{'path':'function_features.csv','bytes':source.stat().st_size,
                                  'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}]}
        (self.root/'manifest.json').write_text(json.dumps(manifest))

    def run_nav(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.root), *args],
                              check=True, text=True, capture_output=True)

    def test_html_escaped_graph_and_pack(self):
        self.run_nav('--compare', str(self.root))
        output = self.root/'varkai_reports'
        data=(output/'investigation_dashboard.html').read_text()
        self.assertIn('&lt;script&gt;', data)
        self.assertNotIn('<script>alert(1)</script>',data)
        self.assertIn('1004', (output/'evidence_pack.md').read_text())
        self.assertIn('digraph', (output/'priority_call_graph.dot').read_text())
        self.assertIn('Different instruction fingerprints', (output/'export_comparison.md').read_text())

    def test_tamper_detection(self):
        self.root.joinpath('function_features.csv').write_text('tampered')
        self.run_nav()
        self.assertIn('Size mismatch', (self.root/'varkai_reports/investigation_dashboard.html').read_text())

    def test_incomplete_warning(self):
        (self.root/'EXPORT_INCOMPLETE.txt').write_text('incomplete')
        self.run_nav()
        self.assertIn('partial', (self.root/'varkai_reports/investigation_dashboard.html').read_text())

if __name__ == '__main__':
    unittest.main()
