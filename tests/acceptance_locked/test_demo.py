"""Actual Rust adapter boundaries and offline report security, independent of network."""
import importlib.util
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.fixed_scope import FixedScopeAdapter

spec = importlib.util.spec_from_file_location('product_demo', ROOT / 'scripts/demo.py')
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)

class Inspector(HTMLParser):
    def __init__(self): super().__init__(); self.tags = []; self.attributes = []; self.text = []
    def handle_starttag(self, tag, attrs): self.tags.append(tag); self.attributes.extend(attrs)
    def handle_data(self, data): self.text.append(data)

class RustDemo(unittest.TestCase):
    def client(self):
        return FixedScopeAdapter(binary=ROOT / 'target/debug' / ('rillscope.exe' if os.name == 'nt' else 'rillscope'),
                                 catalog=ROOT / 'examples/catalog.json', context=ROOT / 'examples/context.json')

    def test_fixed_scope_rejects_authority_fields_and_ignores_ambient_hooks(self):
        request = {'query': {'format': 'json', 'source': (ROOT / 'examples/query.json').read_text()}, 'output': 'rows'}
        client = self.client()
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'unexpected-telemetry.txt'
            with patch.dict(os.environ, {'RILLSCOPE_TEST_CANCEL_BEFORE_PUBLISH': '1',
                                         'RILLSCOPE_TEST_SCAN_COUNTER_FILE': str(marker),
                                         'FAKE_MODEL_KEY': 'FAKE_SECRET_CANARY'}):
                result = client.call(request)
            self.assertEqual(result['implementation'], 'rust')
            self.assertEqual(result['rows'], [[3, 40]])
            self.assertFalse(marker.exists())
        for field in ('tenant', 'catalog', 'context', 'binary', 'limits', 'path', 'optimize'):
            malicious = dict(request, **{field: 'beta'})
            result = client.call(malicious)
            self.assertEqual(result['error']['code'], 'E_INPUT')
            self.assertNotIn('rows', result)
        invalid = {'query': {'format': 'json', 'source': request['query']['source'], 'tenant': 'beta'}, 'output': 'rows'}
        self.assertEqual(client.call(invalid)['error']['code'], 'E_INPUT')
        self.assertEqual(client.call({'query': {'format': 'json', 'source': 'x' * 65537}, 'output': 'rows'})['error']['code'], 'E_LIMIT')

    def test_actual_text_output_and_supplied_labels_are_escaped_offline(self):
        malicious = '<img src=x onerror="alert(1)"><script>alert(1)</script>'
        source = 'SELECT ' + "'" + malicious + "'" + ' AS label FROM sales LIMIT 1'
        result = self.client().call({'query': {'format': 'sql', 'source': source}, 'output': 'rows'})
        self.assertEqual(result['implementation'], 'rust')
        self.assertEqual(result['rows'], [[malicious]])
        cases = [{'id': 'allowed', 'scope': 'Synthetic alpha', 'title': malicious, 'result': result}]
        markup = demo.render(cases, {'status': 'ok', 'operators': ['PolicyScan']}, label=malicious)
        parsed = Inspector(); parsed.feed(markup)
        self.assertNotIn('script', parsed.tags)
        self.assertNotIn('img', parsed.tags)
        self.assertIn(malicious, ''.join(parsed.text))
        self.assertIn('h1', parsed.tags); self.assertIn('h2', parsed.tags)
        self.assertIn('caption', parsed.tags); self.assertIn(('scope', 'col'), parsed.attributes)
        self.assertFalse(any(key.startswith('on') for key, _ in parsed.attributes))
        self.assertFalse(any(key in ('src', 'href') and not value.startswith('#') for key, value in parsed.attributes))
        self.assertIn("default-src 'none'", markup)
        self.assertIn('&lt;img', markup)

if __name__ == '__main__': unittest.main()
