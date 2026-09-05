import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('export_source', Path(__file__).with_name('export-source.py'))
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)

class ExportTests(unittest.TestCase):
    def test_source_only_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve() / 'source'
            for name in ['README.md', 'agent/main.go', 'mcp-server/src/index.ts',
                         'target-windows/start-relay.cmd', 'target-windows/rendezvous.example.json',
                         'target-windows/rendezvous.json', 'target-windows/agent.exe',
                         'agent/dist/agent', 'mcp-server/node_modules/private.txt',
                         'rendezvous/wrangler.local.jsonc', 'rendezvous/.dev.vars',
                         'rendezvous/secrets.json', '.git/private-history']:
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('fixture')
            output = Path(d).resolve() / 'output'
            self.assertEqual(exporter.export(output, root), 5)
            names = {p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()}
            self.assertEqual(names, {'README.md','agent/main.go','mcp-server/src/index.ts','target-windows/start-relay.cmd','target-windows/rendezvous.example.json'})
            with self.assertRaises(ValueError):
                exporter.export(output, root)
    def test_source_link_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve() / 'source'
            root.mkdir()
            secret = Path(d).resolve() / 'private.txt'
            secret.write_text('do not publish')
            (root / 'README.md').symlink_to(secret)
            with self.assertRaises(ValueError):
                exporter.export(Path(d).resolve() / 'out', root)

if __name__ == '__main__':
    unittest.main()
