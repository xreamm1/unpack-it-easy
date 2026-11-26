"""Offline verification must not download or overwrite a readiness manifest."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import prepare_offline


class OfflinePreparationTests(unittest.TestCase):
    def test_shared_tokenizer_does_not_replace_a_pinned_model_revision(self):
        config = {'v3.14': {'segmenter': {'REPO': 'org/model', 'REVISION': 'commit', 'TOKENIZER': 'org/model'}}}
        self.assertEqual(prepare_offline.repositories(config, '3.14'), {'org/model': 'commit'})

    def run_verification(self, missing=False, empty=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'config.yaml'
            config.write_text(json.dumps({'v3.14': {'segmenter': {'REPO': 'org/model', 'TOKENIZER': 'org/tok'}}}))
            marker = root / 'offline-ready.json'
            marker.write_text(json.dumps({'3.14': [
                {'repo': 'org/model', 'revision': 'main', 'files': ['config.json', 'model.safetensors']},
                {'repo': 'org/tok', 'revision': 'main', 'files': ['tokenizer.json']},
            ]}))
            original = marker.read_bytes()
            hub = types.ModuleType('huggingface_hub')
            hub.HfApi = Mock()
            hub.HfApi.return_value.list_repo_files.side_effect = AssertionError('network listing')
            hub.snapshot_download = Mock(side_effect=AssertionError('network download'))
            def cached(repo, filename, **kwargs):
                self.assertTrue(kwargs['local_files_only'])
                if missing and filename == 'model.safetensors':
                    raise FileNotFoundError(filename)
                path = root / filename
                path.write_bytes(b'' if empty and filename == 'model.safetensors' else b'offline cache fixture')
                return str(path)
            hub.hf_hub_download = Mock(side_effect=cached)
            with patch.dict(sys.modules, {'huggingface_hub': hub}), \
                 patch.dict(os.environ, {'HF_HOME': 'wrong-cache', 'UV_PYTHON_INSTALL_DIR': 'wrong-python'}), \
                 patch.object(sys, 'argv', ['prepare_offline.py', '--root', directory, '--versions', '3.14', '--verify-only']), \
                 patch('importlib.resources.files', return_value=root), \
                 patch.object(prepare_offline.subprocess, 'run') as interpreter, \
                 patch.object(prepare_offline, 'install_downloads', side_effect=AssertionError('installer')), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                config.rename(root / 'decompiler_config.yaml')
                if missing or empty:
                    with self.assertRaisesRegex(RuntimeError, 'model.safetensors'):
                        prepare_offline.main()
                else:
                    prepare_offline.main()
                    self.assertIn('"done": 3, "total": 3', output.getvalue())
                command = interpreter.call_args.args[0]
                self.assertIn('--offline', command)
                self.assertIn('--no-python-downloads', command)
                hub.snapshot_download.assert_not_called()
                hub.HfApi.return_value.list_repo_files.assert_not_called()
                self.assertEqual(Path(os.environ['HF_HOME']), root / 'models')
                self.assertEqual(Path(os.environ['UV_PYTHON_INSTALL_DIR']), root / 'python')
                self.assertEqual(os.environ['HF_HUB_OFFLINE'], '1')
            self.assertEqual(marker.read_bytes(), original)

    def test_verified_cache_never_contacts_network_and_uses_exact_progress(self):
        self.run_verification()

    def test_missing_weight_fails_without_changing_readiness_manifest(self):
        self.run_verification(missing=True)

    def test_empty_weight_is_not_reported_as_available(self):
        self.run_verification(empty=True)


if __name__ == '__main__':
    unittest.main()
