"""Cache PyLingual models and managed interpreters without running target code."""
import argparse
import importlib.resources
import json
import os
from pathlib import Path
import subprocess
import time
from model_download import install as install_downloads

def repositories(config, version):
    repos = {}
    for model in config[f'v{version}'].values():
        repos[model['REPO']] = model.get('REVISION', 'main')
        repos.setdefault(model['TOKENIZER'], 'main')
    return repos

def cached_files(ready, version, repo, revision):
    for entry in ready.get(version, []):
        if entry.get('repo') == repo and entry.get('revision') == revision:
            names = entry.get('files')
            if isinstance(names, list) and names and all(isinstance(name, str) and name for name in names):
                return names
    raise RuntimeError(f'No completed offline manifest for Python {version}: {repo}@{revision}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--versions', default='all')
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--verify-only', action='store_true', help='Check prepared interpreters and model files without network access')
    args = parser.parse_args()
    args.root = args.root.resolve()
    for variable, directory in [('HF_HOME', 'models'), ('HF_HUB_CACHE', 'models/hub'),
                                ('UV_PYTHON_INSTALL_DIR', 'python'), ('UV_CACHE_DIR', 'cache'),
                                ('UV_PYTHON_BIN_DIR', 'python-bin')]:
        os.environ[variable] = str(args.root / directory)
    if args.verify_only:
        os.environ['HF_HUB_OFFLINE'] = '1'
        os.environ['UV_OFFLINE'] = '1'
    else:
        os.environ.pop('HF_HUB_OFFLINE', None)
        os.environ.pop('UV_OFFLINE', None)
    if not args.verify_only:
        install_downloads()
    versions = [f'3.{minor}' for minor in range(8, 15)] if args.versions == 'all' else args.versions.split(',')
    if any(version not in [f'3.{minor}' for minor in range(8, 15)] for version in versions):
        raise ValueError('supported offline Python versions: 3.8–3.14')
    import yaml
    from huggingface_hub import HfApi, snapshot_download, hf_hub_download
    config = yaml.safe_load(importlib.resources.files('pylingual').joinpath('decompiler_config.yaml').read_text())
    api = HfApi()
    marker = args.root / "offline-ready.json"
    ready = json.loads(marker.read_text(encoding="utf-8")) if marker.exists() else {}
    failures = {}
    def retry(call):
        for attempt in range(3):
            try:
                return call()
            except Exception:
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)
    def checkpoint():
        temporary = marker.with_suffix(".tmp")
        temporary.write_text(json.dumps(ready, indent=2), encoding="utf-8")
        os.replace(temporary, marker)
    plans = {version: repositories(config, version) for version in versions}
    total = sum(1 + len(repos) for repos in plans.values())
    done = 0
    def progress(file):
        print('UIE_EVENT ' + json.dumps(dict(kind='progress', phase='offline verification' if args.verify_only else 'offline preparation', file=file, done=done, total=total)), flush=True)
    for version in versions:
        try:
            if args.verify_only:
                subprocess.run(['uv', 'python', 'find', '--managed-python', '--no-python-downloads', '--offline', '--no-project', version], check=True, timeout=30)
            else:
                retry(lambda: subprocess.run(['uv', 'python', 'install', version], check=True, timeout=900))
            done += 1
            progress(f'Python {version}')
            repos = plans[version]
            cached = []
            for repo, revision in repos.items():
                listing = cached_files(ready, version, repo, revision) if args.verify_only else retry(lambda: api.list_repo_files(repo, revision=revision))
                use_safe = any(name.endswith('.safetensors') for name in listing)
                names = [name for name in listing if name.endswith(('.json', '.txt', '.model', '.safetensors')) or (not use_safe and name.endswith('.bin'))]
                print(f'{"Checking" if args.verify_only else "Caching"} {repo}: {len(names)} files', flush=True)
                if not args.verify_only:
                    retry(lambda: snapshot_download(repo, revision=revision, allow_patterns=names, max_workers=2))
                for name in names:
                    cached_path = Path(hf_hub_download(repo, filename=name, revision=revision, local_files_only=True))
                    if not cached_path.is_file() or cached_path.stat().st_size == 0:
                        raise RuntimeError(f'Missing or empty cached file: {repo}/{name}')
                cached.append(dict(repo=repo, revision=revision, files=names))
                done += 1
                progress(repo)
            if not args.verify_only:
                ready[version] = cached
                checkpoint()
        except Exception as error:
            failures[version] = str(error)
            print(f"Offline preparation failed for Python {version}: {error}", flush=True)
    if not args.verify_only:
        checkpoint()
    if failures:
        raise RuntimeError("Some versions could not be prepared; completed versions were saved: " + json.dumps(failures))
    print(('Offline verification complete: ' if args.verify_only else 'Offline preparation complete: ') + ', '.join(versions), flush=True)

if __name__ == '__main__':
    main()
