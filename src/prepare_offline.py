"""Cache PyLingual models and managed interpreters without running target code."""
import argparse
import importlib.resources
import json
import os
from pathlib import Path
import subprocess

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--versions', default='all')
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    versions = [f'3.{minor}' for minor in range(8, 15)] if args.versions == 'all' else args.versions.split(',')
    if any(version not in [f'3.{minor}' for minor in range(8, 15)] for version in versions):
        raise ValueError('supported offline Python versions: 3.8–3.14')
    import yaml
    from huggingface_hub import HfApi, snapshot_download, hf_hub_download
    config = yaml.safe_load(importlib.resources.files('pylingual').joinpath('decompiler_config.yaml').read_text())
    api = HfApi()
    ready = {}
    total = len(versions) * 5
    done = 0
    def progress(file):
        print('UIE_EVENT ' + json.dumps(dict(kind='progress', phase='offline preparation', file=file, done=done, total=total)), flush=True)
    for version in versions:
        subprocess.run(['uv', 'python', 'install', version], check=True)
        done += 1
        progress(f'Python {version}')
        repos = {}
        for model in config[f'v{version}'].values():
            repos[model['REPO']] = model.get('REVISION', 'main')
            repos[model['TOKENIZER']] = 'main'
        cached = []
        for repo, revision in repos.items():
            listing = api.list_repo_files(repo, revision=revision)
            use_safe = any(name.endswith('.safetensors') for name in listing)
            names = [name for name in listing if name.endswith(('.json', '.txt', '.model', '.safetensors')) or (not use_safe and name.endswith('.bin'))]
            print(f'Caching {repo}: {len(names)} files', flush=True)
            snapshot_download(repo, revision=revision, allow_patterns=names, max_workers=4)
            for name in names:
                hf_hub_download(repo, filename=name, revision=revision, local_files_only=True)
            cached.append(dict(repo=repo, revision=revision, files=names))
            done += 1
            progress(repo)
        ready[version] = cached
    marker = args.root / 'offline-ready.json'
    if marker.exists():
        previous = json.loads(marker.read_text(encoding='utf-8'))
        previous.update(ready)
        ready = previous
    temporary = marker.with_suffix('.tmp')
    temporary.write_text(json.dumps(ready, indent=2), encoding='utf-8')
    os.replace(temporary, marker)
    print('Offline preparation complete: ' + ', '.join(versions), flush=True)

if __name__ == '__main__':
    main()
