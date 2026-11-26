"""Persistent, locked HTTP downloads for the bundled Hugging Face cache."""
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        redirected = super().redirect_request(request, response, code, message, headers, new_url)
        if redirected is not None and urlsplit(request.full_url).netloc != urlsplit(new_url).netloc:
            redirected.remove_header('Authorization')
            redirected.remove_header('Cookie')
        return redirected


def download(destination, url, headers, size, filename, force=False):
    from filelock import FileLock
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + '.uie-part')
    with FileLock(str(partial) + '.lock', timeout=1800):
        if destination.exists() and not force:
            return
        if force:
            partial.unlink(missing_ok=True)
        deadline = time.monotonic() + 1800
        for attempt in range(6):
            offset = partial.stat().st_size if partial.exists() else 0
            if size is not None and offset > size:
                partial.unlink()
                offset = 0
            try:
                if size is None or offset != size:
                    request_headers = dict(headers or {})
                    request_headers['Accept-Encoding'] = 'identity'
                    if offset:
                        request_headers['Range'] = f'bytes={offset}-'
                    request = urllib.request.Request(url, headers=request_headers)
                    with urllib.request.build_opener(SafeRedirect()).open(request, timeout=30) as response:
                        if response.status == 206:
                            match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', response.headers.get('Content-Range', ''))
                            if not match or int(match[1]) != offset or (size is not None and int(match[3]) != size):
                                raise ValueError('invalid download Content-Range')
                        elif response.status == 200:
                            offset = 0  # Range ignored: replace, never append the full response.
                        else:
                            raise ValueError(f'unexpected download status {response.status}')
                        last = 0.0
                        with partial.open('ab' if offset else 'wb') as output:
                            while True:
                                if time.monotonic() >= deadline:
                                    raise TimeoutError('model download exceeded 30 minutes; partial file retained')
                                chunk = response.read(65536)
                                if not chunk:
                                    break
                                output.write(chunk)
                                offset += len(chunk)
                                if size is not None and offset > size:
                                    raise ValueError('model response exceeds expected size')
                                if time.monotonic() - last >= 1:
                                    output.flush()
                                    print('UIE_EVENT ' + json.dumps(dict(kind='progress', phase='model download',
                                          file=f'{filename}: {offset / 1048576:.1f} / {size / 1048576:.1f} MiB' if size else f'{filename}: {offset / 1048576:.1f} MiB',
                                          done=offset, total=size or 0)), flush=True)
                                    last = time.monotonic()
                if size is not None and offset != size:
                    raise OSError(f'incomplete model download: {offset} / {size} bytes')
                # Large Hub objects are named by their SHA-256; validate before publishing.
                if re.fullmatch('[0-9a-f]{64}', destination.name):
                    digest = hashlib.sha256()
                    with partial.open('rb') as source:
                        for block in iter(lambda: source.read(1048576), b''):
                            digest.update(block)
                    if digest.hexdigest() != destination.name:
                        partial.unlink()
                        raise ValueError('model SHA-256 mismatch; corrupt partial removed')
                os.replace(partial, destination)
                return
            except (OSError, urllib.error.URLError) as error:
                if attempt == 5 or time.monotonic() >= deadline:
                    raise RuntimeError('model download interrupted; partial saved for next run') from error
                print(f'Model download interrupted; resuming saved bytes (attempt {attempt + 2}/6)', flush=True)
                time.sleep(min(2 ** attempt, 8))


def install():
    from huggingface_hub import file_download
    original = file_download._download_to_tmp_and_move
    signature = inspect.signature(original)

    def persistent(*args, **kwargs):
        values = signature.bind(*args, **kwargs).arguments
        return download(values['destination_path'], values['url_to_download'], values['headers'],
                        values['expected_size'], values['filename'], values['force_download'])

    file_download._download_to_tmp_and_move = persistent
