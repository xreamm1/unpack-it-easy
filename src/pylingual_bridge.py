"""UIE telemetry adapter for the bundled PyLingual API. Never executes input code."""
import argparse
import functools
import json
import logging
from pathlib import Path
import re
import sys
from model_download import install as install_downloads


def emit(kind, **fields):
    print('\nUIE_EVENT ' + json.dumps(dict(kind=kind, **fields), ensure_ascii=True), flush=True)


def symbol_lines(source):
    result = {}
    stack = []
    for number, line in enumerate(source.splitlines(), 1):
        match = re.match(r'^( *)(?:async\s+)?(def|class)\s+(\w+)', line)
        if match:
            indent = len(match[1])
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, match[3]))
            result['.'.join(name for _, name in stack)] = number
    return result


def locate(symbol, lines):
    name = symbol.removeprefix('<module>.')
    while name:
        if name in lines:
            return lines[name]
        name = name.rpartition('.')[0]
    return 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--out-dir', type=Path, required=True)
    parser.add_argument('-v', '--version')
    parser.add_argument('--application-name', default='application')
    parser.add_argument('--output-prefix', type=Path, default=Path(''))
    parser.add_argument('input', type=Path)
    args = parser.parse_args()
    install_downloads()
    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='%(levelname)s %(message)s', force=True)
    emit('progress', phase='загрузка движка и моделей', file='', done=0, total=0)
    from pylingual.decompiler import Decompiler, decompile
    from pylingual.masking.model_disasm import normalize_masks, fix_jump_targets
    from pylingual.utils.tracked_list import TrackedList, CFLOW_STEP, CORRECTION_STEP

    current_file = ''
    original_translation = Decompiler.run_translation

    @functools.wraps(original_translation)
    def translation(self):
        groups = [self.make_translation_request(views, bounds) for views, bounds in zip(self.codeobj_instruction_lists, self.segmentation_results)]
        keys = [{normalize_masks(fix_jump_targets(request))[0] for request in group} for group in groups]
        completed = set(self.translator.cache)
        original_batch = self.translator._translate_and_decode

        def update():
            emit('progress', phase='перевод объектов', file=current_file,
                 done=sum(group <= completed for group in keys), total=len(keys))

        def batch(requests):
            result = original_batch(requests)
            completed.update(requests)
            update()
            return result

        self.translator._translate_and_decode = batch
        update()
        try:
            result = original_translation(self)
            emit('progress', phase='перевод объектов', file=current_file, done=len(keys), total=len(keys))
            return result
        finally:
            self.translator._translate_and_decode = original_batch

    Decompiler.run_translation = translation
    original_next = TrackedList.__next__

    def next_item(self):
        if self.name not in (CFLOW_STEP, CORRECTION_STEP) or not self.x:
            return original_next(self)
        phase = 'управление потоком' if self.name == CFLOW_STEP else 'исправление несовпадений'
        emit('progress', phase=phase, file=current_file, done=min(self.i, len(self.x)), total=len(self.x))
        return original_next(self)

    TrackedList.__next__ = next_item
    files = sorted(p for p in args.input.rglob('*') if p.is_file() and p.suffix.lower() == '.pyc') if args.input.is_dir() else [args.input]
    args.out_dir.mkdir(parents=True, exist_ok=True)
    primary = next((file for name in ('app', '__main__', 'main') for file in files if file.stem == name and (not args.input.is_dir() or file.parent == args.input)), None)
    primary = primary or next((file for file in files if not args.input.is_dir() or file.parent == args.input), files[0] if files else None)
    failures = []
    summary = []
    for file in files:
        current_file = str(file.relative_to(args.input)) if args.input.is_dir() else file.name
        relative = file.relative_to(args.input) if args.input.is_dir() else Path(file.name)
        target = args.out_dir / relative.parent / ((args.application_name + '_decompiled.py') if file == primary else ('decompiled_' + file.stem + '.py'))
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = decompile(pyc=file, save_to=target, version=args.version)
            lines = symbol_lines(result.decompiled_source)
            for item in result.equivalence_results:
                if not item.success:
                    symbol = item.name_a if hasattr(item, 'name_a') else '<module>'
                    failure_line = locate(symbol, lines)
                    if not hasattr(item, 'name_a'):
                        match = re.search(r'line (\d+)',str(item))
                        if match: failure_line = int(match[1])
                    problem = dict(file=str(args.output_prefix / 'source' / target.relative_to(args.out_dir)), symbol=symbol,
                                   line=failure_line, message=str(getattr(item, 'message', item)))
                    failures.append(problem)
                    emit('problem', **problem)
            passed = sum(item.success for item in result.equivalence_results)
            summary.append(dict(file=current_file, passed=passed, total=len(result.equivalence_results)))
        except Exception as error:
            logging.exception('Failed to decompile %s', file)
            problem = dict(file=str(args.output_prefix / 'source' / target.relative_to(args.out_dir)), symbol='<module>', line=1, message=str(error))
            failures.append(problem)
            emit('problem', **problem)
        (args.out_dir.parent / 'objects-report.json').write_text(json.dumps(dict(files=summary, problems=failures), ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
