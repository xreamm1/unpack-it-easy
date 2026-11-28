"""Bounded layout candidates. A candidate is accepted only by the caller's bytecode verifier."""
import re

MAX_SOURCE = 1024 * 1024
MAX_CANDIDATES = 24


def layout_candidates(source):
    if len(source.encode("utf-8")) > MAX_SOURCE:
        return
    lines = source.splitlines(keepends=True)
    emitted = 0
    for handler, text in enumerate(lines):
        if not re.match(r"^ +except(?: +[^:]+)?:\s*$", text.rstrip("\r\n")):
            continue
        for definition in range(handler - 1, -1, -1):
            header = lines[definition]
            match = re.match(r"^( *)(?:async +)?def +[A-Za-z_]\w*\([^\n]*\):\s*$", header.rstrip("\r\n"))
            if not match:
                continue
            indent = len(match[1]) + 4
            region = lines[definition + 1:handler]
            # Nested definitions, existing handlers and multiline signatures need a CFG pass.
            if any(re.match(r"^ *(?:def |class |async def |try:|except|finally:)", line) for line in region):
                break
            if not region or any(line.strip() and len(line)-len(line.lstrip(" ")) < indent for line in region):
                break
            first = next((line.strip() for line in region if line.strip() and not line.lstrip().startswith("#")), "")
            if first.startswith((chr(34), chr(39))):
                break
            tail_end = handler + 1
            handler_indent = len(text) - len(text.lstrip(" "))
            while tail_end < len(lines):
                line = lines[tail_end]
                if line.strip() and len(line)-len(line.lstrip(" ")) <= handler_indent:
                    break
                tail_end += 1
            tail = lines[handler + 1:tail_end]
            if not tail or not any(line.strip() for line in tail):
                break
            offset = indent - handler_indent
            normalized = []
            for line in tail:
                if line.strip():
                    width = len(line) - len(line.lstrip(" ")) + offset
                    if width <= indent:
                        break
                    normalized.append(" " * width + line.lstrip(" "))
                else:
                    normalized.append(line)
            else:
                newline = "\r\n" if "\r\n" in source else "\n"
                candidate = "".join(lines[:definition+1] + [" "*indent+"try:"+newline] +
                    ["    "+line if line.strip() else line for line in region] +
                    [" "*indent+text.lstrip(" ")] + normalized + lines[tail_end:])
                if candidate != source:
                    yield candidate
                    emitted += 1
                    if emitted >= MAX_CANDIDATES:
                        return
            break


def recover_layout(source, verifier):
    attempts = 0
    for candidate in layout_candidates(source):
        attempts += 1
        results = verifier(candidate)
        if results and all(getattr(result, "success", False) for result in results):
            return candidate, results, attempts
    return None, None, attempts
