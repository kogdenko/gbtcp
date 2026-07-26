#!/usr/bin/env python3
"""Refactor includes in src/gbtcp/ source files.

Rules:
1. All gbtcp-internal includes use <gbtcp/...> prefix
2. Two groups: system first (alphabetical), gbtcp second (alphabetical)
"""

import os
import re
import sys
from pathlib import Path

BASE = Path("/home/kkogdenko/Projects/kogdenko/gbtcp/src/gbtcp")

# Matches: #include "path" or #include <path>, with optional trailing // comment
INC_RE = re.compile(r'^#include\s+("([^"]+)"|<([^>]+)>)\s*(//.*)?$')
IF_RE = re.compile(r'^#\s*(if|ifdef|ifndef)\b')
ENDIF_RE = re.compile(r'^#\s*endif\b')
ELIF_ELSE_RE = re.compile(r'^#\s*(elif|else)\b')


def parse_include(line):
    """Returns (path, is_quoted, comment) or None."""
    m = INC_RE.match(line.strip())
    if not m:
        return None
    is_q = m.group(1).startswith('"')
    path = m.group(2) if is_q else m.group(3)
    comment = (m.group(4) or '').strip()
    return path, is_q, comment


def is_gbtcp(path, is_q):
    if is_q:
        return True
    return (path.startswith('gbtcp/') or
            path.startswith('kernel/') or
            path.startswith('nl/'))


def convert(path, is_q, rel_dir):
    if is_q:
        resolved = os.path.normpath(os.path.join(rel_dir, path))
        return f'<gbtcp/{resolved}>'
    if path.startswith('kernel/') or path.startswith('nl/'):
        return f'<gbtcp/{path}>'
    return f'<{path}>'


def collect_block(lines, start):
    """Collect a full #if...#endif block starting at `start`.
    Returns (block_lines, next_i, is_include_only).
    """
    depth = 1
    i = start + 1
    block = [lines[start].rstrip()]
    only_incs = True

    while i < len(lines) and depth > 0:
        line = lines[i]
        s = line.strip()
        if IF_RE.match(s):
            depth += 1
            block.append(line.rstrip())
        elif ENDIF_RE.match(s):
            depth -= 1
            block.append(line.rstrip())
        elif ELIF_ELSE_RE.match(s):
            block.append(line.rstrip())
        elif INC_RE.match(s) or not s:
            block.append(line.rstrip())
        else:
            only_incs = False
            block.append(line.rstrip())
        i += 1

    return block, i, only_incs


def convert_block(block, rel_dir):
    """Convert include paths and sort within each branch of a conditional block."""
    result = []
    depth = 0
    branch_incs = []

    def flush():
        result.extend(sorted(set(branch_incs)))
        branch_incs.clear()

    for line in block:
        s = line.strip()
        if IF_RE.match(s):
            if depth == 1:
                flush()
            depth += 1
            result.append(line)
        elif ENDIF_RE.match(s):
            depth -= 1
            if depth == 0:
                flush()
            result.append(line)
        elif ELIF_ELSE_RE.match(s) and depth == 1:
            flush()
            result.append(line)
        elif INC_RE.match(s) and depth == 1:
            info = parse_include(s)
            path, is_q, _comment = info
            canonical = convert(path, is_q, rel_dir)
            branch_incs.append(f'#include {canonical}')
        elif not s and depth == 1:
            pass  # blank lines inside branches are implicit
        else:
            if depth == 1:
                flush()
            result.append(line)

    return result


def block_contains_gbtcp(block, rel_dir):
    for line in block:
        info = parse_include(line)
        if info:
            path, is_q, _comment = info
            if is_gbtcp(path, is_q):
                return True
    return False


def convert_line(line, rel_dir):
    """Convert include path in a single line, preserving trailing comment."""
    info = parse_include(line)
    if not info:
        return line
    path, is_q, comment = info
    canonical = convert(path, is_q, rel_dir)
    result = f'#include {canonical}'
    if comment:
        result += f'  {comment}'
    return result


def process_file(fp):
    rel = fp.relative_to(BASE)
    rel_dir = str(rel.parent)

    text = fp.read_text()
    lines = text.splitlines(keepends=False)

    # Find first #include line
    first_inc = None
    for j, line in enumerate(lines):
        if INC_RE.match(line.strip()):
            first_inc = j
            break

    if first_inc is None:
        return None  # no includes to process

    pre = lines[:first_inc]

    # Scan the include zone from first_inc
    i = first_inc
    # Store (sort_key, display_line) to preserve comments
    sys_incs = []   # list of (canonical, display_line)
    gbtcp_incs = []
    sys_cond_blocks = []
    gbtcp_cond_blocks = []

    while i < len(lines):
        line = lines[i]
        s = line.strip()

        if not s:
            i += 1
            continue

        info = parse_include(s)
        if info:
            path, is_q, comment = info
            canonical = convert(path, is_q, rel_dir)
            display = f'#include {canonical}'
            if comment:
                display += f'  {comment}'
            if is_gbtcp(path, is_q):
                gbtcp_incs.append((canonical, display))
            else:
                sys_incs.append((canonical, display))
            i += 1
            continue

        if IF_RE.match(s):
            block_start = i
            block, i, only_incs = collect_block(lines, i)
            if only_incs:
                conv = convert_block(block, rel_dir)
                if block_contains_gbtcp(block, rel_dir):
                    gbtcp_cond_blocks.append(conv)
                else:
                    sys_cond_blocks.append(conv)
                continue
            else:
                i = block_start  # reset to block start
                break

        # Non-include, non-blank, non-conditional: end of include zone
        break

    rest_lines = lines[i:]

    # Convert paths in the rest of file (outside include zone)
    new_rest = [convert_line(l, rel_dir) for l in rest_lines]

    # Build sorted, grouped include section
    # Deduplicate by canonical key, keeping first occurrence's display
    seen = set()
    unique_sys = []
    for key, disp in sys_incs:
        if key not in seen:
            seen.add(key)
            unique_sys.append((key, disp))
    unique_gbtcp = []
    for key, disp in gbtcp_incs:
        if key not in seen:
            seen.add(key)
            unique_gbtcp.append((key, disp))

    sys_sorted = [disp for _, disp in sorted(unique_sys, key=lambda x: x[0])]
    gbtcp_sorted = [disp for _, disp in sorted(unique_gbtcp, key=lambda x: x[0])]

    new_inc = []

    if sys_sorted:
        new_inc.extend(sys_sorted)
    for blk in sys_cond_blocks:
        if new_inc and new_inc[-1] != '':
            new_inc.append('')
        new_inc.extend(blk)

    if gbtcp_sorted:
        if new_inc and new_inc[-1] != '':
            new_inc.append('')
        new_inc.extend(gbtcp_sorted)
    for blk in gbtcp_cond_blocks:
        if new_inc and new_inc[-1] != '':
            new_inc.append('')
        new_inc.extend(blk)

    # Assemble full file
    result = list(pre)
    result.extend(new_inc)

    # Add separator before rest if needed
    if new_rest:
        while new_rest and not new_rest[0].strip():
            new_rest.pop(0)
        if new_rest:
            result.append('')
            result.extend(new_rest)

    final = '\n'.join(result)
    if text.endswith('\n'):
        final += '\n'

    return final


def main():
    dry_run = '--dry-run' in sys.argv
    target = None
    for arg in sys.argv[1:]:
        if not arg.startswith('--'):
            target = Path(arg)

    if target:
        files = [target]
    else:
        files = sorted(BASE.rglob('*.c')) + sorted(BASE.rglob('*.h'))

    changed = 0
    for fp in files:
        original = fp.read_text()
        result = process_file(fp)
        if result is None or result == original:
            continue
        changed += 1
        if dry_run:
            print(f'Would change: {fp.relative_to(BASE)}')
        else:
            fp.write_text(result)
            print(f'Updated: {fp.relative_to(BASE)}')

    print(f'\nTotal files {"to change" if dry_run else "changed"}: {changed}')


if __name__ == '__main__':
    main()
