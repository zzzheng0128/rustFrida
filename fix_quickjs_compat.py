#!/usr/bin/env python3
"""
Batch-fix rustFrida JS scripts for QuickJS compatibility.
Run this in /Users/freeman/project/douyin/rustFrida/
"""

import os
import re

FIXES = {
    # Remove setInterval entirely - replace with comments or manual patterns
    r'setInterval\s*\(\s*function\s*\(\)\s*\{': '# REMOVED: setInterval(function(){',
    r'\}\s*,\s*\d+\s*\)\s*;?': '# REMOVED setInterval block',

    # Java.perform -> Java.ready
    r'Java\.perform\s*\(': 'Java.ready(',

    # impl shorthand -> implementation
    r'\.impl\s*=\s*function': '.implementation = function',
    r'\.impl\s*=\s*': '.implementation = ',

    # NativeCallback -> use hook() or remove
    r'new\s+NativeCallback\s*\(': '# REMOVED NativeCallback(',

    # Process.setExceptionHandler -> remove/comment
    r'Process\.setExceptionHandler\s*\(': '# REMOVED Process.setExceptionHandler(',

    # int64 NativeFunction return type -> int or long
    r"new\s+NativeFunction\s*\(\s*([^,]+),\s*['\"]int64['\"]": r"new NativeFunction(\1, 'long'",
    r"new\s+NativeFunction\s*\(\s*([^,]+),\s*['\"]pointer['\"]": r"new NativeFunction(\1, 'long'",

    # uint64 in type array -> remove or replace
    r"'uint64'": "'long'",
}

FILES_TO_FIX = [
    'douyin_stress_test.js',
    'douyin_java_bomb.js',
    'douyin_native_bomb.js',
    'douyin_svc_stress.js',
    'frida_syscall_monitor.js',
]

SCRIPTS_DIR = '/Users/freeman/project/douyin/rustFrida/'

def fix_file(filename):
    path = os.path.join(SCRIPTS_DIR, filename)
    if not os.path.exists(path):
        print(f"SKIP: {filename} not found")
        return

    with open(path, 'r') as f:
        content = f.read()

    original = content
    changes = []

    # 1. Replace setInterval blocks with comments
    # Pattern: setInterval(function(){ ... }, N);
    # This is tricky with regex, do line-by-line for simple cases
    lines = content.split('\n')
    new_lines = []
    in_setinterval = False
    brace_depth = 0
    skip_until_semicolon = False

    for i, line in enumerate(lines):
        # Handle setInterval(function() { ... }, 1000); across multiple lines
        if re.search(r'setInterval\s*\(', line) and not in_setinterval:
            in_setinterval = True
            brace_depth = line.count('{') - line.count('}')
            # Check if it's a single-line setInterval
            if brace_depth <= 0 and line.strip().endswith(');'):
                new_lines.append('    // REMOVED setInterval: ' + line.strip())
                changes.append(f"line {i+1}: removed single-line setInterval")
                in_setinterval = False
            else:
                new_lines.append('    /* REMOVED setInterval block start */')
                changes.append(f"line {i+1}: removed multi-line setInterval")
            continue

        if in_setinterval:
            brace_depth += line.count('{') - line.count('}')
            if brace_depth <= 0:
                # End of setInterval block
                # Check for trailing );
                stripped = line.strip()
                if stripped.endswith(');') or stripped.endswith(')'):
                    new_lines.append('    /* REMOVED setInterval block end */')
                    in_setinterval = False
                else:
                    new_lines.append('    /* REMOVED setInterval block end */')
                    in_setinterval = False
            continue

        new_lines.append(line)

    content = '\n'.join(new_lines)

    # 2. Simple regex replacements
    replacements = [
        (r'Java\.perform\s*\(', 'Java.ready(', 'Java.perform -> Java.ready'),
        (r'\.impl\s*=\s*function', '.implementation = function', '.impl -> .implementation (function)'),
        (r'\.impl\s*=\s*(?!function)', '.implementation = ', '.impl -> .implementation'),
        (r'Process\.setExceptionHandler\s*\(', '# REMOVED Process.setExceptionHandler(', 'removed setExceptionHandler'),
        (r"new\s+NativeCallback\s*\(", '# REMOVED NativeCallback(', 'removed NativeCallback'),
        (r"'uint64'", "'long'", "'uint64' -> 'long'"),
    ]

    for pattern, replacement, desc in replacements:
        new_content, count = re.subn(pattern, replacement, content)
        if count > 0:
            content = new_content
            changes.append(f"{desc} x{count}")

    # 3. Fix NativeFunction int64/pointer return types
    # Pattern: new NativeFunction(addr, 'int64', ...)
    # Only for return type (second arg)
    def fix_nativefunction_type(match):
        addr = match.group(1)
        old_type = match.group(2)
        rest = match.group(3)
        if old_type in ('int64', 'pointer', 'uint64'):
            return f"new NativeFunction({addr}, 'long'{rest}"
        return match.group(0)

    content = re.sub(r"new\s+NativeFunction\s*\(\s*([^,]+),\s*['\"](\w+)['\"](.*?)\)",
                     fix_nativefunction_type, content)

    if content != original:
        with open(path, 'w') as f:
            f.write(content)
        print(f"FIXED {filename}:")
        for c in changes:
            print(f"  - {c}")
    else:
        print(f"OK {filename}: no changes needed")

if __name__ == '__main__':
    for fname in FILES_TO_FIX:
        fix_file(fname)
    print("\nDone. Review changes before using.")
