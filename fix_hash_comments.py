#!/usr/bin/env python3
import sys

for path in sys.argv[1:]:
    with open(path) as f:
        lines = f.readlines()

    new_lines = []
    skip = False
    for line in lines:
        if '# REMOVED' in line:
            skip = True
            continue
        if skip:
            # Stop skipping when we hit a line that looks like the end of the block
            # or a non-indented line that's a comment or empty
            stripped = line.strip()
            if stripped == '});' or stripped == '' or stripped.startswith('//'):
                skip = False
                if stripped == '});':
                    continue
        if not skip:
            new_lines.append(line)

    with open(path, 'w') as f:
        f.writelines(new_lines)

    print(f"Fixed {path}: removed # REMOVED blocks")
