#!/usr/bin/env python3
"""Batch fix .isNull() -> isNullPtr() in rustFrida JS scripts for QuickJS compat"""
import re, os, glob

scripts_dir = "/Users/freeman/project/douyin/rustFrida"
isnull_pattern = re.compile(r'(\w+)\.isNull\(\)')

isnull_func = """
function isNullPtr(ptr) {
    if (!ptr) return true;
    if (typeof ptr.toInt32 === 'function') return ptr.toInt32() === 0;
    return ptr.toString() === '0x0';
}
""".strip()

def fix_file(path):
    with open(path, 'r') as f:
        content = f.read()
    
    # Check if already has isNullPtr function
    has_func = 'function isNullPtr(' in content
    
    # Find all .isNull() calls
    matches = list(isnull_pattern.finditer(content))
    if not matches:
        return 0
    
    # Replace from end to start to preserve positions
    for m in reversed(matches):
        varname = m.group(1)
        content = content[:m.start()] + f'isNullPtr({varname})' + content[m.end():]
    
    # Add isNullPtr function if not present
    if not has_func:
        # Insert after 'use strict' or at the top
        if "'use strict';" in content:
            content = content.replace("'use strict';", "'use strict';\n\n" + isnull_func)
        else:
            content = isnull_func + "\n\n" + content
    
    with open(path, 'w') as f:
        f.write(content)
    
    return len(matches)

total = 0
for js_file in glob.glob(os.path.join(scripts_dir, "*.js")):
    n = fix_file(js_file)
    if n:
        print(f"Fixed {n} occurrences in {os.path.basename(js_file)}")
        total += n

print(f"\nTotal fixed: {total}")
