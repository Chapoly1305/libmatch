#!/usr/bin/env python3
"""Patch CLE's ARM Cortex-M detection to support ARMv8-M"""

import sys

def patch_cle_file(filepath):
    """Patch the CLE ELF architecture detection"""
    with open(filepath, 'r') as f:
        content = f.read()

    # Find and replace the buggy detection logic
    old_code = 'if arm_attrs["TAG_CPU_NAME"].endswith("-M") or "Cortex-M" in arm_attrs["TAG_CPU_NAME"]:'

    new_code = '''# Match Cortex-M variants:
                # - Explicit: "Cortex-M3", "Cortex-M4", "Cortex-M33", etc.
                # - ARMv*-M: "6-M", "7-M", "8-M.MAIN", "8-M.BASE", "8.1-M.MAIN", etc.
                cpu_name = arm_attrs["TAG_CPU_NAME"]
                if "Cortex-M" in cpu_name or "-M" in cpu_name:'''

    if old_code in content:
        content = content.replace(old_code, new_code)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"✅ Patched {filepath}")
        return True
    else:
        print(f"⚠️  Pattern not found in {filepath}")
        print("File might already be patched or have a different version")
        return False

if __name__ == "__main__":
    import os
    # Find CLE installation
    cle_path = None
    for path in sys.path:
        candidate = os.path.join(path, 'cle', 'backends', 'elf', 'elf.py')
        if os.path.exists(candidate):
            cle_path = candidate
            break

    if cle_path:
        print(f"Found CLE at: {cle_path}")
        if patch_cle_file(cle_path):
            print("✅ ARM Cortex-M patch applied successfully!")
        else:
            sys.exit(1)
    else:
        print("❌ Could not find CLE installation")
        sys.exit(1)
