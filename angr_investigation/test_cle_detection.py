#!/usr/bin/env python3
"""Test CLE's architecture detection for Silicon Labs binary"""

import sys
sys.path.insert(0, '/home/chen/libmatch/angr_investigation/cle')
sys.path.insert(0, '/home/chen/libmatch/angr_investigation/archinfo')

import cle
from elftools.elf.elffile import ELFFile

binary_path = "/home/chen/connectedhomeip/out/smoke/thread/BRD2601B/matter-silabs-smoke-co-alarm-example.out"

print("Testing CLE architecture detection\n")
print(f"Binary: {binary_path}\n")

# Test using ELFFile directly (what CLE uses internally)
with open(binary_path, 'rb') as f:
    reader = ELFFile(f)

    print(f"Machine: {reader['e_machine']}")
    print(f"Flags: {hex(reader.header.e_flags)}")
    print(f"Little endian: {reader.little_endian}")
    print()

    # Extract ARM attrs using CLE's method
    from cle.backends.elf.elf import ELF
    arm_attrs = ELF._extract_arm_attrs(reader)

    print("ARM Attributes extracted by CLE:")
    if arm_attrs:
        for key, value in arm_attrs.items():
            print(f"  {key}: {value}")
    else:
        print("  None!")
    print()

    # Now test the actual extraction
    arch = ELF.extract_arch(reader)
    print(f"Detected architecture: {arch}")
    print(f"Architecture name: {arch.name}")

print("\n--- Now test with full CLE loader ---")
loader = cle.Loader(binary_path, auto_load_libs=False)
print(f"Main object arch: {loader.main_object.arch}")
print(f"Arch name: {loader.main_object.arch.name}")
