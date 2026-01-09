#!/usr/bin/env python3
"""Test script to examine ARM attributes in ELF binary"""

from elftools.elf.elffile import ELFFile
from elftools.elf import sections

binary_path = "/home/chen/connectedhomeip/out/smoke/thread/BRD2601B/matter-silabs-smoke-co-alarm-example.out"

with open(binary_path, 'rb') as f:
    elf = ELFFile(f)

    # Find ARM attributes section
    attrs_sec = elf.get_section_by_name(".ARM.attributes")

    if not attrs_sec:
        print("No .ARM.attributes section found")
        exit(1)

    print(f"Found .ARM.attributes section")
    print(f"Subsections: {len(attrs_sec.subsections)}")

    for subsec in attrs_sec.subsections:
        print(f"\n  Subsection type: {type(subsec).__name__}")
        if isinstance(subsec, sections.ARMAttributesSubsection):
            print(f"  Sub-subsections: {len(subsec.subsubsections)}")
            for subsubsec in subsec.subsubsections:
                print(f"\n    Sub-subsection type: {type(subsubsec).__name__}")
                if isinstance(subsubsec, sections.ARMAttributesSubsubsection):
                    print(f"    Attributes:")
                    for attr in subsubsec.attributes:
                        print(f"      Tag: {attr.tag} (type: {type(attr.tag).__name__})")
                        print(f"      Value: {attr.value}")
                        print(f"      Extra: {attr.extra if hasattr(attr, 'extra') else 'N/A'}")
                        print()
