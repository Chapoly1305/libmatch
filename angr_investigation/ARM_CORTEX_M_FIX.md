# ARM Cortex-M Support Investigation & Fix

**Date**: January 9, 2026
**Issue**: angr 9.2.192 fails to detect ARM Cortex-M33 architecture in Silicon Labs Matter firmware
**Error**: `ValueError: Register primask does not exist!`

---

## Root Cause Analysis

### The Problem

When analyzing Silicon Labs Matter firmware (ARM Cortex-M33), angr detects it as **ARMHF** (ARM Hard Float) instead of **ARMCortexM**, causing VEX lifting to fail when encountering Cortex-M specific registers.

### Why This Happens

1. **CLE (Binary Loader) Architecture Detection**: `cle/cle/backends/elf/elf.py` lines 332-341

```python
if "ARM" in arch_str:
    # Check the ARM attributes, if they exist
    arm_attrs = ELF._extract_arm_attrs(reader)
    if arm_attrs and "TAG_CPU_NAME" in arm_attrs:
        if arm_attrs["TAG_CPU_NAME"].endswith("-M") or "Cortex-M" in arm_attrs["TAG_CPU_NAME"]:
            return archinfo.ArchARMCortexM("Iend_LE")
    if reader.header.e_flags & 0x200:
        return archinfo.ArchARMEL("Iend_LE" if reader.little_endian else "Iend_BE")
    elif reader.header.e_flags & 0x400:
        return archinfo.ArchARMHF("Iend_LE" if reader.little_endian else "Iend_BE")
```

2. **Silicon Labs Binary Attributes**:

```
Tag_CPU_name: "8-M.MAIN"
Tag_CPU_arch: v8-M.mainline
Tag_CPU_arch_profile: Microcontroller
```

3. **The Match Failure**:
   - Current check: `arm_attrs["TAG_CPU_NAME"].endswith("-M") or "Cortex-M" in ...`
   - Binary value: `"8-M.MAIN"`
   - Result: Doesn't end with `"-M"` (ends with `"MAIN"`)
   - Result: Doesn't contain `"Cortex-M"` (contains `"-M"` but not `"Cortex-M"`)
   - **Falls through to e_flags check** → Detects hard-float (0x400) → Returns `ArchARMHF`

4. **ARMHF Doesn't Have Cortex-M Registers**:
   - `primask`, `basepri`, `faultmask`, `control` are only in `ArchARMCortexM`
   - VEX lifter tries to access these registers → **ERROR**

---

## The Fix

### Required Change

**File**: `cle/cle/backends/elf/elf.py`, line 336

**Current Code**:
```python
if arm_attrs["TAG_CPU_NAME"].endswith("-M") or "Cortex-M" in arm_attrs["TAG_CPU_NAME"]:
    return archinfo.ArchARMCortexM("Iend_LE")
```

**Fixed Code**:
```python
cpu_name = arm_attrs["TAG_CPU_NAME"]
# Check for Cortex-M: explicit name, ARMv*-M variants, or architecture profile
if ("Cortex-M" in cpu_name or
    "-M" in cpu_name or  # Matches "7-M", "8-M.MAIN", "8-M.BASE", etc.
    cpu_name.endswith("-M")):  # Matches older "7-M" style
    return archinfo.ArchARMCortexM("Iend_LE")

# Alternative: Also check TAG_CPU_ARCH_PROFILE if available
if arm_attrs.get("TAG_CPU_ARCH_PROFILE") == 77:  # 'M' = Microcontroller profile
    return archinfo.ArchARMCortexM("Iend_LE")
```

### Why This Works

- **"8-M.MAIN"** contains `"-M"` ✅
- **"7-M"** ends with `"-M"` ✅
- **"Cortex-M3"**, **"Cortex-M4"**, **"Cortex-M33"** contain `"Cortex-M"` ✅
- Alternative check using `TAG_CPU_ARCH_PROFILE = 77` (ASCII 'M') catches edge cases

---

## ARMCortexM Architecture Support

### Registers Already Defined

**File**: `archinfo/archinfo/arch_arm.py`, class `ArchARMCortexM` (line 361)

The `ArchARMCortexM` class **already has** all necessary Cortex-M specific registers:

```python
Register(name="faultmask", size=4, default_value=(0, False, None)),
Register(name="faultmask_s", size=4, default_value=(0, False, None)),
Register(name="faultmask_ns", size=4, default_value=(0, False, None)),

Register(name="basepri", size=4, default_value=(0, False, None)),
Register(name="basepri_s", size=4, default_value=(0, False, None)),
Register(name="basepri_ns", size=4, default_value=(0, False, None)),

Register(name="primask", size=4, default_value=(0, False, None)),
Register(name="primask_s", size=4, default_value=(0, False, None)),
Register(name="primask_ns", size=4, default_value=(0, False, None)),

Register(name="control", size=4, default_value=(0, False, None)),
```

**Note**: Includes TrustZone variants (`_s` for secure, `_ns` for non-secure)

### Architecture Registration

**File**: `archinfo/archinfo/arch_arm.py`, line 556

```python
register_arch([r".*cortexm|.*cortex\-m.*|.*v7\-m.*"], 32, Endness.ANY, ArchARMCortexM)
```

This handles architecture string matching for:
- `.*cortexm.*` - "cortexm" variants
- `.*cortex-m.*` - "cortex-m" with hyphens
- `.*v7-m.*` - ARMv7-M architecture strings

**Issue**: This doesn't help because CLE returns an `Arch` object directly, not an architecture string that goes through this regex matching.

---

## Implementation Strategy

### Option 1: Patch Local CLE (Quick Fix)

1. Clone CLE: ✅ Done
2. Edit `cle/cle/backends/elf/elf.py` line 336
3. Install patched CLE in Docker:
   ```bash
   pip uninstall cle
   pip install -e ./cle
   ```
4. Test with Silicon Labs firmware

### Option 2: Contribute to angr Project (Long-term)

1. Fork angr/cle repository
2. Create branch: `fix/arm-cortex-m-detection`
3. Implement comprehensive fix with tests
4. Submit Pull Request to angr project

**Test Cases to Add**:
- ARMv7-M binaries (Cortex-M3, M4)
- ARMv8-M.BASE binaries (Cortex-M23)
- ARMv8-M.MAIN binaries (Cortex-M33, M35P) ← **Our case**
- ARMv8.1-M.MAIN binaries (Cortex-M55, M85)

### Option 3: Use angr-management or IDA Integration

LibMatch has IDA Pro integration stubs (`bdsig/ida_it.py`, `bdsig/ida_decomp.py`). Could:
1. Use IDA for initial CFG analysis
2. Export function information
3. Use libmatch's matching algorithms

---

## Testing Plan

### Test 1: Verify Architecture Detection

```python
import cle
binary = "/home/chen/connectedhomeip/out/smoke/thread/BRD2601B/matter-silabs-smoke-co-alarm-example.out"
loader = cle.Loader(binary, auto_load_libs=False)
print(f"Detected: {loader.main_object.arch.name}")
# Expected: "ARMCortexM"
# Currently: "ARMHF"
```

### Test 2: Verify Register Access

```python
import angr
p = angr.Project(binary, auto_load_libs=False)
arch = p.arch
print(f"Has primask: {arch.get_register_offset('primask')}")
# Should succeed after fix
```

### Test 3: Full LibMatch Pipeline

```bash
docker run --rm \
  -v /home/chen/connectedhomeip:/connectedhomeip \
  -v /home/chen/libmatch:/libmatch \
  libmatch \
  /libmatch/utils/unblob -U --scoring \
  -L /libmatch/test_silabs/silabs_hal.lmdb \
  -Y /connectedhomeip/out/smoke/thread/BRD2601B/matter-silabs-smoke-co-alarm-example.out \
  results.yml
```

Expected: Should complete CFG analysis and function matching without errors.

---

## Affected ARM Cortex-M Variants

| Series | Architecture | CPU Names | Status |
|--------|--------------|-----------|---------|
| Cortex-M0/M0+ | ARMv6-M | "6-M" | May work |
| Cortex-M3 | ARMv7-M | "7-M", "Cortex-M3" | Should work |
| Cortex-M4/M7 | ARMv7-M | "7-M", "Cortex-M4/7" | Should work |
| Cortex-M23 | ARMv8-M.BASE | "8-M.BASE" | **BROKEN** |
| Cortex-M33/M35P | ARMv8-M.MAIN | "8-M.MAIN" | **BROKEN** ← Silicon Labs |
| Cortex-M55/M85 | ARMv8.1-M.MAIN | "8.1-M.MAIN" | **BROKEN** |

---

## Recommended Fix (Comprehensive)

```python
@staticmethod
def extract_arch(reader):
    e_machine_header_val = reader["e_machine"]
    arch_str = None
    if isinstance(e_machine_header_val, str):
        arch_str = e_machine_header_val
    elif isinstance(e_machine_header_val, int):
        if e_machine_header_val in additional_e_machine_mappings:
            arch_str = additional_e_machine_mappings[e_machine_header_val]
        else:
            raise CLECompatibilityError(
                f"The `e_machine` header value of the ELF file is not known: {e_machine_header_val}"
            )
    else:
        assert False

    if "ARM" in arch_str:
        # Check the ARM attributes, if they exist
        arm_attrs = ELF._extract_arm_attrs(reader)

        if arm_attrs:
            # Check for Cortex-M by CPU name
            if "TAG_CPU_NAME" in arm_attrs:
                cpu_name = arm_attrs["TAG_CPU_NAME"]
                # Match Cortex-M variants:
                # - Explicit: "Cortex-M3", "Cortex-M4", "Cortex-M33", etc.
                # - ARMv*-M: "6-M", "7-M", "8-M.MAIN", "8-M.BASE", "8.1-M.MAIN", etc.
                if "Cortex-M" in cpu_name or "-M" in cpu_name:
                    return archinfo.ArchARMCortexM("Iend_LE")

            # Alternative: Check CPU architecture profile (Tag 7)
            # Value 77 = 'M' = Microcontroller profile (Cortex-M)
            if "TAG_CPU_ARCH_PROFILE" in arm_attrs:
                if arm_attrs["TAG_CPU_ARCH_PROFILE"] == 77:  # 'M' profile
                    return archinfo.ArchARMCortexM("Iend_LE")

        # Fall back to e_flags based detection
        if reader.header.e_flags & 0x200:
            return archinfo.ArchARMEL("Iend_LE" if reader.little_endian else "Iend_BE")
        elif reader.header.e_flags & 0x400:
            return archinfo.ArchARMHF("Iend_LE" if reader.little_endian else "Iend_BE")

    try:
        return archinfo.arch_from_id(arch_str, "le" if reader.little_endian else "be", reader.elfclass)
    except archinfo.ArchNotFound:
        # ... rest of function
```

---

## Summary

**Issue**: CLE's ARM architecture detection doesn't recognize ARMv8-M binaries as Cortex-M
**Cause**: Check for `endswith("-M")` fails on "8-M.MAIN" (ends with "MAIN")
**Fix**: Change to `"-M" in cpu_name` to catch all ARMv*-M variants
**Impact**: Enables libmatch to work with modern ARM Cortex-M33/M55/M85 firmware
**Effort**: Single line change in CLE + testing

**Status**: Ready to implement and test!

---

## Next Steps

1. ✅ Investigation complete
2. ⏭️ Apply patch to local CLE clone
3. ⏭️ Install patched CLE in Docker
4. ⏭️ Test with Silicon Labs firmware
5. ⏭️ Document results
6. ⏭️ (Optional) Submit PR to angr project

