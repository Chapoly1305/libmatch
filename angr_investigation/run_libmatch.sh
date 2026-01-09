#!/bin/bash
set -e

echo "=== Patching CLE for ARM Cortex-M support ==="
python3 /libmatch/angr_investigation/patch_cle.py

echo ""
echo "=== Running LibMatch pipeline ==="
cd /libmatch/test_silabs
/libmatch/utils/unblob -U --scoring \
  -L silabs_hal.lmdb \
  -Y /connectedhomeip/out/smoke/thread/BRD2601B/matter-silabs-smoke-co-alarm-example.out \
  results.yml

echo ""
echo "=== Analysis complete! ==="
