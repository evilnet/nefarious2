#!/bin/sh
# Run the crdt_hlc CBMC proofs.  Exit non-zero on any failure.
cd "$(dirname "$0")" || exit 1
rc=0
for f in harness_local_event harness_receive harness_compare; do
  printf '%-22s ' "$f"
  if cbmc -Istubs -I../../../include crdt_hlc_harness.c --function "$f" \
       --bounds-check --pointer-check --signed-overflow-check \
       --unsigned-overflow-check >"$f.log" 2>&1; then
    echo OK
  else
    echo FAIL; grep FAILURE "$f.log"; rc=1
  fi
done
exit $rc
