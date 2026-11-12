#!/usr/bin/env bash
set -euo pipefail
probe_root=$1
parent_namespace=$2
for input in frozen target bin; do
  mount --bind "$probe_root/$input" "$probe_root/$input"
  mount -o remount,bind,ro,nosuid,nodev "$probe_root/$input"
done
for input in frozen target; do
  mount -o remount,bind,ro,nosuid,nodev,noexec "$probe_root/$input"
done
mount --bind "$probe_root/work" "$probe_root/work"
mount -o remount,bind,nosuid,nodev,noexec "$probe_root/work"
exec setpriv --reuid=65534 --regid=65534 --clear-groups \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
  env -i PATH="$probe_root/bin" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    TMPDIR="$probe_root/work" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
    "$probe_root/bin/timeout" --kill-after=5s 420s \
    "$probe_root/bin/python3" -I -B "$probe_root/frozen/probe.py" analyze "$probe_root" "$parent_namespace"
