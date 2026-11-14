#!/usr/bin/env bash
set -euo pipefail
probe_root=$(mktemp -d /tmp/node115-r11-XXXXXXXX)
chmod 755 "$probe_root"
mkdir "$probe_root/output" "$probe_root/target" "$probe_root/work" "$probe_root/bin"
mkdir -p "$GITHUB_WORKSPACE/probe-receipts"
cp -R payload "$probe_root/frozen"
collect() {
  /usr/bin/python3 -I -B "$probe_root/frozen/probe.py" collect "$probe_root" "$GITHUB_WORKSPACE/probe-receipts"
}
trap collect EXIT
timeout --kill-after=5s 100s /usr/bin/python3 -I -B "$probe_root/frozen/probe.py" prepare "$probe_root"
chmod 777 "$probe_root/output"
sudo chown 65534:65534 "$probe_root/work"
parent_namespace=$(readlink /proc/self/ns/net)
sudo unshare --mount --net --pid --fork --mount-proc --propagation private \
  /bin/bash "$probe_root/frozen/isolate.sh" "$probe_root" "$parent_namespace"
