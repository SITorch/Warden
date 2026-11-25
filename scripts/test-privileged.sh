#!/usr/bin/env bash
# WARDEN-PRQ-01 — unambiguous privileged qualification runner.
#
# Runs the BPF-LSM pre-opened-fd denial test ONLY when every precondition is
# present, and stops with an explicit SKIP otherwise. A SKIP is never a PASS.
#
# Exit convention (documented for CI and operators):
#   0  PASS   - the privileged test was executed and all assertions succeeded.
#   1  FAIL   - the test ran and failed, or a precondition failed after execution.
#   77 SKIP   - a precondition was absent; the test was NOT executed.
#
# SAFETY: this script loads a BPF-LSM program and performs file denials in the
# current process. Run it ONLY inside a disposable, isolated VM with console
# recovery. Never run it on a production host or the primary development host.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
BIN_DIR="$(pwd)"

skip() {
  printf 'SKIP: %s\n' "$1"
  printf 'SKIP: privileged qualification was NOT executed (exit 77); this is not a PASS.\n'
  exit 77
}

# 1. Root.
[[ "$(id -u)" -eq 0 ]] || skip "not root (CAP_BPF cannot be assumed)"

# 2. CAP_BPF (capability 39) in the effective set.
if ! python3 - <<'PY'
import re, sys
cap_eff = None
with open('/proc/self/status') as f:
    for line in f:
        if line.startswith('CapEff:'):
            cap_eff = int(line.split()[1], 16)
            break
sys.exit(0 if cap_eff is not None and (cap_eff >> 39) & 1 else 1)
PY
then
  skip "CAP_BPF (bit 39) is not in the effective capability set"
fi

# 3. The bpf LSM must be active in the boot lsm= list.
if [[ ! -r /sys/kernel/security/lsm ]]; then
  skip "/sys/kernel/security/lsm is not readable"
fi
if ! grep -qw 'bpf' /sys/kernel/security/lsm; then
  skip "bpf is not in the active LSM list"
fi

# 4. A rebuilt shipped object must exist (the test embeds it at compile time).
[[ -f bpf/warden.bpf.o ]] || skip "bpf/warden.bpf.o is missing (run make bpf)"

echo "PRECONDITIONS: root + CAP_BPF + active bpf LSM + shipped object all present."
echo "Executing privileged BPF-LSM qualification (ignored test) on $(uname -r)."
cargo test --release --locked --offline --test preopened_fd_guard -- \
  --ignored --nocapture
rc=$?
if [[ "$rc" -eq 0 ]]; then
  echo "PASS: privileged BPF-LSM pre-opened-fd qualification executed successfully."
else
  echo "FAIL: privileged BPF-LSM qualification failed (cargo exit $rc)." >&2
fi
exit "$rc"
