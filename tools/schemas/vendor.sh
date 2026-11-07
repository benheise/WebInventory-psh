#!/usr/bin/env bash
# Copies the schemas WebInventory writes to from a Tideline checkout (benheise/Tideline at a schemas-v* tag) into
# schemas/, with their lines of Tideline's SHA256SUMS, then runs tools/schemas/check.py against src/.
#   tools/schemas/vendor.sh <tideline-checkout> <tag-or-commit>
set -euo pipefail
T=${1:?Tideline checkout}; REF=${2:?tag or commit}
here=$(cd "$(dirname "$0")/../.." && pwd)
src="$T/schemas"
[ -f "$src/SHA256SUMS" ] || { echo "no schemas/SHA256SUMS in $T" >&2; exit 1; }
rm -f "$here"/schemas/*.json "$here/schemas/SHA256SUMS"
for f in "$src"/schemas/tideline-envelope.1.json "$src"/schemas/webinventory.*.json; do cp "$f" "$here/schemas/"; done
grep -E '  schemas/(tideline-envelope|webinventory)\.' "$src/SHA256SUMS" | sed 's#  schemas/#  #' > "$here/schemas/SHA256SUMS"
(cd "$here/schemas" && sha256sum -c --quiet SHA256SUMS)
commit=$(git -C "$T" rev-parse --short=12 "$REF^{commit}" 2>/dev/null || echo "$REF")
cat > "$here/schemas/VENDORED.txt" <<TXT
Vendored from benheise/Tideline schemas/ at $REF (commit $commit) by tools/schemas/vendor.sh, with their lines
of Tideline's SHA256SUMS. Do not edit them here: change them in Tideline, tag a schemas-v* release and vendor again.
tools/schemas/check.py (run in CI) checks they match the columns src/ writes, and tests/v26/contract.py validates
real output against them.
TXT
python3 "$here/tools/schemas/check.py"
