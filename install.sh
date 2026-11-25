#!/bin/bash
set -euo pipefail

ADAPTIX_DIR="${1%/}"
[ -z "$ADAPTIX_DIR" ] && { echo "Usage: ./install.sh /path/to/AdaptixC2"; exit 1; }
[ ! -d "$ADAPTIX_DIR/AdaptixServer" ] && { echo "[-] Not AdaptixC2: $ADAPTIX_DIR"; exit 1; }

OPSGRAPH_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "[*] OpsGraph installing to: $ADAPTIX_DIR"

# ─── 1) SERVER: yangi fayllar ───
echo "[*] Server files..."
mkdir -p "$ADAPTIX_DIR/AdaptixServer/core/opsgraph"
cp "$OPSGRAPH_DIR"/server/core/opsgraph/*.go            "$ADAPTIX_DIR/AdaptixServer/core/opsgraph/"
cp "$OPSGRAPH_DIR"/server/core/connector/tc_opsgraph.go "$ADAPTIX_DIR/AdaptixServer/core/connector/"
cp "$OPSGRAPH_DIR"/server/core/server/ts_opsgraph.go    "$ADAPTIX_DIR/AdaptixServer/core/server/"
cp "$OPSGRAPH_DIR"/server/core/database/db_opsgraph*.go "$ADAPTIX_DIR/AdaptixServer/core/database/"
cp "$OPSGRAPH_DIR"/server/core/database/opsgraph_schema.sql "$ADAPTIX_DIR/AdaptixServer/core/database/"

# ─── 2) SERVER: upstream modified files (override) ───
echo "[*] Upstream modified files (OpsGraph integration)..."
cp "$OPSGRAPH_DIR"/server/core/database/database.go     "$ADAPTIX_DIR/AdaptixServer/core/database/"
cp "$OPSGRAPH_DIR"/server/core/server/server.go         "$ADAPTIX_DIR/AdaptixServer/core/server/"
cp "$OPSGRAPH_DIR"/server/core/server/utils.go          "$ADAPTIX_DIR/AdaptixServer/core/server/"
cp "$OPSGRAPH_DIR"/server/core/server/ts_agent.go       "$ADAPTIX_DIR/AdaptixServer/core/server/"

# ─── 3) CLIENT ───
echo "[*] Client files..."
mkdir -p "$ADAPTIX_DIR/AdaptixClient/Headers/UI/OpsGraph"
mkdir -p "$ADAPTIX_DIR/AdaptixClient/Source/UI/OpsGraph"
cp "$OPSGRAPH_DIR"/client/Headers/UI/OpsGraph/*.h   "$ADAPTIX_DIR/AdaptixClient/Headers/UI/OpsGraph/"
cp "$OPSGRAPH_DIR"/client/Source/UI/OpsGraph/*.cpp  "$ADAPTIX_DIR/AdaptixClient/Source/UI/OpsGraph/"

if [ -d "$OPSGRAPH_DIR/client/Assets/OpsGraph" ]; then
    mkdir -p "$ADAPTIX_DIR/AdaptixClient/Assets"
    cp -r "$OPSGRAPH_DIR/client/Assets/OpsGraph" "$ADAPTIX_DIR/AdaptixClient/Assets/"
fi

# ─── 4) IMPORT PATH REWRITE ───
MODULE=$(awk '/^module /{print $2; exit}' "$ADAPTIX_DIR/AdaptixServer/go.mod")
echo "[*] Module: $MODULE"
find "$ADAPTIX_DIR/AdaptixServer" -name "*.go" -type f \
     -exec grep -l '"opsgraph/server/' {} \; 2>/dev/null \
  | while read -r f; do
      sed -i "s|\"opsgraph/server/|\"${MODULE}/|g" "$f"
  done

# ─── 5) PATCH (3-way detect) ───
PATCH="$OPSGRAPH_DIR/patches/opsgraph-integration.patch"
cd "$ADAPTIX_DIR"
if git apply --reverse --check "$PATCH" 2>/dev/null; then
    echo "[+] Patch allaqachon qo'llangan — skip"
elif git apply --check "$PATCH" 2>/dev/null; then
    git apply "$PATCH"
    echo "[+] Patch qo'llandi"
else
    echo "[!] Patch conflict — qo'lda tekshiring:"
    git apply --check "$PATCH"
    exit 1
fi

echo "[+] OpsGraph o'rnatildi. Endi: make all"
