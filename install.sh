#!/bin/bash
set -e

ADAPTIX_DIR="${1:-}"

if [ -z "$ADAPTIX_DIR" ]; then
    echo "Usage: ./install.sh /path/to/AdaptixC2"
    exit 1
fi

if [ ! -d "$ADAPTIX_DIR/AdaptixServer" ] || [ ! -d "$ADAPTIX_DIR/AdaptixClient" ]; then
    echo "[-] AdaptixC2 repo topilmadi: $ADAPTIX_DIR"
    exit 1
fi

echo "[*] OpsGraph installing to: $ADAPTIX_DIR"

# Server
echo "[*] Server fayllar..."
mkdir -p "$ADAPTIX_DIR/AdaptixServer/core/opsgraph"
cp server/core/opsgraph/*.go "$ADAPTIX_DIR/AdaptixServer/core/opsgraph/"
cp server/core/connector/tc_opsgraph.go "$ADAPTIX_DIR/AdaptixServer/core/connector/"
cp server/core/database/db_opsgraph*.go "$ADAPTIX_DIR/AdaptixServer/core/database/"
cp server/core/database/opsgraph_schema.sql "$ADAPTIX_DIR/AdaptixServer/core/database/"
cp server/core/server/ts_opsgraph.go "$ADAPTIX_DIR/AdaptixServer/core/server/"

# Client
echo "[*] Client fayllar..."
mkdir -p "$ADAPTIX_DIR/AdaptixClient/Headers/UI/OpsGraph"
mkdir -p "$ADAPTIX_DIR/AdaptixClient/Source/UI/OpsGraph"
cp client/Headers/UI/OpsGraph/*.h "$ADAPTIX_DIR/AdaptixClient/Headers/UI/OpsGraph/"
cp client/Source/UI/OpsGraph/*.cpp "$ADAPTIX_DIR/AdaptixClient/Source/UI/OpsGraph/"

# Patch
echo "[*] Integration patch qo'llanmoqda..."
cd "$ADAPTIX_DIR"
if git apply --check ../opsgraph/patches/opsgraph-integration.patch 2>/dev/null; then
    git apply ../opsgraph/patches/opsgraph-integration.patch
    echo "[+] Patch muvaffaqiyatli qo'llandi"
else
    echo "[!] Patch avval qo'llangan yoki conflict bor — tekshiring"
fi

echo "[+] OpsGraph o'rnatildi. Endi Adaptix'ni rebuild qiling."
