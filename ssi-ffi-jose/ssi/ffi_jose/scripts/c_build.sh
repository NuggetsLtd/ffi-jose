#!/bin/sh

BLUE='\033[1;36m'
GREEN='\033[1;32m'
NC='\033[0m' # No Color

echo ""
echo "${BLUE}----- ⏳ BUILD: C -> RUST FOREIGN FUNCTION INTERFACE ----------------------------------${NC}"
echo ""
pwd
CARGO_CFG_TARGET_OS='ios' CARGO_CFG_FEATURE='c' CARGO_CFG_MANIFEST_DIR='.' neon build --release
echo ""
echo "${GREEN}----- ✅ DONE: C -> RUST FOREIGN FUNCTION INTERFACE ----------------------------------${NC}"
echo ""
