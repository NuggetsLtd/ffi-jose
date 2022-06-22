#!/bin/sh

BLUE='\033[1;36m'
GREEN='\033[1;32m'
NC='\033[0m' # No Color

echo ""
echo "${BLUE}----- ⏳ BUILD: C -> RUST FOREIGN FUNCTION INTERFACE ----------------------------------${NC}"
echo ""
CARGO_CFG_TARGET_OS='ios' CARGO_CFG_FEATURE='c' CARGO_CFG_MANIFEST_DIR='.' neon build --release
echo ""
echo "${GREEN}----- ✅ DONE: C -> RUST FOREIGN FUNCTION INTERFACE ----------------------------------${NC}"
echo ""

echo ""
echo "${BLUE}----- ⏳ COMPILE: C TEST CODE ---------------------------------------------------------${NC}"
echo ""
gcc c/main.c -L native/target/release/ -lffi_jose -o c/test.out
echo ""
echo "${GREEN}----- ✅ DONE: C TEST CODE -----------------------------------------------------------${NC}"
echo ""

echo ""
echo "${BLUE}----- ⏳ RUN: C TEST CODE -------------------------------------------------------------${NC}"
echo ""
c/test.out
echo ""
echo "${GREEN}----- ✅ DONE: C TEST CODE -----------------------------------------------------------${NC}"
echo ""
