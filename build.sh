#!/bin/bash

set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_TYPE="${1:-Debug}"

case "$BUILD_TYPE" in
    release|Release|-r|--release)
        BUILD_TYPE="Release"
        ;;
    debug|Debug|-d|--debug|"")
        BUILD_TYPE="Debug"
        ;;
    -h|--help)
        echo "Usage: $0 [release|debug]"
        echo ""
        echo "  release  Build in Release mode (optimized)"
        echo "  debug    Build in Debug mode (default, with debug info)"
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid argument: $1${NC}"
        echo "Use: $0 [release|debug] or $0 --help"
        exit 1
        ;;
esac

BUILD_DIR="$SCRIPT_DIR/build"
echo -e "${BLUE}Build Type:${NC} $BUILD_TYPE"
echo -e "${BLUE}Build Directory:${NC} $BUILD_DIR"

for tool in clang++-18 clang-18 ninja cmake; do
    command -v $tool &> /dev/null || {
        echo -e "${RED}Required tool not found: $tool${NC}"
        echo -e "${RED}This project requires clang-18 toolchain${NC}"
        exit 1
    }
done
echo -e "${GREEN}✓ Clang-18 toolchain verified${NC}"

CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
echo -e "${BLUE}Parallel jobs: $CORES${NC}"

PRESERVE_FILES=(
    "FancyReentrancy_bytecode.json"
    "UnsafeResolutionHub_bytecode.json"
)
if [ -d "$BUILD_DIR" ]; then
    TEMP_DIR=$(mktemp -d)
    for file in "${PRESERVE_FILES[@]}"; do
        [ -f "$BUILD_DIR/$file" ] && cp "$BUILD_DIR/$file" "$TEMP_DIR/"
    done
    rm -rf "$BUILD_DIR"/* "$BUILD_DIR"/.[^.]* 2>/dev/null || true
    [ "$(ls -A "$TEMP_DIR" 2>/dev/null)" ] && cp "$TEMP_DIR"/* "$BUILD_DIR/" 2>/dev/null || true
    rm -rf "$TEMP_DIR"
else
    mkdir -p "$BUILD_DIR"
fi

cd "$BUILD_DIR"
cmake -G "Ninja" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_CXX_COMPILER="/usr/bin/clang++-18" \
    -DCMAKE_C_COMPILER="/usr/bin/clang-18" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_CXX_STANDARD_REQUIRED=ON \
    -DCMAKE_CXX_SCAN_FOR_MODULES=ON \
    -DCMAKE_RUNTIME_OUTPUT_DIRECTORY="$BUILD_DIR" \
    "$SCRIPT_DIR" || {
    echo -e "${RED}✗ CMake configuration failed${NC}"
    exit 1
}
echo -e "${GREEN}✓ CMake configuration successful${NC}"

ninja -j "$CORES" || {
    echo -e "${RED}✗ Compilation failed${NC}"
    exit 1
}
echo -e "${GREEN}✓ Compilation successful${NC}"

EXPECTED_ORDER=("deploy_vulnerable" "deploy_attackers" "setup_vulnerable" "execute_attack" "withdraw")
echo -e "${BLUE}Executables:${NC}"
for exe in "${EXPECTED_ORDER[@]}"; do
    [ -f "$exe" ] && echo "  $exe"
done

MODULE_COUNT=$(find "$SCRIPT_DIR/include" -name "*.cppm" 2>/dev/null | wc -l)
[ "$MODULE_COUNT" -gt 0 ] && echo -e "${BLUE}Modules compiled: $MODULE_COUNT${NC}"
echo -e "${BLUE}Output directory: $BUILD_DIR${NC}"
