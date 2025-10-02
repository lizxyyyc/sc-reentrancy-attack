#!/bin/bash

set -e
echo "Setting up environment..."
if ! grep -q "noble" /etc/os-release 2>/dev/null; then
    echo "⚠️  Warning: This script is designed for Ubuntu Noble 24.04"
    read -p "Continue anyway? (Y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "Adding required repositories..."
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | sudo tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null
sudo apt-add-repository "deb https://apt.kitware.com/ubuntu/ noble main" -y
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key 2>/dev/null | gpg --dearmor - | sudo tee /etc/apt/trusted.gpg.d/llvm-snapshot.gpg >/dev/null
echo "deb https://apt.llvm.org/noble/ llvm-toolchain-noble-18 main" | sudo tee /etc/apt/sources.list.d/llvm-18.list >/dev/null
sudo apt update

echo "Installing dependencies..."
sudo apt install -y curl git cmake ninja-build clang-18 clang-tools-18 libcurl4-openssl-dev nlohmann-json3-dev libspdlog-dev libssl-dev

echo "✓ Dependencies installed successfully!"
echo "Dependencies verification:"
echo "CMake: $(cmake --version | head -1 | cut -d' ' -f3)"
echo "Ninja: $(ninja --version)"
echo "Clang: $(clang-18 --version | head -1 | cut -d' ' -f4)"
