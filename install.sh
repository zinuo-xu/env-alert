#!/usr/bin/env bash
#
# env-alert installer
# Usage: curl -fsSL https://raw.githubusercontent.com/zinuo-xu/env-alert/main/install.sh | bash
#

set -euo pipefail

REPO="zinuo-xu/env-alert"
TOOL_NAME="env-alert"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${ARCH}" in
    x86_64)  ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)
        echo "Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

case "${OS}" in
    linux|darwin) ;;
    *)
        echo "Unsupported OS: ${OS}"
        echo "Please install via cargo: cargo install ${TOOL_NAME}"
        exit 1
        ;;
esac

# Get the latest release version
echo "Fetching latest release..."
VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)

if [ -z "${VERSION}" ]; then
    echo "Failed to fetch latest version. Falling back to cargo install..."
    if command -v cargo &>/dev/null; then
        cargo install "${TOOL_NAME}"
    else
        echo "Error: Could not find cargo. Please install Rust: https://rustup.rs"
        exit 1
    fi
    exit 0
fi

echo "Downloading ${TOOL_NAME} ${VERSION} for ${OS}/${ARCH}..."
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TOOL_NAME}-${VERSION}-${OS}-${ARCH}.tar.gz"
TMP_DIR=$(mktemp -d)
TAR_FILE="${TMP_DIR}/${TOOL_NAME}.tar.gz"

if ! curl -fsSL "${DOWNLOAD_URL}" -o "${TAR_FILE}"; then
    echo "Pre-built binary not available for this platform. Falling back to cargo install..."
    rm -rf "${TMP_DIR}"
    if command -v cargo &>/dev/null; then
        cargo install "${TOOL_NAME}"
    else
        echo "Error: Could not find cargo. Please install Rust: https://rustup.rs"
        exit 1
    fi
    exit 0
fi

echo "Extracting..."
tar -xzf "${TAR_FILE}" -C "${TMP_DIR}"

echo "Installing to ${INSTALL_DIR}/${TOOL_NAME}..."
mkdir -p "${INSTALL_DIR}"
cp "${TMP_DIR}/${TOOL_NAME}" "${INSTALL_DIR}/${TOOL_NAME}"
chmod +x "${INSTALL_DIR}/${TOOL_NAME}"

rm -rf "${TMP_DIR}"

echo ""
echo "env-alert ${VERSION} installed successfully!"
echo "Run 'env-alert --help' to get started."
