#!/bin/bash

# AI Emergency Tools Installation Script
# Updated for Python 3 compatibility

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Installing AI Emergency Tools..."

# Check Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "[!] Error: python3 is not installed. Please install Python 3 first."
    exit 1
fi

# Check pip3 is available
if ! command -v pip3 &> /dev/null; then
    echo "[!] Error: pip3 is not installed. Please install pip3 first."
    exit 1
fi

# Install required Python packages
echo "[*] Installing required Python packages..."
pip3 install --upgrade pip
pip3 install psutil

# Note: simplejson, httplib, mimetypes are built-in modules in Python 3
# - simplejson replaced by 'json' module
# - httplib replaced by 'http.client' module
# - mimetypes is part of Python standard library

# Detect shell configuration file
SHELL_CONFIG=""
if [ -n "$ZSH_VERSION" ]; then
    SHELL_CONFIG="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
        SHELL_CONFIG="$HOME/.bashrc"
    else
        SHELL_CONFIG="$HOME/.bash_profile"
    fi
else
    SHELL_CONFIG="$HOME/.profile"
fi

echo "[*] Shell config file: $SHELL_CONFIG"

# Remove old aliases if they exist
echo "[*] Removing old aliases (if any)..."
sed -i '/alias emg=/d' "$SHELL_CONFIG" 2>/dev/null || true
sed -i '/alias whois=/d' "$SHELL_CONFIG" 2>/dev/null || true
sed -i '/alias vt=/d' "$SHELL_CONFIG" 2>/dev/null || true

# Add new aliases
echo "[*] Adding aliases to $SHELL_CONFIG..."
cat >> "$SHELL_CONFIG" << EOF

# AI Emergency Tools aliases
alias emg='python3 $SCRIPT_DIR/emergency.py'
alias whois='python3 $SCRIPT_DIR/mywhois.py'
alias vt='python3 $SCRIPT_DIR/virustotal.py'
EOF

echo "[+] Installation complete!"
echo "[*] Please run: source $SHELL_CONFIG"
echo "[*] Or restart your shell to use the aliases."
echo ""
echo "Available commands:"
echo "  emg  - Linux emergency process and network info viewer"
echo "  vt   - VirusTotal threat intelligence checker"
echo "  whois - Domain whois lookup"
