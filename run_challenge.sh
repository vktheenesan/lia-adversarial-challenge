#!/usr/bin/env bash
# ==============================================================================
# LIA Sovereign Formal Verification & Adversarial Challenge Arena
# Librae AI Labs Sdn Bhd • https://github.com/vktheenesan/lia-adversarial-challenge
# ==============================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "Checking Python 3 environment..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

python3 challenge_runner.py "$@"
