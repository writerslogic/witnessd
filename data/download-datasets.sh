#!/usr/bin/env bash
# Download publicly available keystroke dynamics datasets
# Run from the witnessd/data directory

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAW_DIR="${SCRIPT_DIR}/raw"
EXTERNAL_DIR="${SCRIPT_DIR}/external"

echo "=== Keystroke Dynamics Dataset Downloader ==="
echo "Target directory: ${RAW_DIR}"
echo ""

# CMU Keystroke Dynamics Benchmark
echo "[1/4] CMU Keystroke Dynamics Benchmark Dataset"
CMU_DIR="${RAW_DIR}/cmu-keystroke"
if [ ! -d "${CMU_DIR}" ]; then
    mkdir -p "${CMU_DIR}"
    echo "Downloading CMU dataset..."
    curl -L "https://www.cs.cmu.edu/~keystroke/DSL-StrongPasswordData.csv" \
        -o "${CMU_DIR}/DSL-StrongPasswordData.csv"
    echo "Downloaded: DSL-StrongPasswordData.csv"

    # Download the documentation
    curl -L "https://www.cs.cmu.edu/~keystroke/DSL-StrongPasswordData-Documentation.txt" \
        -o "${CMU_DIR}/README.txt" 2>/dev/null || echo "Note: Documentation not available"
else
    echo "Already exists: ${CMU_DIR}"
fi
echo ""

# KeyRecs Dataset from Zenodo
echo "[2/4] KeyRecs Dataset (Zenodo)"
KEYRECS_DIR="${RAW_DIR}/keyrecs"
if [ ! -d "${KEYRECS_DIR}" ]; then
    mkdir -p "${KEYRECS_DIR}"
    echo "Downloading KeyRecs dataset from Zenodo..."
    # Zenodo record 7886743
    curl -L "https://zenodo.org/records/7886743/files/KeyRecs.zip?download=1" \
        -o "${KEYRECS_DIR}/KeyRecs.zip"
    echo "Extracting..."
    unzip -q "${KEYRECS_DIR}/KeyRecs.zip" -d "${KEYRECS_DIR}/"
    rm "${KEYRECS_DIR}/KeyRecs.zip"
    echo "Downloaded and extracted KeyRecs dataset"
else
    echo "Already exists: ${KEYRECS_DIR}"
fi
echo ""

# Mendeley Human vs Synthesized Dataset
echo "[3/4] Mendeley Human vs Synthesized Keystroke Dataset"
MENDELEY_DIR="${RAW_DIR}/mendeley-synthesized"
if [ ! -d "${MENDELEY_DIR}" ]; then
    mkdir -p "${MENDELEY_DIR}"
    echo "Note: Mendeley datasets require manual download."
    echo "Visit: https://data.mendeley.com/datasets/mzm86rcxxd/2"
    echo "Download and extract to: ${MENDELEY_DIR}"
    touch "${MENDELEY_DIR}/.download-manually"
else
    echo "Already exists: ${MENDELEY_DIR}"
fi
echo ""

# IKDD Dataset
echo "[4/4] IKDD Dataset (MDPI)"
IKDD_DIR="${RAW_DIR}/ikdd"
if [ ! -d "${IKDD_DIR}" ]; then
    mkdir -p "${IKDD_DIR}"
    echo "Note: IKDD dataset requires download from MDPI supplementary materials."
    echo "Visit: https://www.mdpi.com/2078-2489/15/9/511"
    echo "Download supplementary materials to: ${IKDD_DIR}"
    touch "${IKDD_DIR}/.download-manually"
else
    echo "Already exists: ${IKDD_DIR}"
fi
echo ""

# Summary
echo "=== Download Summary ==="
echo ""
echo "Automatically downloaded:"
ls -la "${RAW_DIR}/cmu-keystroke" 2>/dev/null | head -5 || echo "  CMU: Not downloaded"
ls -la "${RAW_DIR}/keyrecs" 2>/dev/null | head -5 || echo "  KeyRecs: Not downloaded"
echo ""
echo "Manual download required:"
echo "  - Mendeley: https://data.mendeley.com/datasets/mzm86rcxxd/2"
echo "  - IKDD: https://www.mdpi.com/2078-2489/15/9/511 (supplementary)"
echo ""
echo "Done."
