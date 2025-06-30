#!/bin/bash

# Exit on error
set -e

# Defaults
INPUT_DIR=${1:-"./src"}
LANGUAGE=${2:-"python"}
OUTPUT_DIR=${3:-"./output"}
OUTPUT_FILE="$OUTPUT_DIR/blujay_findings.csv"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Run BluJay
echo "[+] Running BluJay SAST scan..."
blujay scan --input "$INPUT_DIR" --lang "$LANGUAGE" --output "$OUTPUT_FILE"

# Print result path
echo "[+] Report saved to: $OUTPUT_FILE"
