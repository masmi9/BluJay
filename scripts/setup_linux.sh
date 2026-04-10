#!/usr/bin/env bash
# Downloads apktool, jadx, and Android platform-tools (adb) into tools/
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)/tools"
mkdir -p "$TOOLS_DIR"

echo "Installing tools to $TOOLS_DIR"

# --- apktool ---
APKTOOL_VERSION="2.9.3"
APKTOOL_JAR="$TOOLS_DIR/apktool.jar"
if [ ! -f "$APKTOOL_JAR" ]; then
  echo "Downloading apktool $APKTOOL_VERSION..."
  curl -L "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    -o "$APKTOOL_JAR"
  echo "apktool downloaded."
else
  echo "apktool already present."
fi

# --- jadx ---
JADX_VERSION="1.5.0"
JADX_DIR="$TOOLS_DIR/jadx"
if [ ! -d "$JADX_DIR" ]; then
  echo "Downloading jadx $JADX_VERSION..."
  TMP=$(mktemp -d)
  curl -L "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o "$TMP/jadx.zip"
  unzip -q "$TMP/jadx.zip" -d "$JADX_DIR"
  chmod +x "$JADX_DIR/bin/jadx"
  rm -rf "$TMP"
  echo "jadx downloaded."
else
  echo "jadx already present."
fi

# --- Android platform-tools (adb) ---
PLATFORM_TOOLS_DIR="$TOOLS_DIR/platform-tools"
if [ ! -d "$PLATFORM_TOOLS_DIR" ]; then
  echo "Downloading Android platform-tools..."
  TMP=$(mktemp -d)
  curl -L "https://dl.google.com/android/repository/platform-tools-latest-linux.zip" -o "$TMP/pt.zip"
  unzip -q "$TMP/pt.zip" -d "$TOOLS_DIR"
  chmod +x "$PLATFORM_TOOLS_DIR/adb"
  rm -rf "$TMP"
  echo "platform-tools downloaded."
else
  echo "platform-tools already present."
fi

echo ""
echo "All tools ready. Now install Python dependencies:"
echo "  cd backend && pip install -r requirements.txt"
echo ""
echo "And frontend dependencies:"
echo "  cd frontend && npm install"
echo ""
echo "Start the app (dev mode):"
echo "  cd backend && uvicorn main:app --reload --port 8000 &"
echo "  cd frontend && npm run dev"
