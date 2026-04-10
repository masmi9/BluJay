# Downloads apktool, jadx, and Android platform-tools into tools/
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ToolsDir = Join-Path $ProjectRoot "tools"
New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

Write-Host "Installing tools to $ToolsDir" -ForegroundColor Cyan

# --- apktool ---
$ApktoolVersion = "2.9.3"
$ApktoolJar = Join-Path $ToolsDir "apktool.jar"
if (-not (Test-Path $ApktoolJar)) {
    Write-Host "Downloading apktool $ApktoolVersion..."
    Invoke-WebRequest -Uri "https://github.com/iBotPeaches/Apktool/releases/download/v$ApktoolVersion/apktool_$ApktoolVersion.jar" `
        -OutFile $ApktoolJar
    Write-Host "apktool downloaded." -ForegroundColor Green
} else {
    Write-Host "apktool already present."
}

# --- jadx ---
$JadxVersion = "1.5.0"
$JadxDir = Join-Path $ToolsDir "jadx"
if (-not (Test-Path $JadxDir)) {
    Write-Host "Downloading jadx $JadxVersion..."
    $TmpZip = [System.IO.Path]::GetTempFileName() + ".zip"
    Invoke-WebRequest -Uri "https://github.com/skylot/jadx/releases/download/v$JadxVersion/jadx-$JadxVersion.zip" `
        -OutFile $TmpZip
    Expand-Archive -Path $TmpZip -DestinationPath $JadxDir
    Remove-Item $TmpZip
    Write-Host "jadx downloaded." -ForegroundColor Green
} else {
    Write-Host "jadx already present."
}

# --- Android platform-tools (adb) ---
$PtDir = Join-Path $ToolsDir "platform-tools"
if (-not (Test-Path $PtDir)) {
    Write-Host "Downloading Android platform-tools..."
    $TmpZip = [System.IO.Path]::GetTempFileName() + ".zip"
    Invoke-WebRequest -Uri "https://dl.google.com/android/repository/platform-tools-latest-windows.zip" `
        -OutFile $TmpZip
    Expand-Archive -Path $TmpZip -DestinationPath $ToolsDir
    Remove-Item $TmpZip
    Write-Host "platform-tools downloaded." -ForegroundColor Green
} else {
    Write-Host "platform-tools already present."
}

Write-Host ""
Write-Host "All tools ready." -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1. cd backend && pip install -r requirements.txt"
Write-Host "  2. cd frontend && npm install"
Write-Host "  3. Start (dev): cd backend && uvicorn main:app --reload --port 8000"
Write-Host "     In another terminal: cd frontend && npm run dev"
