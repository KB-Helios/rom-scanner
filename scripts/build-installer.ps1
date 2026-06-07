# Build standalone Windows executables with PyInstaller.
# Run from the repository root: .\scripts\build-installer.ps1

Param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

$DistDir = Join-Path $RepoRoot "dist"
$ReleaseDir = Join-Path $RepoRoot "release"

if ($Clean) {
    Write-Host "Cleaning build directories..." -ForegroundColor Yellow
    if (Test-Path $DistDir) {
        Remove-Item -Recurse -Force $DistDir
    }
    if (Test-Path $ReleaseDir) {
        Remove-Item -Recurse -Force $ReleaseDir
    }
    Write-Host "Clean complete." -ForegroundColor Green
    exit 0
}

Write-Host "Installing build dependencies..." -ForegroundColor Cyan
python -m pip install -e ".[build,tray]"

Write-Host "Building executables (rom-scanner, rom-scanner-tray)..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --clean rom_scanner.spec

if (-not (Test-Path $DistDir)) {
    Write-Error "PyInstaller dist/ folder not found."
}

New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null
Copy-Item -Force (Join-Path $DistDir "rom-scanner.exe") $ReleaseDir
Copy-Item -Force (Join-Path $DistDir "rom-scanner-tray.exe") $ReleaseDir

Write-Host ""
Write-Host "Build complete." -ForegroundColor Green
Write-Host "  $ReleaseDir\rom-scanner.exe"
Write-Host "  $ReleaseDir\rom-scanner-tray.exe"
Write-Host ""
Write-Host "Deploy:"
Write-Host "  1. Copy release\*.exe to your deployment folder"
Write-Host "  2. Set ROM_SCANNER_HOME and run: rom-scanner.exe init"
Write-Host "  3. Register watch daemon / tray per docs/production-deployment.md"
