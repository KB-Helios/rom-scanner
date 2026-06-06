# ROM Scanner production installer (Windows)
# Run from the repository root: .\scripts\install.ps1

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

Write-Host "Installing rom-scanner with tray extras..." -ForegroundColor Cyan
python -m pip install -e ".[tray]"

Write-Host "Initializing ROM_SCANNER_HOME layout..." -ForegroundColor Cyan
rom-scanner init

$TaskName = "RomScannerWatch"
$WatchCommand = "rom-scanner watch --daemon"

Write-Host "Registering Task Scheduler job: $TaskName" -ForegroundColor Cyan
$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $WatchCommand"
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "ROM Scanner watch daemon" | Out-Null
Write-Host "Scheduled task registered (runs at logon)." -ForegroundColor Green

$StartupFolder = [Environment]::GetFolderPath("Startup")
$TrayShortcut = Join-Path $StartupFolder "ROM Scanner Tray.lnk"
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($TrayShortcut)
$Shortcut.TargetPath = "rom-scanner-tray"
$Shortcut.WorkingDirectory = $RepoRoot
$Shortcut.Description = "ROM Scanner system tray notifier"
$Shortcut.Save()
Write-Host "Tray shortcut created: $TrayShortcut" -ForegroundColor Green

Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
Write-Host "  Pipeline home: $env:ROM_SCANNER_HOME (default C:\RomScanner if unset)"
Write-Host "  Watch daemon: registered as scheduled task '$TaskName'"
Write-Host "  Tray app: starts at logon via Startup shortcut"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Copy config/sandboxie/RomQuarantine.ini into Sandboxie-Plus (see docs/sandboxie-setup.md)"
Write-Host "  2. Set VIRUSTOTAL_API_KEY if using VirusTotal lookups"
Write-Host "  3. Run rom-scanner-tray or reboot to start the tray notifier"
