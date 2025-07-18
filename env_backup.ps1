# Backing up all registries and group policies before deploying automation tools.
Import-Module GroupPolicy

$envBackupPath = "C:\EnvBackup"

if(!(Test-Path $envBackupPath)){
    Write-Host "Backup folder does not exist, creating folder at $envBackupPath..."
    New-Item -Path $envBackupPath -ItemType Directory
}

$regList = @("HKLM", "HKCU", "HKCR", "HKU", "HKCC")
foreach($regType in $regList){
    $filePath = "$envBackupPath\backup$regType.reg"
    Write-Host "Exporting $regType to $filePath..."
    reg export $regType $filePath /y
}

Write-Host "Exporting all GPO backup to $envBackupPath..."
Backup-GPO -All -Path $envBackupPath