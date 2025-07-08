# This file configures Advanced Audit Policies needed for Defender Identity Sensor

param(
    [switch]$Revert
)

$mdiIdentity = "FDS-MDI-Autobot"

# Backup current config into JSON
$fullConfig = Get-MDIConfiguration -Mode Domain -Configuration All -Identity $mdiIdentity -WarningAction SilentlyContinue
$backupPath = "$PSScriptRoot\AuditConfigBackup.json"
$fullConfig | Select-Object Configuration, Status | ConvertTo-Json -Depth 2 | Set-Content -Path $backupPath -Encoding UTF8
Write-Host "Backup complete. Saved to: $backupPath" -ForegroundColor Green

# List of policies that needs to be set
$auditList = @(
    "AdvancedAuditPolicyDCs",
    "ConfigurationContainerAuditing",
    "DomainObjectAuditing",
    "NTLMAuditing"
)

# Applying Advanced Audit Policy settings using PowerShell method
function Apply-Audit{
    foreach($auditItem in $auditList){
        Set-MDIConfiguration -Mode Domain -Configuration $auditItem -Verbose
    }
}

# Reverting Advanced Audit Policy settings
function Revert-Audit{
    $backupConfig = Get-Content $backupPath | ConvertFrom-Json
    foreach($entry in $backupConfig){
        $config = $entry.Configuration
        $status = $entry.Status
        # Set-MDIConfiguration -Mode Domain -Configuration $config
    }
}

# Display the audit configuration before change
Write-Host "Audit policy config before change:" -Foreground Cyan
Get-MDIConfiguration -Mode Domain -Configuration All -Identity FDS-MDI-Autobot -WarningAction SilentlyContinue | Out-Host

if($Revert){
    Revert-Audit
}
else{
    Apply-Audit
}

# Display the audit configuration after change
Write-Host "Audit policy config after change:" -Foreground Cyan
Get-MDIConfiguration -Mode Domain -Configuration All -Identity FDS-MDI-Autobot -WarningAction SilentlyContinue | Out-Host