# This file configures Advanced Audit Policies needed for Defender Identity Sensor

# Display the audit configuration before change
Write-Host "Audit policy config before change:"
Get-MDIConfiguration -Mode Domain -Configuration All

# List of policies that needs to be set
$auditList = @(
    "AdvancedAuditPolicyDCs",
    "ConfigurationContainerAuditing",
    "DomainObjectAuditing",
    "NTLMAuditing"
)
# Configuring Advanced Audit Policy settings using PowerShell method
foreach($auditItem in $auditList){
    Set-MDIConfiguration -Mode Domain -Configuration $auditItem -Verbose
}

# Display the audit configuration after change
Write-Host "Audit policy config after change:"
Get-MDIConfiguration -Mode Domain -Configuration All