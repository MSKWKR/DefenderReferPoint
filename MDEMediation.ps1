Import-Module GroupPolicy

$customGPOName = "EndpointRecommendedSettings"
$organizationUnit = Get-ADOrganizationalUnit -Filter 'Name -eq "Domain Controllers"' | Select-Object -ExpandProperty DistinguishedName

if(Get-GPO -Name $customGPOName -ErrorAction SilentlyContinue){
    Write-Host "GPO exists. Proceeding with update..."
    Set-GPLink -Name $customGPOName -Target $organizationUnit -LinkEnabled Yes -Enforced Yes
}
else{
    Write-Host "GPO does not exist. Creating it now..."
    New-GPO -Name $customGPOName -Comment "Group policy that applied recommended settings suggested by Microsoft Defender Endpoint."
    New-GPLink -Name $customGPOName -Target $organizationUnit -LinkEnabled Yes -Enforced Yes
}



$regParams = @{
    UACHardening = @{  
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        ValueName   = "ConsentPromptBehaviorUser"
        Value       = 0
        Type        = "DWORD"
    }

    adminEnumerateLock = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
        ValueName   = "EnumerateAdministrators"
        Value       = 0
        Type        = "DWORD"
    }

    solicitRemoteAccessLock = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        ValueName   = "fAllowToGetHelp"
        Value       = 0
        Type        = "DWORD"
    }

    anonymousEnumerationLock = @{
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
        ValueName   = "RestrictAnonymous"
        Value       = 1
        Type        = "DWORD"
    }

    disableAutoRunCommand = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        ValueName   = "NoAutoRun"
        Value       = 1
        Type        = "DWORD"        
    }
}



foreach($paramBlock in $regParams.Values){
    Set-GPRegistryValue -Name $customGPOName @paramBlock
}
