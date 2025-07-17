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
    # Set User Account Control (UAC) to automatically deny elevation requests
    UACHardening = @{  
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        ValueName   = "ConsentPromptBehaviorUser"
        Value       = 0
        Type        = "DWORD"
    }

    # Disable 'Enumerate administrator accounts on elevation'
    adminEnumerateLock = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
        ValueName   = "EnumerateAdministrators"
        Value       = 0
        Type        = "DWORD"
    }

    # Disable Solicited Remote Assistance
    solicitRemoteAccessLock = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        ValueName   = "fAllowToGetHelp"
        Value       = 0
        Type        = "DWORD"
    }

    # Disable Anonymous enumeration of shares
    anonymousEnumerationLock = @{
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
        ValueName   = "RestrictAnonymous"
        Value       = 1
        Type        = "DWORD"
    }

    # Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands'
    disableAutoRunCommand = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        ValueName   = "NoAutoRun"
        Value       = 1
        Type        = "DWORD"        
    }

    # Enable 'Local Security Authority (LSA) protection'
    enableLSA = @{
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
        ValueName   = "RunAsPPL"
        Value       = 1
        Type        = "DWORD"         
    }

    # Set controlled folder access to enabled or audit mode
    controlledFolderAccess = @{
        Key         = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
        ValueName   = "EnableControlledFolderAccess"
        Value       = 1
        Type        = "DWORD"         
    }

    # Disable 'Autoplay for non-volume devices'
    disableNonVolumeAutoplay = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        ValueName   = "NoAutoplayfornonVolume"
        Value       = 1
        Type        = "DWORD"
    }

    # Disable 'Autoplay' for all drives
    disableDriverAutoplay = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        ValueName   = "NoDriveTypeAutoRun"
        Value       = 255
        Type        = "DWORD"
    }

    # Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'
    refuseNTLM = @{
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
        ValueName   = "LmCompatibilityLevel"
        Value       = 5
        Type        = "DWORD"        
    }

    # Disable 'Allow Basic authentication' for WinRM Client
    disableBasicAuthenCLient = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        ValueName   = "AllowBasic"
        Value       = 0
        Type        = "DWORD" 
    }

    # Disable 'Allow Basic authentication' for WinRM Service
    disableBasicAuthenService = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        ValueName   = "AllowBasic"
        Value       = 0
        Type        = "DWORD" 
    }

    # Set IPv6 source routing to highest protection
    ipv6Protection = @{
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        ValueName   = "DisableIPSourceRouting"
        Value       = 2
        Type        = "DWORD"        
    }

    # Disable IP source routing
    ipv4Protection = @{
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        ValueName   = "DisableIPSourceRouting"
        Value       = 2
        Type        = "DWORD"         
    }

    # Disable the local storage of passwords and credentials
    disableLocalCredStorage = @{
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
        ValueName   = "DisableDomainCreds"
        Value       = 1
        Type        = "DWORD"        
    }

    # Enable 'Network Protection'
    enableNetworkProtection = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
        ValueName   = "EnableNetworkProtection"
        Value       = 1
        Type        = "DWORD"          
    }

    # Turn on PUA protection in block mode
    enablePUAProtection = @{
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
        ValueName   = "PUAProtection"
        Value       = 1
        Type        = "DWORD"        
    }
}



foreach($paramBlock in $regParams.Values){
    Set-GPRegistryValue -Name $customGPOName @paramBlock -Verbose
}
Write-Host "Finished creating GPO."