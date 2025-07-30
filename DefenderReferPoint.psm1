# Hash table of all available ASR rules
$asrRuleMap = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
    "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools"
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
}

function Confirm-Module{
    <#
        .SYNOPSIS
        Helper function to ensure required modules are installed and imported for the function.
        .PARAMETER Name
        Name of the function calling the helper function.
        .Functionality
        Internal
    #>
    param(
        [parameter(Mandatory=$true)]
        [string]$Name
    )
    $requirementsMap = @{
        "Backup-Env"    = @("GroupPolicy")
        "Set-ASR"       = @("Defender")
        "Set-Audit"     = @("DefenderForIdentity")
    }
    foreach($module in $requirementsMap[$Name]){
        try{
            if(Get-Module -ListAvailable -Name $module){
                Import-Module $module
            }
            else{
                Write-Host "Required Module: $module not found, please ensure it is installed." -ForegroundColor Red
                switch($module){
                    "GroupPolicy"{
                        Write-Host "If your machine is a Windows Server try: Install-WindowsFeature GPMC" -ForegroundColor Yellow
                        Write-Host "If your machine is a Windows Client try: Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0" -ForegroundColor Yellow
                    }
                    "Defender"{
                        Write-Host "Please ensure Windows Defender is enabled." -ForegroundColor Yellow
                    }
                    "DefenderForIdentity"{
                        Write-Host "To install the module: Install-Module -Name DefenderForIdentity" -ForegroundColor Yellow
                    }
                }
                throw "Module: $module not installed."
            }
        }
        catch{
            Write-Host "Failed to import module: $module. Exiting script." -ForegroundColor Red
            Write-Host $_.Exception.Message
            throw $_
        }
    }
}

function Backup-Env{
    <#
        .SYNOPSIS
        Create a backup folder for all group policy objects and registries.
        .PARAMETER Path
        Path to a folder where the backups are saved. Defaults to the 'C:\EnvBackup' folder.
        .PARAMETER Name
        Name of the backup folder to be created. Defaults to the backup date.
        .PARAMETER Overwrite
        If specified, the folder will be overwritten without prompting.
        If omitted, the user will be asked whether to overwrite.
        .EXAMPLE
        Backup-Env -Path "C:\temp\myBackupFolder" -Name "Version1.0" -Overwrite
        .Functionality
        Public
    #>
    param(
        [string]$Path = "C:\EnvBackup",
        [string]$Name = (Get-Date -Format "yyyy-MM-dd"),
        [switch]$Overwrite
    )
    # Load required modules
    Confirm-Module -Name "Backup-Env"

    function Modify-Folder{
        <#
            .SYNOPSIS
            Helper function for applying operations on folders.
            .PARAMETER Operation
            Choose the operation to perform on the folder. Options include: Create, Remove, Copy.
            .PARAMETER sourcePath
            Path to the folder to be operated on. If Operation is Copy, this would be the source folder path.
            .PARAMETER destinationPath
            Required if Operation is Copy, this is the destination folder path.
            .Functionality
            Internal 
        #>
        param(
            [ValidateSet("Create", "Remove", "Copy")]
            [string]$Operation,
            [string]$sourcePath,
            [string]$destinationPath
        )
        try{
            switch($Operation){
                "Create"    { New-Item -Path $sourcePath -ItemType Directory -ErrorAction Stop > $null }
                "Remove"    { Remove-Item -Path $sourcePath -Recurse -Force -ErrorAction Stop }
                "Copy"      { Copy-Item -Path $sourcePath\* -Destination $destinationPath -Recurse -Force -ErrorAction Stop}
            }
            Write-Host "Successfully $Operation folder: $sourcePath" -ForegroundColor Cyan
        }
        catch{
            Write-Host "Failed to $Operation folder: $sourcePath" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            throw $_
        }
    }

    # Preparing backup directory
    if(!(Test-Path $Path)){
        Write-Host "Backup directory does not exist, creating directory at $Path..."
        Modify-Folder -Operation Create -sourcePath $Path
    }
    else{
        Write-Host "Backup directory exists, proceeding..." -ForegroundColor Cyan
    }

    # Preparing temp folder in %temp%
    $tempFolder = Join-Path -Path $env:TEMP -ChildPath "derp_temp"
    if((Test-Path $tempFolder)){
        Write-Host "Removing unresolved temp folder..."
        Modify-Folder -Operation Remove -sourcePath $tempFolder
    }
    Write-Host "Creating temp folder..."
    Modify-Folder -Operation Create -sourcePath $tempFolder
    
    # Backingup GPO settings
    Write-Host "Exporting all GPO backup to $tempFolder..."
    try{
        Backup-GPO -All -Path $tempFolder -ErrorAction Stop > $tempFolder\gpo.log
        Write-Host "Successfully exported GPO settings to $tempFolder" -ForegroundColor Cyan
    }
    catch{
        Write-Host "Failed to export GPO settings to $tempFolder" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            throw $_
    }
    
    # Backingup ASR settings from MpPreference
    $asrValueMap = @{}
    try{
        $MpPreference = Get-MpPreference
        $asrList = @($($MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids))
        foreach($asrId in $asrList){
            $asrValueMap[$asrId] = $MpPreference.AttackSurfaceReductionRules_Actions[$MpPreference.AttackSurfaceReductionRules_Ids.Indexof($asrId)]
        }
        $asrValueMap | ConvertTo-Json | Out-File -FilePath $tempFolder\asr.json
    }
    catch{
        Write-Host "Failed to export ASR settings to $tempFolder" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        throw $_
    }

    # Copying contents from temp into target folder
    $backupFolder = Join-Path -Path $Path -ChildPath $Name
    if(Test-Path $backupFolder){
        # If overwrite tag is unspecified then prompt for overwrite
        if(!($Overwrite.IsPresent)){
            $retries = 3
            do{
                $response = Read-Host "Do you want to overwrite the file? (yes/no)"
                $response = $response.ToLower()
                if($response -eq "yes" -or $response -eq "y"){
                    break
                }
                elseif($response -eq "no" -or $response -eq "n"){
                    Write-Host "Skipping overwrite."
                    return
                }
                elseif($retries -eq 0){
                    Write-Host "Too many invalid attempts. Exiting script." -ForegroundColor Red
                    return
                }
                else{
                    Write-Host "Invalid input. Please type 'yes' or 'no'." -ForegroundColor Yellow
                    $retries--
                }
            } while ($true)  
        }
        Write-Host "Overwriting..."
        Modify-Folder -Operation Remove -sourcePath $backupFolder
        Modify-Folder -Operation Create -sourcePath $backupFolder
        Modify-Folder -Operation Copy -sourcePath $tempFolder -destinationPath $backupFolder
    }
    else{
        Write-Host "Creating backup at $backupFolder..."
        Modify-Folder -Operation Create -sourcePath $backupFolder
        Modify-Folder -Operation Copy -sourcePath $tempFolder -destinationPath $backupFolder
    }
    # Remove temp folder as it is not needed anymore
    Write-Host "Removing temp folder..."
    Modify-Folder -Operation Remove -sourcePath $tempFolder

    Write-Host "Successfully created backup at $backupFolder." -ForegroundColor Cyan
}

function Restore-Env{
    <#
        .SYNOPSIS
        Restoring environment settings from backup.
        .PARAMETER Path
        Path to the backup folder.
        .PARAMETER Mode
        The settings to be restored. Defaults to All.
        .EXAMPLE
        Restore-Env -Path "C:\EnvBackup\<date>" -Mode "ASR"
        .Functionality
        Public
    #>
    param(
        [PARAMETER(Mandatory=$true)]
        [string]$Path,
        [ValidateSet("All", "ASR", "Audit")]
        [string]$Mode = "All"
    )
    $Mode = $Mode.ToLower()
    function Restore-ASRBackup{
        param(
            [string]$Path
        )
        $asrPath = Join-Path -Path $Path -ChildPath "asr.json"
        if(Test-Path $asrPath){
            try{
                $asrJSON = Get-Content -Raw $asrPath | ConvertFrom-Json
                $asrValueMap = @{}
                foreach($asrId in $asrJSON.PSObject.Properties){
                    $asrValueMap[$asrId.Name] = $asrId.Value
                }
            }
            catch{
                Write-Host "Unable to convert file to hashtable. Please ensure asr.json is in JSON format." -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                throw $_
            }
            foreach($ruleId in $asrValueMap.Keys){
                try{
                    Write-Host "Applying [$ruleId] settings..."
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions $($asrValueMap[$ruleId]) -ErrorAction Stop
                    Write-Host "Successfully set [$ruleId] to $($asrValueMap[$ruleId]) mode." -ForegroundColor Cyan
                }
                catch{
                    Write-Host "Unable to apply settings to [$ruleId]." -ForegroundColor Red
                    Write-Host $_.Exception.Message -ForegroundColor Red
                    throw $_
                }
            }
        }
        else{
            Write-Host "ASR settings not found within backup folder: $asrPath" -ForegroundColor Red
            return
        }        
    }

    function Restore-AuditBackup{
        param(
            [string]$Path
        )
        # Set GPO
        try{
            $gpoList = @($(Get-ChildItem -Path $Path -Directory | Select-Object -ExpandProperty Name | ForEach-Object { $_.Trim('{}') }))
        }
        catch{
            Write-Host "Unable to fetch GPO backup folders." -ForegroundColor Red
        }
        foreach($backupId in $gpoList){
            try{
                Write-Host "Restoring GPO [$backupId] settings..."
                Restore-GPO -Path $Path -BackupId $backupId
            }
            catch{
                Write-Host "Failed to restore GPO: $backupId" -ForegroundColor Red
                throw
            }
            Write-Host "Successfully restored GPO [$backupId] settings." -ForegroundColor Cyan
        }
    }

    if(Test-Path $Path){
        switch($Mode){
            "all"{
                Restore-ASRBackup -Path $Path
                Restore-AuditBackup -Path $Path
                break
            }
            "asr"{
                Restore-ASRBackup -Path $Path
                break
            }
            "audit"{
                Restore-AuditBackup -Path $Path
                break
            }
        }
    }
    else{
        Write-Host "Backup folder not found, please check for typos or formatting." -ForegroundColor Red
        Write-Host "eg: C:\EnvBackup\<date>" -ForegroundColor Yellow
        throw "Path invalid. Exiting script."
    }
}

function Set-ASR{
    <#
        .SYNOPSIS
        Applying Attack Surface Reduction rules.
        .PARAMETER ID
        ID of the ASR rule to be applied. Defaults to All.
        .PARAMETER Mode
        The mode to be set for the ASR rule. Defaults to Enable.
        .EXAMPLE
        Set-ASR -ID "All" -Mode "Warn"
        .Functionality
        Public
    #>
    param(
        [string]$ID = "All",
        [ValidateSet("Enable", "Audit", "Warn", "Disable")]
        [string]$Mode = "Enable"
    )
    # Load required modules
    Confirm-Module -Name "Set-ASR"
    $ID = $ID.ToLower()

    function Set-SingleASR{
        <#
            .SYNOPSIS
            Helper function for Set-ASR, which applies a single ASR rule.
            .PARAMETER ruleId
            ID of the ASR rule to be applied.
            .PARAMETER Mode
            The mode to be set for the ASR rule.
            .Functionality
            Internal
        #>
        param(
            [string]$ruleId,
            [string]$Mode
        )
        try{
            Write-Host "Setting ASR rule '$($asrRuleMap[$ruleId]) [$ruleId]' to $Mode mode."
            Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions $Mode -ErrorAction Stop
            Write-Host "Successfully set ASR rule '$($asrRuleMap[$ruleId]) [$ruleId]' to $Mode mode." -ForegroundColor Cyan
        }
        catch{
            Write-Host "Failed to apply settings: $($asrRuleMap[$ruleId]) [$ruleId]" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            throw $_
        }
    }
    
    if($ID -eq "all"){
        foreach($ruleId in $asrRuleMap.Keys){
            Set-SingleASR -ruleID $ruleId -Mode $Mode
        }
    }
    elseif($asrRuleMap.ContainsKey($ID)){
        Set-SingleASR -ruleId $ID -Mode $Mode
    }
    else{
        Write-Host "The ASR ID '$ID' was not found." -ForegroundColor Red
        Write-Host "Please check the ID for typos or formatting" -ForegroundColor Yellow
        Write-Host "Valid rule IDs include:"
        $asrRuleMap.Keys | ForEach-Object { Write-Host "- $_" -ForegroundColor Gray }
        throw "ASR ID not within table. Exiting script."
    }
}

function Set-Audit{
    <#
        .SYNOPSIS
        Applying audit settings recommended by Microsoft Defender Identity.
        .PARAMETER Item
        Audit item to be set. Defaults to Default.
        .PARAMETER Mode
        Domain applies the settings via GPO, LocalMachine applies the settings via registry. Defaults to Domain.
        .EXAMPLE
        Set-Audit -Item NTLMAuditing -Mode Domain
        .Functionality
        Public
    #>
    param(
        [string]$Item = "Default",
        [ValidateSet("Domain", "LocalMachine")]
        [string]$Mode = "Domain"
    )
    # Load required modules
    Confirm-Module -Name "Set-Audit"

    $auditList = @(
        "Default",
        "AdfsAuditing",
        "AdRecycleBin",
        "AdvancedAuditPolicyCAs",
        "AdvancedAuditPolicyDCs",
        "CAAuditing",
        "ConfigurationContainerAuditing",
        "EntraConnectAuditing", # Must be in domain mode
        "RemoteSAM", # Must be in domain mode
        "DomainObjectAuditing",
        "NTLMAuditing",
        "ProcessorPerformance"
    )
    if($auditList.Contains($Item)){
        try{
            Write-Host "Applying settings of '$Item' in '$Mode' mode..."
            switch($Item){
                "Default"{
                    $exclude = @("Default", "EntraConnectAuditing", "RemoteSAM")
                    foreach($auditItem in $auditList | Where-Object { $_ -notin $exclude }){
                        Set-MDIConfiguration -Mode $Mode -Configuration $auditItem -ErrorAction Stop
                    }
                    break
                }
                {$_ -in "EntraConnectAuditing", "RemoteSAM"} {
                    Write-Host "Audit setting '$Item' can only be run in Domain mode." -ForegroundColor Yellow
                    $identity = Read-Host "Please enter your identity: "
                    Set-MDIConfiguration -Mode Domain -Configuration $Item -Identity $identity -ErrorAction Stop
                    break
                }
                default{
                    Set-MDIConfiguration -Mode $Mode -Configuration $Item -ErrorAction Stop
                }
            }
        }
        catch{
            Write-Host "Failed to apply settings: $Item" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            throw $_ 
        }
        Write-Host "Successfully applied settings of '$Item' in '$Mode' mode." -ForegroundColor Cyan
    }
    else{
        Write-Host "The audit setting $Item was not found." -ForegroundColor Red
        Write-Host "Please check the item name for typos or formatting" -ForegroundColor Yellow
        Write-Host "Valid item names include:"
        $auditList | ForEach-Object{
            Write-Host "- $_" -ForegroundColor Gray
        }
        throw "Audit item not within list. Exiting script."
    }
}

Export-ModuleMember -Function Backup-Env, Restore-Env, Set-ASR, Set-Audit