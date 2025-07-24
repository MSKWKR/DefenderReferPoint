# DefenderReferPoint (DERP)
**DERP** is a PowerShell module designed to simplify the deployment of Microsoft Defender's recommended security settings.
## Build Environment
- **Operating System:** Windows Server 2022 21H2

## Installation
1. Download the package and place the folder within WindowsPowerShell Module path.  
eg: *`C:\ProgramFiles\WindowsPowerShell\Modules`*  
2. To import the module: `Import-Module DefenderReferPoint`

## Usage
### Backup-Env
Create a backup folder for all group policy objects and registries.  
- `-Path`: Path to a folder where the backups are saved. Defaults to the *`C:\EnvBackup`* folder.
- `-Name`: Name of the backup folder to be created. Defaults to the backup date.
- `-Overwrite`: If specified, the folder will be overwritten without prompting. If omitted, the user will be asked whether to overwrite.

**Example usage:**  
```powershell
> Backup-Env -Path "C:\temp\myBackupFolder" -Name "Version1.0" -Overwrite
> Backup-Env
```

### Set-ASR
Applying Attack Surface Reduction rules.
- `-ID`: ID of the ASR rule to be applied. Defaults to All.
- `-Mode`: The mode to be set for the ASR rule. Defaults to Enable.

**Example usage:**  
```powershell
> Set-ASR -ID "56a863a9-875e-4185-98a7-b882c64b5ce5" -Mode "Warn"
> Set-ASR
```
