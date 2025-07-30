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
Create a backup folder for all Group policy objects and Attack surface reduction preferences.  
- `-Path`: Path to a folder where the backups are saved. Defaults to the *`C:\EnvBackup`* folder.
- `-Name`: Name of the backup folder to be created. Defaults to the backup date.
- `-Overwrite`: If specified, the folder will be overwritten without prompting. If omitted, the user will be asked whether to overwrite.

**Example usage:**  
```powershell
> Backup-Env -Path "C:\temp\myBackupFolder" -Name "Version1.0" -Overwrite
```
> [!TIP]  
> You can simply run `Backup-Env` without parameters in the terminal, default settings will be applied.

### Restore-Env
Restore settings based on contents of the backup folder.  
- `-Path`: Path to a folder where the backups are saved.
- `-Mode`: The settings to be restored. Defaults to All.
    - `All`: Include all settings below.
    - `ASR`: Include ASR preferences.
    - `Audit`: Include Group policy objects.
> [!NOTE]  
> `-Path` is **MANDATORY**, it must be specified.  

**Example usage:**  
```powershell
> Restore-Env -Path "C:\temp\myBackupFolder" -Mode "Audit"
```


### Set-ASR
Applying Attack Surface Reduction rules.
- `-ID`: ID of the ASR rule to be applied. Defaults to All.
- `-Mode`: The mode to be set for the ASR rule. Defaults to Enable.
    - `Disable`: Rule disabled.
    - `Enable`: Rule enabled.
    - `Audit`: Rule is evaulated but not enforced.
    - `Warn`: Rule is enabled and notifies end-user, but permits end-user to bypass the block. 

**Example usage:**  
```powershell
> Set-ASR -ID "56a863a9-875e-4185-98a7-b882c64b5ce5" -Mode "Warn"
```
> [!TIP]  
> You can simply run `Set-ASR` without parameters in the terminal, default settings will be applied.

### Set-Audit
Applying Microsoft Defender Identity recommended audit settings.
- `-Item`: Audit item to be set. Defaults to Default, which is all settings except for "EntraConnectAuditing" and "RemoteSAM".
- `-Mode`: Domain applies the settings via GPO, LocalMachine applies the settings via registry. Defaults to Domain.  
> [!NOTE]  
> "EntraConnectAuditing" and "RemoteSAM" can only be set under "Domain" mode, a prompt for identity will show.  

**Example usage:**  
```powershell
> Set-Audit -Item "NTLMAuditing" -Mode "LocalMachine" 
```
> [!TIP]  
> You can simply run `Set-Audit` without parameters in the terminal, default settings will be applied.