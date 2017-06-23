[cmdletbinding()]
param (
        [Parameter(Mandatory=$False)]
        [String]$SQLAdminName="saadm",
        [Parameter(Mandatory=$False)]
        [String]$SQLSvcAccountName="sqlsvc",
        [Parameter(Mandatory=$False)]
        [String]$SQLAgtSvcAccountName="sqlagtsvc",
        [Parameter(Mandatory=$False)]
        [String]$SQLRssSvcAccountName="sqlrsssvc",
        [Parameter(Mandatory=$False)]
        [String]$SCOMManagementGroup="SCOM01MGMT",
        [Parameter(Mandatory=$False)]
        [String]$SCOMActionAccountName="scomacc",
        [Parameter(Mandatory=$False)]
        [String]$SCOMDataAccessAccountName="scomdaa",
        [Parameter(Mandatory=$False)]
        [String]$SCOMDataReaderAccountName="scomdra",
        [Parameter(Mandatory=$False)]
        [String]$SCOMDataWriterAccountName="scomdwa",
        [Parameter(Mandatory=$False)]
        [String]$DomainName="ad.contoso.com",
        [Parameter(Mandatory=$False)]
        [String]$DomainUserName="DemoAdmin",
        [Parameter(Mandatory=$False)]
        [String]$DomainUserPassword="Password12345",
        [string]$DefaultPassword = "Password12345"
      )


function Write-LogEntry{
    param(
        $Message
    )
    Add-Content -Path "$env:Temp\install-Scom-log.txt" -Value $Message
}


$ErrorActionPreference = "Stop"
Write-LogEntry "Starting process"
# For logging purposes - remove file in the end of deployment
Start-Transcript -Path "$env:TEMP\Install-SCOM.log" -NoClobber -Force -Append

# Create credential object from user name and user password
$domainCreds = New-Object System.Management.Automation.PSCredential ("$DomainName`\$DomainUserName", $(ConvertTo-SecureString $DomainUserPassword -AsPlainText -Force))

#region Preparation - Static variables
$sqlInstanceName="SCOM"

$sqlDataDir = "F:\Program Files\Microsoft SQL Server"
$sqlUserDBDir = "M:\SQLData"
$sqlUserDBLogDir = "L:\SQLLogs"
$sqlBackupsDir = "K:\SQLBackups"
$sqlTempDBDir = "D:\SQLTemp"
$sqlBinariesDir = "C:\Install\SQL"

$scomBinariesDir = "C:\Install\SCOM"
$scomDir = "F:\Program Files"

$scomIsoFileUrl = ("https://samslmedia.blob.local.azurestack.external/iso/SCOM-2016-RTM.iso")
$sqlSysClrFileUrl = ("https://samslmedia.blob.local.azurestack.external/msi/SQLSysClrTypes.msi")
$reportViewerFileUrl = ("https://samslmedia.blob.local.azurestack.external/msi/ReportViewer.msi")



$sqlServerUrl = ("https://samslmedia.blob.local.azurestack.external/iso/SQLServer2016SP1-FullSlipstream-x64-ENU.iso")
$sqlServerManagementStudioUrl = ("https://samslmedia.blob.local.azurestack.external/exe/SSMS-Setup-ENU.exe")
$UserRightsUrl = "https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Query-user-26e259b0/file/169808/1/UserRights.ps1"

Write-LogEntry -Message "SQL URL: $sqlServerUrl"
Write-LogEntry -Message "SCOM URL: $scomIsoFileUrl"
Write-LogEntry -Message "RV URL: $reportViewerFileUrl"
Write-LogEntry -Message "CLR URL: $sqlSysClrFileUrl"
Write-LogEntry -Message "SMMS URL: $sqlServerManagementStudioUrl"
Write-LogEntry -Message "USR URL: $UserRightsUrl"


$VDiskSCOMBinariesSize = 20GB
$VDiskSQLDataSize = 50GB
$VDiskSQLLogSize = 10GB
$VDiskSQLBackupSize = 10GB

$sqlSCOMOpsDBDataSize = "5GB"
$sqlSCOMOpsDBLogSize = "2GB"
$sqlSCOMOpsDWDataSize = "10GB"
$sqlSCOMOpsDWLogSize = "2GB"
#endregion
Write-LogEntry "Preparation - Static variables - Complete"
#region Create Users
    $DomainDetails = (Get-WMIObject Win32_NTDomain)
    [string]$DCName = $DomainDetails.DomainControllerName
    $DCName = $DCName.Replace("\\","").Trim()
    [string]$DNSForestName = $DomainDetails.DnsForestName
    
    $SQLAdminName = $DomainUserName

    $UsersToCreate = @($SQLSvcAccountName,$SQLAgtSvcAccountName,$SQLRssSvcAccountName,$SCOMActionAccountName,$SCOMDataAccessAccountName,$SCOMDataReaderAccountName,$SCOMDataWriterAccountName)
    $UserString = $UsersToCreate -join ";"
    Write-LogEntry "Creating users: $UserString"

    $CreatedUsers = Invoke-Command -ComputerName $DCName -Credential $domainCreds -ScriptBlock {
        param(
            [string]$UserString,
            [string]$DNSForestName,
            [string]$DefaultPassword
        )
        $UsersToCreate = $UserString -split ";"
        $DomainName = $DNSForestName
        $DNSForestName = (("DC=") + ($DNSForestName.Replace(".",",DC=").Trim()))
        $secPwd = ConvertTo-SecureString -String $DefaultPassword -AsPlainText -Force
        ForEach($User in $UsersToCreate){
        
            New-ADUser -DisplayName:$User -GivenName:$User -Name:$User -Path:"CN=Users,$DNSForestName" -SamAccountName:$User -Type:"user" -UserPrincipalName:"$User@$DomainName"
        
            Set-ADAccountPassword -Identity:"CN=$User,CN=Users,$DNSForestName" -NewPassword:$secPwd -Reset:$true 
            Enable-ADAccount -Identity:"CN=$User,CN=Users,$DNSForestName"
            Set-ADAccountControl -AccountNotDelegated:$false -AllowReversiblePasswordEncryption:$false -CannotChangePassword:$false -DoesNotRequirePreAuth:$false -Identity:"CN=$User,CN=Users,$DNSForestName" -PasswordNeverExpires:$true -UseDESKeyOnly:$false

            Set-ADUser -ChangePasswordAtLogon:$false -Identity:"CN=$User,CN=Users,$DNSForestName" -SmartcardLogonRequired:$false
        
        }


    } -ArgumentList $UserString,$DNSForestName,$DefaultPassword
    Write-LogEntry "Users created"
    Write-LogEntry "Adding $SCOMActionAccountName to Domain Admins"
    $AddToDomainAdmins = Invoke-Command -ComputerName $DCName -Credential $domainCreds -ScriptBlock {
        param(
            $AccAccount,
            [string]$DNSForestName
        )
        $DomainName = $DNSForestName
        $DNSForestName = (("DC=") + ($DNSForestName.Replace(".",",DC=").Trim()))
        Add-ADPrincipalGroupMembership -Identity:"CN=$AccAccount,CN=Users,$DNSForestName" -MemberOf:"CN=Domain Admins,CN=Users,$DNSForestName" 
    } -ArgumentList $SCOMActionAccountName,$DNSForestName

#endregion

Write-LogEntry "Storage Pools"
#region OS - Create Storage Pool and virtual disks

$spName = 'SP-SCOM01'
$spMembers = ';2;3;'

If (-not(Get-StoragePool -FriendlyName $spName -ErrorAction SilentlyContinue)) {
    $vdInterleave = 64KB
    $Disks = Get-PhysicalDisk | ? { “$spMembers”.Contains(“;”+$_.DeviceID+”;”) -and $_.CanPool -eq $True } | Sort-Object -Property FriendlyName
    New-StoragePool –FriendlyName $spName –StorageSubsystemFriendlyName "Windows Storage*" -PhysicalDisks $Disks
}
else {
    Write-Output "Storage Pool - $spName exists"
}

#Create virtual disk 'VD-SCCM-Binaries'
$vdName = 'VD-SCOM-Binaries'
If (-not(Get-VirtualDisk -FriendlyName $vdName -ErrorAction SilentlyContinue)) {

    New-VirtualDisk -FriendlyName $vdName -StoragePoolFriendlyName $spName -ResiliencySettingName Simple -NumberOfColumns $Disks.Count -Size $VDiskSCOMBinariesSize -ProvisioningType Fixed -Interleave $vdInterleave 
    $d = Get-VirtualDisk -FriendlyName $vdName | Get-Disk
    $vdLetter = 'F'
    Initialize-Disk -Number $d.Number -PartitionStyle GPT # Defaults to GPT
    New-Partition -DiskNumber $d.Number -DriveLetter $vdLetter -UseMaximumSize
    Start-Sleep -s 5
    Format-Volume -DriveLetter $vdLetter -FileSystem NTFS -NewFileSystemLabel $vdName -Confirm:$false
}
else {
    Write-Output "Virtual disk - $vdName exists"
}

#Create virtual disk 'VD-SQL-Data'
$vdName = 'VD-SQL-Data'
If (-not(Get-VirtualDisk -FriendlyName $vdName -ErrorAction SilentlyContinue)) {
    New-VirtualDisk -FriendlyName $vdName -StoragePoolFriendlyName $spName -ResiliencySettingName Simple -NumberOfColumns $Disks.Count -Size $VDiskSQLDataSize -ProvisioningType Fixed -Interleave $vdInterleave 
    $d = Get-VirtualDisk -FriendlyName $vdName | Get-Disk
    $vdLetter = 'M'
    Initialize-Disk -Number $d.Number -PartitionStyle GPT # Defaults to GPT
    New-Partition -DiskNumber $d.Number -DriveLetter $vdLetter -UseMaximumSize
    Start-Sleep -s 5
    Format-Volume -DriveLetter $vdLetter -FileSystem NTFS -NewFileSystemLabel $vdName -AllocationUnitSize 64KB -Confirm:$false
}
else {
    Write-Output "Virtual disk - $vdName exists"
}
#Create virtual disk 'VD-SQL-Logs'
$vdName = 'VD-SQL-Logs'
If (-not(Get-VirtualDisk -FriendlyName $vdName -ErrorAction SilentlyContinue)) {
    New-VirtualDisk -FriendlyName $vdName -StoragePoolFriendlyName $spName -ResiliencySettingName Simple -NumberOfColumns $Disks.Count -Size $VDiskSQLLogSize -ProvisioningType Fixed -Interleave $vdInterleave 
    $d = Get-VirtualDisk -FriendlyName $vdName | Get-Disk
    $vdLetter = 'L'
    Initialize-Disk -Number $d.Number -PartitionStyle GPT # Defaults to GPT
    New-Partition -DiskNumber $d.Number -DriveLetter $vdLetter -UseMaximumSize
    Start-Sleep -s 5
    Format-Volume -DriveLetter $vdLetter -FileSystem NTFS -NewFileSystemLabel $vdName -AllocationUnitSize 64KB -Confirm:$false
}
else {
    Write-Output "Virtual disk - $vdName exists"
}
#Create virtual disk 'VD-SQL-Backups'
$vdName = 'VD-SQL-Backups'
If (-not(Get-VirtualDisk -FriendlyName $vdName -ErrorAction SilentlyContinue)) {
    New-VirtualDisk -FriendlyName $vdName -StoragePoolFriendlyName $spName -ResiliencySettingName Simple -NumberOfColumns $Disks.Count -Size $VDiskSQLBackupSize -ProvisioningType Fixed -Interleave $vdInterleave 
    $d = Get-VirtualDisk -FriendlyName $vdName | Get-Disk
    $vdLetter = 'K'
    Initialize-Disk -Number $d.Number -PartitionStyle GPT # Defaults to GPT
    New-Partition -DiskNumber $d.Number -DriveLetter $vdLetter -UseMaximumSize
    Start-Sleep -s 5
    Format-Volume -DriveLetter $vdLetter -FileSystem NTFS -NewFileSystemLabel $vdName -AllocationUnitSize 64KB -Confirm:$false
}
else {
    Write-Output "Virtual disk - $vdName exists"
}
#endregion
Write-LogEntry "Local Dirs"
#region OS - Create local directories
# ------------------------------------
# Create SCOM Binaries directory
If (-not(Test-Path -Path $scomBinariesDir)) {
    New-Item -Path "$scomBinariesDir" -ItemType Directory -Force
}
else {
    Write-Output "Directory - '$scomBinariesDir' exists"
}
# Create SQL Binaries directory
If (-not(Test-Path -Path $sqlBinariesDir)) {
    New-Item -Path "$sqlBinariesDir" -ItemType Directory -Force
}
else {
    Write-Output "Directory - '$sqlBinariesDir' exists"
}
# Create SCOM directory
If (-not(Test-Path -Path $scomDir)) {
    New-Item -Path "$scomDir" -ItemType Directory -Force
}
else {
    Write-Output "Directory - '$scomDir' exists"
}
# Create SCOM PreReq directory
If (-not(Test-Path -Path "$scomBinariesDir\PreReq")) {
    New-Item -Path "$scomBinariesDir\PreReq" -ItemType Directory -Force
}
else {
    Write-Output "Directory - '$scomBinariesDir\PreReq' exists"
}
# Create SQL Data directory
If (-not(Test-Path -Path $sqlDataDir)) {
    New-Item -Path "$sqlDataDir" -ItemType Directory -Force
}
else {
    Write-Output "Directory - '$sqlDataDir' exists"
}
# Create SQL User DB directory
If (-not(Test-Path -Path $sqlUserDBDir)) {
    New-Item -Path "$sqlUserDBDir" -ItemType Directory -Force
}
else {
    Write-Output "Directory - '$sqlUserDBDir' exists"
}
# Create SQL User DB Log directory
If (-not(Test-Path -Path $sqlUserDBLogDir)) {
    New-Item -Path "$sqlUserDBLogDir" -ItemType Directory -Force
}
else {
    Write-Output "Directory - '$sqlUserDBLogDir' exists"
}
# Create SQL User DB Backups directory
If (-not(Test-Path -Path $sqlBackupsDir)) {
    New-Item -Path "$sqlBackupsDir" -ItemType Directory -Force
}
else {
    Write-Output "Directory - '$sqlBackupsDir' exists"
}
# Create SQL Temp DB directory
If (-not(Test-Path -Path $sqlTempDBDir)) {
    New-Item -Path "$sqlTempDBDir" -ItemType Directory -Force
}
else {
    Write-Output "Directory - '$sqlTempDBDir' exists"
}
#endregion
Write-LogEntry "Downloading SQL Binaries"
#region SQL - Download and extract the installer binaries
$Web = New-Object System.Net.WebClient
If (-not(Test-Path -Path "$sqlBinariesDir\SQLServer2016.iso")) {
    Write-Output "Download file - '$sqlBinariesDir\SQLServer2016.iso'"
    $Web.DownloadFile("$sqlServerUrl", "$sqlBinariesDir\SQLServer2016.iso")
}
else {
    Write-Output "File - '$sqlBinariesDir\SQLServer2016.iso' exists"
}

If (-not(Test-Path -Path "$sqlBinariesDir\SSMS-Setup-ENU.exe")) {
    Write-Output "Download file - '$sqlBinariesDir\SSMS-Setup-ENU.exe'"
    $Web.DownloadFile("$sqlServerManagementStudioUrl", "$sqlBinariesDir\SSMS-Setup-ENU.exe")
}
else {
    Write-Output "File - '$sqlBinariesDir\SSMS-Setup-ENU.exe' exists"
}

If (-not(Test-Path -Path "$sqlBinariesDir\UserRights.ps1")) {
    Write-Output "Download file - '$sqlBinariesDir\UserRights.ps1'"
    $Web.DownloadFile("$UserRightsUrl", "$sqlBinariesDir\UserRights.ps1")
}
else {
    Write-Output "File - '$sqlBinariesDir\UserRights.ps1' exists"
}

#endregion
Write-LogEntry "Installing SQL Windows Features"
#region SQL - Install Windows Features
Write-Output "SQL - Install Windows Features"
Add-WindowsFeature NET-Framework-Core, NET-Framework-45-Core
#endregion
Write-LogEntry "Setting local admin"
#region SQL - Add domain account to local Administrators group 
$ErrorActionPreference = "SilentlyContinue"
    Write-Output "Add domain account to local Administrators group"
    $Group = [ADSI]"WinNT://./Administrators,group"
    $User = [ADSI]"WinNT://$DomainName/$DomainUserName"
    $Group.Add($User.Path)
$ErrorActionPreference = "Stop"
#endregion

#region SQL - Install SQL Management Studio 2016
Write-LogEntry "Installing SSMS"
if (-not(Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object {$_.DisplayName -eq "SQL Server 2016 Management Studio"})) {
    Write-Output "Install SQL Management Studio 2016"

    $ProcessName = "$sqlBinariesDir\SSMS-Setup-ENU.exe"
    $Args = "/install /quiet /norestart"

    $pInfo = New-Object System.Diagnostics.ProcessStartInfo
    $pInfo.FileName = $ProcessName
    $pinfo.Arguments = $Args
    $pInfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pInfo.Verb = "runas"

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $pInfo
    $process.Start() | Out-Null
    $process.WaitForExit()
    Write-Output "Exit code: $($process.ExitCode) More information: $($process.StandardOutput.ReadToEnd())"
    If ($($process.ExitCode) -ne "0") {
        $process.Dispose()
        Throw "SQL Server Management Studio installation failed"
    }
    $process.Dispose()
}
else {
    Write-Output "SQL Server Management Studio is installed"
}
#endregion
Write-LogEntry "Mount SQL ISO"
#region SQL - Mount SQL Server ISO and get the drive letter
$isoPath = "$sqlBinariesDir\SQLServer2016.iso"
if (-not($(Get-DiskImage -ImagePath $isoPath).Attached)) {
    Write-Output "Mount SQL Server ISO and get the drive letter"
    $DriveLetter = (Mount-DiskImage -ImagePath "$isoPath" -PassThru  | Get-Volume).DriveLetter + ":"
}
else {
    $DriveLetter = $(Get-WMIObject -Class Win32_CDROMDrive | Where-Object {$_.Caption -eq "Microsoft Virtual DVD-ROM" -and $_.VolumeName -eq "SQL2016_x64_ENU"}).Drive
    Write-Output "ISO file '$isoPath' is attached"
}
#endregion
Write-LogEntry "Install SQL"
#region SQL - Install and configure SQL Server 2016
$sqlService = "MSSQL`$$sqlInstanceName"
if (-not(Get-Service $sqlService -ErrorAction SilentlyContinue)) {
    Write-Output "Install SQL Server 2016"

    $SQLAdminName = "$DomainName\$SQLAdminName"
    $SQLSvcAccountName = "$DomainName\$SQLSvcAccountName"
    $SQLAgtSvcAccountName = "$DomainName\$SQLAgtSvcAccountName"
    $SQLRssSvcAccountName = "$DomainName\$SQLRssSvcAccountName"

    $sqlFeatures="SQLENGINE,FullText,RS"
    $sqlCollation="SQL_Latin1_General_CP1_CI_AS"
    $sqlRsMode="DefaultNativeMode"

    $ProcessName = "$($DriveLetter)\Setup.exe"
    $sqlArgs =  "/Quiet='True' /ACTION='Install' /FEATURES='$sqlFeatures' /INSTANCENAME='$sqlInstanceName' /INSTANCEID='$sqlInstanceName' /SQLCOLLATION='$sqlCollation' /INSTALLSQLDATADIR='$sqlDataDir' /SQLUSERDBDIR='$sqlUserDBDir' /SQLUSERDBLOGDIR='$sqlUserDBLogDir' /SQLBACKUPDIR='$sqlBackupsDir' /SQLTEMPDBDIR='$sqlTempDBDir' /SQLTEMPDBLOGDIR='$sqlTempDBDir' /RSINSTALLMODE='$sqlRsMode' /SQLSYSADMINACCOUNTS='$SQLAdminName' /SQLSVCACCOUNT='$SQLSvcAccountName' /SQLSVCPASSWORD='$SQLSvcAccountPassword' /AGTSVCACCOUNT='$SQLAgtSvcAccountName' /AGTSVCPASSWORD='$SQLAgtSvcAccountPassword' /RSSVCACCOUNT='$SQLRssSvcAccountName' /RSSVCPASSWORD='$SQLRssSvcAccountPassword' /IACCEPTSQLSERVERLICENSETERMS /UpdateEnabled='FALSE'"

    $command = "$ProcessName $sqlArgs"

    $scheduledTaskName = ‘Install SQL Server'
    $Action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument "-NonInteractive -NoLogo -NoProfile -Command `"$command`""
    #$Trigger = New-ScheduledTaskTrigger -Once -At "$($(Get-Date).AddSeconds(5))"
    $Task = New-ScheduledTask -Action $Action -Settings (New-ScheduledTaskSettingsSet) #-Trigger $Trigger 
    $Task | Register-ScheduledTask -TaskName $scheduledTaskName -User $($domainCreds.UserName) -Password $($domainCreds.GetNetworkCredential().Password)
    Start-ScheduledTask -TaskName $scheduledTaskName

    $TaskInfo = Get-ScheduledTask $scheduledTaskName
    while ($($TaskInfo.State) -eq "Running"){
      Start-Sleep -s 15
      $TaskInfo = Get-ScheduledTask $scheduledTaskName
    }

    Start-Sleep -s 5
    $TaskDetails = Get-ScheduledTaskInfo $scheduledTaskName
    If ($($TaskDetails.LastTaskResult) -ne "0") {
        Throw "SQL Server installation failed"
        Unregister-ScheduledTask -TaskName $scheduledTaskName -Confirm:$false
    }
    else {
        Write-Output "SQL Server installation successful"
        Unregister-ScheduledTask -TaskName $scheduledTaskName -Confirm:$false
    }

    Dismount-DiskImage -ImagePath "$sqlBinariesDir\SQLServer2016.iso"
}
else {
    Write-Output "SQL Server is installed"
}
#endregion
Write-LogEntry "SQL Temp Folder"
#region SQL - Create scheduled task to recreate SQLTemp folder after machine reboot
Write-Output "SQL - Create scheduled task to recreate SQLTemp folder after machine reboot"

$scheduledTaskName = ‘Recreate SQLTemp folder'

if (-not(Get-ScheduledTask -TaskName $scheduledTaskName -ErrorAction SilentlyContinue)) {

    $sqlScheduledTask = @"

`$sqlTempDir="$sqlTempDBDir"
`$sqlInstanceName = "$sqlInstanceName"

`$SQLServices = @("MSSQL`$`$sqlInstanceName","ReportServer`$`$sqlInstanceName")
if(-not(Test-Path `$sqlTempDir)) {
    New-Item -ItemType Directory -Path `$sqlTempDir -Force
}
`$SQLServices | foreach { Restart-Service -Name `$_ -Force} 
"@

    Set-Content -Path "C:\Windows\recreateSQLTempFolder.ps1" -Value $sqlScheduledTask

    $Action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument "-NonInteractive -NoLogo -NoProfile -File `"C:\Windows\recreateSQLTempFolder.ps1`""
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Task = New-ScheduledTask -Action $Action -Settings (New-ScheduledTaskSettingsSet) -Trigger $Trigger
    $Task | Register-ScheduledTask -TaskName $scheduledTaskName -User "System"
}
else {
    Write-Output "Scheduled task '$scheduledTaskName' exists"
}
#endregion

#region SCOM - Start SQL Server Agent service
Write-Output "SCOM - Start SQL Server Agent service"
Set-Service -Name "SQLAgent`$$sqlInstanceName" -StartupType Automatic
Restart-Service -Name "SQLAgent`$$sqlInstanceName"  -Force
#endregion

#region SQL - Change SQL Server port number to 1433
import-module "C:\Program Files (x86)\Microsoft SQL Server\130\Tools\PowerShell\Modules\SQLPS\SQLPS.psd1";
$MachineObject = new-object ('Microsoft.SqlServer.Management.Smo.WMI.ManagedComputer') "$env:COMPUTERNAME"
$instance = $MachineObject.getSmoObject(
    "ManagedComputer[@Name='$env:COMPUTERNAME']/" + 
    "ServerInstance[@Name='$sqlInstanceName']"
)

if ($instance.ServerProtocols['Tcp'].IPAddresses['IPAll'].IPAddressProperties['TcpPort'].Value -ne "1433") {
    Write-Output "Change SQL Server port number to 1433"
    $instance.ServerProtocols['Tcp'].IPAddresses['IPAll'].IPAddressProperties['TcpPort'].Value = "1433"
    $instance.ServerProtocols['Tcp'].IPAddresses['IPAll'].IPAddressProperties['TcpDynamicPorts'].Value = ""
    $instance.ServerProtocols['Tcp'].Alter()
    Restart-Service -Force "MSSQL`$$sqlInstanceName"
}
else {
    Write-Output "SQL Server port is set to 1433"
}
#endregion
Write-LogEntry "SQL Post Install"
#region SQL - SQL Post installation steps
$scriptFileContent = @"
`$ErrorActionPreference = "Stop"

# Setup privileges for SQL accounts
Import-Module "$sqlBinariesDir\UserRights.ps1"
Grant-UserRight -Account `"$SQLSvcAccountName`" -Right SeLockMemoryPrivilege, SeManageVolumePrivilege
Grant-UserRight -Account `"$SQLAgtSvcAccountName`" -Right SeManageVolumePrivilege
Remove-Module "UserRights"
`$SQLQuery = `@"
/* This shows the advanced options */
EXEC sys.sp_configure N'show advanced options', N'1'  RECONFIGURE WITH OVERRIDE
GO

/* Find the optimal max degree of parallelism setting */
BEGIN
DECLARE @MAXDOP int;
SET @MAXDOP = 
(
	SELECT CASE WHEN cpu_count / hyperthread_ratio > 8 THEN 8 ELSE cpu_count / hyperthread_ratio END AS optimal_maxdop FROM sys.dm_os_sys_info
)
EXEC sys.sp_configure N'max degree of parallelism', @MAXDOP  RECONFIGURE WITH OVERRIDE;
END
GO

/* Change the size and growth parameters of TempDB */
USE [master]
GO
ALTER DATABASE [tempdb] MODIFY FILE ( NAME = N'tempdev', SIZE = 8388608KB , FILEGROWTH = 512000KB )
GO
ALTER DATABASE [tempdb] MODIFY FILE ( NAME = N'templog', SIZE = 2097152KB , FILEGROWTH = 102400KB )
GO

/* Configure server memory settings */
DECLARE @MAXMEMORY int;
DECLARE @MINMEMORY int;
SET @MINMEMORY = (select CEILING((physical_memory_kb/1048576.0)*1024*0.30) FROM sys.dm_os_sys_info)
SET @MAXMEMORY = (select CEILING((physical_memory_kb/1048576.0)*1024*0.80) FROM sys.dm_os_sys_info)
EXEC sp_configure 'min server memory', @MINMEMORY;  
EXEC sp_configure 'max server memory', @MAXMEMORY;
GO

/* Hide the advanced options */
EXEC sys.sp_configure N'show advanced options', N'0'  RECONFIGURE WITH OVERRIDE
GO
`"@

#Import SQL module
import-module "C:\Program Files (x86)\Microsoft SQL Server\130\Tools\PowerShell\Modules\SQLPS\SQLPS.psd1";
#Run the SQL statement
Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$sqlInstanceName" -Query `$SQLQuery -querytimeout 240
"@

Set-Content -Path "$env:TEMP\configureSQL.ps1" -Value $scriptFileContent

$scheduledTaskName = ‘Configure SQL Server'

if (-not(Get-ScheduledTask -TaskName $scheduledTaskName -ErrorAction SilentlyContinue)) {

    $Action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument "-NonInteractive -NoLogo -NoProfile -File `"$env:TEMP\configureSQL.ps1`""
    #$Trigger = New-ScheduledTaskTrigger -Once -At "$($(Get-Date).AddSeconds(5))"
    $Task = New-ScheduledTask -Action $Action -Settings (New-ScheduledTaskSettingsSet) #-Trigger $Trigger 
    $Task | Register-ScheduledTask -TaskName $scheduledTaskName -User $($domainCreds.UserName) -Password $($domainCreds.GetNetworkCredential().Password)
    Start-ScheduledTask -TaskName $scheduledTaskName

    $TaskInfo = Get-ScheduledTask $scheduledTaskName
    while ($($TaskInfo.State) -eq "Running"){
        Start-Sleep -s 15
        $TaskInfo = Get-ScheduledTask $scheduledTaskName
    }

    Start-Sleep -s 5
    $TaskDetails = Get-ScheduledTaskInfo $scheduledTaskName
    If ($($TaskDetails.LastTaskResult) -ne "0") {
        Unregister-ScheduledTask -TaskName $scheduledTaskName -Confirm:$false
        Remove-Item "$env:TEMP\configureSQL.ps1" -Force
        Throw "SQL Server configuration failed"
    }
    else {
        Write-Output "SQL Server configuration ok"
        Unregister-ScheduledTask -TaskName $scheduledTaskName -Confirm:$false
        Remove-Item "$env:TEMP\configureSQL.ps1" -Force
    }
}
else{
    Write-Output "Scheduled task '$scheduledTaskName' exists"
}
#endregion
Write-LogEntry "Download SCOM"
#region SCOM - Download and extract the installer binaries
$Web = New-Object System.Net.WebClient
If (-not(Test-Path -Path "$scomBinariesDir\OpsMgr2016.iso")) {
    Write-Output "Download file - '$scomBinariesDir\OpsMgr2016.iso'"
    $Web.DownloadFile("$scomIsoFileUrl", "$scomBinariesDir\OpsMgr2016.iso")
}
else {
    Write-Output "File - '$scomBinariesDir\OpsMgr2016.iso' exists"
}
If (-not(Test-Path -Path "$scomBinariesDir\PreReq\SQLSysClrTypes.msi")) {
    Write-Output "Download file - '$scomBinariesDir\PreReq\SQLSysClrTypes.msi'"
    $Web.DownloadFile("$sqlSysClrFileUrl", "$scomBinariesDir\PreReq\SQLSysClrTypes.msi")
}
else {
    Write-Output "File - '$scomBinariesDir\PreReq\SQLSysClrTypes.msi' exists"
}
If (-not(Test-Path -Path "$scomBinariesDir\PreReq\ReportViewer.msi")) {
    Write-Output "Download file - '$scomBinariesDir\PreReq\ReportViewer.msi'"
    $Web.DownloadFile("$reportViewerFileUrl", "$scomBinariesDir\PreReq\ReportViewer.msi")
}
else {
    Write-Output "File - '$scomBinariesDir\PreReq\ReportViewer.msi' exists"
}
#endregion
Write-LogEntry "Install SCOM Windows Features"
#region SCOM - Install Windows Features
Write-Output "SCOM - Install Windows Features"
Add-WindowsFeature Web-Server, Web-WebServer, Web-Common-Http, Web-Default-Doc, Web-Dir-Browsing, Web-Http-Errors, Web-Static-Content, Web-Health, Web-Http-Logging, Web-Log-Libraries, Web-Request-Monitor, Web-Performance, Web-Stat-Compression, Web-Security, Web-Filtering, Web-Windows-Auth, Web-App-Dev, Web-Net-Ext45, Web-Asp-Net45, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Mgmt-Tools, Web-Mgmt-Console, Web-Mgmt-Compat, Web-Metabase, NET-Framework-45-Features, NET-Framework-45-Core, NET-Framework-45-ASPNET, NET-WCF-Services45, NET-WCF-HTTP-Activation45, NET-WCF-TCP-PortSharing45, WAS, WAS-Process-Model, WAS-Config-APIs, Web-Asp-Net
#endregion
Write-LogEntry "Install SCOM Prerequisites"
#region SCOM - Install Prerequisites
if (-not(Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object {$_.DisplayName -eq "Microsoft System CLR Types for SQL Server 2014"})) {
    Write-Output "SCOM - Install Prerequisites - Microsoft System CLR Types"
    $pInfo = New-Object System.Diagnostics.ProcessStartInfo
    $pInfo.FileName = "$($env:SystemRoot)\System32\msiexec.exe"
    $pInfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = "/i $scomBinariesDir\PreReq\SQLSysClrTypes.msi /qn /norestart"
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $pInfo
    $process.Start() | Out-Null
    $process.WaitForExit()
    Write-Output "Exit code: $($process.ExitCode) More information: $($process.StandardOutput.ReadToEnd())"
    If ($($process.ExitCode) -ne "0") {
        $process.Dispose()
        Throw "Microsoft System CLR Types installation failed"
    }
    $process.Dispose()
}
else {
    Write-Output "Microsoft System CLR Types is installed"
}

if (-not(Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object {$_.DisplayName -eq "Microsoft Report Viewer 2015 Runtime"})) {
    Write-Output "SCOM - Install Prerequisites - Microsoft Report Viewer 2015"
    $pInfo = New-Object System.Diagnostics.ProcessStartInfo
    $pInfo.FileName = "$($env:SystemRoot)\System32\msiexec.exe"
    $pInfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = "/i $scomBinariesDir\PreReq\ReportViewer.msi /qn /norestart"
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $pInfo
    $process.Start() | Out-Null
    $process.WaitForExit()
    Write-Output "Exit code: $($process.ExitCode) More information: $($process.StandardOutput.ReadToEnd())"
    If ($($process.ExitCode) -ne "0") {
        $process.Dispose()
        Throw "Microsoft Report Viewer 2015 installation failed"
    }
    $process.Dispose()
}
else {
    Write-Output "Microsoft Report Viewer 2015 is installed"
}

#endregion 
Write-LogEntry "Register IIS Changes"
#region SCOM - Register IIS
Write-Output "SCOM - Register ASPNET IIS"
Start-Process -FilePath "$env:windir\Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe" -ArgumentList "-r" -Wait
Start-Process -FilePath "$env:windir\System32\iisreset.exe" -ArgumentList "/RESTART" -Wait
#endregion

#region SCOM - Mount OpsMgr ISO and get the drive letter
Write-Output "Mount OpsMgr ISO and get the drive letter"
$DriveLetter = (Mount-DiskImage -ImagePath "$scomBinariesDir\OpsMgr2016.iso" -PassThru | Get-Volume).DriveLetter + ":"
#endregion

#region SCOM - Add action and data access accounts as local administrators
Write-Output "Add SCOM action account as local administrator"
$ErrorActionPreference = "SilentlyContinue"
    Write-Output "Add domain account to local Administrators group"
    $Group = [ADSI]"WinNT://./Administrators,group"
    $User = [ADSI]"WinNT://$DomainName/$SCOMActionAccountName"
    $Group.Add($User.Path)
$ErrorActionPreference = "Stop"

Write-Output "Add SCOM data access account as local administrator"
$ErrorActionPreference = "SilentlyContinue"
    Write-Output "Add domain account to local Administrators group"
    $Group = [ADSI]"WinNT://./Administrators,group"
    $User = [ADSI]"WinNT://$DomainName/$SCOMDataAccessAccountName"
    $Group.Add($User.Path)
$ErrorActionPreference = "Stop"
#endregion
Write-LogEntry "Extract and Install SCOM"
#region SCOM - Install SCOM
Write-Output "Install SCOM"
$installSCOMScript = @"
`$ErrorActionPreference = "Stop"

`#Extract SCOM 2016
`$ProcessName = "$DriveLetter\SC2016_SCOM_EN.exe"
`$Argumentlist = "/Dir=C:\Install\SCOM /VERYSILENT"

`$pInfo = New-Object System.Diagnostics.ProcessStartInfo
`$pInfo.FileName = `$ProcessName
`$pinfo.Arguments = `$Argumentlist
`$pInfo.RedirectStandardError = `$true
`$pinfo.RedirectStandardOutput = `$true
`$pinfo.UseShellExecute = `$false

`$process = New-Object System.Diagnostics.Process
`$process.StartInfo = `$pInfo
`$process.Start() | Out-Null
`$process.WaitForExit()
Write-Output "Exit code: `$(`$process.ExitCode) More information: `$(`$process.StandardOutput.ReadToEnd())"
If (`$(`$process.ExitCode) -ne "0") {
    `$process.Dispose()
    Throw "Operations Manager installation failed"
}
`$process.Dispose()


`#SCOM - Install Operations Manager Management Server
`$ProcessName = "C:\install\scom\setup.exe"
`$Argumentlist = "/silent /install /components:``"OMServer,OMConsole,OMWebConsole,OMReporting``" /InstallPath:``"$scomDir\Microsoft System Center 2016\Operations Manager``" /ManagementGroupName:``"$SCOMManagementGroup``" /SqlServerInstance:``"$env:COMPUTERNAME\$sqlInstanceName``" /DatabaseName:``"OperationsManager``" /DWSqlServerInstance:``"$env:COMPUTERNAME`\$sqlInstanceName``" /DWDatabaseName:``"OperationsManagerDW``" /ActionAccountUser:``"$DomainName`\$SCOMActionAccountName``" /ActionAccountPassword:``"$SCOMActionAccountPassword``" /DASAccountUser:``"$DomainName`\$SCOMDataAccessAccountName``" /DASAccountPassword:``"$SCOMDataAccessAccountPassword``" /DataReaderUser:``"$DomainName`\$SCOMDataReaderAccountName``" /DataReaderPassword:``"$SCOMDataReaderAccountPassword``" /DataWriterUser:``"$DomainName`\$SCOMDataWriterAccountName``" /DataWriterPassword:``"$SCOMDataWriterAccountPassword``" /WebSiteName:``"Default Web Site``" /WebConsoleAuthorizationMode:``"Mixed``" /SRSInstance:``"$env:COMPUTERNAME`\$sqlInstanceName``" /SendODRReports:0 /EnableErrorReporting:``"Never``" /SendCEIPReports:0 /UseMicrosoftUpdate:0 /AcceptEndUserLicenseAgreement:1"

`$pInfo = New-Object System.Diagnostics.ProcessStartInfo
`$pInfo.FileName = `$ProcessName
`$pinfo.Arguments = `$Argumentlist
`$pInfo.RedirectStandardError = `$true
`$pinfo.RedirectStandardOutput = `$true
`$pinfo.UseShellExecute = `$false

`$process = New-Object System.Diagnostics.Process
`$process.StartInfo = `$pInfo
`$process.Start() | Out-Null
`$process.WaitForExit()
Write-Output "Exit code: `$(`$process.ExitCode) More information: `$(`$process.StandardOutput.ReadToEnd())"
If (`$(`$process.ExitCode) -ne "0") {
    `$process.Dispose()
    Throw "Operations Manager installation failed"
}
`$process.Dispose()


"@

Set-Content -Path "C:\Install\installSCOM.ps1" -Value $installSCOMScript 

$scheduledTaskName = ‘Install SCOM'
$Action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File `"C:\Install\installSCOM.ps1`""
#$Trigger = New-ScheduledTaskTrigger -Once -At "$($(Get-Date).AddSeconds(5))"
$Task = New-ScheduledTask -Action $Action -Settings (New-ScheduledTaskSettingsSet) #-Trigger $Trigger 
$Task | Register-ScheduledTask -TaskName $scheduledTaskName -User $($domainCreds.UserName) -Password $($domainCreds.GetNetworkCredential().Password)
Start-ScheduledTask -TaskName $scheduledTaskName

$TaskInfo = Get-ScheduledTask $scheduledTaskName
while ($($TaskInfo.State) -eq "Running"){
    Start-Sleep -s 30
    $TaskInfo = Get-ScheduledTask $scheduledTaskName
}

Start-Sleep -s 5
$TaskDetails = Get-ScheduledTaskInfo $scheduledTaskName
If ($($TaskDetails.LastTaskResult) -ne "0") {
    Unregister-ScheduledTask -TaskName $scheduledTaskName -Confirm:$false
    Remove-Item "$env:TEMP\installSCOM.ps1" -Force
    Throw "Operations Manager installation failed"
}
else {
    Write-Output "Operations Manager installation ok"
    Unregister-ScheduledTask -TaskName $scheduledTaskName -Confirm:$false
    Remove-Item "$env:TEMP\installSCOM.ps1" -Force
}

Dismount-DiskImage -ImagePath "$scomBinariesDir\OpsMgr2016.iso"
#endregion
Write-LogEntry "Optimize SCOM"
#region SCOM - Optimize SCOM
Write-Output "SCOM - Apply registry optimizations"
reg add "HKLM\SYSTEM\CurrentControlSet\services\HealthService\Parameters" /v "State Queue Items" /t REG_DWORD /d 20480 /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\HealthService\Parameters" /v "Persistence Checkpoint Depth Maximum" /t REG_DWORD /d 104857600 /f
reg add "HKLM\SOFTWARE\Microsoft\System Center\2010\Common\DAL" /v "DALInitiateClearPool" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\System Center\2010\Common\DAL" /v "DALInitiateClearPoolSeconds" /t REG_DWORD /d 60 /f
reg add "HKLM\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0" /v "GroupCalcPollingIntervalMilliseconds" /t REG_DWORD /d 900000 /f
reg add "HKLM\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Data Warehouse" /v "Command Timeout Seconds" /t REG_DWORD /d 1800 /f
reg add "HKLM\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Data Warehouse" /v "Deployment Command Timeout Seconds" /t REG_DWORD /d 86400 /f
#endregion 

#region SCOM - Change database sizes
$scriptFileContent = @"
`$ErrorActionPreference = "Stop"

`$SQLQuery = `@"
/* Setup database sizes */
USE master;
GO
ALTER DATABASE OperationsManager 
MODIFY FILE
    (NAME = MOM_DATA, SIZE = $sqlSCOMOpsDBDataSize)
GO
ALTER DATABASE OperationsManager 
MODIFY FILE
    (NAME = MOM_LOG, SIZE = $sqlSCOMOpsDBLogSize)
GO
ALTER DATABASE OperationsManagerDW 
MODIFY FILE
    (NAME = MOM_DATA, SIZE = $sqlSCOMOpsDWDataSize)
GO
ALTER DATABASE OperationsManagerDW 
MODIFY FILE
    (NAME = MOM_LOG, SIZE = $sqlSCOMOpsDWLogSize)
GO
`"@

#Import SQL module
import-module "C:\Program Files (x86)\Microsoft SQL Server\130\Tools\PowerShell\Modules\SQLPS\SQLPS.psd1";
#Run the SQL statement
Invoke-Sqlcmd -ServerInstance "$env:COMPUTERNAME\$sqlInstanceName" -Query `$SQLQuery -querytimeout 1800
"@

Set-Content -Path "$env:TEMP\configureSQL.ps1" -Value $scriptFileContent

$scheduledTaskName = ‘Change SCOM databases sizes'

if (-not(Get-ScheduledTask -TaskName $scheduledTaskName -ErrorAction SilentlyContinue)) {

    $Action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument "-NonInteractive -NoLogo -NoProfile -File `"$env:TEMP\configureSQL.ps1`""
    #$Trigger = New-ScheduledTaskTrigger -Once -At "$($(Get-Date).AddSeconds(5))"
    $Task = New-ScheduledTask -Action $Action -Settings (New-ScheduledTaskSettingsSet) #-Trigger $Trigger 
    $Task | Register-ScheduledTask -TaskName $scheduledTaskName -User $($domainCreds.UserName) -Password $($domainCreds.GetNetworkCredential().Password)
    Start-ScheduledTask -TaskName $scheduledTaskName

    $TaskInfo = Get-ScheduledTask $scheduledTaskName
    while ($($TaskInfo.State) -eq "Running"){
        Start-Sleep -s 15
        $TaskInfo = Get-ScheduledTask $scheduledTaskName
    }

    Start-Sleep -s 5
    $TaskDetails = Get-ScheduledTaskInfo $scheduledTaskName
    If ($($TaskDetails.LastTaskResult) -ne "0") {
        Unregister-ScheduledTask -TaskName $scheduledTaskName -Confirm:$false
        Remove-Item "$env:TEMP\configureSQL.ps1" -Force
        Throw "Change SCOM databases sizes failed"
    }
    else {
        Write-Output "Change SCOM databases sizes ok"
        Unregister-ScheduledTask -TaskName $scheduledTaskName -Confirm:$false
        Remove-Item "$env:TEMP\configureSQL.ps1" -Force
    }
}
else{
    Write-Output "Scheduled task '$scheduledTaskName' exists"
}
#endregion

#region SCOM - Install Update Rollups
# TO DO IN THE FUTURE
#endregion

#region SCOM - Install management packs
# TO DO IN THE FUTURE
#endregion    

#region SCOM - reboot server
Write-LogEntry "Complete"
Write-Output "Reboot server"
Restart-Computer -Force 
#endregion
