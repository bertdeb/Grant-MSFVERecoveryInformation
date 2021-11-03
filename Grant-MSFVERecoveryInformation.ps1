<#
    .SYNOPSIS
        Bulk assignment of MS_FVE_RECOVERY_INFORMATION rights to security groups in specified OUs.

    .DESCRIPTION
        This script does a bulk grant of BitLocker recovery password "ReadProperty and Control
        access ExtendedRight" to security groups in Active Directory based on an input CSV file and the Active
        Directory Module.

    .PARAMETER FileName
        Specifies the name the CSV-based input file containing the OUs and security groups.

    .INPUTS
        None. You cannot pipe objects to Grant-MSFVERecoveryInformation.ps1.

    .OUTPUTS
        The script provides detailed success/failure reports for each row of the CSV file.

    .EXAMPLE
        Grant-MSFVERecoveryInformation .\inputfile.csv

    .NOTES
        The input CSV file has two columns:
        GroupName,OU
        Thanks to Marius Hican for the original script to bulk create AD Groups

    .LINK
        https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Bulk-AD-Group-4d873f35/view/Discussions/2

    .LINK
        https://social.technet.microsoft.com/Forums/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects?forum=winserverpowershell
#>

Param(
    [Parameter(Mandatory = $true)][string]$FileName
) #end param

#Requires -Version 5.1
Set-StrictMode -Version 5.1

New-Variable -Name 'MS_FVE_RECOVERY_INFORMATION_GUID' -Value 'ea715d30-8f53-40d0-bd1e-6109186d782c' -Option Constant
New-Variable -Name 'ACCESS_ALLOWED_OBJECT_ACE_TYPE' -Value 'OA' -Option Constant
New-Variable -Name 'CONTAINER_INHERIT_ACE' -Value 'CI' -Option Constant
New-Variable -Name 'ADS_RIGHT_DS_READ_PROP' -Value 'RP' -Option Constant
New-Variable -Name 'ADS_RIGHT_DS_CONTROL_ACCESS' -Value 'CR' -Option Constant

$objectguid = new-object Guid $MS_FVE_RECOVERY_INFORMATION_GUID
$nullGUID = [guid]'00000000-0000-0000-0000-000000000000'

Import-Module ActiveDirectory
#Import CSV
$path = Split-Path -parent $MyInvocation.MyCommand.Definition 
$newpath = "$path$FileName"
$csv = @()
$csv = Import-Csv -Path $newpath

#Get Domain Base
$searchbase = Get-ADDomain | ForEach-Object { $_.DistinguishedName }

$adRights = [System.DirectoryServices.ActiveDirectoryRights] "ReadProperty, ExtendedRight"
$type = [System.Security.AccessControl.AccessControlType]::"Allow"
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::"All"

#Loop through all items in the CSV
ForEach ($item In $csv) {
    $itemError = $False
    $OUPath = $item.OU + "," + $searchbase
    Try {
        $OU = Get-ADOrganizationalUnit -Identity ($OUPath)
    } Catch {
        Write-Host -ForegroundColor Red "Error with item" $item.GroupName $item.OU
        Write-Host -ForegroundColor Red "OU Path $OUPath does not exist, skipping!"
        $itemError = $True
    }

    $groupName = $item.GroupName
    Try {
        $group = Get-ADgroup $groupName
    } Catch {
        Write-Host -ForegroundColor Red "Error with item" $item.GroupName $item.OU
        Write-Host -ForegroundColor Red "Security Group $groupName does not exist, skipping!"
        $itemError = $True
    }
     
    If (-Not $itemError) { 
        Write-Host "Proceeding with" $item.OU "and $groupName"
        $ACL = Get-Acl ("AD:" + $OU)
        $sddl = $ACL.Sddl
        $sid = new-object System.Security.Principal.SecurityIdentifier $group.SID
        $groupSID = (Get-ADGroup $groupName).SID
        $identity = [System.Security.Principal.IdentityReference] $SID
        $constructedACE = "($ACCESS_ALLOWED_OBJECT_ACE_TYPE;$CONTAINER_INHERIT_ACE;$ADS_RIGHT_DS_READ_PROP" +
        "$ADS_RIGHT_DS_CONTROL_ACCESS;;$MS_FVE_RECOVERY_INFORMATION_GUID;$GroupSID)"

        If ($sddl -match $constructedACE) { # Check if the ACE already exists
            Write-Host "$groupName already has ReadProperty and Control Access for msFVE-RecoveryInformation on $OU, skipping!"
        }
        Else { # Add ACE
            $ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $nullGUID, $inheritanceType, $objectguid
            Try {
                $ACL.AddAccessRule($ace)
                Set-Acl -aclobject $ACL ("AD:" + $OU)
                Write-Host -ForegroundColor Green "ReadProperty, Control Access granted to $groupName for ms-FVE-RecoveryInformation object on $OU"
            }
            Catch {
                Write-Host $_.Exception.Message`n
            }
        }
    }
}
