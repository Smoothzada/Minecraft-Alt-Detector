$ErrorActionPreference = "SilentlyContinue"
$UserRN = $env:USERNAME
clear-host
Write-Host @"

 █████╗ ██╗  ████████╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
██╔══██╗██║  ╚══██╔══╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
███████║██║     ██║       ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
██╔══██║██║     ██║       ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
██║  ██║███████╗██║       ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝       ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                                                                                                 
"@ -ForegroundColor Red                                                           
    Write-Host -ForegroundColor Blue "By Smooth | Discord: smoothzada"
    Write-Host ""
    function Test-Admin {;$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent());$currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);}
if (!(Test-Admin)) {
    Write-Warning "Execute o script como Administrador"
    Start-Sleep 5
    Exit
}
    Start-Sleep -Seconds 1
    Write-Host -ForegroundColor Yellow "Starting scan"




$OutputFile = "$env:USERPROFILE\Downloads\Alt Detector.txt"

if (Test-Path $OutputFile) {
    Remove-Item -Path $OutputFile -Force
}


New-Item -ItemType File -Path $OutputFile -Force | Out-Null


Add-Content -Path $OutputFile -Value "ALT Detector - By: Smooth"
Add-Content -Path $OutputFile -Value "Scan Result:"
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""  

$UserCachePath = "C:\Users\$UserRN\AppData\Roaming\.minecraft\usercache.json"
$UsernameCachePath = "C:\Users\$UserRN\AppData\Roaming\.minecraft\usernamecache.json"
$LauncherCachePath = "C:\Users\$UserRN\AppData\Roaming\.minecraft\launcher_accounts_microsoft_store.json"
$IASCachePath = "C:\Users\$UserRN\AppData\Roaming\.minecraft\config\ias.json"  

function Get-BrazilianDate {
    return (Get-Date).ToString("dd/MM/yyyy HH:mm")
}

# UserCache
$UserCacheExists = Test-Path $UserCachePath
$UserCacheModificationDate = if ($UserCacheExists) { (Get-Item $UserCachePath).LastWriteTime.ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

Add-Content -Path $OutputFile -Value "Usercache: $(if ($UserCacheExists) { 'Existe' } else { 'Não existe' })"
Add-Content -Path $OutputFile -Value "Data de modificação: $UserCacheModificationDate"
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""

if ($UserCacheExists) {
    $UserCacheContent = Get-Content -Path $UserCachePath -Raw | ConvertFrom-Json

    $FlattenedList = @()
    foreach ($entry in $UserCacheContent) {
        if ($entry -is [array]) {
            $FlattenedList += $entry
        } else {
            $FlattenedList += @($entry)
        }
    }
    $UserNames = $FlattenedList | ForEach-Object { $_.name }
    Add-Content -Path $OutputFile -Value "Contas encontradas no usercache.json:"
    Add-Content -Path $OutputFile -Value ""  
    $UserNames | ForEach-Object { Add-Content -Path $OutputFile -Value "    $_" }
}
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value ""

# UsernameCache
$UsernameCacheExists = Test-Path $UsernameCachePath
$UsernameCacheModificationDate = if ($UsernameCacheExists) { (Get-Item $UsernameCachePath).LastWriteTime.ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

Add-Content -Path $OutputFile -Value "Usernamecache: $(if ($UsernameCacheExists) { 'Existe' } else { 'Não existe' })"
Add-Content -Path $OutputFile -Value "Data de modificação: $UsernameCacheModificationDate"
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""

if ($UsernameCacheExists) {
    $UsernameCacheContent = Get-Content -Path $UsernameCachePath -Raw | ConvertFrom-Json

    Add-Content -Path $OutputFile -Value "Contas: "
    Add-Content -Path $OutputFile -Value ""  
    foreach ($key in $UsernameCacheContent.PSObject.Properties) {
        Add-Content -Path $OutputFile -Value "    $($key.Value)"
    }
}
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value ""


# Microsoft Accounts
$LauncherCacheExists = Test-Path $LauncherCachePath
$LauncherCacheModificationDate = if ($LauncherCacheExists) { (Get-Item $LauncherCachePath).LastWriteTime.ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

Add-Content -Path $OutputFile -Value "Launcher Accounts (Microsoft Store): $(if ($LauncherCacheExists) { 'Existe' } else { 'Não existe' })"
Add-Content -Path $OutputFile -Value "Data de modificação: $LauncherCacheModificationDate"
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""

if ($LauncherCacheExists) {
    $LauncherCacheContent = Get-Content -Path $LauncherCachePath -Raw | ConvertFrom-Json

    $AccountName = $LauncherCacheContent.accounts.PSObject.Properties | ForEach-Object { $_.Value.minecraftProfile.name }

    Add-Content -Path $OutputFile -Value "Contas :"
    Add-Content -Path $OutputFile -Value ""  
    $AccountName | ForEach-Object { Add-Content -Path $OutputFile -Value "    $_" }
}
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value ""

# In Game Account Switcher
$IASCacheExists = Test-Path $IASCachePath
$IASCacheModificationDate = if ($IASCacheExists) { (Get-Item $IASCachePath).LastWriteTime.ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

Add-Content -Path $OutputFile -Value "In-Game Account Switcher: $(if ($IASCacheExists) { 'Existe' } else { 'Não existe' })"
Add-Content -Path $OutputFile -Value "Data de modificação: $IASCacheModificationDate"
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""

if ($IASCacheExists) {
    $IASCacheContent = Get-Content -Path $IASCachePath -Raw | ConvertFrom-Json

    Add-Content -Path $OutputFile -Value "Contas :"
    Add-Content -Path $OutputFile -Value ""
    foreach ($account in $IASCacheContent.accounts) {
        $accountType = if ($account.type -eq "ias:offline") { "Pirata" } else { "Original" }
        Add-Content -Path $OutputFile -Value "    Nome: $($account.name) | Tipo: $accountType"
    }
}
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value ""

# Minecraft Logs
$MinecraftLogsPath = "C:\Users\$UserRN\AppData\Roaming\.minecraft\logs"

function Get-BrazilianDate {
    return (Get-Date).ToString("dd/MM/yyyy HH:mm")
}

$LogsExists = Test-Path $MinecraftLogsPath
$LogsModificationDate = if ($LogsExists) { (Get-Item $MinecraftLogsPath).LastWriteTime.ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

Add-Content -Path $OutputFile -Value "Minecraft Logs: $(if ($LogsExists) { 'Existe' } else { 'Não existe' })"
Add-Content -Path $OutputFile -Value "Data de modificação: $LogsModificationDate"
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""

if ($LogsExists) {
    $foundAccounts = @()
    $logFiles = Get-ChildItem -Path $MinecraftLogsPath -Filter *.log.gz
    
    foreach ($logFile in $logFiles) {
        $extractedLogPath = "$env:TEMP\$($logFile.BaseName).log"
        try {
            $gzipStream = [System.IO.Compression.GzipStream]::new([System.IO.File]::OpenRead($logFile.FullName), [System.IO.Compression.CompressionMode]::Decompress)
            $reader = [System.IO.StreamReader]::new($gzipStream, [System.Text.Encoding]::GetEncoding("ISO-8859-1"))
            $logFileContent = $reader.ReadToEnd() -split "`r`n"
            $reader.Close()
            $gzipStream.Close()

            foreach ($line in $logFileContent) {
                if ($line -match "\[\d{2}:\d{2}:\d{2}\] \[Client thread/INFO\]: Setting user: ([^\s]+)") {
                    $accountName = $matches[1]
                    if ($foundAccounts -notcontains $accountName) {
                        Add-Content -Path $OutputFile -Value "Conta Minecraft: $accountName"
                        $foundAccounts += $accountName
                    }
                }
            }
        } catch {
            Write-Host "Erro ao processar: $logFile.FullName" -ForegroundColor Red
        }
    }
    
    $latestLogPath = "$MinecraftLogsPath\latest.log"
    if (Test-Path $latestLogPath) {
        $latestLogContent = Get-Content -Path $latestLogPath
        foreach ($line in $latestLogContent) {
            if ($line -match "\[\d{2}:\d{2}:\d{2}\] \[Client thread/INFO\]: Setting user: ([^\s]+)") {
                $accountName = $matches[1]
                if ($foundAccounts -notcontains $accountName) {
                    Add-Content -Path $OutputFile -Value "Conta Minecraft: $accountName"
                    $foundAccounts += $accountName
                }
            }
        }
    }
    
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value ""
}

# LUNAR CLIENT
$LunarClientPath = "C:\Users\$UserRN\.lunarclient"
$LunarClientLogsPath = "C:\Users\$UserRN\.lunarclient\logs\game"
$LunarClientLauncherLog = "C:\Users\$UserRN\.lunarclient\logs\launcher\main.log"

$foundLcAccounts = @()


if (Test-Path $LunarClientPath) {
    
    Add-Content -Path $OutputFile -Value "LunarClient Detectado!"
    Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
    Add-Content -Path $OutputFile -Value ""

    
    if (Test-Path $LunarClientLogsPath) {
        $logFiles = Get-ChildItem -Path $LunarClientLogsPath -Filter *.log
        
        foreach ($logFile in $logFiles) {
            $logFileContent = Get-Content -Path $logFile.FullName
            foreach ($line in $logFileContent) {
                if ($line -match "\[LC\] Setting user: (\S+)") {
                    $accountName = $matches[1]  
                    if ($foundLcAccounts -notcontains $accountName) {
                        Add-Content -Path $OutputFile -Value "Conta Lunar (Game Logs): $accountName"
                        $foundLcAccounts += $accountName
                    }
                }
            }
        }
    }
    if (Test-Path $LunarClientLauncherLog) {
        $launcherLogContent = Get-Content -Path $LunarClientLauncherLog
        
        foreach ($line in $launcherLogContent) {
            if ($line -match "\[Authenticator\] Creating Minecraft session for (\S+)") {
                $launcherAccount = $matches[1]
                if ($foundLcAccounts -notcontains $launcherAccount) {
                    Add-Content -Path $OutputFile -Value "Conta Lunar (Launcher Logs): $launcherAccount"
                    $foundLcAccounts += $launcherAccount
                }
            }
        }
    }
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value ""
} 

# LUNAR CLIENT2
$lunar1 = "C:\Users\$UserRN\.lunarclient\offline\multiver\logs"

function Get-BrazilianDate {
    return (Get-Date).ToString("dd/MM/yyyy HH:mm")
}

$lunar2 = Test-Path $lunar1
$lunar3 = if ($lunar2) { (Get-Item $lunar1).LastWriteTime.ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

Add-Content -Path $OutputFile -Value "Offline Lunar: $(if ($lunar2) { 'Existe' } else { 'Não existe' })"
Add-Content -Path $OutputFile -Value "Data de modificação: $lunar3"
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""

if ($lunar2) {
    $lunar4 = @()
    $lunar5 = Get-ChildItem -Path $lunar1 -Filter *.log.gz
    
    foreach ($lunar6 in $lunar5) {
        $lunar7 = "$env:TEMP\$($lunar6.BaseName).log"
        try {
            $lunar8 = [System.IO.Compression.GzipStream]::new([System.IO.File]::OpenRead($lunar6.FullName), [System.IO.Compression.CompressionMode]::Decompress)
            $lunar9 = [System.IO.StreamReader]::new($lunar8, [System.Text.Encoding]::GetEncoding("ISO-8859-1"))
            $lunar10 = $lunar9.ReadToEnd() -split "`r`n"
            $lunar9.Close()
            $lunar8.Close()

            foreach ($lunar11 in $lunar10) {
                if ($lunar11 -match "Setting user: ([^\s]+)") {
                    $lunar12 = $matches[1]
                    if ($lunar12 -notmatch "^Player\d+$") {
                        if ($lunar4 -notcontains $lunar12) {
                            Add-Content -Path $OutputFile -Value "Conta: $lunar12"
                            $lunar4 += $lunar12
                        }
                    }
                }
            }
        } catch {
            Write-Host "Erro ao processar: $lunar6.FullName" -ForegroundColor Red
        }
    }
    
    $lunar13 = "$lunar1\latest.log"
    if (Test-Path $lunar13) {
        $lunar14 = Get-Content -Path $lunar13
        foreach ($lunar15 in $lunar14) {
            if ($lunar15 -match "Setting user: ([^\s]+)") {
                $lunar16 = $matches[1]
                if ($lunar16 -notmatch "^Player\d+$") {
                    if ($lunar4 -notcontains $lunar16) {
                        Add-Content -Path $OutputFile -Value "Conta: $lunar16"
                        $lunar4 += $lunar16
                    }
                }
            }
        }
    }
    
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value ""
}

# BADLION
$BadlionClientPath = "C:\Users\$UserRN\AppData\Roaming\.minecraft\logs\blclient"
$BadlionClientLogsPath = "$BadlionClientPath\minecraft"

if (Test-Path $BadlionClientPath) {
    Add-Content -Path $OutputFile -Value "Badlion Client Detectado!"
    Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
    Add-Content -Path $OutputFile -Value ""

    if (Test-Path $BadlionClientLogsPath) {
        $logFiles = Get-ChildItem -Path $BadlionClientLogsPath -Filter *.log
       
        foreach ($logFile in $logFiles) {
            $logFileContent = Get-Content -Path $logFile.FullName

            foreach ($line in $logFileContent) {
                if ($line -match "Setting user: (\S+)") {
                    $accountName = $matches[1] 
                    Add-Content -Path $OutputFile -Value "Conta Badlion: $accountName"
                }
            }
        }
    } 
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value ""
}

# TLAUCHER
$TLauncherPath = "C:\Users\$UserRN\AppData\Roaming\.tlauncher"
$TLauncherLogsPath = "$TLauncherPath\logs\tlauncher"

$foundAccounts = @()

if (Test-Path $TLauncherPath) {
    Add-Content -Path $OutputFile -Value "TLauncher Detectado!"
    Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
    Add-Content -Path $OutputFile -Value ""

    if (Test-Path $TLauncherLogsPath) {
        $logFiles = Get-ChildItem -Path $TLauncherLogsPath -Filter *.log
        
        foreach ($logFile in $logFiles) {
            $logFileContent = Get-Content -Path $logFile.FullName

            foreach ($line in $logFileContent) {
                if ($line -match "displayName=([^\s,]+)") {
                    $accountName = $matches[1]  

                    if ($foundAccounts -notcontains $accountName) {
                        Add-Content -Path $OutputFile -Value "Conta TLauncher: $accountName"
                        $foundAccounts += $accountName
                    }
                }
            }
        }
    }
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value ""
}


# Hwid Colector by bxbben 
# Link: https://github.com/MrBebben/RAM-CPU-Serialnumber-of-PC-
$commands = @(
    'Get-WmiObject win32_processor | Select-Object ProcessorId',
    'Get-WmiObject Win32_PhysicalMemory | Select-Object SerialNumber',
    'Get-WmiObject Win32_DiskDrive | Select-Object SerialNumber'
)

$outputFile2 = "$env:USERPROFILE\Downloads\Serial Colector.txt"

"==================================================" | Out-File -FilePath $outputFile2

foreach ($command in $commands) {

    $result = Invoke-Expression $command
    $result | Out-File -FilePath $outputFile2 -Append
    ("=" * 50) | Out-File -FilePath $outputFile2 -Append  
}
Write-Host ""
Write-Host -ForegroundColor Green "Scan completo " 
Write-Host ""

# Formatação
$osInfo = Get-WmiObject -Class Win32_OperatingSystem

if ($osInfo) {
    $installationDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($osInfo.InstallDate)
    $lastBootUpTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($osInfo.LastBootUpTime)

    $formattedInstallationDate = $installationDate.ToString("dd/MM/yyyy, HH:mm:ss")
    $formattedLastBootUpTime = $lastBootUpTime.ToString("dd/MM/yyyy, HH:mm:ss")


    Write-Host -ForegroundColor RED "Data da instalação original: " -NoNewLine
    Write-Host "$formattedInstallationDate"
    Write-Host ""
    Write-Host -ForegroundColor RED "Tempo de Inicialização do Sistema: " -NoNewLine
    Write-Host "$formattedLastBootUpTime"
} else {
    Write-Host "Erro: Não foi possível obter as informações do sistema."
}
Write-Host "" 
Write-Host -ForegroundColor Yellow "Alt Scan salvo em: " -NoNewLine  
Write-Host "$OutputFile"
Write-Host ""
Write-Host -ForegroundColor Yellow "Serial Scanner salvo em: " -NoNewLine  
Write-Host "$outputFile2"
