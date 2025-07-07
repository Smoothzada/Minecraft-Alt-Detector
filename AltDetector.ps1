$ErrorActionPreference = "SilentlyContinue"
$UserRN = $env:USERNAME
clear-host
function ScannerAltLogoN {
Write-Host @"

    .--------------------------------------------------------.
    |      _    _ _   ____                                   |
    |     / \  | | |_/ ___|  ___ __ _ _ __  _ __   ___ _ __  |
    |    / _ \ | | __\___ \ / __/ _`  | '_ \| '_ \ / _ \ '__| |
    |   / ___ \| | |_ ___) | (_| (_| | | | | | | |  __/ |    |
    |  /_/   \_\_|\__|____/ \___\____|_| |_|_| |_|\___|_|    |
    '--------------------------------------------------------' 

"@ -ForegroundColor Red                                                           
    Write-Host -ForegroundColor Blue "     by Smooth | Discord: smoothzada"
    Write-Host ""
}

function Get-ValidID {
    while ($true) {
        $ID = Read-Host "Insira o ID do usuario"
        if ($ID -match '^\d+$') {  
            return $ID
        }
        else {
            Write-Host "[ERRO] O ID deve conter apenas numeros! Tente novamente." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Clear-Host  
            ScannerAltLogoN
        }
    }
}

ScannerAltLogoN
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (!(Test-Admin)) {
    Write-Warning "Execute o script como Administrador"
    Start-Sleep 5
    Exit
} 
    
$ID = Get-ValidID
Write-Host ""
Write-Host "[*] Deseja instalar o SystemInformer?" -ForegroundColor Cyan
Write-Host "    [1] Sim"
Write-Host "    [2] Não"
Write-Host ""
$Systemchose = Read-Host "Escolha"
if ($Systemchose -eq "1") {
    $destination = "$env:USERPROFILE\Downloads\systeminformer-setup.exe"
    $url = "https://github.com/winsiderss/si-builds/releases/download/3.2.25152.1910/systeminformer-3.2.25152.1910-canary-setup.exe"
    Write-Host "Baixando System Informer..." -ForegroundColor Green
    Invoke-WebRequest -Uri $url -OutFile $destination
    Write-Host "Download completo!" -ForegroundColor Green
    Write-Host "Abrindo setup do System Informer..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1
    Start-Process -FilePath $destination
    cls
    ScannerAltLogoN
} else {
    cls
    ScannerAltLogoN
}

Start-Sleep -Seconds 1
Write-Host -ForegroundColor Yellow "Starting scan"
Write-Host ""

#1231
$scanFlagFile = Join-Path -Path $env:SystemRoot -ChildPath "System32\Scan_Alt.txt"
$scanFlagFile2 = Join-Path -Path $env:TEMP -ChildPath "HAHAHAHAHAHAHAHAHA.llogamcache"
$scanFlagFile3 = Join-Path -Path $env:SystemRoot -ChildPath "System32\ASmoothadw.raw"
$scanFlagFile4 = Join-Path -Path $env:APPDATA -ChildPath ".minecraft\scan_marker.log"
$scanFlagFile5 = Join-Path -Path $env:TEMP -ChildPath "40009c63-d158-ca66d0dc00b4-nigg-amotha3.tmp"

$scanDetected = (Test-Path $scanFlagFile) -or (Test-Path $scanFlagFile2) -or (Test-Path $scanFlagFile3) -or (Test-Path $scanFlagFile4) -or (Test-Path $scanFlagFile5)

if ($scanDetected) {
    $existingFile = @($scanFlagFile, $scanFlagFile2, $scanFlagFile3, $scanFlagFile4, $scanFlagFile5 | Where-Object { Test-Path $_ })[0]
    $lastModified = (Get-Item $existingFile).LastWriteTime.ToString("dd/MM/yyyy -- HH:mm")
    
    $storedID = "Unknown"
    if (Test-Path $scanFlagFile) {
        $content = Get-Content $scanFlagFile -ErrorAction SilentlyContinue
        if ($content -match "ID do Usuario: (\d+)") { $storedID = $matches[1] }
    }
    if ($storedID -eq "Unknown" -and (Test-Path $scanFlagFile4)) {
        $content = Get-Content $scanFlagFile4 -ErrorAction SilentlyContinue
        if ($content -match "ID do Usuario: (\d+)") { $storedID = $matches[1] }
    }
    
    Write-Host "[!] Esse computador ja foi escaneado anteriormente! ($lastModified | ID: $storedID)" -ForegroundColor Red
    Write-Host ""
    
    Set-Content -Path $scanFlagFile -Value "ID do Usuario: $ID" -Force -ErrorAction SilentlyContinue
    Set-Content -Path $scanFlagFile4 -Value "ID do Usuario: $ID" -Force -ErrorAction SilentlyContinue
}
else {
    try {
        $minecraftDir = Join-Path -Path $env:APPDATA -ChildPath ".minecraft"
        if (-not (Test-Path $minecraftDir)) {
            New-Item -Path $minecraftDir -ItemType Directory -Force | Out-Null
        }
        
        New-Item -Path $scanFlagFile -ItemType File -Force | Out-Null
        New-Item -Path $scanFlagFile2 -ItemType File -Force | Out-Null
        New-Item -Path $scanFlagFile3 -ItemType File -Force | Out-Null
        New-Item -Path $scanFlagFile4 -ItemType File -Force | Out-Null
        New-Item -Path $scanFlagFile5 -ItemType File -Force | Out-Null
        
        Set-Content -Path $scanFlagFile -Value "ID do Usuario: $ID" -Force
        Set-Content -Path $scanFlagFile4 -Value "ID do Usuario: $ID" -Force
    }
    catch {
        Write-Host "[ERRO] Dm Smooth" -ForegroundColor Yellow
    }
}

#VM
$VMIdentified = $false

$systemInfo = Get-WmiObject -Class Win32_ComputerSystem
if ($systemInfo.Model -imatch "virtual") {
    $VMIdentified = $true
    Write-Host "[!] Generic VM detectada" -ForegroundColor Red
}
if ($systemInfo.Manufacturer -imatch "Microsoft Corporation" -and $systemInfo.Model -imatch "Virtual Machine") {
    $VMIdentified = $true
    Write-Host "[!] Maquina Virtual detectada (Hyper-V)" -ForegroundColor Red
}
$biosInfo = Get-WmiObject -Namespace "root\cimv2" -Class Win32_BIOS
if ($biosInfo.Manufacturer -imatch "VMware" -or $biosInfo.SMBIOSBIOSVersion -imatch "VMware") {
    $VMIdentified = $true
    Write-Host "[!] Maquina Virtual detectada (VMware)" -ForegroundColor Red
}
if ($systemInfo.Manufacturer -imatch "Oracle" -or $systemInfo.Model -imatch "VirtualBox") {
    $VMIdentified = $true
    Write-Host "[!] Maquina Virtual detectada (VirtualBox)" -ForegroundColor Red
}
if ($systemInfo.Model -imatch "Xen" -or $systemInfo.Manufacturer -imatch "Xen") {
    $VMIdentified = $true
    Write-Host "[!] Maquina Virtual detectada (Xen)" -ForegroundColor Red
}
if ($systemInfo.Model -imatch "KVM" -or $systemInfo.Manufacturer -imatch "QEMU") {
    $VMIdentified = $true
    Write-Host "[!] Maquina Virtual detectada (QEMU/KVM)" -ForegroundColor Red
}
if ($systemInfo.Manufacturer -imatch "Parallels" -or $systemInfo.Model -imatch "Parallels") {
    $VMIdentified = $true
    Write-Host "[!] Maquina Virtual detectada (Parallels)" -ForegroundColor Red
}
if ($systemInfo.Model -imatch "Amazon EC2" -or $systemInfo.Manufacturer -imatch "Amazon") {
    $VMIdentified = $true
    Write-Host "[!] Maquina Virtual detectada (Amazon EC2)" -ForegroundColor Red
}
if ($systemInfo.Model -imatch "Google" -or $systemInfo.Manufacturer -imatch "Google") {
    $VMIdentified = $true
    Write-Host "[!] Maquina Virtual detectada (Google Compute Engine)" -ForegroundColor Red
}
$dockerEnv = Test-Path -Path "C:\ProgramData\Docker"
if ($dockerEnv) {
    $VMIdentified = $true
    Write-Host "[!] Container Docker detectado" -ForegroundColor Red
}
if (-not $VMIdentified) {
    Write-Host "[*] Maquina virtual nao encontrada" -ForegroundColor Green
}
Write-Host ""

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

Add-Content -Path $OutputFile -Value "Usercache: $(if ($UserCacheExists) { 'Existe' } else { 'Nao existe' })"
Add-Content -Path $OutputFile -Value "Data de modificacao: $UserCacheModificationDate"
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
    $UserNames | ForEach-Object { Add-Content -Path $OutputFile -Value "    Conta: $_" }
}
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value ""

# UsernameCache
$UsernameCacheExists = Test-Path $UsernameCachePath
$UsernameCacheModificationDate = if ($UsernameCacheExists) { (Get-Item $UsernameCachePath).LastWriteTime.ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

Add-Content -Path $OutputFile -Value "Usernamecache: $(if ($UsernameCacheExists) { 'Existe' } else { 'Nao existe' })"
Add-Content -Path $OutputFile -Value "Data de modificacao: $UsernameCacheModificationDate"
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""

if ($UsernameCacheExists) {
    $UsernameCacheContent = Get-Content -Path $UsernameCachePath -Raw | ConvertFrom-Json

    Add-Content -Path $OutputFile -Value "Contas: "
    Add-Content -Path $OutputFile -Value ""  
    foreach ($key in $UsernameCacheContent.PSObject.Properties) {
        Add-Content -Path $OutputFile -Value "    Conta: $($key.Value)"
    }
}
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value ""

# Microsoft Accounts
$LauncherCacheExists = Test-Path $LauncherCachePath
$LauncherCacheModificationDate = if ($LauncherCacheExists) { (Get-Item $LauncherCachePath).LastWriteTime.ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

Add-Content -Path $OutputFile -Value "Launcher Accounts (Microsoft Store): $(if ($LauncherCacheExists) { 'Existe' } else { 'Nao existe' })"
Add-Content -Path $OutputFile -Value "Data de modificacao: $LauncherCacheModificationDate"
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""

if ($LauncherCacheExists) {
    $LauncherCacheContent = Get-Content -Path $LauncherCachePath -Raw | ConvertFrom-Json

    $AccountName = $LauncherCacheContent.accounts.PSObject.Properties | ForEach-Object { $_.Value.minecraftProfile.name }

    Add-Content -Path $OutputFile -Value "Contas :"
    Add-Content -Path $OutputFile -Value ""  
    $AccountName | ForEach-Object { Add-Content -Path $OutputFile -Value "    Conta: $_" }
}
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value ""

# In Game Account Switcher
$IASCacheExists = Test-Path $IASCachePath
$IASCacheModificationDate = if ($IASCacheExists) { (Get-Item $IASCachePath).LastWriteTime.ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

Add-Content -Path $OutputFile -Value "In-Game Account Switcher: $(if ($IASCacheExists) { 'Existe' } else { 'Nao existe' })"
Add-Content -Path $OutputFile -Value "Data de modificacao: $IASCacheModificationDate"
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""

if ($IASCacheExists) {
    $IASCacheContent = Get-Content -Path $IASCachePath -Raw | ConvertFrom-Json

    Add-Content -Path $OutputFile -Value "Contas :"
    Add-Content -Path $OutputFile -Value ""
    foreach ($account in $IASCacheContent.accounts) {
        $accountType = if ($account.type -eq "ias:offline") { "Pirata" } else { "Original" }
        Add-Content -Path $OutputFile -Value "    Conta: $($account.name) | Tipo: $accountType"
    }
}
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""
Add-Content -Path $OutputFile -Value ""

# Minecraft Logs
$MinecraftLogsPath = "C:\Users\$env:USERNAME\AppData\Roaming\.minecraft\logs"

function Get-BrazilianDate {
    return (Get-Date).ToString("dd/MM/yyyy HH:mm")
}
$LogsExists = Test-Path $MinecraftLogsPath
$LogsModificationDate = if ($LogsExists) { (Get-Item $MinecraftLogsPath).LastWriteTime.ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

Add-Content -Path $OutputFile -Value "Minecraft Logs: $(if ($LogsExists) { 'Existe' } else { 'Nao existe' })"
Add-Content -Path $OutputFile -Value "Data de modificacao: $LogsModificationDate"
Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
Add-Content -Path $OutputFile -Value ""

if ($LogsExists) {
    $foundAccounts = @()
    $logFiles = Get-ChildItem -Path $MinecraftLogsPath -Filter *.log.gz

    foreach ($logFile in $logFiles) {
        try {
            $gzipStream = [System.IO.Compression.GzipStream]::new([System.IO.File]::OpenRead($logFile.FullName), [System.IO.Compression.CompressionMode]::Decompress)
            $reader = [System.IO.StreamReader]::new($gzipStream, [System.Text.Encoding]::UTF8)  
            $logFileContent = $reader.ReadToEnd() -split "`n"  
            $reader.Close()
            $gzipStream.Close()

            foreach ($line in $logFileContent) {
                if ($line -match "Setting user: (\w+)") {
                    $accountName = $matches[1]
                    if ($foundAccounts -notcontains $accountName) {
                        Add-Content -Path $OutputFile -Value "Conta: $accountName"  
                        $foundAccounts += $accountName
                    }
                }
            }
        } catch {
            Write-Host "Erro ao processar: $($logFile.FullName)" -ForegroundColor Red  
        }
    }
    $latestLogPath = "$MinecraftLogsPath\latest.log"
    if (Test-Path $latestLogPath) {
        try {
            $latestLogContent = Get-Content -Path $latestLogPath -Encoding UTF8
            foreach ($line in $latestLogContent) {
                if ($line -match "Setting user: (\w+)") {
                    $accountName = $matches[1]
                    if ($foundAccounts -notcontains $accountName) {
                        Add-Content -Path $OutputFile -Value "Conta: $accountName"  
                        $foundAccounts += $accountName
                    }
                }
            }
        } catch {
            Write-Host "Erro ao processar: $latestLogPath" -ForegroundColor Red  
        }
    }

    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value "----------------------------------------------------------"
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value ""
} else {
    Write-Host "Pasta de logs do Minecraft nao encontrada: $MinecraftLogsPath" -ForegroundColor Red
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
                        Add-Content -Path $OutputFile -Value "    Conta: $accountName"
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
                    Add-Content -Path $OutputFile -Value "    Conta: $launcherAccount"
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

Add-Content -Path $OutputFile -Value "Offline Lunar: $(if ($lunar2) { 'Existe' } else { 'Nao existe' })"
Add-Content -Path $OutputFile -Value "Data de modificacao: $lunar3"
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
                            Add-Content -Path $OutputFile -Value "    Conta: $lunar12"
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
                        Add-Content -Path $OutputFile -Value "    Conta: $lunar16"
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
                    Add-Content -Path $OutputFile -Value "    Conta: $accountName"
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
                        Add-Content -Path $OutputFile -Value "    Conta: $accountName"
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
# Hwid
$outputFile2 = "$env:USERPROFILE\Downloads\Serial Collector.txt"

$pcName = (Get-WmiObject Win32_ComputerSystem).Name
$mbUUID = (Get-WmiObject Win32_ComputerSystemProduct).UUID
$cpuId = (Get-WmiObject Win32_Processor).ProcessorId
$ramSerials = Get-WmiObject Win32_PhysicalMemory | ForEach-Object { $_.SerialNumber }
$diskSerials = Get-WmiObject Win32_DiskDrive | ForEach-Object { $_.SerialNumber }
$volumeSerials = Get-WmiObject Win32_LogicalDisk | ForEach-Object { $_.VolumeSerialNumber }
$macAddresses = (Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.MACAddress -ne $null } | ForEach-Object { $_.MACAddress })[0]
$displayDeviceID = Get-WmiObject Win32_DesktopMonitor | ForEach-Object { $_.PNPDeviceID }

@"
==================================================
PC Name: $pcName
==================================================
UUID: $mbUUID
==================================================
DisplayDeviceID:
`t$($displayDeviceID -join "`n`t")
==================================================
MAC Address:
`t$macAddresses
==================================================
RAM Serials:
`t$($ramSerials -join "`n`t")
==================================================
Disk Serials:
`t$($diskSerials -join "`n`t")
==================================================
LogicalDisk VolumeSerial:
`t$($volumeSerials -join "`n`t")
==================================================
"@ | Out-File -FilePath $outputFile2 -Encoding UTF8


# Formatacao
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
if ($osInfo) {
    $installationDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($osInfo.InstallDate)
    $lastBootUpTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($osInfo.LastBootUpTime)

    $formattedInstallationDate = $installationDate.ToString("dd/MM/yyyy, HH:mm:ss")
    $formattedLastBootUpTime = $lastBootUpTime.ToString("dd/MM/yyyy, HH:mm:ss")

    Write-Host -ForegroundColor RED "Data da instalacao original: " -NoNewLine
    Write-Host "$formattedInstallationDate"
    Write-Host ""
    Write-Host -ForegroundColor RED "Tempo de Inicializacao do Sistema: " -NoNewLine
    Write-Host "$formattedLastBootUpTime"
} else {
    Write-Host "Erro: Nao foi possível obter as informacões do sistema."
}
Write-Host "" 
Write-Host -ForegroundColor Yellow "Alt Scan salvo em: " -NoNewLine  
Write-Host "$OutputFile"
Write-Host ""
Write-Host -ForegroundColor Yellow "Serial Scanner salvo em: " -NoNewLine  
Write-Host "$outputFile2"
Write-Host ""
Write-Host @"
    .---------------------------------------------------------------------.
    |   ____                     ____                      _      _       |
    |  / ___|  ___ __ _ _ __    / ___|___  _ __ ___  _ __ | | ___| |_ ___ |
    |  \___ \ / __/ _`  | '_ \  | |   / _ \| '_ ` _  \| '_ \| |/ _ \ __/ _ \|
    |   ___) | (_| (_| | | | | | |__| (_) | | | | | | |_) | |  __/ ||  __/|
    |  |____/ \___\__,_|_| |_|  \____\___/|_| |_| |_| .__/|_|\___|\__\___||
    |                                               |_|                   |
    '---------------------------------------------------------------------'                                                                                                                           
"@ -ForegroundColor Green 
