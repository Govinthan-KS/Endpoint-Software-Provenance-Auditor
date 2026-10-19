<#
.SYNOPSIS
    AppAudit Local Service Supervision & Startup Helper.
.DESCRIPTION
    Ensures Docker Desktop, the SearXNG search container, and Ollama serve are running,
    verifying both endpoints for AppAudit offline/local AI reasoning.
#>

[CmdletBinding()]
param(
    [string]$OllamaUrl = "http://localhost:11434",
    [string]$SearxngUrl = "http://localhost:8080",
    [string]$TargetModel = "audit-phi:q6k"
)

$ErrorActionPreference = "Stop"

$OllamaProbeUrl = $OllamaUrl -replace "://localhost", "://127.0.0.1"
$SearxngProbeUrl = $SearxngUrl -replace "://localhost", "://127.0.0.1"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " AppAudit - Local AI & Search Grounding Stack Supervisor" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Docker Desktop / Docker Daemon
Write-Host "[1/3] Checking Docker daemon status..." -NoNewline
$dockerAvailable = $false
cmd.exe /c "docker info >nul 2>nul"
if ($LASTEXITCODE -eq 0) {
    $dockerAvailable = $true
    Write-Host " [RUNNING]" -ForegroundColor Green
}

if (-not $dockerAvailable) {
    Write-Host " [STOPPED]" -ForegroundColor Yellow
    $dockerBackendPath = "$env:ProgramFiles\Docker\Docker\resources\com.docker.backend.exe"
    $dockerDesktopPath = "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
    $targetExe = ""
    if (Test-Path $dockerBackendPath) {
        $targetExe = $dockerBackendPath
    } elseif (Test-Path $dockerDesktopPath) {
        $targetExe = $dockerDesktopPath
    }

    if ($targetExe) {
        Write-Host "      Starting Docker daemon in background..." -ForegroundColor Yellow
        Start-Process -FilePath $targetExe -WindowStyle Hidden
        Write-Host "      Waiting for Docker engine to initialize (up to 40s)..." -NoNewline
        $ddReady = $false
        for ($i = 0; $i -lt 40; $i++) {
            Start-Sleep -Seconds 1
            cmd.exe /c "docker info >nul 2>nul"
            if ($LASTEXITCODE -eq 0) {
                $ddReady = $true
                break
            }
        }
        if ($ddReady) {
            Write-Host " [READY]" -ForegroundColor Green
        } else {
            Write-Host " [TIMEOUT]" -ForegroundColor Red
            Write-Warning "Docker daemon did not become ready in time. SearXNG startup may fail."
        }
    } else {
        Write-Warning "Docker executable not found. Please start Docker manually."
    }
}

# 2. Check and start SearXNG container
Write-Host "[2/3] Checking SearXNG search container..." -NoNewline
$searxngRunning = $false
try {
    $resp = Invoke-WebRequest -Uri "$SearxngProbeUrl/healthz" -Method Get -TimeoutSec 1 -UseBasicParsing -ErrorAction Stop
    if ($resp.StatusCode -eq 200) {
        $searxngRunning = $true
        Write-Host " [ONLINE]" -ForegroundColor Green
    }
} catch {
    try {
        $resp = Invoke-RestMethod -Uri "$SearxngProbeUrl/search?q=ping&format=json" -Method Get -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
        $searxngRunning = $true
        Write-Host " [ONLINE]" -ForegroundColor Green
    } catch {
        $searxngRunning = $false
    }
}

if (-not $searxngRunning) {
    Write-Host " [OFFLINE]" -ForegroundColor Yellow
    $containerInfo = (docker ps -a --filter "name=searxng" --format "{{.Names}}|{{.Status}}" 2>$null) | Out-String
    if ($containerInfo -match "searxng\|") {
        Write-Host "      Starting existing 'searxng' container..." -ForegroundColor Yellow
        docker start searxng | Out-Null
    } else {
        Write-Host "      Creating and starting new 'searxng' container..." -ForegroundColor Yellow
        $settingsFile = Join-Path $PSScriptRoot "..\settings.yml"
        if (Test-Path $settingsFile) {
            $absSettings = (Resolve-Path $settingsFile).Path
            docker run -d --name searxng -p 8080:8080 -v "$($absSettings):/etc/searxng/settings.yml:ro" --restart always searxng/searxng:latest | Out-Null
        } else {
            docker run -d --name searxng -p 8080:8080 --restart always searxng/searxng:latest | Out-Null
        }
    }

    Write-Host "      Waiting for SearXNG endpoint to respond..." -NoNewline
    $ready = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1
        try {
            $test = Invoke-WebRequest -Uri "$SearxngProbeUrl/healthz" -Method Get -TimeoutSec 1 -UseBasicParsing -ErrorAction Stop
            if ($test.StatusCode -eq 200) {
                $ready = $true
                break
            }
        } catch {
            try {
                $test = Invoke-RestMethod -Uri "$SearxngProbeUrl/search?q=ping&format=json" -Method Get -TimeoutSec 1 -UseBasicParsing -ErrorAction Stop
                $ready = $true
                break
            } catch { }
        }
    }
    if ($ready) {
        Write-Host " [ONLINE]" -ForegroundColor Green
    } else {
        Write-Host " [FAILED / TIMEOUT]" -ForegroundColor Red
    }
}

# 3. Check and start Ollama
Write-Host "[3/3] Checking Ollama daemon status..." -NoNewline
$ollamaRunning = $false
try {
    $resp = Invoke-WebRequest -Uri "$OllamaProbeUrl/api/tags" -Method Get -TimeoutSec 1 -UseBasicParsing -ErrorAction Stop
    if ($resp.StatusCode -eq 200) {
        $ollamaRunning = $true
        Write-Host " [ONLINE]" -ForegroundColor Green
    }
} catch {
    $ollamaRunning = $false
}

if (-not $ollamaRunning) {
    Write-Host " [OFFLINE]" -ForegroundColor Yellow
    $ollamaExe = (Get-Command "ollama.exe" -ErrorAction SilentlyContinue).Source
    if (-not $ollamaExe -and (Test-Path "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe")) {
        $ollamaExe = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"
    }

    if ($ollamaExe) {
        Write-Host "      Launching 'ollama serve' in background..." -ForegroundColor Yellow
        Start-Process -FilePath $ollamaExe -ArgumentList "serve" -WindowStyle Hidden
        Write-Host "      Waiting for Ollama API endpoint to respond..." -NoNewline
        $ready = $false
        for ($i = 0; $i -lt 20; $i++) {
            Start-Sleep -Milliseconds 500
            try {
                $poll = Invoke-WebRequest -Uri "$OllamaProbeUrl/api/tags" -Method Get -TimeoutSec 1 -UseBasicParsing -ErrorAction Stop
                if ($poll.StatusCode -eq 200) {
                    $ready = $true
                    break
                }
            } catch { }
        }
        if ($ready) {
            Write-Host " [ONLINE]" -ForegroundColor Green
        } else {
            Write-Host " [FAILED / TIMEOUT]" -ForegroundColor Red
        }
    } else {
        Write-Warning "Ollama executable not found. Please install Ollama from https://ollama.com"
    }
}

# Verify model presence
try {
    $tagsRaw = Invoke-WebRequest -Uri "$OllamaProbeUrl/api/tags" -Method Get -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
    $tags = $tagsRaw.Content | ConvertFrom-Json
    $modelNames = $tags.models | ForEach-Object { $_.name }
    $hasModel = $false
    if ($modelNames -contains $TargetModel) {
        $hasModel = $true
    } else {
        foreach ($m in $modelNames) {
            if ($m -like "$TargetModel*") {
                $hasModel = $true
                break
            }
        }
    }
    if ($hasModel) {
        Write-Host "[+] Target model '$TargetModel' is installed and ready." -ForegroundColor Green
    } else {
        Write-Host "[!] Notice: Model '$TargetModel' was not found in Ollama." -ForegroundColor Yellow
        Write-Host "    To create it, run: ollama create $TargetModel -f Modelfile.local" -ForegroundColor Yellow
    }
} catch { }

Write-Host ""
Write-Host "[+] Local service supervision complete. AppAudit offline mode ready." -ForegroundColor Green
