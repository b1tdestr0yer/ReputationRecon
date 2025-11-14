# ReputationRecon Startup Script for Windows
# This script sets up and runs the application

Write-Host "ReputationRecon - Starting Application" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Try to find Python
$pythonCmd = $null
$pythonPaths = @("python", "python3", "py")

# First, try common command names
foreach ($cmd in $pythonPaths) {
    try {
        $result = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($result) {
            $testVersion = & $cmd --version 2>&1
            if ($LASTEXITCODE -eq 0 -and $testVersion -notmatch "not found|Microsoft Store") {
                $pythonCmd = $cmd
                Write-Host "Found Python: $testVersion" -ForegroundColor Green
                break
            }
        }
    } catch {
        continue
    }
}

# If not found, try common installation paths
if (-not $pythonCmd) {
    Write-Host "Python not in PATH, checking common installation locations..." -ForegroundColor Yellow
    
    $commonPaths = @(
        "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe",
        "$env:PROGRAMFILES\Python3*\python.exe",
        "$env:PROGRAMFILES(X86)\Python3*\python.exe",
        "C:\Python3*\python.exe",
        "$env:USERPROFILE\AppData\Local\Programs\Python\Python3*\python.exe"
    )
    
    foreach ($pathPattern in $commonPaths) {
        $found = Get-ChildItem -Path $pathPattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            $pythonCmd = $found.FullName
            $version = & $pythonCmd --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Found Python at: $pythonCmd" -ForegroundColor Green
                Write-Host "Version: $version" -ForegroundColor Green
                break
            }
        }
    }
}

if (-not $pythonCmd) {
    Write-Host ""
    Write-Host "ERROR: Python not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Python 3.8+ is required to run ReputationRecon." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please install Python from one of these sources:" -ForegroundColor Yellow
    Write-Host "  1. Official: https://www.python.org/downloads/" -ForegroundColor Cyan
    Write-Host "  2. Microsoft Store: Search for 'Python' in the Microsoft Store" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "IMPORTANT: During installation, check 'Add Python to PATH'" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "After installing Python, close and reopen this terminal, then run:" -ForegroundColor Yellow
    Write-Host "  .\start.ps1" -ForegroundColor Cyan
    Write-Host ""
    pause
    exit 1
}

# Check if virtual environment exists
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    $venvResult = & $pythonCmd -m venv venv 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to create virtual environment" -ForegroundColor Red
        Write-Host $venvResult -ForegroundColor Red
        Write-Host ""
        Write-Host "Make sure Python is properly installed and try again." -ForegroundColor Yellow
        pause
        exit 1
    }
    Write-Host "Virtual environment created!" -ForegroundColor Green
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
if (Test-Path "venv\Scripts\Activate.ps1") {
    & "venv\Scripts\Activate.ps1"
} else {
    Write-Host "WARNING: Could not activate virtual environment, continuing anyway..." -ForegroundColor Yellow
}

# Use venv Python if available, otherwise use found Python
$venvPython = "venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    $pythonCmd = $venvPython
    Write-Host "Using virtual environment Python" -ForegroundColor Green
}

# Check if dependencies are installed
Write-Host "Checking dependencies..." -ForegroundColor Yellow
$fastapiCheck = & $pythonCmd -c "import fastapi" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing dependencies (this may take a few minutes)..." -ForegroundColor Yellow
    $pipResult = & $pythonCmd -m pip install -r requirements.txt 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install dependencies" -ForegroundColor Red
        Write-Host $pipResult -ForegroundColor Red
        Write-Host ""
        Write-Host "Try running manually: $pythonCmd -m pip install -r requirements.txt" -ForegroundColor Yellow
        pause
        exit 1
    }
    Write-Host "Dependencies installed successfully!" -ForegroundColor Green
} else {
    Write-Host "Dependencies already installed!" -ForegroundColor Green
}

# Check for .env file
if (-not (Test-Path ".env")) {
    Write-Host ""
    Write-Host "WARNING: .env file not found!" -ForegroundColor Yellow
    Write-Host "Run .\setup_env.ps1 to configure API keys (optional)" -ForegroundColor Yellow
    Write-Host ""
}

# Start the server
Write-Host ""
Write-Host "Starting ReputationRecon server..." -ForegroundColor Cyan
Write-Host "Server will be available at: http://localhost:8000" -ForegroundColor Green
Write-Host "API Documentation: http://localhost:8000/docs" -ForegroundColor Green
Write-Host "Web UI: http://localhost:8000/static/index.html" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

& $pythonCmd main.py

