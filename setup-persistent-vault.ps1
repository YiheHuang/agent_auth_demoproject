[CmdletBinding()]
param(
    [string]$VaultCommand = "vault",
    [string]$VaultAddr = "http://127.0.0.1:8200",
    [string]$TransitMount = "transit",
    [string]$RuntimeDir = "runtime",
    [switch]$ForceRewriteConfig,
    [switch]$NoStartServer
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$script:ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:RuntimeRoot = Join-Path $script:ProjectRoot $RuntimeDir
$script:VaultRoot = Join-Path $script:RuntimeRoot "vault"
$script:VaultDataDir = Join-Path $script:VaultRoot "data"
$script:VaultLogsDir = Join-Path $script:VaultRoot "logs"
$script:VaultConfigPath = Join-Path $script:VaultRoot "config.hcl"
$script:VaultInitPath = Join-Path $script:VaultRoot "init.json"
$script:VaultRootTokenPath = Join-Path $script:VaultRoot "root-token.txt"
$script:VaultUnsealKeyPath = Join-Path $script:VaultRoot "unseal-key.txt"
$script:DemoVaultTokenPath = Join-Path $script:RuntimeRoot "vault-token.txt"
$script:VaultServerLogPath = Join-Path $script:VaultLogsDir "server.log"
$script:VaultServerErrPath = Join-Path $script:VaultLogsDir "server.err.log"

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Resolve-VaultExecutable {
    param([string]$CommandName)

    $command = Get-Command $CommandName -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    if (Test-Path -LiteralPath $CommandName) {
        return (Resolve-Path -LiteralPath $CommandName).Path
    }

    throw "找不到 Vault 命令。请先确保 `vault` 已加入 PATH，或执行脚本时传入 -VaultCommand `"C:\path\to\vault.exe`"。"
}

function New-VaultConfigIfNeeded {
    $vaultUri = [Uri]$VaultAddr
    $vaultDataPath = ($script:VaultDataDir -replace "\\", "/")
    $configContent = @'
ui = true
disable_mlock = true

storage "file" {
  path = "__VAULT_DATA_PATH__"
}

listener "tcp" {
  address = "__VAULT_LISTENER__"
  tls_disable = 1
}
'@
    $configContent = $configContent.Replace("__VAULT_DATA_PATH__", $vaultDataPath)
    $configContent = $configContent.Replace("__VAULT_LISTENER__", $vaultUri.Authority)

    if ((Test-Path -LiteralPath $script:VaultConfigPath) -and -not $ForceRewriteConfig) {
        return
    }

    Set-Content -LiteralPath $script:VaultConfigPath -Value $configContent -Encoding ascii
}

function Invoke-VaultJson {
    param(
        [string[]]$Arguments,
        [string]$Token,
        [int[]]$AllowedExitCodes = @(0)
    )

    $oldAddr = $env:VAULT_ADDR
    $oldToken = $env:VAULT_TOKEN
    try {
        $env:VAULT_ADDR = $VaultAddr
        if ($Token) {
            $env:VAULT_TOKEN = $Token
        } else {
            Remove-Item Env:VAULT_TOKEN -ErrorAction SilentlyContinue
        }

        $output = & $script:VaultExe @Arguments 2>&1
        if ($AllowedExitCodes -notcontains $LASTEXITCODE) {
            throw (($output | Out-String).Trim())
        }

        $text = ($output | Out-String).Trim()
        if (-not $text) {
            return $null
        }
        return $text | ConvertFrom-Json
    }
    finally {
        $env:VAULT_ADDR = $oldAddr
        if ($null -eq $oldToken) {
            Remove-Item Env:VAULT_TOKEN -ErrorAction SilentlyContinue
        } else {
            $env:VAULT_TOKEN = $oldToken
        }
    }
}

function Invoke-Vault {
    param(
        [string[]]$Arguments,
        [string]$Token
    )

    $oldAddr = $env:VAULT_ADDR
    $oldToken = $env:VAULT_TOKEN
    try {
        $env:VAULT_ADDR = $VaultAddr
        if ($Token) {
            $env:VAULT_TOKEN = $Token
        } else {
            Remove-Item Env:VAULT_TOKEN -ErrorAction SilentlyContinue
        }

        & $script:VaultExe @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Vault 命令失败: $($Arguments -join ' ')"
        }
    }
    finally {
        $env:VAULT_ADDR = $oldAddr
        if ($null -eq $oldToken) {
            Remove-Item Env:VAULT_TOKEN -ErrorAction SilentlyContinue
        } else {
            $env:VAULT_TOKEN = $oldToken
        }
    }
}

function Get-VaultStatus {
    try {
        return Invoke-VaultJson -Arguments @("status", "-format=json") -AllowedExitCodes @(0, 1, 2)
    }
    catch {
        return $null
    }
}

function Wait-ForVaultReady {
    param([int]$TimeoutSeconds = 20)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $status = Get-VaultStatus
        if ($status) {
            return $status
        }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)

    throw "Vault 服务启动后在 ${TimeoutSeconds}s 内仍不可用，请检查日志：$script:VaultServerLogPath / $script:VaultServerErrPath"
}

function Ensure-VaultServerRunning {
    $status = Get-VaultStatus
    if ($status) {
        Write-Step "检测到 Vault 已在运行"
        return $status
    }

    if ($NoStartServer) {
        throw "当前 Vault 未运行，且指定了 -NoStartServer。请先手动启动 Vault。"
    }

    Write-Step "启动 Vault server"
    $process = Start-Process -FilePath $script:VaultExe `
        -ArgumentList @("server", "-config=$script:VaultConfigPath") `
        -WorkingDirectory $script:ProjectRoot `
        -RedirectStandardOutput $script:VaultServerLogPath `
        -RedirectStandardError $script:VaultServerErrPath `
        -WindowStyle Hidden `
        -PassThru

    Write-Host "Vault server 已启动，PID=$($process.Id)"
    return Wait-ForVaultReady
}

function Initialize-VaultIfNeeded {
    param($Status)

    if ($Status.initialized) {
        Write-Step "Vault 已初始化"
        return
    }

    Write-Step "首次初始化 Vault"
    $init = Invoke-VaultJson -Arguments @("operator", "init", "-key-shares=1", "-key-threshold=1", "-format=json")
    $initJson = $init | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $script:VaultInitPath -Value $initJson -Encoding utf8
    Set-Content -LiteralPath $script:VaultUnsealKeyPath -Value $init.unseal_keys_b64[0] -Encoding ascii
    Set-Content -LiteralPath $script:VaultRootTokenPath -Value $init.root_token -Encoding ascii
    Set-Content -LiteralPath $script:DemoVaultTokenPath -Value $init.root_token -Encoding ascii
}

function Unseal-VaultIfNeeded {
    $status = Wait-ForVaultReady
    if (-not $status.sealed) {
        Write-Step "Vault 已解封"
        return $status
    }

    if (-not (Test-Path -LiteralPath $script:VaultUnsealKeyPath)) {
        throw "Vault 处于 sealed 状态，但缺少 $script:VaultUnsealKeyPath，无法自动解封。"
    }

    Write-Step "解封 Vault"
    $unsealKey = (Get-Content -Raw -LiteralPath $script:VaultUnsealKeyPath).Trim()
    Invoke-Vault -Arguments @("operator", "unseal", $unsealKey)
    return Wait-ForVaultReady
}

function Get-RootToken {
    if (-not (Test-Path -LiteralPath $script:VaultRootTokenPath)) {
        throw "缺少 $script:VaultRootTokenPath，无法继续配置 Transit。"
    }
    return (Get-Content -Raw -LiteralPath $script:VaultRootTokenPath).Trim()
}

function Ensure-TransitEnabled {
    param([string]$Token)

    $mounts = Invoke-VaultJson -Arguments @("secrets", "list", "-format=json") -Token $Token
    $mountKey = "$TransitMount/"
    if ($mounts.PSObject.Properties.Name -contains $mountKey) {
        Write-Step "Transit mount 已存在: $TransitMount"
        return
    }

    Write-Step "启用 Transit mount: $TransitMount"
    Invoke-Vault -Arguments @("secrets", "enable", "-path=$TransitMount", "transit") -Token $Token
}

New-Item -ItemType Directory -Force -Path $script:VaultDataDir | Out-Null
New-Item -ItemType Directory -Force -Path $script:VaultLogsDir | Out-Null

$script:VaultExe = Resolve-VaultExecutable -CommandName $VaultCommand

Write-Step "使用 Vault 命令: $script:VaultExe"
New-VaultConfigIfNeeded
$status = Ensure-VaultServerRunning
Initialize-VaultIfNeeded -Status $status
$status = Unseal-VaultIfNeeded
$rootToken = Get-RootToken
Ensure-TransitEnabled -Token $rootToken
Set-Content -LiteralPath $script:DemoVaultTokenPath -Value $rootToken -Encoding ascii

Write-Host ""
Write-Host "完成。后续使用方式：" -ForegroundColor Green
Write-Host "1. `. .\demo-local-env.ps1`"
Write-Host "2. `python run_demo.py`"
Write-Host ""
Write-Host "如需查看 Vault 日志："
Write-Host "- $script:VaultServerLogPath"
Write-Host "- $script:VaultServerErrPath"
