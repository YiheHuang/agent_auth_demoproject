# ===========================================================================
# 清空 Vault Transit 中所有 Demo Agent 密钥（PowerShell 版）
# 用法:
#   . .\demo-local-env.ps1    # 先加载环境变量
#   .\clear-vault-keys.ps1
# ===========================================================================
[CmdletBinding()]
param(
    [string]$VaultAddr = $env:DEMO_VAULT_ADDR,
    [string]$VaultTokenFile = $env:DEMO_VAULT_TOKEN_FILE,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if (-not $VaultAddr) { $VaultAddr = "http://127.0.0.1:8200" }
if (-not $VaultTokenFile) { $VaultTokenFile = "runtime\vault-token.txt" }

$env:VAULT_ADDR = $VaultAddr

# 尝试读取 token
if (-not $env:VAULT_TOKEN) {
    if (Test-Path -LiteralPath $VaultTokenFile) {
        $env:VAULT_TOKEN = (Get-Content -Raw -LiteralPath $VaultTokenFile).Trim()
    } else {
        Write-Host "错误：未找到 Vault token。请先 . .\demo-local-env.ps1 或设置 `$env:VAULT_TOKEN。" -ForegroundColor Red
        exit 1
    }
}

$keys = @(
    "coordinator-agent",
    "architecture-agent",
    "security-agent",
    "performance-agent",
    "compliance-agent"
)

Write-Host "==> Vault 地址: $VaultAddr" -ForegroundColor Cyan
Write-Host "==> 将删除以下 Transit keys:"
foreach ($key in $keys) {
    Write-Host "    transit/keys/$key"
}
Write-Host ""

if (-not $Force) {
    $confirm = Read-Host "确认删除？[y/N]"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "已取消。"
        exit 0
    }
}

$deleted = 0
$skipped = 0
foreach ($key in $keys) {
    $result = vault read "transit/keys/$key" 2>&1
    if ($LASTEXITCODE -eq 0) {
        vault delete "transit/keys/$key"
        Write-Host "  已删除: $key" -ForegroundColor Green
        $deleted++
    } else {
        Write-Host "  不存在，跳过: $key" -ForegroundColor DarkGray
        $skipped++
    }
}

Write-Host ""
Write-Host "完成。删除 $deleted 个 key，跳过 $skipped 个。" -ForegroundColor Green
Write-Host ""
Write-Host "剩余 transit keys:"
vault list transit/keys
