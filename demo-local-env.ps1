# Agent Auth Demo — 本地环境变量（静态脚本，提交到 git）
# 使用方式： . .\demo-local-env.ps1

# --- Vault 连接 ---
$env:DEMO_VAULT_ADDR          = "http://127.0.0.1:8200"
$env:DEMO_VAULT_TOKEN_FILE    = "runtime\vault-token.txt"
$env:DEMO_VAULT_TRANSIT_MOUNT = "transit"

# --- Agent Vault key 名称（SDK 启动时通过 auto_create_key 自动创建） ---
$env:DEMO_COORDINATOR_KMS_KEY_ID  = "coordinator-agent"
$env:DEMO_ARCHITECTURE_KMS_KEY_ID = "architecture-agent"
$env:DEMO_SECURITY_KMS_KEY_ID     = "security-agent"
$env:DEMO_PERFORMANCE_KMS_KEY_ID  = "performance-agent"
$env:DEMO_COMPLIANCE_KMS_KEY_ID   = "compliance-agent"

# --- Registry 认证（远程 registry，使用 HTTP） ---
$env:DEMO_USE_LOCAL_REGISTRY   = "0"
$env:DEMO_REGISTRY_URL         = "http://192.144.228.237/.well-known/agent.json"
$env:DEMO_REGISTRY_PUBLISH_URL = "http://192.144.228.237/registry/agents/publish"
$env:DEMO_REGISTRY_CLIENT_ID   = "huangyihe"
$env:DEMO_REGISTRY_API_KEY     = "T3r1fEoIvQUA9JQjgbsIjDcZC6-dTRb-IsJG7oZanNY"

# --- 可选：切换到本地 registry ---
# $env:DEMO_USE_LOCAL_REGISTRY   = "1"
# $env:DEMO_REGISTRY_CLIENT_ID   = "demo-local-client"
# $env:DEMO_REGISTRY_API_KEY     = "demo-local-api-key"
