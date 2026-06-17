# Agent Auth Demo Project

这个 demo 用来真实展示 `agent_auth_sdk` 的核心价值：多 agent 协作时，谁在发消息、谁被信任、谁被拒绝、为什么被拒绝，都能被直观看到。

当前正式安全模型：

- 所有正式签名能力均使用开发者自己的 HashiCorp Vault Transit
- 不使用本地私钥文件作为正式路径
- 所有跨 agent HTTP 请求都要验签
- 所有 agent metadata 都发布到中心 registry

## 运行前准备

先安装依赖：

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .
pip install -e ..\agent_auth_sdk
```

## Git Clone 后如何配置持久化 Vault

这个 demo 使用 HashiCorp Vault Transit 作为唯一正式签名路径。不要使用 `vault server -dev` 搭配远程 registry：dev server 重启后会丢失 Transit key，导致本地私钥和 registry 里的旧公钥不匹配。

本项目约定本地 Vault 二进制位于：

```text
runtime/tools/vault.exe
```

如果 clone 后没有这个文件，请先下载 HashiCorp Vault，并把 `vault.exe` 放到 `runtime/tools/vault.exe`。Vault 数据、root token、unseal key 和 demo token file 都放在 `runtime/` 目录下；这些是本机运行产物，不要提交到 git。

demo 需要 4 个 Transit key，分别给 4 个 agent 使用：

| Agent | Vault Transit key name | 环境变量 |
| --- | --- | --- |
| Intake Agent | `intake-agent` | `DEMO_INTAKE_KMS_KEY_ID` |
| Triage Agent | `triage-agent` | `DEMO_TRIAGE_KMS_KEY_ID` |
| Resolver Agent | `resolver-agent` | `DEMO_RESOLVER_KMS_KEY_ID` |
| Approval Agent | `approval-agent` | `DEMO_APPROVAL_KMS_KEY_ID` |

### 1. 创建持久化 Vault 配置

```powershell
cd "C:\path\to\agent_auth_demoproject"

New-Item -ItemType Directory -Force runtime\vault\data | Out-Null
New-Item -ItemType Directory -Force runtime\vault\logs | Out-Null

@'
ui = true
disable_mlock = true

storage "file" {
  path = "runtime/vault/data"
}

listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = 1
}
'@ | Set-Content -Path runtime\vault\config.hcl -Encoding ascii
```

### 2. 启动 Vault server

打开一个 PowerShell 终端，执行：

```powershell
cd "C:\path\to\agent_auth_demoproject"
.\runtime\tools\vault.exe server -config=runtime\vault\config.hcl
```

这个终端保持打开。以后每次运行 demo 前，都先用同一条命令启动 Vault。

### 3. 首次初始化和解封

另开一个 PowerShell 终端，在项目目录执行：

```powershell
cd "C:\path\to\agent_auth_demoproject"

$env:VAULT_ADDR = "http://127.0.0.1:8200"

.\runtime\tools\vault.exe operator init -key-shares=1 -key-threshold=1 -format=json |
  Set-Content -Path runtime\vault\init.json -Encoding utf8

$init = Get-Content -Raw runtime\vault\init.json | ConvertFrom-Json
$init.unseal_keys_b64[0] | Set-Content -Path runtime\vault\unseal-key.txt -Encoding ascii
$init.root_token | Set-Content -Path runtime\vault\root-token.txt -Encoding ascii
$init.root_token | Set-Content -Path runtime\vault-token.txt -Encoding ascii

.\runtime\tools\vault.exe operator unseal $init.unseal_keys_b64[0]
```

`runtime\vault-token.txt` 是 demo 读取的 token file。这个文件里是本地 demo token，不能提交，也不能用于生产。

后续重启 Vault 时，不需要重新 init，只需要启动 server 后解封：

```powershell
cd "C:\path\to\agent_auth_demoproject"

$env:VAULT_ADDR = "http://127.0.0.1:8200"
$unsealKey = (Get-Content -Raw runtime\vault\unseal-key.txt).Trim()
.\runtime\tools\vault.exe operator unseal $unsealKey
```

### 4. 启用 Transit 并创建 4 个 key

首次初始化后执行一次：

```powershell
cd "C:\path\to\agent_auth_demoproject"

$env:VAULT_ADDR = "http://127.0.0.1:8200"
$env:VAULT_TOKEN = (Get-Content -Raw runtime\vault\root-token.txt).Trim()

.\runtime\tools\vault.exe secrets enable transit
.\runtime\tools\vault.exe write -f transit/keys/intake-agent type=ecdsa-p256
.\runtime\tools\vault.exe write -f transit/keys/triage-agent type=ecdsa-p256
.\runtime\tools\vault.exe write -f transit/keys/resolver-agent type=ecdsa-p256
.\runtime\tools\vault.exe write -f transit/keys/approval-agent type=ecdsa-p256

.\runtime\tools\vault.exe list transit/keys
```

如果这些 key 已经存在，不要删除重建。持久化 Vault 的价值就是让这 4 个 key 的公私钥持续保留，并和 registry 中的 metadata 保持一致。

### 5. 配置 demo 环境变量

```powershell
$env:DEMO_VAULT_ADDR = "http://127.0.0.1:8200"
$env:DEMO_VAULT_TOKEN_FILE = "runtime\vault-token.txt"
$env:DEMO_VAULT_TRANSIT_MOUNT = "transit"
$env:DEMO_INTAKE_KMS_KEY_ID = "intake-agent"
$env:DEMO_TRIAGE_KMS_KEY_ID = "triage-agent"
$env:DEMO_RESOLVER_KMS_KEY_ID = "resolver-agent"
$env:DEMO_APPROVAL_KMS_KEY_ID = "approval-agent"
```

### Vault 权限说明

当前本地 demo 为了便于运行，`runtime\vault-token.txt` 使用 root token。更接近准生产的做法是创建最小权限 token。以 `intake-agent` 为例：

```hcl
path "transit/keys/intake-agent" {
  capabilities = ["read"]
}

path "transit/sign/intake-agent" {
  capabilities = ["update"]
}
```

其他三个 key 按同样方式配置。一个 demo 服务如果要同时启动 4 个 agent，则运行 token 需要覆盖 4 组 `read` 和 `sign` 权限。

### 不要使用 raw token 环境变量

不要设置 `DEMO_VAULT_TOKEN`。正常路径始终使用 `DEMO_VAULT_TOKEN_FILE`，避免 token 暴露在环境变量、进程列表或日志里。

## Registry 与开发者凭证

demo 启动时，4 个 agent 会把 metadata 发布到 registry。使用远程 registry 时需要配置开发者身份：

```powershell
$env:DEMO_REGISTRY_CLIENT_ID = "developer-a"
$env:DEMO_REGISTRY_API_KEY = "your-registry-api-key"
$env:DEMO_REGISTRY_URL = "http://192.144.228.237/.well-known/agent.json"
$env:DEMO_REGISTRY_PUBLISH_URL = "http://192.144.228.237/registry/agents/publish"
```

如果你想用本地 registry 调试：

```powershell
$env:DEMO_USE_LOCAL_REGISTRY = "1"
```

本地 registry 模式下，`run_demo.py` 会自动创建本地 demo developer，并使用本地 registry：

```text
http://127.0.0.1:8008/.well-known/agent.json
```

## 推荐：写入本地环境脚本

为了避免每次打开终端都重新输入环境变量，可以在 `demo-local-env.ps1` 中保存本机配置：

```powershell
$env:DEMO_USE_LOCAL_REGISTRY = "1"
$env:DEMO_VAULT_ADDR = "http://127.0.0.1:8200"
$env:DEMO_VAULT_TOKEN_FILE = "runtime\vault-token.txt"
$env:DEMO_VAULT_TRANSIT_MOUNT = "transit"
$env:DEMO_INTAKE_KMS_KEY_ID = "intake-agent"
$env:DEMO_TRIAGE_KMS_KEY_ID = "triage-agent"
$env:DEMO_RESOLVER_KMS_KEY_ID = "resolver-agent"
$env:DEMO_APPROVAL_KMS_KEY_ID = "approval-agent"
```

使用时：

```powershell
.\demo-local-env.ps1
python run_demo.py
```


## 启动方式

```powershell
python run_demo.py
```

启动成功后：

- Console: `http://127.0.0.1:8010`
- Registry: 本地模式为 `http://127.0.0.1:8008/.well-known/agent.json`
- 服务器模式默认为 `http://192.144.228.237/.well-known/agent.json`，请用 `DEMO_REGISTRY_URL` 和 `DEMO_REGISTRY_PUBLISH_URL` 指向真实 registry

## 正常业务流程

1. 用户在控制台创建工单。
2. `intake-agent` 接收工单并做初步分类。
3. `intake-agent` 用自己的 Vault Transit key 对请求签名，发送给 `triage-agent`。
4. `triage-agent` 从 registry 解析发送方 metadata，并验签。
5. 普通工单流向 `resolver-agent`；高风险工单先进入 `approval-agent` 再转 `resolver-agent`。
6. 所有链路上的成功验签事件，都会写入时间线和认证事件面板。
7. 最终工单进入 `resolved` 或其他明确状态。

## 攻击演示流程

控制台提供 5 种攻击演示：

1. 未注册 Agent 攻击：没有发布到 registry 的伪 agent 发请求，目标 agent 因无法解析身份而拒绝。
2. 签名篡改攻击：先对原始消息签名，再发送被篡改的请求体，目标 agent 返回 `SIGNATURE_INVALID`。
3. Nonce 重放攻击：重复发送同一组签名头，目标 agent 第二次返回 `NONCE_REPLAYED`。
4. 盗取 API Key 发布攻击：攻击者拿到 registry API key，但没有目标 agent 对应的签名 key，发布被拒绝。
5. Owner 冲突发布攻击：非 owner developer 试图更新已绑定的 agent，registry 返回 `OWNER_MISMATCH`。

## 职责边界

`agent_auth_sdk` 是 SDK，不托管 Vault。开发者需要自己安装、初始化、解封、授权、审计并备份 Vault；SDK 只使用开发者提供的 token file 调用 `read_key` 与 `sign_data`。

## 测试

```bash
pytest
```

如果没有配置真实 Vault，依赖真实 Vault 的 demo 集成测试会显式 `skip`。
