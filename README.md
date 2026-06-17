# Agent Auth Demo Project

这个 demo 用来演示 `agent_auth_sdk` 在多 agent 协作里的身份发布、签名、验签、拒绝和攻击拦截流程。

正式路径使用 HashiCorp Vault Transit。为了方便本地运行，项目现在提供了一键脚本来完成持久化 Vault 的初始化，不再要求把 `vault.exe` 放到 `runtime\tools`。

## 1. 安装依赖

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .
pip install -e ..\agent_auth_sdk
```

## 2. 一键配置持久化 Vault

默认要求系统里可以直接执行 `vault`。如果你的 Vault 不在 `PATH`，可以用 `-VaultCommand` 传绝对路径。

```powershell
.\setup-persistent-vault.ps1
```

脚本会自动完成这些事：

- 创建 `runtime\vault\data` 和 `runtime\vault\logs`
- 生成 `runtime\vault\config.hcl`
- 启动 Vault server
- 首次初始化 Vault，并保存 `init.json`、`root-token.txt`、`unseal-key.txt`
- 自动解封 Vault
- 启用 `transit` mount
- 创建 4 个 demo agent 对应的 Transit key
- 生成本机环境脚本 `demo-local-env.ps1`

如果你需要显式指定 Vault 可执行文件：

```powershell
.\setup-persistent-vault.ps1 -VaultCommand "C:\path\to\vault.exe"
```

如果想切到本地 registry：

```powershell
.\setup-persistent-vault.ps1 -UseLocalRegistry -ForceRewriteEnv
```

说明：

- 脚本默认会保留已有的 `demo-local-env.ps1`；想重写就加 `-ForceRewriteEnv`
- 脚本默认会复用已有的持久化数据，不会重建已有 Transit key
- `runtime\` 已被 `.gitignore` 忽略，不会提交本机 Vault 数据

## 3. 加载环境并启动 demo

```powershell
. .\demo-local-env.ps1
python run_demo.py
```

启动成功后：

- Console: `http://127.0.0.1:8010`
- 本地 registry: `http://127.0.0.1:8008/.well-known/agent.json`
- 远程 registry 默认值来自 `demo-local-env.ps1`

## 4. 常见文件

- 环境脚本模板：[demo-real-env.ps1](/D:/FDU/agent_auth/agent_auth_demoproject/demo-real-env.ps1)
- 一键配置脚本：[setup-persistent-vault.ps1](/D:/FDU/agent_auth/agent_auth_demoproject/setup-persistent-vault.ps1)
- 持久化 Vault 配置：`runtime\vault\config.hcl`
- 运行 token 文件：`runtime\vault-token.txt`

## 5. 安全提醒

- 不要使用 `vault server -dev` 搭配远程 registry；重启后 key 会丢
- 不要设置 `DEMO_VAULT_TOKEN` 作为常规路径；优先使用 `DEMO_VAULT_TOKEN_FILE`
- 当前脚本为了本地跑通，默认把 root token 写到 `runtime\vault-token.txt`
- 更接近生产的方式是为 demo 进程单独签发最小权限 token

## 6. 攻击演示

控制台内置 5 种攻击演示：

1. 未注册 Agent 攻击
2. 签名篡改攻击
3. Nonce 重放攻击
4. 盗取 API Key 发布攻击
5. Owner 冲突发布攻击

## 7. 测试

```powershell
pytest
```

未配置真实 Vault 时，依赖真实 Vault 的集成测试会 `skip`。
