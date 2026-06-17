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

Agent 的 Transit key 由 SDK 在首次启动时自动创建（`auto_create_key=True`），无需脚本预创建。

如果你需要显式指定 Vault 可执行文件：

```powershell
.\setup-persistent-vault.ps1 -VaultCommand "C:\path\to\vault.exe"
```

说明：

- 脚本默认会复用已有的持久化数据
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

- 环境变量脚本：[demo-local-env.ps1](demo-local-env.ps1)（静态，已提交到 git）
- 一键配置脚本：[setup-persistent-vault.ps1](setup-persistent-vault.ps1)（Vault 运维）
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

## 8. 相关文档

- SDK 接口文档：[agent_auth_sdk/docs/API_REFERENCE.md](../agent_auth_sdk/docs/API_REFERENCE.md)
- Vault 环境配置指南：[agent_auth_sdk/docs/VAULT_SETUP.md](../agent_auth_sdk/docs/VAULT_SETUP.md)
