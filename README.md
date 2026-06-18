# Agent Auth Demo Project

这个 demo 用来演示 `agent_auth_sdk` 在多 agent 协作里的身份发布、签名、验签、拒绝和攻击拦截流程。

正式路径使用 HashiCorp Vault Transit。为了方便本地运行，项目现在提供了一键脚本来完成持久化 Vault 的初始化，不再要求把 `vault.exe` 放到 `runtime\tools`。

### Agent 角色

Demo 部署 5 个 LLM Agent，协作完成多维度代码审查：

| Agent | 端口 | 角色 | 审查维度 |
|-------|------|------|----------|
| Coordinator | 8101 | 编排器 | 预分析代码 → 并行分发任务 → 综合报告 |
| Architecture | 8102 | 架构审查 | 代码结构、设计模式、模块划分 |
| Security | 8103 | 安全审查 | 漏洞扫描、注入检测、密钥泄露 |
| Performance | 8104 | 性能审查 | 算法复杂度、资源使用、瓶颈分析 |
| Compliance | 8105 | 合规审查 | 编码规范、最佳实践、许可证合规 |

### 审查工作流

提交代码后，Coordinator 调用 LLM 预分析语言和复杂度 → 并行签名任务分发给 4 个 Specialist → 每个 Specialist 验签后调用领域 LLM 审查 → Coordinator 收集结果，LLM 合成最终报告。LLM 不可用时自动回退到 `shared/rules.py` 的静态规则引擎。

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
- 默认使用远程 Registry（`192.144.228.237`，配置在 `demo-local-env.ps1`）。若需本地 Registry，设置环境变量 `DEMO_USE_LOCAL_REGISTRY=1` 后重启，本地 Registry 地址为 `http://127.0.0.1:8008/.well-known/agent.json`

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

## 6. LLM 配置

Demo 使用 OpenAI 兼容 API 驱动代码审查。各 Agent 通过 `shared/llm.py` 调用 LLM，失败时自动回退到 `shared/rules.py` 的静态规则引擎。

环境变量（在 `demo-local-env.ps1` 中或自行设置）：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `LLM_BASE_URL` | `https://yunwu.ai/v1` | OpenAI 兼容 API 地址 |
| `LLM_API_KEY` | — | API 密钥（覆盖 `shared/settings.py` 中的默认值） |
| `LLM_MODEL` | `gpt-4o` | 模型名称 |
| `LLM_TEMPERATURE` | `0.3` | 采样温度 |
| `LLM_MAX_TOKENS` | `1024` | 每次请求最大 token 数 |

## 7. 攻击演示

控制台内置 5 种攻击演示：

1. **未注册 Agent 攻击** — 未发布到 Registry 的冒名 Agent 尝试签名请求
2. **审查结果篡改** — 签名后篡改请求体，验证签名不匹配被拒绝
3. **Nonce 重放攻击** — 使用相同 nonce 重复发送已签名的请求
4. **API Key 盗取** — 持有合法 API Key 但无对应 Agent 私钥，伪造发布请求
5. **能力越权攻击** — 架构 Agent 试图以安全审查员身份提交结果，能力校验拒绝

## 8. 测试

```powershell
pytest
```

未配置真实 Vault 时，依赖真实 Vault 的集成测试会 `skip`。

单独验证 SDK 全接口功能：

```powershell
. .\demo-local-env.ps1
python test_all_interfaces.py
```

该脚本连接 Vault + Registry，逐一验证 `from_vault` / `publish` / `resolve_agent` / `sign_http` + `verify_http_request` / `sign_message` + `verify_agent_message` / `add_key` / `rotate_key` / `revoke_key` / `revoke_agent` 共 10 个接口。

`test_code.txt` 包含审查样本输入（一个有漏洞的 `user_auth.py` 和一个性能较差的 `data_processor.py`），可用于手动测试。

## 9. 相关文档

- SDK 接口文档：[agent_auth_sdk/docs/API_REFERENCE.md](../agent_auth_sdk/docs/API_REFERENCE.md)
- Vault 环境配置指南：[agent_auth_sdk/docs/VAULT_SETUP.md](../agent_auth_sdk/docs/VAULT_SETUP.md)
- 架构流程图：[docs/diagrams/sdk-llm-integration.svg](docs/diagrams/sdk-llm-integration.svg)（SDK + LLM 集成序列图）
