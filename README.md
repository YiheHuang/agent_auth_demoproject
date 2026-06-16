# Agent Auth Demo Project

这个 demo 用来真实展示 `agent_auth_sdk` 的核心价值：多 agent 协作时，谁在发消息、谁被信任、谁被拒绝、为什么被拒绝，都能被直观看到。

当前正式安全模型：

- 所有正式签名能力均使用开发者自己的 HashiCorp Vault Transit
- 不使用本地私钥文件作为正式路径
- 所有跨 agent HTTP 请求都要验签
- 所有 agent metadata 都发布到中心 registry

## 运行前准备

先安装依赖：

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
pip install -e ..\agent_auth_sdk
```

本地 Vault 演示配置：

```bash
vault server -dev -dev-root-token-id=root
set VAULT_ADDR=http://127.0.0.1:8200
set VAULT_TOKEN=root
echo root > runtime\vault-token.txt
vault secrets enable transit
vault write -f transit/keys/intake-agent type=ecdsa-p256
vault write -f transit/keys/triage-agent type=ecdsa-p256
vault write -f transit/keys/resolver-agent type=ecdsa-p256
vault write -f transit/keys/approval-agent type=ecdsa-p256
```

demo 环境变量：

```bash
set DEMO_REGISTRY_CLIENT_ID=developer-a
set DEMO_REGISTRY_API_KEY=your-registry-api-key
set DEMO_VAULT_ADDR=http://127.0.0.1:8200
set DEMO_VAULT_TOKEN_FILE=runtime\vault-token.txt
set DEMO_VAULT_TRANSIT_MOUNT=transit
set DEMO_INTAKE_KMS_KEY_ID=intake-agent
set DEMO_TRIAGE_KMS_KEY_ID=triage-agent
set DEMO_RESOLVER_KMS_KEY_ID=resolver-agent
set DEMO_APPROVAL_KMS_KEY_ID=approval-agent
```

这里的 `DEMO_*_KMS_KEY_ID` 表示 Vault Transit key name。

生产或准生产环境不要设置 `DEMO_VAULT_TOKEN`。如果只是本地临时演示，可以显式设置 `DEMO_ALLOW_INSECURE_VAULT_TOKEN=1` 后再使用 `DEMO_VAULT_TOKEN=root`。

如果你想用本地 registry 调试：

```bash
set DEMO_USE_LOCAL_REGISTRY=1
```

## 启动方式

```bash
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

`agent_auth_sdk` 是 SDK，不托管 Vault。开发者需要自己安装、初始化、解封、授权并备份 Vault；SDK 只使用开发者提供的 Vault token 调用 `read_key` 与 `sign_data`。

## 测试

```bash
pytest
```

如果没有配置真实 Vault，依赖真实 Vault 的 demo 集成测试会显式 `skip`。
