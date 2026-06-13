# Agent Auth Demo Project

一个真实可运行的多 Agent 工单协作演示系统，用来展示 `agent_auth_sdk` 的核心能力：

- Agent 身份创建与中心 registry 发布
- Agent 间签名 HTTP 调用
- 基于中心 registry 的身份解析与验签
- 未注册 Agent、篡改签名、nonce 重放等攻击场景拦截

## 结构

- `apps/console/`：Web 控制台与聚合 API
- `apps/agents/`：4 个 agent 服务
- `shared/`：共享模型、规则、存储、配置
- `tests/`：单元测试与集成测试
- `run_demo.py`：本机一键启动入口

## 运行

先确保同级目录存在 `agent_auth_sdk` 仓库源码。

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
pip install -e ..\agent_auth_sdk
python run_demo.py
```

启动后访问：

- 控制台：`http://127.0.0.1:8010`
- 服务器 registry：`http://192.144.228.237/.well-known/agent.json`

## Registry 设计

这个 demo 现在默认使用服务器上的中心 registry，而不是本地 `runtime/registry/.well-known/agent.json` 作为权威数据源。

- 发布默认写入：`http://192.144.228.237/registry/agents`
- 验签默认读取：`http://192.144.228.237/.well-known/agent.json`
- 默认会随发布请求附带 demo registry token：`123`
- 本地 `runtime/agents/*/metadata/.well-known/agent.json` 仍然保留，但它只作为 agent 启动时的本地缓存与签名材料，不作为跨 agent 验签的权威来源

如果你需要覆盖默认 token，可以设置：

```bash
set DEMO_REGISTRY_TOKEN=你的token
python run_demo.py
```

如果你要把 demo 临时切回本地 registry，可以手动设置：

```bash
set DEMO_USE_LOCAL_REGISTRY=1
python run_demo.py
```

## 运行流程

### 正常流程

1. 启动 `run_demo.py` 后，会自动拉起 4 个 agent 和 Web 控制台，并默认连接服务器 registry。
2. 每个 agent 启动时会自动生成或读取本地密钥，并向服务器 registry 发布自己的 metadata。
3. 用户在控制台创建工单后，工单会按如下路径流转：
   - `user -> intake-agent`
   - `intake-agent -> triage-agent`
   - 普通工单：`triage-agent -> resolver-agent`
   - 高风险工单：`triage-agent -> approval-agent -> resolver-agent`
4. 每次 agent 间 HTTP 调用都会先签名，再由目标 agent 基于服务器 registry 完成身份解析与验签。
5. 控制台会同步展示：
   - 工单状态变化
   - 时间线中的每一步流转
   - 认证事件面板中的验签成功记录
   - Agent 注册表中的已注册身份
   - 以上所有长列表均支持分页，避免页面过长

### 被攻击/异常流程

控制台右上角的“攻击演示面板”提供 3 个异常场景：

1. 未注册 Agent 攻击
   - 构造一个没有发布到 registry 的伪 agent
   - 伪 agent 尝试向 `triage-agent` 发起签名请求
   - 由于中心仓库中找不到其 metadata，请求会被拒绝

2. 签名篡改攻击
   - 用合法 agent 对原始消息签名
   - 发送时偷偷篡改消息内容，但保留原签名
   - 目标 agent 会返回 `SIGNATURE_INVALID`

3. Nonce 重放攻击
   - 用相同 nonce 重复发送两次同一请求
   - 首次请求通过，第二次会被识别为重放
   - 目标 agent 会返回 `NONCE_REPLAYED`

这些异常都会记录到认证事件面板与工单时间线中，用来直观证明 `agent_auth_sdk` 在真实多 agent 系统中的价值。

## 测试

```bash
pytest
```
