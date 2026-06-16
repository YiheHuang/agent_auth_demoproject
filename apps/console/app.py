from __future__ import annotations

import json
import math
from typing import Callable

from shared.sdk_loader import ensure_sdk_path

ensure_sdk_path()

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from agent_auth_sdk import AgentInstance, sign_registry_publish_request
from shared.models import AgentTask, AuthEvent, CreateTicketRequest, TicketEvent
from shared.settings import DemoSettings, get_demo_settings
from shared.store import DemoStore, utc_now


HttpClientFactory = Callable[[], httpx.AsyncClient]


def create_console_app(
    settings: DemoSettings | None = None,
    *,
    http_client_factory: HttpClientFactory | None = None,
) -> FastAPI:
    settings = settings or get_demo_settings()
    store = DemoStore(settings.database_path)
    factory = http_client_factory or (lambda: httpx.AsyncClient())
    app = FastAPI(title="Agent Auth Demo Console")

    def paginate_response(items: list[dict], total: int, page: int, page_size: int) -> dict:
        normalized_page_size = max(1, min(page_size, 20))
        page_count = max(1, math.ceil(total / normalized_page_size)) if total else 1
        normalized_page = max(1, min(page, page_count))
        return {
            "items": items,
            "total": total,
            "page": normalized_page,
            "page_size": normalized_page_size,
            "page_count": page_count,
        }

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return _html()

    @app.get("/api/tickets")
    async def list_tickets(page: int = 1, page_size: int = 6) -> dict:
        tickets, total = store.list_tickets_page(page=page, page_size=page_size)
        return paginate_response([ticket.model_dump(mode="json") for ticket in tickets], total, page, page_size)

    @app.get("/api/tickets/{ticket_id}")
    async def ticket_detail(ticket_id: str, events_page: int = 1, events_page_size: int = 6) -> dict:
        ticket = store.get_ticket(ticket_id)
        if ticket is None:
            raise HTTPException(status_code=404, detail="ticket not found")
        events, total = store.list_ticket_events_page(ticket_id, page=events_page, page_size=events_page_size)
        return {
            "ticket": ticket.model_dump(mode="json"),
            "events": [event.model_dump(mode="json") for event in events],
            "events_total": total,
            "events_page": max(1, events_page),
            "events_page_size": max(1, min(events_page_size, 20)),
            "events_page_count": max(1, math.ceil(total / max(1, min(events_page_size, 20)))) if total else 1,
        }

    @app.get("/api/auth-events")
    async def auth_events(page: int = 1, page_size: int = 6) -> dict:
        events, total = store.list_auth_events_page(page=page, page_size=page_size)
        return paginate_response([event.model_dump(mode="json") for event in events], total, page, page_size)

    @app.get("/api/registry")
    async def registry_view(page: int = 1, page_size: int = 5) -> dict:
        async with factory() as client:
            response = await client.get(settings.registry_base_url)
            response.raise_for_status()
            payload = response.json()
            agents = sorted(
                payload.get("agents", []),
                key=lambda item: item.get("published_at") or "",
                reverse=True,
            )
            normalized_page_size = max(1, min(page_size, 20))
            total = len(agents)
            page_count = max(1, math.ceil(total / normalized_page_size)) if total else 1
            normalized_page = max(1, min(page, page_count))
            start = (normalized_page - 1) * normalized_page_size
            end = start + normalized_page_size
            payload["agents"] = agents[start:end]
            payload["total"] = total
            payload["page"] = normalized_page
            payload["page_size"] = normalized_page_size
            payload["page_count"] = page_count
            return payload

    @app.post("/api/tickets")
    async def create_ticket(payload: CreateTicketRequest) -> dict:
        ticket = store.create_ticket(payload.title, payload.description)
        store.add_ticket_event(
            TicketEvent(
                ticket_id=ticket.ticket_id,
                event_type="user_submitted",
                from_agent="user",
                to_agent="intake-agent",
                verification_result="n/a",
                reason=None,
                payload_summary=payload.title,
                created_at=utc_now(),
            )
        )
        async with factory() as client:
            response = await client.post(
                f"{settings.agent_url('intake-agent')}/tasks/ingest",
                json={"ticket_id": ticket.ticket_id},
            )
            response.raise_for_status()
        return {"ticket_id": ticket.ticket_id}

    @app.post("/api/scenarios/unregistered")
    async def attack_unregistered() -> dict:
        rogue = AgentInstance.from_vault(
            domain="127.0.0.1:8999",
            name="rogue-agent",
            organization="Rogue Org",
            endpoint="http://127.0.0.1:8999/tasks/handle",
            vault_addr=_require(settings.vault_addr, "DEMO_VAULT_ADDR"),
            vault_token_file=settings.vault_token_file,
            vault_token=settings.vault_token,
            allow_insecure_raw_token=settings.allow_insecure_vault_token,
            transit_mount=settings.vault_transit_mount,
            key_name=_require(settings.agent_kms_key_id("approval-agent"), "DEMO_APPROVAL_KMS_KEY_ID"),
            namespace=settings.vault_namespace,
            verify=settings.vault_verify(),
            capabilities=["sign"],
            environment="attack",
            kid="rogue-unregistered",
        )
        body = AgentTask(ticket_id=_latest_ticket_id(store), action="replay_probe").model_dump(mode="json")
        target_url = settings.agents["triage-agent"].endpoint
        signed = await rogue.sign_http(method="POST", url=target_url, body=body)
        async with factory() as client:
            response = await client.post(target_url, json=body, headers=signed.headers)
        return {"status_code": response.status_code, "payload": response.json()}

    @app.post("/api/scenarios/tampered")
    async def attack_tampered() -> dict:
        intake = _load_local_agent("intake-agent", settings)
        target_url = settings.agents["triage-agent"].endpoint
        original = AgentTask(ticket_id=_latest_ticket_id(store), action="replay_probe", context="safe").model_dump(mode="json")
        tampered = AgentTask(ticket_id=_latest_ticket_id(store), action="replay_probe", context="tampered").model_dump(mode="json")
        signed = await intake.sign_http(method="POST", url=target_url, body=original)
        async with factory() as client:
            response = await client.post(target_url, json=tampered, headers=signed.headers)
        return {"status_code": response.status_code, "payload": response.json()}

    @app.post("/api/scenarios/replay")
    async def attack_replay() -> dict:
        intake = _load_local_agent("intake-agent", settings)
        body = AgentTask(ticket_id=_latest_ticket_id(store), action="replay_probe").model_dump(mode="json")
        target_url = settings.agents["triage-agent"].endpoint
        signed = await intake.sign_http(method="POST", url=target_url, body=body, nonce="fixed-replay-nonce")
        async with factory() as client:
            first = await client.post(target_url, json=body, headers=signed.headers)
            second = await client.post(target_url, json=body, headers=signed.headers)
        return {"first": {"status_code": first.status_code, "payload": first.json()}, "second": {"status_code": second.status_code, "payload": second.json()}}

    @app.post("/api/scenarios/stolen-api-key")
    async def attack_stolen_api_key() -> dict:
        rogue = AgentInstance.from_vault(
            domain="127.0.0.1:8998",
            name="intake-agent",
            organization="Rogue Org",
            endpoint="http://127.0.0.1:8998/tasks/handle",
            vault_addr=_require(settings.vault_addr, "DEMO_VAULT_ADDR"),
            vault_token_file=settings.vault_token_file,
            vault_token=settings.vault_token,
            allow_insecure_raw_token=settings.allow_insecure_vault_token,
            transit_mount=settings.vault_transit_mount,
            key_name=_require(settings.agent_kms_key_id("approval-agent"), "DEMO_APPROVAL_KMS_KEY_ID"),
            namespace=settings.vault_namespace,
            verify=settings.vault_verify(),
            capabilities=["publish"],
            environment="attack",
            kid="rogue-stolen-api",
        )
        legitimate = _load_local_agent("intake-agent", settings)
        payload = {
            "agent_id": legitimate.agent_id,
            "metadata": rogue.metadata.model_dump(mode="json"),
            "publish_intent": "upsert_metadata",
        }
        signed = await sign_registry_publish_request(
            path="/registry/agents/publish",
            host=_registry_host(settings.registry_publish_url),
            body=payload,
            agent_id=legitimate.agent_id,
            client_id=_require(settings.registry_client_id, "DEMO_REGISTRY_CLIENT_ID"),
            signer=rogue.signer,
        )
        headers = {
            "authorization": f"Bearer {_require(settings.registry_api_key, 'DEMO_REGISTRY_API_KEY')}",
            **signed.headers,
        }
        async with factory() as client:
            response = await client.post(settings.registry_publish_url, json=payload, headers=headers)
        _record_registry_attack(
            store,
            scenario="stolen_api_key_publish",
            source_agent_id=rogue.agent_id,
            status_code=response.status_code,
            payload=response.json(),
        )
        return {"status_code": response.status_code, "payload": response.json()}

    @app.post("/api/scenarios/owner-conflict")
    async def attack_owner_conflict() -> dict:
        legitimate = _load_local_agent("intake-agent", settings)
        payload = {
            "agent_id": legitimate.agent_id,
            "metadata": legitimate.metadata.model_dump(mode="json"),
            "publish_intent": "upsert_metadata",
        }
        signed = await sign_registry_publish_request(
            path="/registry/agents/publish",
            host=_registry_host(settings.registry_publish_url),
            body=payload,
            agent_id=legitimate.agent_id,
            client_id="rogue-client",
            signer=legitimate.signer,
        )
        headers = {
            "authorization": "Bearer rogue-api-key",
            **signed.headers,
        }
        async with factory() as client:
            response = await client.post(settings.registry_publish_url, json=payload, headers=headers)
        _record_registry_attack(
            store,
            scenario="owner_conflict_publish",
            source_agent_id=legitimate.agent_id,
            status_code=response.status_code,
            payload=response.json(),
        )
        return {"status_code": response.status_code, "payload": response.json()}

    return app


def _latest_ticket_id(store: DemoStore) -> str:
    tickets = store.list_tickets()
    if not tickets:
        ticket = store.create_ticket("Replay probe", "urgent password reset")
        return ticket.ticket_id
    return tickets[0].ticket_id


def _record_registry_attack(
    store: DemoStore,
    *,
    scenario: str,
    source_agent_id: str | None,
    status_code: int,
    payload: dict,
) -> None:
    ticket_id = _latest_ticket_id(store)
    reason = str(payload.get("detail") or payload)
    result = "rejected" if status_code >= 400 else "verified"
    store.add_auth_event(
        AuthEvent(
            source_agent_id=source_agent_id,
            target_agent="registry",
            result=result,
            error_code=reason if status_code >= 400 else None,
            detail=f"{scenario} returned HTTP {status_code}: {reason}",
            created_at=utc_now(),
        )
    )
    store.add_ticket_event(
        TicketEvent(
            ticket_id=ticket_id,
            event_type=scenario,
            from_agent=source_agent_id or "unknown",
            to_agent="registry",
            verification_result=reason if status_code >= 400 else "accepted",
            reason=reason,
            payload_summary=f"registry publish attempt returned HTTP {status_code}",
            created_at=utc_now(),
        )
    )


def _load_local_agent(role: str, settings: DemoSettings) -> AgentInstance:
    metadata_path = settings.agent_metadata_dir(role) / ".well-known" / "agent.json"
    if not metadata_path.exists():
        raise HTTPException(status_code=503, detail=f"{role} identity is not ready yet")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    return AgentInstance.from_vault(
        domain=metadata["domain"],
        name=metadata["name"],
        organization=metadata["organization"],
        endpoint=metadata["endpoint"],
        vault_addr=_require(settings.vault_addr, "DEMO_VAULT_ADDR"),
        vault_token_file=settings.vault_token_file,
        vault_token=settings.vault_token,
        allow_insecure_raw_token=settings.allow_insecure_vault_token,
        transit_mount=settings.vault_transit_mount,
        key_name=_require(settings.agent_kms_key_id(role), f"{role} Vault key"),
        namespace=settings.vault_namespace,
        verify=settings.vault_verify(),
        capabilities=metadata["capabilities"],
        environment=metadata.get("environment"),
        kid=metadata["keys"][0]["kid"],
    )


def _registry_host(registry_publish_url: str) -> str:
    return __import__("urllib.parse").parse.urlparse(registry_publish_url).netloc


def _require(value: str | None, env_name: str) -> str:
    if not value:
        raise HTTPException(status_code=503, detail=f"{env_name} is required")
    return value


def _html() -> str:
    return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Agent Auth Demo</title>
  <style>
    :root { --bg:#f3f1ea; --panel:#fffdf7; --ink:#1f2a2e; --accent:#b14d2b; --line:#d9d0c4; --good:#1b7f5a; --bad:#a12d2d; }
    body { margin:0; font-family:Georgia, "Microsoft YaHei", serif; background:linear-gradient(180deg,#efe8dc 0%,#f7f4ee 100%); color:var(--ink); }
    .wrap { max-width:1400px; margin:0 auto; padding:24px; }
    h1 { margin:0 0 16px; font-size:40px; }
    .hero { display:grid; grid-template-columns:1.2fr .8fr; gap:18px; margin-bottom:18px; }
    .grid { display:grid; grid-template-columns:repeat(2,1fr); gap:18px; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:18px; padding:18px; box-shadow:0 12px 30px rgba(68,50,24,.08); }
    .panel h2 { margin:0 0 12px; font-size:22px; }
    .badge { display:inline-block; padding:4px 10px; border-radius:999px; background:#f6e5dc; color:var(--accent); margin-right:8px; margin-bottom:8px; }
    input, textarea, button { width:100%; box-sizing:border-box; border-radius:12px; border:1px solid var(--line); padding:10px 12px; font:inherit; }
    textarea { min-height:100px; resize:vertical; }
    button { background:var(--ink); color:white; cursor:pointer; margin-top:10px; }
    button.alt { background:var(--accent); }
    ul { list-style:none; padding:0; margin:0; }
    li { padding:10px 0; border-top:1px solid #eee1d1; }
    li:first-child { border-top:none; }
    .muted { color:#7c7468; font-size:14px; }
    .good { color:var(--good); }
    .bad { color:var(--bad); }
    pre { white-space:pre-wrap; word-break:break-word; background:#f5efe5; padding:12px; border-radius:12px; }
    .timeline { max-height:420px; overflow:auto; }
    .registry-list { max-height:420px; overflow:auto; }
    .list-scroll { max-height:420px; overflow:auto; }
    .pager { display:flex; gap:10px; align-items:center; margin-top:12px; }
    .pager button { width:auto; margin-top:0; padding:8px 14px; }
    .registry-card { border-top:1px solid #eee1d1; padding:12px 0; }
    .registry-card:first-child { border-top:none; }
    @media (max-width: 980px) { .hero,.grid { grid-template-columns:1fr; } h1{font-size:30px;} }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Agent Auth Demo Console</h1>
    <div class="hero">
      <section class="panel">
        <h2>新建工单</h2>
        <div class="muted">用户提交后，工单会在 4 个 agent 间流转，并记录完整验签与协作轨迹。</div>
        <input id="title" placeholder="例如：Urgent password reset for CFO" />
        <textarea id="desc" placeholder="描述工单内容，尝试包含 password / invoice / urgent / missing 等关键词。"></textarea>
        <button onclick="createTicket()">创建并启动协作</button>
      </section>
      <section class="panel">
        <h2>攻击演示面板</h2>
        <button class="alt" onclick="runScenario('unregistered')">未注册 Agent 攻击</button>
        <button class="alt" onclick="runScenario('tampered')">签名篡改攻击</button>
        <button class="alt" onclick="runScenario('replay')">Nonce 重放攻击</button>
        <button class="alt" onclick="runScenario('stolen-api-key')">盗取 API Key 发布攻击</button>
        <button class="alt" onclick="runScenario('owner-conflict')">Owner 冲突发布攻击</button>
        <pre id="scenario-output">等待执行场景...</pre>
      </section>
    </div>
    <div class="grid">
      <section class="panel">
        <h2>工单列表</h2>
        <div id="tickets"></div>
      </section>
      <section class="panel">
        <h2>Agent 注册表</h2>
        <div id="registry"></div>
      </section>
      <section class="panel">
        <h2>工单详情时间线</h2>
        <div id="timeline" class="timeline muted">点击左侧工单查看详情。</div>
      </section>
      <section class="panel">
        <h2>认证事件面板</h2>
        <div id="auth-events"></div>
      </section>
    </div>
  </div>
  <script>
    let selectedTicketId = null;
    let ticketsPage = 1;
    let timelinePage = 1;
    let authPage = 1;
    let registryPage = 1;

    async function loadAll() {
      await Promise.all([loadTickets(), loadRegistry(), loadAuthEvents()]);
      if (selectedTicketId) await loadTicketDetail(selectedTicketId);
    }

    async function createTicket() {
      const title = document.getElementById('title').value.trim();
      const description = document.getElementById('desc').value.trim();
      const res = await fetch('/api/tickets', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({title, description})});
      const data = await res.json();
      selectedTicketId = data.ticket_id;
      await loadAll();
    }

    async function runScenario(name) {
      const res = await fetch(`/api/scenarios/${name}`, {method:'POST'});
      const data = await res.json();
      document.getElementById('scenario-output').textContent = JSON.stringify(data, null, 2);
      await loadAll();
    }

    async function loadTickets() {
      const data = await (await fetch(`/api/tickets?page=${ticketsPage}&page_size=6`)).json();
      const tickets = data.items || [];
      const el = document.getElementById('tickets');
      el.innerHTML = `
        <div class="muted">按更新时间倒序展示，共 ${data.total} 张工单。</div>
        <div class="list-scroll">
          <ul>${tickets.map(ticket => `
        <li>
          <div><strong>${ticket.title}</strong></div>
          <div class="muted">状态：${ticket.status} | 当前：${ticket.current_agent} | 优先级：${ticket.priority}</div>
          <button onclick="selectTicket('${ticket.ticket_id}')">查看详情</button>
        </li>
      `).join('') || '<li class="muted">暂无工单</li>'}</ul>
        </div>
        <div class="pager">
          <button onclick="changeTicketsPage(-1)" ${data.page <= 1 ? 'disabled' : ''}>上一页</button>
          <span class="muted">第 ${data.page} / ${data.page_count} 页</span>
          <button onclick="changeTicketsPage(1)" ${data.page >= data.page_count ? 'disabled' : ''}>下一页</button>
        </div>
      `;
    }

    async function selectTicket(ticketId) {
      selectedTicketId = ticketId;
      timelinePage = 1;
      await loadTicketDetail(ticketId);
    }

    async function loadTicketDetail(ticketId) {
      const data = await (await fetch(`/api/tickets/${ticketId}?events_page=${timelinePage}&events_page_size=6`)).json();
      const ticket = data.ticket;
      const events = data.events;
      const el = document.getElementById('timeline');
      el.innerHTML = `
        <div><strong>${ticket.title}</strong></div>
        <div class="muted">分类：${ticket.category} | 优先级：${ticket.priority} | 当前：${ticket.current_agent} | 状态：${ticket.status}</div>
        <div class="muted">结论：${ticket.resolution || '处理中'}</div>
        <div class="muted">时间线共 ${data.events_total} 条事件。</div>
        <ul>${events.map(event => `
          <li>
            <div><strong>${event.event_type}</strong></div>
            <div class="muted">${event.from_agent} → ${event.to_agent} | 验证：${event.verification_result}</div>
            <div>${event.payload_summary}</div>
            <div class="muted">${event.reason || ''}</div>
          </li>
        `).join('') || '<li class="muted">暂无事件</li>'}</ul>
        <div class="pager">
          <button onclick="changeTimelinePage(-1)" ${data.events_page <= 1 ? 'disabled' : ''}>上一页</button>
          <span class="muted">第 ${data.events_page} / ${data.events_page_count} 页</span>
          <button onclick="changeTimelinePage(1)" ${data.events_page >= data.events_page_count ? 'disabled' : ''}>下一页</button>
        </div>
      `;
    }

    async function loadRegistry() {
      const data = await (await fetch(`/api/registry?page=${registryPage}&page_size=5`)).json();
      const agents = data.agents || [];
      const rows = agents.map(item => `
        <div class="registry-card">
          <div><strong>${item.metadata.name}</strong> <span class="badge">${item.agent_id}</span></div>
          <div class="muted">组织：${item.metadata.organization} | 发布时间：${item.published_at}</div>
          <div class="muted">能力：${(item.metadata.capabilities || []).join(', ') || '无'}</div>
          <div class="muted">入口：${item.metadata.endpoint}</div>
        </div>
      `).join('');
      document.getElementById('registry').innerHTML = `
        <div class="muted">按发布时间倒序展示，共 ${data.total} 个 agent。</div>
        <div class="registry-list">${rows || '<div class="muted">暂无 agent</div>'}</div>
        <div class="pager">
          <button onclick="changeRegistryPage(-1)" ${data.page <= 1 ? 'disabled' : ''}>上一页</button>
          <span class="muted">第 ${data.page} / ${data.page_count} 页</span>
          <button onclick="changeRegistryPage(1)" ${data.page >= data.page_count ? 'disabled' : ''}>下一页</button>
        </div>
      `;
    }

    async function changeRegistryPage(delta) {
      registryPage = Math.max(1, registryPage + delta);
      await loadRegistry();
    }

    async function loadAuthEvents() {
      const data = await (await fetch(`/api/auth-events?page=${authPage}&page_size=6`)).json();
      const events = data.items || [];
      document.getElementById('auth-events').innerHTML = `
        <div class="muted">按时间倒序展示，共 ${data.total} 条认证事件。</div>
        <div class="list-scroll">
          <ul>${events.map(event => `
        <li>
          <div><strong class="${event.result === 'verified' ? 'good' : 'bad'}">${event.result}</strong> @ ${event.target_agent}</div>
          <div class="muted">${event.source_agent_id || 'unknown'} | ${event.error_code || 'OK'}</div>
          <div>${event.detail}</div>
        </li>
      `).join('') || '<li class="muted">暂无认证事件</li>'}</ul>
        </div>
        <div class="pager">
          <button onclick="changeAuthPage(-1)" ${data.page <= 1 ? 'disabled' : ''}>上一页</button>
          <span class="muted">第 ${data.page} / ${data.page_count} 页</span>
          <button onclick="changeAuthPage(1)" ${data.page >= data.page_count ? 'disabled' : ''}>下一页</button>
        </div>
      `;
    }

    async function changeTicketsPage(delta) {
      ticketsPage = Math.max(1, ticketsPage + delta);
      await loadTickets();
    }

    async function changeTimelinePage(delta) {
      if (!selectedTicketId) return;
      timelinePage = Math.max(1, timelinePage + delta);
      await loadTicketDetail(selectedTicketId);
    }

    async function changeAuthPage(delta) {
      authPage = Math.max(1, authPage + delta);
      await loadAuthEvents();
    }

    loadAll();
    setInterval(loadAll, 3000);
  </script>
</body>
</html>"""
