"""Console web application for the Multi-Agent Code Review & Security Audit system.

Provides:
  - Web UI (single-page app)
  - Review submission and listing APIs
  - 5 attack scenario endpoints
  - Auth event listing
  - Data clearing
"""

from __future__ import annotations

import json
import math
from typing import Callable

from shared.sdk_loader import ensure_sdk_path

ensure_sdk_path()

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from agent_auth_sdk import AgentInstance
from agent_auth_sdk.registry_security import sign_registry_publish_request
from shared.models import AgentTask, AgentTaskResult, AuthEvent, SubmitReviewRequest
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
    app = FastAPI(title="Code Review Console")

    def paginate(items: list[dict], total: int, page: int, page_size: int) -> dict:
        nsize = max(1, min(page_size, 20))
        pcount = max(1, math.ceil(total / nsize)) if total else 1
        npage = max(1, min(page, pcount))
        return {"items": items, "total": total, "page": npage,
                "page_size": nsize, "page_count": pcount}

    # -- Core endpoints ------------------------------------------------------

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return _html()

    # -- Review APIs ---------------------------------------------------------

    @app.get("/api/reviews")
    async def list_reviews(page: int = 1, page_size: int = 6) -> dict:
        reviews, total = store.list_reviews_page(page=page, page_size=page_size)
        return paginate([r.model_dump(mode="json") for r in reviews], total, page, page_size)

    @app.get("/api/reviews/{review_id}")
    async def review_detail(review_id: str) -> dict:
        review = store.get_review(review_id)
        if review is None:
            raise HTTPException(status_code=404, detail="review not found")
        events, _ = store.list_review_events_page(review_id, page=1, page_size=50)
        findings = store.list_findings(review_id)
        return {
            "review": review.model_dump(mode="json"),
            "events": [e.model_dump(mode="json") for e in events],
            "findings": [f.model_dump(mode="json") for f in findings],
        }

    @app.post("/api/reviews")
    async def submit_review(payload: SubmitReviewRequest) -> dict:
        async with factory() as client:
            response = await client.post(
                f"{settings.agent_url('coordinator-agent')}/reviews/submit",
                json=payload.model_dump(mode="json"),
                timeout=300,
            )
            response.raise_for_status()
        return response.json()

    # -- Auth events ---------------------------------------------------------

    @app.get("/api/auth-events")
    async def auth_events(page: int = 1, page_size: int = 6) -> dict:
        events, total = store.list_auth_events_page(page=page, page_size=page_size)
        return paginate([e.model_dump(mode="json") for e in events], total, page, page_size)

    # -- Registry view -------------------------------------------------------

    @app.get("/api/registry")
    async def registry_view(page: int = 1, page_size: int = 5) -> dict:
        async with factory() as client:
            response = await client.get(settings.registry_base_url)
            response.raise_for_status()
            payload = response.json()
            agents = sorted(
                payload.get("agents", []),
                key=lambda item: item.get("published_at") or "", reverse=True,
            )
            nsize = max(1, min(page_size, 20))
            total = len(agents)
            pcount = max(1, math.ceil(total / nsize)) if total else 1
            npage = max(1, min(page, pcount))
            start = (npage - 1) * nsize
            payload["agents"] = agents[start:start + nsize]
            payload["total"] = total
            payload["page"] = npage
            payload["page_size"] = nsize
            payload["page_count"] = pcount
            return payload

    # -- Attack Scenarios ----------------------------------------------------

    @app.post("/api/scenarios/unregistered")
    async def attack_unregistered() -> dict:
        rogue = AgentInstance.from_vault(
            domain="127.0.0.1:8999", name="rogue-agent", organization="Rogue Org",
            endpoint="http://127.0.0.1:8999/tasks/handle",
            vault_addr=_require(settings.vault_addr, "DEMO_VAULT_ADDR"),
            vault_token_file=settings.vault_token_file,
            vault_token=settings.vault_token,
            allow_insecure_raw_token=settings.allow_insecure_vault_token,
            transit_mount=settings.vault_transit_mount,
            key_name=_require(settings.agent_kms_key_id("architecture-agent"), "DEMO_ARCHITECTURE_KMS_KEY_ID"),
            namespace=settings.vault_namespace, verify=settings.vault_verify(),
            capabilities=["sign"], environment="attack", kid="rogue-unregistered",
        )
        body = AgentTask(review_id="attack-probe-unregistered", action="review_architecture",
                         code="print('hello')", language="python").model_dump(mode="json")
        target_url = settings.agents["architecture-agent"].endpoint
        signed = await rogue.sign_http(method="POST", url=target_url, body=body)
        async with factory() as client:
            response = await client.post(target_url, json=body, headers=signed.headers)
        _record_attack(store, "unregistered", rogue.agent_id, response.status_code,
                       _safe_json(response))
        return {"status_code": response.status_code, "payload": _safe_json(response)}

    @app.post("/api/scenarios/tampered")
    async def attack_tampered() -> dict:
        arch = _load_local_agent("architecture-agent", settings)
        target_url = settings.agents["architecture-agent"].endpoint
        original = AgentTask(review_id="attack-probe-tampered", action="review_architecture",
                             code="print('safe')", language="python").model_dump(mode="json")
        tampered = AgentTask(review_id="attack-probe-tampered", action="review_architecture",
                             code="print('MALICIOUS PAYLOAD INJECTED')", language="python").model_dump(mode="json")
        signed = await arch.sign_http(method="POST", url=target_url, body=original)
        async with factory() as client:
            response = await client.post(target_url, json=tampered, headers=signed.headers)
        _record_attack(store, "tampered", arch.agent_id, response.status_code,
                       _safe_json(response))
        return {"status_code": response.status_code, "payload": _safe_json(response)}

    @app.post("/api/scenarios/replay")
    async def attack_replay() -> dict:
        coord = _load_local_agent("coordinator-agent", settings)
        body = AgentTask(review_id="attack-probe-replay", action="review_architecture",
                         code="print('test')", language="python").model_dump(mode="json")
        target_url = settings.agents["architecture-agent"].endpoint
        signed = await coord.sign_http(method="POST", url=target_url, body=body, nonce="fixed-replay-nonce-002")
        async with factory() as client:
            first = await client.post(target_url, json=body, headers=signed.headers)
            second = await client.post(target_url, json=body, headers=signed.headers)
        _record_attack(store, "replay", coord.agent_id, second.status_code,
                       _safe_json(second))
        return {"first": {"status_code": first.status_code, "payload": _safe_json(first)},
                "second": {"status_code": second.status_code, "payload": _safe_json(second)}}

    @app.post("/api/scenarios/stolen-api-key")
    async def attack_stolen_api_key() -> dict:
        rogue = AgentInstance.from_vault(
            domain="127.0.0.1:8998", name="coordinator-agent", organization="Rogue Org",
            endpoint="http://127.0.0.1:8998/tasks/handle",
            vault_addr=_require(settings.vault_addr, "DEMO_VAULT_ADDR"),
            vault_token_file=settings.vault_token_file,
            vault_token=settings.vault_token,
            allow_insecure_raw_token=settings.allow_insecure_vault_token,
            transit_mount=settings.vault_transit_mount,
            key_name=_require(settings.agent_kms_key_id("architecture-agent"), "DEMO_ARCHITECTURE_KMS_KEY_ID"),
            namespace=settings.vault_namespace, verify=settings.vault_verify(),
            capabilities=["publish"], environment="attack", kid="rogue-stolen-key",
        )
        legitimate = _load_local_agent("coordinator-agent", settings)
        payload = {"agent_id": legitimate.agent_id, "metadata": rogue.metadata.model_dump(mode="json"),
                    "publish_intent": "upsert_metadata"}
        signed = await sign_registry_publish_request(
            path="/registry/agents/publish", host=_registry_host(settings.registry_publish_url),
            body=payload, agent_id=legitimate.agent_id,
            client_id=_require(settings.registry_client_id, "DEMO_REGISTRY_CLIENT_ID"),
            signer=rogue.signer,
        )
        headers = {"authorization": f"Bearer {_require(settings.registry_api_key, 'DEMO_REGISTRY_API_KEY')}",
                    **signed.headers}
        async with factory() as client:
            response = await client.post(settings.registry_publish_url, json=payload, headers=headers)
        _record_attack(store, "stolen_api_key", rogue.agent_id, response.status_code,
                       _safe_json(response))
        return {"status_code": response.status_code, "payload": _safe_json(response)}

    @app.post("/api/scenarios/capability-escalation")
    async def attack_capability_escalation() -> dict:
        # Architecture agent tries to submit a security review result to Coordinator
        arch = _load_local_agent("architecture-agent", settings)
        target_url = settings.agents["coordinator-agent"].endpoint
        # Send as AgentTask — architecture agent claiming to do security review
        body = AgentTask(
            review_id="attack-probe-capability", action="review_security",
            code="print('test')", language="python",
            context="architecture agent pretending to be security reviewer",
        ).model_dump(mode="json")
        signed = await arch.sign_http(method="POST", url=target_url, body=body)
        async with factory() as client:
            response = await client.post(target_url, json=body, headers=signed.headers)
        _record_attack(store, "capability_escalation", arch.agent_id, response.status_code,
                       _safe_json(response))
        return {"status_code": response.status_code, "payload": _safe_json(response)}

    # -- Clear data ----------------------------------------------------------

    @app.post("/api/clear-data")
    async def clear_data() -> dict:
        counts = store.clear_all()
        return {"ok": True, "cleared": counts}

    return app


# ===========================================================================
# Helpers
# ===========================================================================

def _attack_ticket_id(scenario: str) -> str:
    return f"attack-probe-{scenario}"


def _safe_json(response) -> dict:
    """Safely parse response body as JSON, returning error dict on failure."""
    try:
        return response.json()
    except Exception:
        text = response.text[:500] if response.text else "(empty body)"
        return {"error": "invalid JSON", "status_code": response.status_code, "body": text}


def _record_attack(
    store: DemoStore, scenario: str, source_agent_id: str | None,
    status_code: int, payload: dict,
) -> None:
    reason = str(payload.get("detail") or payload)
    result = "rejected" if status_code >= 400 else "verified"
    store.add_auth_event(AuthEvent(
        source_agent_id=source_agent_id, target_agent="attack-scenario",
        result=result,
        error_code=reason if status_code >= 400 else None,
        detail=f"[{scenario}] HTTP {status_code}: {reason}",
        created_at=utc_now(),
    ))


def _load_local_agent(role: str, settings: DemoSettings) -> AgentInstance:
    metadata_path = settings.agent_metadata_dir(role) / ".well-known" / "agent.json"
    if not metadata_path.exists():
        raise HTTPException(status_code=503, detail=f"{role} identity is not ready yet")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    return AgentInstance.from_vault(
        domain=metadata["domain"], name=metadata["name"],
        organization=metadata["organization"], endpoint=metadata["endpoint"],
        vault_addr=_require(settings.vault_addr, "DEMO_VAULT_ADDR"),
        vault_token_file=settings.vault_token_file,
        vault_token=settings.vault_token,
        allow_insecure_raw_token=settings.allow_insecure_vault_token,
        transit_mount=settings.vault_transit_mount,
        key_name=_require(settings.agent_kms_key_id(role), f"{role} Vault key"),
        namespace=settings.vault_namespace, verify=settings.vault_verify(),
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


# ===========================================================================
# HTML UI
# ===========================================================================

def _html() -> str:
    return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Code Review & Security Audit</title>
<style>
:root{
  --bg:#f6f8fb;--surface:#ffffff;--surface-soft:#f8fafc;--ink:#172033;--muted:#667085;
  --line:#e4e7ec;--line-strong:#cfd6df;--primary:#2563eb;--primary-dark:#1d4ed8;
  --success:#12805c;--danger:#b42318;--warning:#b54708;--violet:#6941c6;--teal:#0e9384;
  --shadow:0 16px 40px rgba(15,23,42,.08);
}
*{box-sizing:border-box}
body{
  margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",Arial,sans-serif;
  background:
    radial-gradient(circle at top left,rgba(37,99,235,.08),transparent 32rem),
    linear-gradient(180deg,#ffffff 0%,var(--bg) 30%,#eef3f8 100%);
  color:var(--ink);font-size:14px;line-height:1.5;
}
.wrap{max-width:1480px;margin:0 auto;padding:28px 24px 36px;}
.topbar{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:20px;}
h1{margin:0;font-size:30px;line-height:1.15;font-weight:750;letter-spacing:0;}
.subtitle{margin-top:8px;color:var(--muted);max-width:720px;}
.status-strip{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;}
.pill{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.86);padding:7px 11px;color:#344054;font-size:12px;font-weight:650;}
.hero{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(340px,.85fr);gap:16px;margin-bottom:16px;}
.grid2{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:16px;}
.panel{background:rgba(255,255,255,.92);border:1px solid var(--line);border-radius:8px;padding:18px;box-shadow:var(--shadow);}
.panel h2{margin:0;font-size:17px;line-height:1.25;font-weight:740;}
.panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:14px;}
.panel-note{color:var(--muted);font-size:13px;margin-top:3px;}
.field-stack{display:grid;gap:10px;}
input,textarea,button{width:100%;border-radius:8px;border:1px solid var(--line-strong);padding:10px 12px;font:inherit;}
input,textarea{background:#fff;color:var(--ink);outline:none;transition:border-color .16s ease,box-shadow .16s ease,background .16s ease;}
input:focus,textarea:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(37,99,235,.13);}
textarea{min-height:220px;resize:vertical;font-family:"Cascadia Code","Fira Code",Consolas,monospace;font-size:13px;line-height:1.55;}
button{display:inline-flex;align-items:center;justify-content:center;gap:8px;border-color:transparent;background:var(--primary);color:white;cursor:pointer;font-weight:700;transition:transform .12s ease,background .12s ease,box-shadow .12s ease;}
button:hover{background:var(--primary-dark);box-shadow:0 8px 18px rgba(37,99,235,.18);transform:translateY(-1px);}
button:disabled{background:#e4e7ec;color:#98a2b3;cursor:not-allowed;box-shadow:none;transform:none;}
button.alt{background:#344054;} button.alt:hover{background:#1d2939;box-shadow:0 8px 18px rgba(52,64,84,.16);}
button.danger{background:var(--danger);} button.danger:hover{background:#912018;box-shadow:0 8px 18px rgba(180,35,24,.16);}
.actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;}
.actions button{min-height:40px;margin:0;}
.badge{display:inline-flex;align-items:center;min-height:22px;padding:2px 8px;border-radius:999px;margin-right:6px;margin-bottom:4px;font-size:12px;font-weight:700;color:#344054;background:#eef2f6;border:1px solid transparent;}
.badge.good,.badge.completed{background:#e8f5ee;color:var(--success);}
.badge.bad,.badge.failed,.badge.crit{background:#fee4e2;color:var(--danger);}
.badge.high{background:#fff1e5;color:var(--warning);}
.badge.med{background:#fff8d6;color:#854a0e;}
.badge.low{background:#e8f5ee;color:var(--success);}
.badge.info,.badge.in_review,.badge.analyzing,.badge.synthesizing{background:#eaf1ff;color:var(--primary-dark);}
.score{display:inline-flex;width:46px;height:42px;align-items:center;justify-content:center;border-radius:8px;font-weight:800;margin-right:8px;background:#fff;border:1px solid var(--line-strong);box-shadow:inset 4px 0 0 var(--primary);}
.score.good{color:var(--success);box-shadow:inset 4px 0 0 var(--success);}
.score.warn{color:var(--warning);box-shadow:inset 4px 0 0 var(--warning);}
.score.bad{color:var(--danger);box-shadow:inset 4px 0 0 var(--danger);}
ul{list-style:none;padding:0;margin:0;}
li{padding:12px 0;border-top:1px solid var(--line);}
li:first-child{border-top:none;}
.muted{color:var(--muted);font-size:13px;}
.good{color:var(--success);} .bad{color:var(--danger);}
pre{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#dbeafe;padding:12px;border-radius:8px;font-size:12px;line-height:1.55;margin:12px 0 0;}
.scroll{max-height:430px;overflow:auto;padding-right:2px;}
.pager{display:flex;gap:8px;align-items:center;margin-top:12px;padding-top:10px;border-top:1px solid var(--line);}
.pager button{width:auto;margin-top:0;padding:7px 12px;min-width:74px;}
.finding-card{border:1px solid var(--line);border-radius:8px;padding:12px;margin-bottom:10px;background:var(--surface-soft);}
.finding-card .title{font-weight:750;margin-bottom:5px;}
.review-row{display:grid;gap:6px;}
.row-title{display:flex;align-items:center;justify-content:space-between;gap:10px;}
.row-meta{display:flex;flex-wrap:wrap;gap:8px;color:var(--muted);font-size:13px;}
.detail-section{margin-top:16px;padding-top:14px;border-top:1px solid var(--line);}
.detail-section h3,.detail-section h4{margin:0 0 10px;}
.empty{display:flex;align-items:center;justify-content:center;min-height:96px;border:1px dashed var(--line-strong);border-radius:8px;background:var(--surface-soft);color:var(--muted);}
code{background:#eef2f6;padding:2px 6px;border-radius:4px;font-size:12px;}
@media(max-width:1040px){.hero,.grid2{grid-template-columns:1fr}.topbar{align-items:flex-start;flex-direction:column}.status-strip{justify-content:flex-start}h1{font-size:26px}}
@media(max-width:640px){.wrap{padding:20px 14px 28px}.panel{padding:14px}.actions{grid-template-columns:1fr}.row-title{align-items:flex-start;flex-direction:column}textarea{min-height:180px}}
</style>
</head>
<body>
<div class="wrap">
<header class="topbar">
  <div>
    <h1>Agent Auth Code Review Console</h1>
    <div class="subtitle">一个用于演示 Agent 身份认证、消息签名、能力校验和多 Agent 代码审查协作的控制台。</div>
  </div>
  <div class="status-strip">
    <span class="pill">HTTP 签名</span>
    <span class="pill">Nonce 防重放</span>
    <span class="pill">Capability 校验</span>
  </div>
</header>
<div class="hero">
<section class="panel">
  <div class="panel-head">
    <div>
      <h2>提交代码审查</h2>
      <div class="panel-note">提交后，Coordinator 将调度 4 个专家 Agent 完成审查。</div>
    </div>
  </div>
  <div class="field-stack">
    <input id="title" placeholder="审查标题，如：Review auth_service.py"/>
    <textarea id="code" placeholder="粘贴需要审查的代码..."></textarea>
    <input id="lang-hint" placeholder="语言提示（可选，如 python）"/>
  </div>
  <button onclick="submitReview()" style="margin-top:12px;">提交审查</button>
  <div id="submit-status" class="muted" style="margin-top:8px;"></div>
</section>
<section class="panel">
  <div class="panel-head">
    <div>
      <h2>攻击演示面板</h2>
      <div class="panel-note">验证 SDK 如何拒绝未注册、篡改、重放和越权请求。</div>
    </div>
  </div>
  <div class="actions">
    <button class="alt" onclick="runScenario('unregistered')">未注册 Agent 攻击</button>
    <button class="alt" onclick="runScenario('tampered')">审查结果篡改</button>
    <button class="alt" onclick="runScenario('replay')">Nonce 重放攻击</button>
    <button class="alt" onclick="runScenario('stolen-api-key')">API Key 盗取</button>
    <button class="alt" onclick="runScenario('capability-escalation')">能力越权攻击</button>
  </div>
  <pre id="scenario-output">等待执行场景...</pre>
  <button class="danger" onclick="clearAllData()" style="margin-top:12px;">清空全部数据</button>
</section>
</div>
<div class="grid2">
<section class="panel">
  <div class="panel-head"><div><h2>审查列表</h2><div class="panel-note">最近提交的代码审查任务。</div></div></div>
  <div id="reviews" class="scroll"></div>
</section>
<section class="panel">
  <div class="panel-head"><div><h2>审查详情 & 报告</h2><div class="panel-note">查看评分、发现项和认证时间线。</div></div></div>
  <div id="detail" class="scroll"><div class="empty">点击左侧审查查看详情</div></div>
</section>
<section class="panel">
  <div class="panel-head"><div><h2>Agent 注册表</h2><div class="panel-note">来自本地 registry 的 Agent 元数据。</div></div></div>
  <div id="registry" class="scroll"></div>
</section>
<section class="panel">
  <div class="panel-head"><div><h2>认证事件</h2><div class="panel-note">签名验证、拒绝原因和攻击演示结果。</div></div></div>
  <div id="auth-events" class="scroll"></div>
</section>
</div>
</div>
<script>
let selectedReviewId=null,reviewsPage=1,authPage=1,registryPage=1;

async function loadAll(){await Promise.all([loadReviews(),loadRegistry(),loadAuthEvents()]);if(selectedReviewId)await loadDetail(selectedReviewId);}

async function submitReview(){
  const title=document.getElementById('title').value.trim();
  const code=document.getElementById('code').value.trim();
  const lang=document.getElementById('lang-hint').value.trim();
  if(!title||!code){document.getElementById('submit-status').textContent='请填写标题和代码。';return;}
  document.getElementById('submit-status').textContent='提交中...';
  const res=await fetch('/api/reviews',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title,code,language_hint:lang||null})});
  const data=await res.json();
  if(data.ok){document.getElementById('submit-status').textContent='审查已提交: '+data.review_id;selectedReviewId=data.review_id;await loadAll();}
  else{document.getElementById('submit-status').textContent='提交失败: '+JSON.stringify(data);}
}

async function runScenario(name){
  const res=await fetch(`/api/scenarios/${name}`,{method:'POST'});
  const data=await res.json();
  document.getElementById('scenario-output').textContent=JSON.stringify(data,null,2);
  await loadAll();
}

async function clearAllData(){
  if(!confirm('确定要清空全部数据吗？'))return;
  const res=await fetch('/api/clear-data',{method:'POST'});
  const data=await res.json();
  document.getElementById('scenario-output').textContent='已清空: '+JSON.stringify(data.cleared,null,2);
  selectedReviewId=null;reviewsPage=1;authPage=1;registryPage=1;
  await loadAll();
}

async function loadReviews(){
  const data=await(await fetch(`/api/reviews?page=${reviewsPage}&page_size=6`)).json();
  const items=data.items||[];
  document.getElementById('reviews').innerHTML=`
    <div class="muted">共 ${data.total} 条审查。</div>
    <ul>${items.map(r=>`
      <li>
        <div class="review-row">
          <div class="row-title"><strong>${r.title}</strong><span class="badge ${r.status}">${r.status}</span></div>
          <div class="row-meta"><span>语言: ${r.language}</span><span>评分: ${r.overall_score??'-'}/10</span><span>${r.updated_at?.slice(0,19)||''}</span></div>
          <button onclick="selectReview('${r.review_id}')">查看详情</button>
        </div>
      </li>
    `).join('')||'<li><div class="empty">暂无审查</div></li>'}</ul>
    <div class="pager">
      <button onclick="changeReviewsPage(-1)" ${data.page<=1?'disabled':''}>上一页</button>
      <span class="muted">${data.page}/${data.page_count}</span>
      <button onclick="changeReviewsPage(1)" ${data.page>=data.page_count?'disabled':''}>下一页</button>
    </div>`;
}

async function changeReviewsPage(d){reviewsPage=Math.max(1,reviewsPage+d);await loadReviews();}

async function selectReview(id){selectedReviewId=id;await loadDetail(id);}

async function loadDetail(id){
  const data=await(await fetch(`/api/reviews/${id}`)).json();
  const r=data.review,f=data.findings,e=data.events;
  const sevBadge=s=>`<span class="badge ${s==='critical'?'crit':s==='high'?'high':s==='medium'?'med':s==='low'?'low':'info'}">${s}</span>`;
  const scoreClass=v=>v>=8?'good':v>=5?'warn':'bad';
  const domainName={architecture:'架构审查',security:'安全审查',performance:'性能审查',compliance:'合规审查'};

  // Group findings by agent_role
  const byRole={};
  f.forEach(fi=>{const k=fi.agent_role;if(!byRole[k])byRole[k]=[];byRole[k].push(fi);});

  let findingsHtml='<div class="detail-section"><h3>审查发现</h3>';
  if(Object.keys(byRole).length===0)findingsHtml+='<div class="empty">暂无发现</div>';
  Object.entries(byRole).forEach(([role,items])=>{
    findingsHtml+=`<h4>${domainName[role]||role} (${items.length})</h4>`;
    items.forEach(fi=>findingsHtml+=`
      <div class="finding-card">
        <div class="title">${sevBadge(fi.severity)} ${fi.title}</div>
        <div class="muted">类别: ${fi.category}</div>
        <div>${fi.description}</div>
        <div><strong>建议:</strong> ${fi.recommendation}</div>
        ${fi.code_snippet?`<pre>${fi.code_snippet}</pre>`:''}
        ${fi.line_numbers?`<div class="muted">行号: ${fi.line_numbers}</div>`:''}
      </div>`);
  });
  findingsHtml+='</div>';

  let scoresHtml='<div class="detail-section"><h3>评分</h3>';
  if(r.overall_score){
    scoresHtml+=`<div><span class="score ${scoreClass(r.overall_score)}">${r.overall_score}</span> 综合评分</div>`;
  }else{
    scoresHtml+='<div class="muted">暂未生成评分。</div>';
  }
  scoresHtml+='</div>';

  document.getElementById('detail').innerHTML=`
    <h3>${r.title}</h3>
    <div class="row-meta"><span>ID: ${r.review_id}</span><span>语言: ${r.language}</span><span>状态: ${r.status}</span></div>
    ${r.coordinator_analysis?`<div class="muted">分析: ${r.coordinator_analysis}</div>`:''}
    ${scoresHtml}
    ${findingsHtml}
    <div class="detail-section"><h3>事件时间线 (${e.length})</h3>
    <ul>${e.map(ev=>`<li><div><strong>${ev.event_type}</strong></div><div class="row-meta"><span>${ev.from_agent} -> ${ev.to_agent}</span><span>${ev.verification_result}</span></div><div>${ev.payload_summary}</div>${ev.reason?`<div class="muted">${ev.reason}</div>`:''}</li>`).join('')||'<li><div class="empty">无事件</div></li>'}</ul></div>`;
}

async function loadRegistry(){
  const data=await(await fetch(`/api/registry?page=${registryPage}&page_size=5`)).json();
  const agents=data.agents||[];
  document.getElementById('registry').innerHTML=`
    <div class="muted">共 ${data.total} 个 agent。</div>
    ${agents.map(a=>`<div class="finding-card"><div><strong>${a.metadata.name}</strong></div><div class="muted">${a.agent_id}</div><div class="muted">能力: ${(a.metadata.capabilities||[]).join(', ')}</div></div>`).join('')||'<div class="empty">无 agent</div>'}
    <div class="pager">
      <button onclick="changeRegistryPage(-1)" ${data.page<=1?'disabled':''}>上一页</button><span class="muted">${data.page}/${data.page_count}</span>
      <button onclick="changeRegistryPage(1)" ${data.page>=data.page_count?'disabled':''}>下一页</button>
    </div>`;
}

async function changeRegistryPage(d){registryPage=Math.max(1,registryPage+d);await loadRegistry();}

async function loadAuthEvents(){
  const data=await(await fetch(`/api/auth-events?page=${authPage}&page_size=6`)).json();
  const events=data.items||[];
  document.getElementById('auth-events').innerHTML=`
    <div class="muted">共 ${data.total} 条认证事件。</div>
    <ul>${events.map(e=>`<li><div><span class="badge ${e.result==='verified'?'good':'bad'}">${e.result}</span><strong>${e.target_agent}</strong></div><div class="muted">${e.source_agent_id||'unknown'} | ${e.error_code||'OK'}</div><div>${e.detail}</div></li>`).join('')||'<li><div class="empty">暂无事件</div></li>'}</ul>
    <div class="pager">
      <button onclick="changeAuthPage(-1)" ${data.page<=1?'disabled':''}>上一页</button><span class="muted">${data.page}/${data.page_count}</span>
      <button onclick="changeAuthPage(1)" ${data.page>=data.page_count?'disabled':''}>下一页</button>
    </div>`;
}

async function changeAuthPage(d){authPage=Math.max(1,authPage+d);await loadAuthEvents();}

loadAll();setInterval(loadAll,3000);
</script>
</body>
</html>"""
