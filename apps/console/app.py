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
:root{--bg:#f3f1ea;--panel:#fffdf7;--ink:#1f2a2e;--accent:#b14d2b;--line:#d9d0c4;--good:#1b7f5a;--bad:#a12d2d;--crit:#d32f2f;--high:#e65100;--med:#f57c00;--low:#6d8b3a;--info:#546e7a;}
body{margin:0;font-family:Georgia,"Microsoft YaHei",serif;background:linear-gradient(180deg,#efe8dc 0%,#f7f4ee 100%);color:var(--ink);}
.wrap{max-width:1500px;margin:0 auto;padding:20px;}
h1{margin:0 0 14px;font-size:36px;}
.hero{display:grid;grid-template-columns:1.2fr .8fr;gap:16px;margin-bottom:16px;}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:16px;box-shadow:0 10px 25px rgba(68,50,24,.07);}
.panel h2{margin:0 0 10px;font-size:20px;}
input,textarea,button{width:100%;box-sizing:border-box;border-radius:10px;border:1px solid var(--line);padding:9px 11px;font:inherit;}
textarea{min-height:200px;resize:vertical;font-family:'Cascadia Code','Fira Code',Consolas,monospace;font-size:13px;}
button{background:var(--ink);color:white;cursor:pointer;margin-top:8px;}
button.alt{background:var(--accent);}
.badge{display:inline-block;padding:3px 9px;border-radius:999px;margin-right:6px;margin-bottom:4px;font-size:13px;color:white;}
.badge.crit{background:var(--crit);} .badge.high{background:var(--high);}
.badge.med{background:var(--med);} .badge.low{background:var(--low);} .badge.info{background:var(--info);}
.score{display:inline-block;width:36px;height:36px;line-height:36px;text-align:center;border-radius:50%;color:white;font-weight:bold;margin:0 4px;}
.score.good{background:var(--good);} .score.warn{background:var(--high);} .score.bad{background:var(--crit);}
ul{list-style:none;padding:0;margin:0;}
li{padding:9px 0;border-top:1px solid #eee1d1;}
li:first-child{border-top:none;}
.muted{color:#7c7468;font-size:13px;}
.good{color:var(--good);} .bad{color:var(--bad);}
pre{white-space:pre-wrap;word-break:break-word;background:#f5efe5;padding:10px;border-radius:10px;font-size:12px;}
.scroll{max-height:400px;overflow:auto;}
.pager{display:flex;gap:8px;align-items:center;margin-top:10px;}
.pager button{width:auto;margin-top:0;padding:7px 12px;}
.finding-card{border:1px solid var(--line);border-radius:10px;padding:10px;margin-bottom:8px;background:#faf8f2;}
.finding-card .title{font-weight:bold;margin-bottom:4px;}
.actions button{margin-right:6px;width:auto;}
code{background:#f0ece0;padding:2px 6px;border-radius:4px;font-size:12px;}
@media(max-width:1000px){.hero,.grid2{grid-template-columns:1fr;}h1{font-size:28px;}}
</style>
</head>
<body>
<div class="wrap">
<h1>Code Review & Security Audit</h1>
<div class="hero">
<section class="panel">
  <h2>提交代码审查</h2>
  <div class="muted">提交代码后，5 个 LLM Agent 将协作完成多维度专业审查。</div>
  <input id="title" placeholder="审查标题，如：Review auth_service.py"/>
  <textarea id="code" placeholder="粘贴代码..."></textarea>
  <input id="lang-hint" placeholder="语言提示（可选，如 python）"/>
  <button onclick="submitReview()">提交审查</button>
  <div id="submit-status" class="muted" style="margin-top:8px;"></div>
</section>
<section class="panel">
  <h2>攻击演示面板</h2>
  <div class="muted">攻击场景独立运行，不污染审查数据。</div>
  <div class="actions">
    <button class="alt" onclick="runScenario('unregistered')">未注册 Agent 攻击</button>
    <button class="alt" onclick="runScenario('tampered')">审查结果篡改</button>
    <button class="alt" onclick="runScenario('replay')">Nonce 重放攻击</button>
    <button class="alt" onclick="runScenario('stolen-api-key')">API Key 盗取</button>
    <button class="alt" onclick="runScenario('capability-escalation')">能力越权攻击</button>
  </div>
  <pre id="scenario-output">等待执行场景...</pre>
  <button onclick="clearAllData()" style="background:#a12d2d;margin-top:12px;">清空全部数据</button>
</section>
</div>
<div class="grid2">
<section class="panel">
  <h2>审查列表</h2>
  <div id="reviews" class="scroll"></div>
</section>
<section class="panel">
  <h2>审查详情 & 报告</h2>
  <div id="detail" class="scroll muted">点击左侧审查查看详情。</div>
</section>
<section class="panel">
  <h2>Agent 注册表</h2>
  <div id="registry" class="scroll"></div>
</section>
<section class="panel">
  <h2>认证事件</h2>
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
        <div><strong>${r.title}</strong> <span class="badge ${r.status==='completed'?'good':(r.status==='failed'?'bad':'info')}">${r.status}</span></div>
        <div class="muted">语言: ${r.language} | 评分: ${r.overall_score??'—'}/10 | ${r.updated_at?.slice(0,19)||''}</div>
        <button onclick="selectReview('${r.review_id}')">查看详情</button>
      </li>
    `).join('')||'<li class="muted">暂无审查</li>'}</ul>
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
  const domainEmoji={architecture:'🏗️',security:'🔒',performance:'⚡',compliance:'📋'};

  // Group findings by agent_role
  const byRole={};
  f.forEach(fi=>{const k=fi.agent_role;if(!byRole[k])byRole[k]=[];byRole[k].push(fi);});

  let findingsHtml='<h3>审查发现</h3>';
  if(Object.keys(byRole).length===0)findingsHtml+='<div class="muted">暂无发现。</div>';
  Object.entries(byRole).forEach(([role,items])=>{
    findingsHtml+=`<h4>${domainEmoji[role]||''} ${role.toUpperCase()} (${items.length})</h4>`;
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

  let scoresHtml='<h3>评分</h3>';
  if(r.overall_score){
    scoresHtml+=`<div><span class="score ${scoreClass(r.overall_score)}">${r.overall_score}</span> 综合评分</div>`;
  }

  document.getElementById('detail').innerHTML=`
    <h3>${r.title}</h3>
    <div class="muted">ID: ${r.review_id} | 语言: ${r.language} | 状态: ${r.status}</div>
    ${r.coordinator_analysis?`<div class="muted">分析: ${r.coordinator_analysis}</div>`:''}
    ${scoresHtml}
    ${findingsHtml}
    <h3>事件时间线 (${e.length})</h3>
    <ul>${e.map(ev=>`<li><div><strong>${ev.event_type}</strong></div><div class="muted">${ev.from_agent} → ${ev.to_agent} | ${ev.verification_result}</div><div>${ev.payload_summary}</div>${ev.reason?`<div class="muted">${ev.reason}</div>`:''}</li>`).join('')||'<li class="muted">无事件</li>'}</ul>`;
}

async function loadRegistry(){
  const data=await(await fetch(`/api/registry?page=${registryPage}&page_size=5`)).json();
  const agents=data.agents||[];
  document.getElementById('registry').innerHTML=`
    <div class="muted">共 ${data.total} 个 agent。</div>
    ${agents.map(a=>`<div class="finding-card"><div><strong>${a.metadata.name}</strong></div><div class="muted">${a.agent_id}</div><div class="muted">能力: ${(a.metadata.capabilities||[]).join(', ')}</div></div>`).join('')||'<div class="muted">无 agent</div>'}
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
    <ul>${events.map(e=>`<li><div><strong class="${e.result==='verified'?'good':'bad'}">${e.result}</strong> @ ${e.target_agent}</div><div class="muted">${e.source_agent_id||'unknown'} | ${e.error_code||'OK'}</div><div>${e.detail}</div></li>`).join('')||'<li class="muted">暂无事件</li>'}</ul>
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
