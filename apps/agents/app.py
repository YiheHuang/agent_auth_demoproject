"""Multi-Agent Code Review & Security Audit — Agent FastAPI applications.

Five agent roles share a common runtime (DemoAgentRuntime) and verification
pattern, with role-specific LLM-driven review logic.

  Coordinator    (8101)  — POST /reviews/submit, POST /tasks/handle
  Architecture   (8102)  — POST /tasks/handle
  Security       (8103)  — POST /tasks/handle
  Performance    (8104)  — POST /tasks/handle
  Compliance     (8105)  — POST /tasks/handle
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

from shared.sdk_loader import ensure_sdk_path

ensure_sdk_path()

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from agent_auth_sdk import (
    AgentInstance,
    FileMetadataCache,
    InMemoryNonceStore,
    MetadataResolverConfig,
    VerificationConfig,
    verify_agent_message,
    verify_http_request,
)
from agent_auth_sdk.config import TEST_PROFILE
from shared.llm import (
    analyze_code_submission,
    review_architecture,
    review_security,
    review_performance,
    review_compliance,
    synthesize_report,
)
from shared.models import (
    AgentTask,
    AgentTaskResult,
    AuthEvent,
    ReviewEvent,
    ReviewFinding,
    SubmitReviewRequest,
)
from shared.settings import AgentSpec, DemoSettings, get_demo_settings
from shared.store import DemoStore, utc_now


HttpClientFactory = Callable[[], httpx.AsyncClient]

# Capability mapping: action → required capability
_ACTION_CAPABILITY: dict[str, str] = {
    "review_architecture": "code-review-architecture",
    "review_security": "code-review-security",
    "review_performance": "code-review-performance",
    "review_compliance": "code-review-compliance",
}


@dataclass(slots=True)
class DemoAgentRuntime:
    spec: AgentSpec
    settings: DemoSettings
    store: DemoStore
    cache: FileMetadataCache
    nonce_store: InMemoryNonceStore
    http_client_factory: HttpClientFactory
    agent: AgentInstance | None = None
    initialized: bool = False
    init_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    async def ensure_initialized(self) -> None:
        if self.initialized:
            return
        async with self.init_lock:
            if self.initialized:
                return
            agent_dir = self.settings.agent_dir(self.spec.role)
            metadata_dir = self.settings.agent_metadata_dir(self.spec.role)
            agent_dir.mkdir(parents=True, exist_ok=True)
            agent = AgentInstance.from_vault(
                domain=self.spec.domain,
                name=self.spec.role,
                organization=self.settings.organization,
                endpoint=self.spec.endpoint,
                vault_addr=_require(self.settings.vault_addr, "DEMO_VAULT_ADDR"),
                vault_token_file=self.settings.vault_token_file,
                vault_token=self.settings.vault_token,
                allow_insecure_raw_token=self.settings.allow_insecure_vault_token,
                transit_mount=self.settings.vault_transit_mount,
                key_name=_require(
                    self.settings.agent_kms_key_id(self.spec.role),
                    f"{self.spec.role} Vault key",
                ),
                namespace=self.settings.vault_namespace,
                verify=self.settings.vault_verify(),
                capabilities=_agent_capabilities(self.spec.role),
                environment="demo",
                auto_create_key=True,
            )
            agent.export_metadata(metadata_dir)
            async with self.http_client_factory() as client:
                await agent.publish(
                    registry_url=self.settings.registry_publish_url,
                    client_id=_require(self.settings.registry_client_id, "DEMO_REGISTRY_CLIENT_ID"),
                    api_key=_require(self.settings.registry_api_key, "DEMO_REGISTRY_API_KEY"),
                    http_client=client,
                )
            self.agent = agent
            self.initialized = True

    async def send_task(
        self,
        target_role: str,
        task: AgentTask,
        *,
        sign_body: dict | None = None,
        send_body: dict | None = None,
        nonce: str | None = None,
    ) -> httpx.Response:
        if self.agent is None:
            raise RuntimeError("Agent runtime is not initialized")
        target_url = self.settings.agents[target_role].endpoint
        body_to_sign = sign_body or task.model_dump(mode="json")
        body_to_send = send_body or task.model_dump(mode="json")
        signed = await self.agent.sign_http(
            method="POST", url=target_url, body=body_to_sign, nonce=nonce,
        )
        async with self.http_client_factory() as client:
            return await client.post(
                target_url, json=body_to_send, headers=signed.headers,
            )


# ===========================================================================
# App factory
# ===========================================================================

def create_agent_app(
    role: str,
    settings: DemoSettings | None = None,
    *,
    http_client_factory: HttpClientFactory | None = None,
) -> FastAPI:
    settings = settings or get_demo_settings()
    spec = settings.agents[role]
    store = DemoStore(settings.database_path)
    cache = FileMetadataCache(settings.metadata_cache_path)
    nonce_store = InMemoryNonceStore()
    factory = http_client_factory or (lambda: httpx.AsyncClient())
    runtime = DemoAgentRuntime(spec, settings, store, cache, nonce_store, factory)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await runtime.ensure_initialized()
        yield

    app = FastAPI(title=spec.display_name, lifespan=lifespan)
    app.state.runtime = runtime

    @app.middleware("http")
    async def ensure_ready(request: Request, call_next):
        await runtime.ensure_initialized()
        return await call_next(request)

    # -- Common endpoints ---------------------------------------------------

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "agent": role}

    @app.get("/identity")
    async def identity() -> dict[str, str]:
        if runtime.agent is None:
            raise HTTPException(status_code=503, detail="agent not ready")
        return {"agent_id": runtime.agent.agent_id, "role": role}

    # -- Coordinator: submit review (user-facing, no auth required) ---------

    if role == "coordinator-agent":

        @app.post("/reviews/submit")
        async def submit_review(payload: SubmitReviewRequest) -> JSONResponse:
            # 1. Create review
            review = store.create_review(payload.title, payload.code)
            store.add_review_event(ReviewEvent(
                review_id=review.review_id, event_type="user_submitted",
                from_agent="user", to_agent="coordinator-agent",
                verification_result="n/a", payload_summary=payload.title,
                created_at=utc_now(),
            ))

            # 2. Analyze code with LLM (or fallback)
            try:
                analysis = await analyze_code_submission(
                    settings=runtime.settings.llm,
                    code=review.code,
                    language_hint=payload.language_hint,
                )
                language = analysis.language
                coordinator_analysis = analysis.summary
            except Exception:
                from shared.rules import analyze_code_submission as _fallback_analyze
                fb = _fallback_analyze(review.code, payload.language_hint)
                language = fb.language
                coordinator_analysis = fb.summary

            store.update_review(
                review.review_id, language=language,
                coordinator_analysis=coordinator_analysis, status="analyzing",
            )
            store.add_review_event(ReviewEvent(
                review_id=review.review_id, event_type="coordinator_analyzed",
                from_agent="coordinator-agent", to_agent="coordinator-agent",
                verification_result="n/a",
                payload_summary=f"language={language}",
                reason=coordinator_analysis, created_at=utc_now(),
            ))

            # 3. Prepare concurrent dispatch to all 4 specialists
            specialist_roles = {
                "review_architecture": "architecture-agent",
                "review_security": "security-agent",
                "review_performance": "performance-agent",
                "review_compliance": "compliance-agent",
            }

            async def dispatch_one(action: str, target: str) -> tuple[str, httpx.Response | None]:
                task = AgentTask(
                    review_id=review.review_id, action=action,
                    code=review.code, language=language,
                    context=coordinator_analysis,
                )
                store.add_review_event(ReviewEvent(
                    review_id=review.review_id, event_type="agent_dispatched",
                    from_agent="coordinator-agent", to_agent=target,
                    verification_result="signed",
                    payload_summary=json.dumps(task.model_dump(mode="json"), ensure_ascii=False),
                    created_at=utc_now(),
                ))
                try:
                    response = await runtime.send_task(target, task)
                    return target, response
                except Exception as exc:
                    return target, None

            store.update_review(review.review_id, status="in_review")

            dispatched = await asyncio.gather(*(
                dispatch_one(action, target)
                for action, target in specialist_roles.items()
            ))

            # 4. Collect + verify results from all specialists
            results: dict[str, dict] = {}
            for target, response in dispatched:
                if response is None:
                    results[target] = {"ok": False, "error": "no response"}
                    continue
                if response.status_code != 200:
                    results[target] = {"ok": False, "error": f"HTTP {response.status_code}"}
                    continue

                try:
                    raw_body = response.json()
                except Exception:
                    results[target] = {"ok": False, "error": "invalid JSON"}
                    continue

                # 验签 Specialist 返回的 SignedAgentMessage
                async with runtime.http_client_factory() as vfy_client:
                    vfy = await verify_agent_message(
                        message=raw_body,
                        nonce_store=runtime.nonce_store,
                        http_client=vfy_client,
                        cache=runtime.cache,
                        config=VerificationConfig(profile=TEST_PROFILE),
                        resolver_config=MetadataResolverConfig(
                            profile=TEST_PROFILE,
                            registry_url=settings.registry_base_url,
                        ),
                        now=datetime.now(timezone.utc),
                    )

                if vfy.ok and vfy.message:
                    results[target] = vfy.message.payload if isinstance(vfy.message.payload, dict) else {"ok": False, "error": "invalid payload"}
                    store.add_review_event(ReviewEvent(
                        review_id=review.review_id,
                        event_type="result_verified",
                        from_agent=target,
                        to_agent="coordinator-agent",
                        verification_result="verified",
                        payload_summary=f"signature verified, kid={vfy.kid}",
                        created_at=utc_now(),
                    ))
                else:
                    results[target] = {"ok": False, "error": f"VERIFICATION_FAILED: {vfy.code}"}
                    store.add_review_event(ReviewEvent(
                        review_id=review.review_id,
                        event_type="result_verification_failed",
                        from_agent=target,
                        to_agent="coordinator-agent",
                        verification_result="rejected",
                        payload_summary=f"code={vfy.code}",
                        reason=vfy.reason,
                        created_at=utc_now(),
                    ))

            # 5. Parse findings from each specialist and save
            all_findings: dict[str, list[dict]] = {
                "architecture": [], "security": [], "performance": [], "compliance": [],
            }
            domain_map = {
                "architecture-agent": ("architecture", "review_architecture"),
                "security-agent": ("security", "review_security"),
                "performance-agent": ("performance", "review_performance"),
                "compliance-agent": ("compliance", "review_compliance"),
            }

            for target, result in results.items():
                if not result.get("ok"):
                    continue
                domain, action = domain_map.get(target, (target, ""))
                # Save each finding to store
                raw_findings = result.get("findings", [])
                all_findings[domain] = raw_findings
                for f in raw_findings:
                    store.add_finding(ReviewFinding(
                        review_id=review.review_id, agent_role=domain,
                        category=f.get("category", "unknown"),
                        severity=f.get("severity", "info"),
                        title=f.get("title", ""),
                        description=f.get("description", ""),
                        recommendation=f.get("recommendation", ""),
                        code_snippet=f.get("code_snippet"),
                        line_numbers=f.get("line_numbers"),
                        created_at=utc_now(),
                    ))
                store.add_review_event(ReviewEvent(
                    review_id=review.review_id, event_type="finding_returned",
                    from_agent=target, to_agent="coordinator-agent",
                    verification_result="verified",
                    payload_summary=(
                        f"score={result.get('score')}, "
                        f"findings={len(raw_findings)}"
                    ),
                    reason=result.get("summary"), created_at=utc_now(),
                ))

            # 6. Synthesize final report
            store.update_review(review.review_id, status="synthesizing")
            try:
                synth = await synthesize_report(
                    settings=runtime.settings.llm,
                    code=review.code, language=language,
                    coordinator_analysis=coordinator_analysis,
                    architecture_result=results.get("architecture-agent", {}),
                    security_result=results.get("security-agent", {}),
                    performance_result=results.get("performance-agent", {}),
                    compliance_result=results.get("compliance-agent", {}),
                )
            except Exception:
                from shared.rules import synthesize_report as _fallback_synth
                synth = _fallback_synth(
                    review.code, language, coordinator_analysis, all_findings,
                )

            store.update_review(
                review.review_id,
                overall_score=synth.overall_score,
                status="completed",
            )

            # Build full report for response
            report = {
                "review_id": review.review_id,
                "overall_score": synth.overall_score,
                "summary": synth.summary,
                "architecture_score": synth.architecture_score,
                "security_score": synth.security_score,
                "performance_score": synth.performance_score,
                "compliance_score": synth.compliance_score,
                "risk_items": synth.risk_items,
                "recommendations": synth.recommendations,
            }
            store.add_review_event(ReviewEvent(
                review_id=review.review_id, event_type="report_synthesized",
                from_agent="coordinator-agent", to_agent="user",
                verification_result="verified",
                payload_summary=f"overall={synth.overall_score}/10",
                reason=synth.summary, created_at=utc_now(),
            ))
            store.add_review_event(ReviewEvent(
                review_id=review.review_id, event_type="review_completed",
                from_agent="coordinator-agent", to_agent="user",
                verification_result="verified",
                payload_summary="review complete",
                created_at=utc_now(),
            ))

            return JSONResponse({"ok": True, "review_id": review.review_id, "report": report})

    # -- All Agents: handle incoming tasks (signed by caller) ----------------

    @app.post("/tasks/handle")
    async def handle_task(request: Request) -> JSONResponse:
        raw_body = await request.body()
        headers = {key: value for key, value in request.headers.items()}
        async with runtime.http_client_factory() as client:
            verification = await verify_http_request(
                method=request.method, url=str(request.url),
                headers=headers, body=raw_body,
                nonce_store=runtime.nonce_store,
                http_client=client, cache=runtime.cache,
                config=VerificationConfig(profile=TEST_PROFILE),
                resolver_config=MetadataResolverConfig(
                    profile=TEST_PROFILE, registry_url=settings.registry_base_url,
                ),
                now=datetime.now(timezone.utc),
            )

        if not verification.ok:
            runtime.store.add_auth_event(AuthEvent(
                source_agent_id=headers.get("x-agent-id"),
                target_agent=role, result="rejected",
                error_code=verification.code, detail=verification.reason,
                created_at=utc_now(),
            ))
            return JSONResponse(
                status_code=401,
                content={"ok": False, "code": verification.code, "reason": verification.reason},
            )

        # Record "agent_received" event for review tracking
        source_id = verification.agent_id or "unknown"
        try:
            body_json = json.loads(raw_body.decode("utf-8"))
            review_id = body_json.get("review_id", "unknown")
        except Exception:
            review_id = "unknown"
        if review_id != "unknown" and not review_id.startswith("attack-probe-"):
            runtime.store.add_review_event(ReviewEvent(
                review_id=review_id, event_type="agent_received",
                from_agent=source_id, to_agent=role,
                verification_result="verified",
                payload_summary=body_json.get("action", "unknown"),
                created_at=utc_now(),
            ))

        runtime.store.add_auth_event(AuthEvent(
            source_agent_id=source_id,
            target_agent=role, result="verified",
            error_code=None, detail=f"verified by {role}",
            created_at=utc_now(),
        ))

        # Parse body — handle both AgentTask and AgentTaskResult
        task = _parse_incoming(raw_body, role)
        result = await _process_verified_task(runtime, task, source_id, verification)

        # 签名返回结果，防止被中间人篡改
        if runtime.agent is not None:
            signed = await runtime.agent.sign_message(
                payload=result.model_dump(mode="json"),
                recipient=source_id,
                message_type="task.result",
            )
            return JSONResponse(signed.model_dump(mode="json"))
        return JSONResponse(result.model_dump(mode="json"))

    return app


# ===========================================================================
# Role-specific processing
# ===========================================================================

async def _process_verified_task(
    runtime: DemoAgentRuntime,
    task: AgentTask,
    source_agent_id: str,
    verification,  # VerificationSuccess from verify_http_request
) -> AgentTaskResult:
    role = runtime.spec.role

    # -- Capability check (application-level authorization) ------------------
    if role != "coordinator-agent":
        required_cap = _ACTION_CAPABILITY.get(task.action)
        if required_cap and runtime.agent and required_cap not in runtime.agent.metadata.capabilities:
            runtime.store.add_auth_event(AuthEvent(
                source_agent_id=source_agent_id, target_agent=role,
                result="rejected", error_code="capability_escalation",
                detail=f"Agent lacks capability: {required_cap}",
                created_at=utc_now(),
            ))
            raise HTTPException(
                status_code=403,
                detail=f"Capability denied: {required_cap}",
            )

    # -- Coordinator: verify source agent's capability for the action -------
    if role == "coordinator-agent":
        # Resolve source agent's metadata to check capabilities
        source_capabilities: list[str] = []
        try:
            async with runtime.http_client_factory() as client:
                from agent_auth_sdk import resolve_agent, MetadataResolverConfig
                from agent_auth_sdk.config import TEST_PROFILE
                resolved = await resolve_agent(
                    source_agent_id,
                    profile=TEST_PROFILE,
                    http_client=client,
                    cache=runtime.cache,
                    config=MetadataResolverConfig(
                        profile=TEST_PROFILE,
                        registry_url=runtime.settings.registry_base_url,
                    ),
                )
                if resolved and resolved.metadata:
                    source_capabilities = resolved.metadata.capabilities or []
        except Exception:
            pass

        required_cap = _ACTION_CAPABILITY.get(task.action)
        if required_cap and required_cap not in source_capabilities:
            runtime.store.add_auth_event(AuthEvent(
                source_agent_id=source_agent_id, target_agent=role,
                result="rejected", error_code="capability_escalation",
                detail=f"Agent {source_agent_id} lacks capability: {required_cap}",
                created_at=utc_now(),
            ))
            raise HTTPException(
                status_code=403,
                detail=f"Capability denied: source agent lacks {required_cap}",
            )

        if task.action == "replay_probe":
            return AgentTaskResult(handled_by=role, review_id=task.review_id,
                                   action=task.action, score=0, summary="replay probe")
        # For other actions, the Coordinator just acknowledges
        return AgentTaskResult(handled_by=role, review_id=task.review_id,
                               action=task.action, score=0, summary="acknowledged")

    # -- Specialist agents: perform their domain review ----------------------
    if role in ("architecture-agent", "security-agent", "performance-agent", "compliance-agent"):
        return await _specialist_review(runtime, task)

    raise HTTPException(status_code=400, detail=f"Unhandled role/action: {role}/{task.action}")


# ===========================================================================
# Specialist review — shared by architecture/security/performance/compliance
# ===========================================================================

_SPECIALIST_LLM: dict[str, Callable] = {
    "architecture-agent": review_architecture,
    "security-agent": review_security,
    "performance-agent": review_performance,
    "compliance-agent": review_compliance,
}

_SPECIALIST_FALLBACK: dict[str, Callable] = {
    "architecture-agent": None,  # set below after import
    "security-agent": None,
    "performance-agent": None,
    "compliance-agent": None,
}


def _init_fallbacks() -> None:
    if _SPECIALIST_FALLBACK["architecture-agent"] is not None:
        return
    from shared.rules import (
        review_architecture as _fb_arch,
        review_security as _fb_sec,
        review_performance as _fb_perf,
        review_compliance as _fb_comp,
    )
    _SPECIALIST_FALLBACK["architecture-agent"] = _fb_arch
    _SPECIALIST_FALLBACK["security-agent"] = _fb_sec
    _SPECIALIST_FALLBACK["performance-agent"] = _fb_perf
    _SPECIALIST_FALLBACK["compliance-agent"] = _fb_comp


async def _specialist_review(
    runtime: DemoAgentRuntime, task: AgentTask,
) -> AgentTaskResult:
    role = runtime.spec.role
    llm_fn = _SPECIALIST_LLM.get(role)

    try:
        if llm_fn is None:
            raise RuntimeError(f"No LLM function for {role}")
        result = await llm_fn(
            settings=runtime.settings.llm,
            code=task.code, language=task.language,
            context=task.context,
        )
    except Exception:
        _init_fallbacks()
        fb = _SPECIALIST_FALLBACK.get(role)
        if fb is not None:
            result = fb(task.code, task.language, task.context)
        else:
            raise

    # Determine domain for findings
    domain_map = {
        "architecture-agent": "architecture",
        "security-agent": "security",
        "performance-agent": "performance",
        "compliance-agent": "compliance",
    }
    domain = domain_map.get(role, role)

    # Save findings to store
    for f in result.findings:
        runtime.store.add_finding(ReviewFinding(
            review_id=task.review_id, agent_role=domain,
            category=f.get("category", "unknown"),
            severity=f.get("severity", "info"),
            title=f.get("title", ""),
            description=f.get("description", ""),
            recommendation=f.get("recommendation", ""),
            code_snippet=f.get("code_snippet"),
            line_numbers=f.get("line_numbers"),
            created_at=utc_now(),
        ))

    return AgentTaskResult(
        ok=True, handled_by=role, review_id=task.review_id,
        action=task.action, score=result.score,
        summary=result.summary, findings=result.findings,
    )


# ===========================================================================
# Capability mapping — each agent only gets its own domain capability
# ===========================================================================

_ROLE_DOMAIN_CAPABILITY: dict[str, str] = {
    "coordinator-agent": "code-review-coordinate",
    "architecture-agent": "code-review-architecture",
    "security-agent": "code-review-security",
    "performance-agent": "code-review-performance",
    "compliance-agent": "code-review-compliance",
}


def _agent_capabilities(role: str) -> list[str]:
    """Return the exact capabilities an agent of this role should possess."""
    domain_cap = _ROLE_DOMAIN_CAPABILITY.get(role)
    base = ["publish", "sign", "verify"]
    if domain_cap:
        base.append(domain_cap)
    return base


# ===========================================================================
# Helpers
# ===========================================================================

def _parse_incoming(raw_body: bytes, role: str) -> AgentTask:
    """Parse an incoming request body as AgentTask.

    Falls back gracefully if the body is an AgentTaskResult (e.g., attack probe).
    """
    try:
        return AgentTask.model_validate_json(raw_body)
    except Exception:
        # Try parsing as AgentTaskResult and convert to a minimal AgentTask
        body = json.loads(raw_body.decode("utf-8"))
        return AgentTask(
            review_id=body.get("review_id", "unknown"),
            action=body.get("action", "unknown"),
            code="",  # AgentTaskResult doesn't carry code
            language="",
            context=body.get("summary"),
        )


def _require(value: str | None, env_name: str) -> str:
    if not value:
        raise RuntimeError(f"{env_name} is required")
    return value
