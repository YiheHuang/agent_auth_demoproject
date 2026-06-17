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

from agent_auth_sdk import AgentInstance, FileMetadataCache, InMemoryNonceStore, MetadataResolverConfig, VerificationConfig, verify_http_request
from agent_auth_sdk.config import TEST_PROFILE
from shared.models import AgentTask, AgentTaskResult, AuthEvent, IntakeRequest, TicketEvent
from shared.llm import (
    approve_ticket,
    classify_ticket,
    resolve_ticket,
    triage_ticket,
)
from shared.settings import AgentSpec, DemoSettings, get_demo_settings
from shared.store import DemoStore, utc_now


HttpClientFactory = Callable[[], httpx.AsyncClient]


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
                key_name=_require(self.settings.agent_kms_key_id(self.spec.role), f"{self.spec.role} Vault key"),
                namespace=self.settings.vault_namespace,
                verify=self.settings.vault_verify(),
                capabilities=["ticket-workflow", "publish", "sign", "verify"],
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
            method="POST",
            url=target_url,
            body=body_to_sign,
            nonce=nonce,
        )
        async with self.http_client_factory() as client:
            return await client.post(target_url, json=body_to_send, headers=signed.headers)


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

    app = FastAPI(title=f"{spec.display_name}", lifespan=lifespan)
    app.state.runtime = runtime

    @app.middleware("http")
    async def ensure_ready(request: Request, call_next):
        await runtime.ensure_initialized()
        return await call_next(request)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "agent": role}

    @app.get("/identity")
    async def identity() -> dict[str, str]:
        if runtime.agent is None:
            raise HTTPException(status_code=503, detail="agent not ready")
        return {"agent_id": runtime.agent.agent_id, "role": role}

    @app.post("/tasks/ingest")
    async def ingest(request: IntakeRequest) -> JSONResponse:
        ticket = store.get_ticket(request.ticket_id)
        if ticket is None:
            raise HTTPException(status_code=404, detail="ticket not found")
        # LLM-driven classification with fallback to static rules
        try:
            intake_result = await classify_ticket(
                settings=runtime.settings.llm,
                title=ticket.title,
                description=ticket.description,
            )
            category = intake_result.category
            priority = intake_result.priority
            risk = intake_result.risk_level
            llm_reasoning = intake_result.reasoning
        except Exception:
            from shared.rules import classify_category, classify_priority, risk_level as _risk_level
            combined = f"{ticket.title}\n{ticket.description}"
            category = classify_category(combined)
            priority = classify_priority(combined)
            risk = _risk_level(category, priority)
            llm_reasoning = "(fallback to static rules)"
        ticket = store.update_ticket(
            ticket.ticket_id,
            category=category,
            priority=priority,
            current_agent=role,
            status="processing",
        )
        store.add_ticket_event(
            TicketEvent(
                ticket_id=ticket.ticket_id,
                event_type="intake_classified",
                from_agent="user",
                to_agent=role,
                verification_result="n/a",
                reason=llm_reasoning,
                payload_summary=f"category={category}, priority={priority}, risk={risk}",
                created_at=utc_now(),
            )
        )
        task = AgentTask(
            ticket_id=ticket.ticket_id,
            action="triage_ticket",
            category=category,
            priority=priority,
            risk_level=risk,
            context=ticket.description,
        )
        store.add_ticket_event(
            TicketEvent(
                ticket_id=ticket.ticket_id,
                event_type="agent_dispatched",
                from_agent=role,
                to_agent="triage-agent",
                verification_result="signed",
                reason=None,
                payload_summary=json.dumps(task.model_dump(mode="json"), ensure_ascii=False),
                created_at=utc_now(),
            )
        )
        await runtime.send_task("triage-agent", task)
        return JSONResponse({"ok": True, "ticket_id": ticket.ticket_id})

    @app.post("/tasks/handle")
    async def handle_task(request: Request) -> JSONResponse:
        raw_body = await request.body()
        headers = {key: value for key, value in request.headers.items()}
        async with runtime.http_client_factory() as client:
            verification = await verify_http_request(
                method=request.method,
                url=str(request.url),
                headers=headers,
                body=raw_body,
                nonce_store=runtime.nonce_store,
                http_client=client,
                cache=runtime.cache,
                config=VerificationConfig(profile=TEST_PROFILE),
                resolver_config=MetadataResolverConfig(profile=TEST_PROFILE, registry_url=settings.registry_base_url),
                now=datetime.now(timezone.utc),
            )
        if not verification.ok:
            try:
                payload = json.loads(raw_body.decode("utf-8"))
                ticket_id = payload.get("ticket_id")
            except Exception:
                ticket_id = None
            runtime.store.add_auth_event(
                AuthEvent(
                    source_agent_id=headers.get("x-agent-id"),
                    target_agent=role,
                    result="rejected",
                    error_code=verification.code,
                    detail=verification.reason,
                    created_at=utc_now(),
                )
            )
            if ticket_id:
                runtime.store.add_ticket_event(
                    TicketEvent(
                        ticket_id=ticket_id,
                        event_type="verification_failed",
                        from_agent=headers.get("x-agent-id", "unknown"),
                        to_agent=role,
                        verification_result=verification.code,
                        reason=verification.reason,
                        payload_summary=raw_body.decode("utf-8", errors="ignore"),
                        created_at=utc_now(),
                    )
                )
            return JSONResponse(
                status_code=401,
                content={"ok": False, "code": verification.code, "reason": verification.reason},
            )

        task = AgentTask.model_validate_json(raw_body)
        runtime.store.add_auth_event(
            AuthEvent(
                source_agent_id=verification.agent_id,
                target_agent=role,
                result="verified",
                error_code=None,
                detail=f"verified by {role}",
                created_at=utc_now(),
            )
        )
        runtime.store.add_ticket_event(
            TicketEvent(
                ticket_id=task.ticket_id,
                event_type="agent_received",
                from_agent=verification.agent_id,
                to_agent=role,
                verification_result="verified",
                reason=None,
                payload_summary=json.dumps(task.model_dump(mode="json"), ensure_ascii=False),
                created_at=utc_now(),
            )
        )
        result = await _process_verified_task(runtime, task, verification.agent_id or "unknown")
        return JSONResponse(result.model_dump(mode="json"))

    return app


async def _process_verified_task(runtime: DemoAgentRuntime, task: AgentTask, source_agent_id: str) -> AgentTaskResult:
    ticket = runtime.store.get_ticket(task.ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="ticket not found")

    role = runtime.spec.role
    if task.action == "replay_probe":
        return AgentTaskResult(handled_by=role, status="replay_probe_ok")

    if role == "triage-agent":
        ticket = runtime.store.update_ticket(
            ticket.ticket_id,
            current_agent=role,
            status="triaged",
        )
        # LLM-driven routing with fallback to static rules
        try:
            triage_result = await triage_ticket(
                settings=runtime.settings.llm,
                title=ticket.title,
                description=ticket.description,
                category=ticket.category,
                priority=ticket.priority,
                risk_level=task.risk_level or "normal",
            )
            target_role = triage_result.route_to
            triage_reason = triage_result.reason
        except Exception:
            from shared.rules import requires_approval
            target_role = "approval-agent" if requires_approval(ticket) else "resolver-agent"
            triage_reason = "(fallback to static rules)"
        runtime.store.add_ticket_event(
            TicketEvent(
                ticket_id=ticket.ticket_id,
                event_type="triage_decision",
                from_agent=role,
                to_agent=target_role,
                verification_result="verified",
                reason=triage_reason,
                payload_summary=f"route_to={target_role}",
                created_at=utc_now(),
            )
        )
        next_task = AgentTask(
            ticket_id=ticket.ticket_id,
            action="approve_ticket" if target_role == "approval-agent" else "resolve_ticket",
            category=ticket.category,
            priority=ticket.priority,
            risk_level=task.risk_level or "normal",
            context=ticket.description,
        )
        await runtime.send_task(target_role, next_task)
        return AgentTaskResult(handled_by=role, next_agent=target_role, status="triaged")

    if role == "approval-agent":
        ticket = runtime.store.update_ticket(
            ticket.ticket_id,
            current_agent=role,
            status="pending_approval",
        )
        # LLM-driven approval with fallback (default approve)
        try:
            approval_result = await approve_ticket(
                settings=runtime.settings.llm,
                title=ticket.title,
                description=ticket.description,
                category=ticket.category,
                priority=ticket.priority,
                risk_level=task.risk_level or "normal",
                notes=task.notes,
            )
            notes = ["approved"]
            if approval_result.conditions:
                notes.append(approval_result.conditions)
            approval_reason = approval_result.reason
            approval_summary = f"approved, conditions={approval_result.conditions}" if approval_result.conditions else "approved"
        except Exception:
            notes = ["approved"]
            approval_reason = "(fallback to static rules)"
            approval_summary = "approval granted for high-risk ticket"
        runtime.store.add_ticket_event(
            TicketEvent(
                ticket_id=ticket.ticket_id,
                event_type="approval_granted",
                from_agent=role,
                to_agent="resolver-agent",
                verification_result="verified",
                reason=approval_reason,
                payload_summary=approval_summary,
                created_at=utc_now(),
            )
        )
        next_task = AgentTask(
            ticket_id=ticket.ticket_id,
            action="resolve_ticket",
            category=ticket.category,
            priority=ticket.priority,
            risk_level=task.risk_level or "normal",
            context=ticket.description,
            notes=notes,
        )
        await runtime.send_task("resolver-agent", next_task)
        return AgentTaskResult(handled_by=role, next_agent="resolver-agent", status="approved")

    if role == "resolver-agent":
        # LLM-driven resolution with fallback to static rules
        try:
            resolver_result = await resolve_ticket(
                settings=runtime.settings.llm,
                title=ticket.title,
                description=ticket.description,
                category=ticket.category,
                priority=ticket.priority,
                notes=task.notes,
            )
            status = resolver_result.status
            resolution = resolver_result.resolution
            resolve_reason = resolver_result.reason
        except Exception:
            from shared.rules import resolution_for
            status, resolution = resolution_for(ticket)
            resolve_reason = "(fallback to static rules)"
        runtime.store.update_ticket(
            ticket.ticket_id,
            current_agent=role,
            status=status,
            resolution=resolution,
        )
        runtime.store.add_ticket_event(
            TicketEvent(
                ticket_id=ticket.ticket_id,
                event_type="ticket_resolved" if status == "resolved" else "waiting_for_user",
                from_agent=role,
                to_agent="user",
                verification_result="verified",
                reason=resolve_reason,
                payload_summary=resolution,
                created_at=utc_now(),
            )
        )
        return AgentTaskResult(handled_by=role, status=status)

    raise HTTPException(status_code=400, detail=f"Unhandled role/action: {role}/{task.action}")


def _require(value: str | None, env_name: str) -> str:
    if not value:
        raise RuntimeError(f"{env_name} is required")
    return value
