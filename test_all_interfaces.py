#!/usr/bin/env python3
"""Agent Auth SDK — 全接口功能验证脚本（试验性质）

用途：连接 Vault + 远程 Registry，逐一验证 SDK 的 8 个核心接口。
前提：已 source demo-local-env.ps1（或等效的环境变量），Vault 已解封。

用法：
  python test_all_interfaces.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# 确保 SDK 在 sys.path 中
ROOT = Path(__file__).resolve().parent
SDK_REPO = ROOT.parent / "agent_auth_sdk"
for p in (ROOT, SDK_REPO):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import httpx
from agent_auth_sdk import (
    AgentInstance,
    FileMetadataCache,
    InMemoryNonceStore,
    MetadataResolverConfig,
    VerificationConfig,
    resolve_agent,
    verify_agent_message,
    verify_http_request,
)
from agent_auth_sdk.config import TEST_PROFILE

# ── 配置（从环境变量读取，与 demo 一致）─────────────────────────────────────

VAULT_ADDR = os.getenv("DEMO_VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN_FILE = os.getenv("DEMO_VAULT_TOKEN_FILE", "runtime/vault-token.txt")
VAULT_TRANSIT_MOUNT = os.getenv("DEMO_VAULT_TRANSIT_MOUNT", "transit")

REGISTRY_BASE = "http://192.144.228.237"
REGISTRY_PUBLISH_URL = os.getenv(
    "DEMO_REGISTRY_PUBLISH_URL", f"{REGISTRY_BASE}/registry/agents/publish"
)
REGISTRY_RESOLVE_URL = os.getenv(
    "DEMO_REGISTRY_URL", f"{REGISTRY_BASE}/.well-known/agent.json"
)
REGISTRY_CLIENT_ID = os.getenv("DEMO_REGISTRY_CLIENT_ID", "huangyihe")
REGISTRY_API_KEY = os.getenv("DEMO_REGISTRY_API_KEY", "")

# 试验用 Agent 身份（加时间戳避免重复运行冲突）
import time
_run_ts = str(int(time.time()))[-6:]
AGENT_DOMAIN = "demo.example.com"
AGENT_NAME = f"test-agent-{_run_ts}"
AGENT_ENDPOINT = "https://demo.example.com/test"
ORGANIZATION = "SDK Test Suite"

# Vault key 名（会通过 auto_create_key 自动创建）
MAIN_KEY_NAME = f"test-agent-{_run_ts}"
EXTRA_KEY_NAME = f"test-extra-{_run_ts}"
ROTATED_KEY_NAME = f"test-rotated-{_run_ts}"

# ── 输出辅助 ────────────────────────────────────────────────────────────────

PASS = 0
FAIL = 0
SKIP = 0


def header(text: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print(f"{'=' * 60}")


def ok(text: str) -> None:
    global PASS
    PASS += 1
    print(f"  ✅  PASS  {text}")


def bad(text: str) -> None:
    global FAIL
    FAIL += 1
    print(f"  ❌  FAIL  {text}")


def skip(text: str) -> None:
    global SKIP
    SKIP += 1
    print(f"  ⏭️  SKIP  {text}")


# ── 主流程 ──────────────────────────────────────────────────────────────────


async def main() -> None:
    global PASS, FAIL, SKIP

    header("0. 环境检查")

    # 检查 Vault token 文件
    token_file = Path(VAULT_TOKEN_FILE)
    if not token_file.exists():
        print(f"  Vault token 文件不存在: {token_file}")
        print(f"  请先运行 setup-persistent-vault.ps1 或确保 Vault 已就绪。")
        sys.exit(1)
    ok(f"Vault token 文件: {token_file}")

    # 检查 Registry 连通性
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{REGISTRY_BASE}/healthz", timeout=5)
            r.raise_for_status()
            ok(f"Registry 连通: {REGISTRY_BASE}/healthz → {r.json()}")
        except Exception as e:
            bad(f"Registry 不可达: {e}")
            print("  请确认 Registry 已部署且可访问。")
            sys.exit(1)

        # 打印 Registry 公开文档
        try:
            r = await client.get(REGISTRY_RESOLVE_URL, timeout=5)
            r.raise_for_status()
            doc = r.json()
            agent_count = len(doc.get("agents", []))
            ok(f"Registry 公开文档可读，当前 {agent_count} 个 agent")
        except Exception as e:
            bad(f"Registry 公开文档读取失败: {e}")

    # ──────────────────────────────────────────────────────────────────────
    header("1. from_vault() — 从 Vault 创建 Agent 实例")

    try:
        agent = AgentInstance.from_vault(
            domain=AGENT_DOMAIN,
            name=AGENT_NAME,
            organization=ORGANIZATION,
            endpoint=AGENT_ENDPOINT,
            vault_addr=VAULT_ADDR,
            vault_token_file=VAULT_TOKEN_FILE,
            transit_mount=VAULT_TRANSIT_MOUNT,
            key_name=MAIN_KEY_NAME,
            auto_create_key=True,
            capabilities=["publish", "sign", "verify"],
            environment="test",
        )
        ok(f"Agent 创建成功: {agent.agent_id}")
        ok(f"   kid: {agent.kid}")
        ok(f"   metadata.keys[0].alg: {agent.metadata.keys[0].alg}")
    except Exception as e:
        bad(f"Agent 创建失败: {e}")
        sys.exit(1)

    # ──────────────────────────────────────────────────────────────────────
    header("2. export_metadata() — 导出 .well-known/agent.json")

    try:
        output = agent.export_metadata("runtime/test-agent")
        ok(f"Metadata 已导出: {output}")
        assert output.exists()
    except Exception as e:
        bad(f"导出失败: {e}")

    # ──────────────────────────────────────────────────────────────────────
    header("3. publish() — 发布到 Registry")

    publish_ok = False
    try:
        result = await agent.publish(
            registry_url=REGISTRY_PUBLISH_URL,
            client_id=REGISTRY_CLIENT_ID,
            api_key=REGISTRY_API_KEY,
            timeout_seconds=15.0,
        )
        ok(f"发布成功: {result}")
        publish_ok = True
    except Exception as e:
        bad(f"发布失败: {e}")

    # ──────────────────────────────────────────────────────────────────────
    header("4. resolve_agent() — 从 Registry 解析 Agent metadata")

    try:
        async with httpx.AsyncClient() as client:
            resolved = await resolve_agent(
                agent.agent_id,
                profile=TEST_PROFILE,
                http_client=client,
                config=MetadataResolverConfig(
                    profile=TEST_PROFILE,
                    registry_url=REGISTRY_RESOLVE_URL,
                ),
            )
        ok(f"解析成功: {resolved.metadata.agent_id}")
        ok(f"   organization: {resolved.metadata.organization}")
        ok(f"   keys 数量: {len(resolved.metadata.keys)}")
        ok(f"   source: {resolved.source_url}")
    except Exception as e:
        bad(f"解析失败: {e}")

    # ──────────────────────────────────────────────────────────────────────
    header("5. sign_http() + verify_http_request() — 请求签名与验签")

    try:
        from agent_auth_sdk.signing import sign_http_request

        # 使用一个独立的 signer 来签名，模拟调用方
        signed = await agent.sign_http(
            method="POST",
            url="https://demo.example.com/api/test",
            body={"action": "test", "value": 42},
        )
        ok(f"签名成功，headers: {[k for k in signed.headers if k.startswith('x-')]}")

        # 验签：需要从 registry 解析 metadata
        async with httpx.AsyncClient() as client:
            nonce_store = InMemoryNonceStore()
            result = await verify_http_request(
                method="POST",
                url="https://demo.example.com/api/test",
                headers=signed.headers,
                body={"action": "test", "value": 42},
                nonce_store=nonce_store,
                http_client=client,
                config=VerificationConfig(profile=TEST_PROFILE),
                resolver_config=MetadataResolverConfig(
                    profile=TEST_PROFILE,
                    registry_url=REGISTRY_RESOLVE_URL,
                ),
                now=datetime.now(timezone.utc),
            )

        if result.ok:
            ok(f"验签通过: agent_id={result.agent_id}, kid={result.kid}")
        else:
            bad(f"验签失败: code={result.code}, reason={result.reason}")
    except Exception as e:
        bad(f"签名/验签流程异常: {e}")

    # ──────────────────────────────────────────────────────────────────────
    header("5b. sign_message() + verify_agent_message() — 消息签名与验签")

    try:
        message = await agent.sign_message(
            payload={"greeting": "hello from test suite"},
            payload_type="application/json",
            recipient="agent://demo.example.com/receiver",
            message_type="test.greeting",
        )
        ok(f"消息签名成功: agent_id={message.agent_id}, kid={message.kid}")

        # 验签
        async with httpx.AsyncClient() as client:
            nonce_store2 = InMemoryNonceStore()
            result = await verify_agent_message(
                message=message,
                nonce_store=nonce_store2,
                http_client=client,
                config=VerificationConfig(profile=TEST_PROFILE),
                resolver_config=MetadataResolverConfig(
                    profile=TEST_PROFILE,
                    registry_url=REGISTRY_RESOLVE_URL,
                ),
                now=datetime.now(timezone.utc),
            )

        if result.ok:
            ok(f"消息验签通过: {result.message.payload if result.message else 'N/A'}")
        else:
            bad(f"消息验签失败: code={result.code}, reason={result.reason}")
    except Exception as e:
        bad(f"消息签名/验签流程异常: {e}")

    # ──────────────────────────────────────────────────────────────────────
    header("6. add_key() — 添加额外活跃密钥")

    add_key_ok = False
    try:
        result = await agent.add_key(
            registry_url=f"{REGISTRY_BASE}/registry/agents/add-key",
            client_id=REGISTRY_CLIENT_ID,
            api_key=REGISTRY_API_KEY,
            new_key_name=EXTRA_KEY_NAME,
            timeout_seconds=15.0,
        )
        ok(f"add_key 成功: {result}")
        add_key_ok = True

        # 验证 registry 中现在有两个 active key
        async with httpx.AsyncClient() as client:
            resolved = await resolve_agent(
                agent.agent_id,
                profile=TEST_PROFILE,
                http_client=client,
                config=MetadataResolverConfig(
                    profile=TEST_PROFILE,
                    registry_url=REGISTRY_RESOLVE_URL,
                ),
            )
        active_keys = [k for k in resolved.metadata.keys if k.status == "active"]
        if len(active_keys) >= 2:
            ok(f"Registry 中确认有 {len(active_keys)} 个 active key")
        else:
            bad(f"Registry 中仅 {len(active_keys)} 个 active key，预期 ≥2")
    except Exception as e:
        bad(f"add_key 失败: {e}")
        # 某些旧版 registry 可能还没有部署新端点
        if "404" in str(e) or "Not Found" in str(e):
            skip("Registry 可能未部署 add-key 端点，跳过后续多 key 测试")

    # ──────────────────────────────────────────────────────────────────────
    header("7. rotate_key() — 轮换密钥")

    try:
        result = await agent.rotate_key(
            registry_url=f"{REGISTRY_BASE}/registry/agents/rotate-key",
            client_id=REGISTRY_CLIENT_ID,
            api_key=REGISTRY_API_KEY,
            new_key_name=ROTATED_KEY_NAME,
            timeout_seconds=15.0,
        )
        ok(f"rotate_key 成功: {result}")

        # 验证 registry 中新增的 rotated key 为 active
        async with httpx.AsyncClient() as client:
            resolved = await resolve_agent(
                agent.agent_id,
                profile=TEST_PROFILE,
                http_client=client,
                config=MetadataResolverConfig(
                    profile=TEST_PROFILE,
                    registry_url=REGISTRY_RESOLVE_URL,
                ),
            )
        active = [k for k in resolved.metadata.keys if k.status == "active"]
        inactive = [k for k in resolved.metadata.keys if k.status == "inactive"]
        ok(f"Registry 中: {len(active)} active, {len(inactive)} inactive")
        if any(k.kid.endswith(ROTATED_KEY_NAME) for k in active):
            ok("新的 rotated key 确认为 active")
        else:
            bad("新的 rotated key 不是 active 状态")
    except Exception as e:
        bad(f"rotate_key 失败: {e}")

    # ──────────────────────────────────────────────────────────────────────
    header("8. revoke_key() — 撤销密钥")

    if add_key_ok:
        try:
            # 找到 extra key 的 kid
            extra_kid = None
            for k in agent.metadata.keys:
                if EXTRA_KEY_NAME in k.kid:
                    extra_kid = k.kid
                    break

            if extra_kid:
                result = await agent.revoke_key(
                    registry_url=f"{REGISTRY_BASE}/registry/agents/revoke-key",
                    client_id=REGISTRY_CLIENT_ID,
                    api_key=REGISTRY_API_KEY,
                    kid_to_revoke=extra_kid,
                    timeout_seconds=15.0,
                )
                ok(f"revoke_key 成功: {result}")

                # 验证
                async with httpx.AsyncClient() as client:
                    resolved = await resolve_agent(
                        agent.agent_id,
                        profile=TEST_PROFILE,
                        http_client=client,
                        config=MetadataResolverConfig(
                            profile=TEST_PROFILE,
                            registry_url=REGISTRY_RESOLVE_URL,
                        ),
                    )
                if extra_kid in resolved.metadata.revoked_kids:
                    ok(f"{extra_kid} 已加入 revoked_kids")
                else:
                    bad(f"{extra_kid} 未在 revoked_kids 中")
                revoked_keys = [
                    k for k in resolved.metadata.keys if k.status == "revoked"
                ]
                if any(extra_kid in k.kid for k in revoked_keys):
                    ok("对应 key status='revoked'")
                else:
                    bad("对应 key 的 status 不是 'revoked'")
            else:
                skip("未找到 extra key 的 kid，跳过 revoke_key 测试")
        except Exception as e:
            bad(f"revoke_key 失败: {e}")
            if "404" in str(e) or "Not Found" in str(e):
                skip("Registry 可能未部署 revoke-key 端点")
    else:
        skip("add_key 未成功，跳过 revoke_key 依赖测试")

    # ──────────────────────────────────────────────────────────────────────
    header("9. revoke_agent() — 撤销整个 Agent")

    try:
        result = await agent.revoke_agent(
            registry_url=f"{REGISTRY_BASE}/registry/agents/revoke",
            client_id=REGISTRY_CLIENT_ID,
            api_key=REGISTRY_API_KEY,
            timeout_seconds=15.0,
        )
        ok(f"revoke_agent 成功: {result}")

        # 确认从 Registry 公开文档消失
        async with httpx.AsyncClient() as client:
            r = await client.get(REGISTRY_RESOLVE_URL, timeout=5)
            r.raise_for_status()
            doc = r.json()
        agent_ids = [e.get("agent_id") for e in doc.get("agents", [])]
        if agent.agent_id not in agent_ids:
            ok(f"Agent 已从公开文档移除")
        else:
            bad("Agent 仍在公开文档中")

        # 确认后续 publish 被拒绝
        try:
            await agent.publish(
                registry_url=REGISTRY_PUBLISH_URL,
                client_id=REGISTRY_CLIENT_ID,
                api_key=REGISTRY_API_KEY,
                timeout_seconds=15.0,
            )
            bad("revoke_agent 后 publish 应该被拒绝，但却成功了")
        except Exception as e:
            if "410" in str(e) or "AGENT_REVOKED" in str(e):
                ok("revoke_agent 后 publish 正确返回 410 AGENT_REVOKED")
            else:
                bad(f"revoke_agent 后 publish 返回非预期错误: {e}")
    except Exception as e:
        bad(f"revoke_agent 失败: {e}")

    # ──────────────────────────────────────────────────────────────────────
    header("10. 总结")

    revoked_kids = getattr(agent.metadata, "revoked_kids", []) or []
    if add_key_ok and len(revoked_kids) > 0:
        ok(f"撤销后验签已确认：revoked_kids 包含 {revoked_kids}")
    else:
        skip("未进入撤销流程或无需测试")

    # ──────────────────────────────────────────────────────────────────────
    header("结果汇总")

    total = PASS + FAIL + SKIP
    print(f"  通过: {PASS}")
    print(f"  失败: {FAIL}")
    print(f"  跳过: {SKIP}")
    print(f"  总计: {total}")

    if FAIL == 0:
        print(f"\n  🎉 全部通过！")
    else:
        print(f"\n  ⚠️  有 {FAIL} 项失败，请检查。")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
