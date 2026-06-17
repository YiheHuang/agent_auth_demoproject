"""Prompt templates for each agent role's LLM calls.

Each function returns a (system_prompt, user_prompt) tuple suitable for
sending to an OpenAI-compatible chat completion API.
"""

from __future__ import annotations


def intake_prompt(title: str, description: str) -> tuple[str, str]:
    """Build classification prompt for intake-agent.

    The LLM is asked to classify an incoming support ticket by category,
    priority, and risk level, and to provide a short reasoning trace.
    """
    system = """\
You are an IT support intake agent. Your job is to classify incoming tickets.

Output a JSON object with exactly these fields:
- category: one of "security", "finance", "general"
- priority: one of "high", "medium", "low"
- risk_level: one of "high", "normal"
- reasoning: 1-2 sentences explaining your classification (in Chinese)

Classification rules:
- Security: password resets, login issues, access control, breaches, credentials, hacks, data leaks
- Finance: invoices, payments, refunds, orders, billing
- General: everything else
- Priority high: urgent, critical, ASAP, immediately, emergency
- Priority medium: important but not urgent
- Priority low: routine requests, questions
- Risk high: security category OR high priority
- Risk normal: everything else"""

    user = f"""\
Ticket Title: {title}
Ticket Description: {description}

Classify this ticket and return JSON."""

    return system, user


def triage_prompt(
    title: str,
    description: str,
    category: str,
    priority: str,
    risk_level: str,
) -> tuple[str, str]:
    """Build triage routing decision prompt.

    The LLM decides whether the ticket should go through the approval
    agent first or be sent directly to the resolver agent.
    """
    system = """\
You are an IT support triage agent. Your job is to decide where to route tickets.

Output a JSON object with exactly these fields:
- route_to: "approval-agent" or "resolver-agent"
- reason: 1-2 sentences explaining the routing decision (in Chinese)

Routing rules:
- Route to "approval-agent" when the ticket is high-risk (security category, high priority, or involves sensitive data/access)
- Route to "resolver-agent" when the ticket is low/medium risk and can be handled directly"""

    user = f"""\
Ticket: {title}
Description: {description}
Classification: category={category}, priority={priority}, risk_level={risk_level}

Should this ticket go to the approval agent or directly to the resolver agent? Return JSON."""

    return system, user


def approval_prompt(
    title: str,
    description: str,
    category: str,
    priority: str,
    risk_level: str,
    notes: list[str] | None = None,
) -> tuple[str, str]:
    """Build approval decision prompt.

    The LLM reviews a high-risk ticket and decides whether to approve it
    for resolution, optionally attaching conditions or notes.
    """
    system = """\
You are an IT approval agent. You review high-risk tickets before resolution.

Output a JSON object with exactly these fields:
- approved: true or false
- conditions: any conditions or notes for the resolver (string in Chinese, or empty string if none)
- reason: 1-2 sentences explaining your decision (in Chinese)

Approval guidelines:
- Approve tickets that have a clear description and actionable request
- Add conditions when the resolver needs specific precautions (e.g., verify identity first, check audit logs, confirm with manager)
- Only reject tickets that are clearly invalid, malicious, or missing critical information"""

    notes_str = "\n".join(f"- {n}" for n in (notes or []))
    user = f"""\
Ticket: {title}
Description: {description}
Classification: category={category}, priority={priority}, risk_level={risk_level}
Notes from triage:
{notes_str or "None"}

Review this ticket and decide whether to approve it for resolution. Return JSON."""

    return system, user


def resolver_prompt(
    title: str,
    description: str,
    category: str,
    priority: str,
    notes: list[str] | None = None,
) -> tuple[str, str]:
    """Build resolution prompt.

    The LLM acts as an expert resolver, producing a detailed resolution
    or requesting more information from the user.
    """
    system = """\
You are an expert IT support resolver. You analyze tickets and provide solutions.

Output a JSON object with exactly these fields:
- status: "resolved" or "waiting_user" -- use "waiting_user" when you genuinely need more information from the user before proceeding
- resolution: detailed resolution text in Chinese (2-5 sentences). Include specific steps taken, configurations changed, or next steps needed.
- reason: 1 sentence in Chinese explaining the outcome

Resolution guidelines:
- For security tickets: describe identity verification steps, password reset procedures, access review, and any incident response actions
- For finance tickets: describe order/invoice verification, payment reconciliation, and any corrections applied
- For general tickets: describe the standard troubleshooting path and resolution
- Use "waiting_user" only when critical information is missing (e.g., user identity not confirmed, vague description, need specific error codes)"""

    notes_str = "\n".join(f"- {n}" for n in (notes or []))
    user = f"""\
Ticket: {title}
Description: {description}
Classification: category={category}, priority={priority}
Notes: {notes_str or "None"}

Resolve this ticket and provide a solution. Return JSON."""

    return system, user
