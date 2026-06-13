from __future__ import annotations

from .models import Ticket


SECURITY_KEYWORDS = ("password", "reset", "login", "access", "credential", "breach")
FINANCE_KEYWORDS = ("invoice", "payment", "refund", "order", "billing")
URGENT_KEYWORDS = ("urgent", "critical", "asap", "immediately")
WAITING_KEYWORDS = ("missing", "need info", "need more information", "cannot reproduce")


def classify_category(text: str) -> str:
    lowered = text.lower()
    if any(keyword in lowered for keyword in SECURITY_KEYWORDS):
        return "security"
    if any(keyword in lowered for keyword in FINANCE_KEYWORDS):
        return "finance"
    return "general"


def classify_priority(text: str) -> str:
    lowered = text.lower()
    if any(keyword in lowered for keyword in URGENT_KEYWORDS):
        return "high"
    return "normal"


def risk_level(category: str, priority: str) -> str:
    if category == "security" or priority == "high":
        return "high"
    return "normal"


def requires_approval(ticket: Ticket) -> bool:
    return risk_level(ticket.category, ticket.priority) == "high"


def resolution_for(ticket: Ticket) -> tuple[str, str]:
    lowered = ticket.description.lower()
    if any(keyword in lowered for keyword in WAITING_KEYWORDS):
        return "waiting_user", "需要用户补充更多上下文后再继续处理。"
    if ticket.category == "security":
        return "resolved", "安全类工单已核验身份并完成处理建议。"
    if ticket.category == "finance":
        return "resolved", "财务/订单类工单已完成标准处理路径。"
    return "resolved", "通用工单已完成分类、协作与处理。"
