"""Static fallback rules for code review — used when LLM is unavailable.

Each function mirrors the LLM equivalent in shared/llm.py, producing the
same output structures so callers don't need to branch on the source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# -- Language detection -------------------------------------------------------

_LANGUAGE_SIGNATURES: dict[str, list[str]] = {
    "python": [
        r"^import\s+\w+", r"^from\s+\w+\s+import", r"def\s+\w+\s*\(.*\)\s*:",
        r"class\s+\w+.*:", r"print\(", r"if __name__ == .__main__.",
    ],
    "javascript": [
        r"\b(const|let|var)\s+\w+\s*=", r"function\s+\w+\s*\(", r"=>\s*\{",
        r"console\.log\(", r"require\(", r"import\s+\{",
    ],
    "java": [
        r"public\s+(static\s+)?(void|class|int|String)", r"System\.out\.print",
        r"@Override", r"extends\s+\w+", r"implements\s+\w+",
    ],
    "go": [
        r"^package\s+\w+", r"func\s+\w+\s*\(.*\)\s*(\w+|\{)", r"fmt\.",
        r"err\s*:?=", r"defer\s+",
    ],
    "rust": [
        r"fn\s+\w+\s*\(.*\)", r"let\s+mut\s+", r"impl\s+\w+", r"use\s+\w+::",
        r"println!\(", r"match\s+\w+\s*\{",
    ],
    "sql": [
        r"\bSELECT\s+.+\s+FROM\b", r"\bINSERT\s+INTO\b", r"\bCREATE\s+TABLE\b",
    ],
}


def detect_language(code: str) -> str:
    """Heuristic language detection by regex signature matching."""
    scores: dict[str, int] = {}
    for lang, patterns in _LANGUAGE_SIGNATURES.items():
        scores[lang] = sum(1 for p in patterns if re.search(p, code, re.MULTILINE))
    if not scores or max(scores.values()) == 0:
        return "unknown"
    return max(scores, key=scores.get)  # type: ignore[arg-type]


# -- Result dataclasses (mirror llm.py) ---------------------------------------

@dataclass(slots=True)
class AnalysisResult:
    language: str
    code_type: str
    complexity: str
    review_focus: list[str] = field(default_factory=list)
    summary: str = ""


@dataclass(slots=True)
class ReviewResult:
    score: int
    summary: str
    findings: list[dict] = field(default_factory=list)


@dataclass(slots=True)
class SynthesisResult:
    overall_score: int
    summary: str
    architecture_score: int
    security_score: int
    performance_score: int
    compliance_score: int
    risk_items: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


# -- Analysis (Coordinator, step 1) -------------------------------------------

def analyze_code_submission(code: str, language_hint: str | None = None) -> AnalysisResult:
    language = language_hint or detect_language(code)
    lines = code.count("\n") + 1

    if lines <= 20:
        complexity = "low"
    elif lines <= 100:
        complexity = "medium"
    else:
        complexity = "high"

    keywords = code.lower()
    code_type = "script"
    if re.search(r"\bclass\s+\w+", code):
        code_type = "module"
    if re.search(r"(def\s+|function\s+|func\s+|fn\s+)", code):
        code_type = "function_library" if code_type == "module" else "function"

    focus = ["architecture", "security", "performance", "compliance"]

    summary = (
        f"静态规则分析：检测到 {language} 代码，约 {lines} 行，"
        f"复杂度 {complexity}。（LLM 不可用，使用降级规则）"
    )
    return AnalysisResult(
        language=language, code_type=code_type, complexity=complexity,
        review_focus=focus, summary=summary,
    )


# -- Architecture review ------------------------------------------------------

_ARCH_PATTERNS = [
    (r"except\s*:", "medium", "error_handling", "泛化异常捕获", "避免使用裸露的 except:，应捕获具体异常类型。", "使用 except SpecificError as e:"),
    (r"\.\.\w+\(\)", "low", "coupling_cohesion", "长调用链", "方法调用链较长，可能存在耦合过紧问题。", "考虑依赖注入或 Facade 模式简化调用。"),
    (r"(if|elif|else)\s+(if|elif|else)", "low", "code_organization", "嵌套条件复杂", "嵌套条件逻辑可能影响可读性。", "考虑提取条件判断为命名函数或使用策略模式。"),
]


def review_architecture(code: str, language: str, context: str | None = None) -> ReviewResult:
    findings = []
    for pattern, sev, cat, title, desc, rec in _ARCH_PATTERNS:
        if re.search(pattern, code):
            findings.append(dict(severity=sev, category=cat, title=title, description=desc, recommendation=rec))
    score = 7 if len(findings) <= 1 else 5
    return ReviewResult(
        score=score,
        summary=f"静态架构审查完成，发现 {len(findings)} 个潜在问题（降级规则）。",
        findings=findings,
    )


# -- Security review ----------------------------------------------------------

_SEC_PATTERNS = [
    (r"(password|passwd|secret|api_key|api_secret|token)\s*=\s*['\"][^'\"]+['\"]", "critical", "sensitive_data", "硬编码凭据", "代码中疑似包含硬编码的密码或 API 密钥。", "将凭据移至环境变量或密钥管理服务。"),
    (r"(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b).*\s*\+", "critical", "injection", "潜在 SQL 注入", "SQL 语句使用字符串拼接，存在注入风险。", "使用参数化查询或 ORM。"),
    (r"subprocess\.(call|run|Popen)\(.*shell\s*=\s*True", "high", "injection", "Shell 注入风险", "使用 shell=True 且包含用户输入时存在命令注入风险。", "避免 shell=True，使用列表传参。"),
    (r"(eval|exec)\(|__import__\(", "high", "injection", "代码注入风险", "使用 eval/exec/__import__ 可能导致任意代码执行。", "除非绝对必要，避免使用动态代码执行；如必须使用，严格过滤输入。"),
    (r"pickle\.(loads|load)\(", "medium", "deserialization", "不安全的反序列化", "使用 pickle 加载不可信数据可能导致远程代码执行。", "使用 json 或其他安全序列化格式替代 pickle。"),
]


def review_security(code: str, language: str, context: str | None = None) -> ReviewResult:
    findings = []
    for pattern, sev, cat, title, desc, rec in _SEC_PATTERNS:
        if re.search(pattern, code):
            findings.append(dict(severity=sev, category=cat, title=title, description=desc, recommendation=rec))
    score = 8 if len(findings) == 0 else (5 if len(findings) <= 2 else 3)
    return ReviewResult(
        score=score,
        summary=f"静态安全审查完成，发现 {len(findings)} 个潜在问题（降级规则）。",
        findings=findings,
    )


# -- Performance review -------------------------------------------------------

_PERF_PATTERNS = [
    (r"for\s+\w+\s+in\s+range\(.*\):\s*\n\s*for\s+\w+\s+in\s+range", "medium", "algorithm_complexity", "嵌套循环", "嵌套循环可能导致 O(n²) 复杂度。", "评估是否可以合并循环或使用更优数据结构。"),
    (r"\.execute\(.*\).*for\s+\w+\s+in\s+.+:\s*\n\s+\.execute\(", "high", "n_plus_one_query", "潜在 N+1 查询", "在循环内执行数据库查询可能导致 N+1 性能问题。", "使用批量查询或预加载关联数据。"),
    (r"time\.sleep\(|Thread\.sleep\(|\.sleep\(", "medium", "blocking_io", "阻塞调用", "代码中使用 sleep 可能导致不必要的延迟。", "考虑使用异步等待或定时器。"),
]


def review_performance(code: str, language: str, context: str | None = None) -> ReviewResult:
    findings = []
    for pattern, sev, cat, title, desc, rec in _PERF_PATTERNS:
        if re.search(pattern, code):
            findings.append(dict(severity=sev, category=cat, title=title, description=desc, recommendation=rec))
    score = 8 if len(findings) == 0 else 6
    return ReviewResult(
        score=score,
        summary=f"静态性能审查完成，发现 {len(findings)} 个潜在问题（降级规则）。",
        findings=findings,
    )


# -- Compliance review --------------------------------------------------------

_COMPLIANCE_PATTERNS = [
    (r"def \w+\(.*\):\s*\n\s+[^\"']", "medium", "documentation", "缺少 docstring", "函数缺少文档字符串。", "为函数添加 docstring 说明参数、返回值和功能。"),
    (r"[a-z]+[A-Z]", "low", "naming_convention", "命名风格不一致", "代码中混用 camelCase 和 snake_case。", "统一使用语言推荐的命名规范。"),
    (r"print\(|console\.log\(|System\.out\.println\(", "low", "logging_practice", "使用 print 调试", "使用 print/console.log 而非正式日志框架。", "使用 logging 模块或日志框架。"),
]


def review_compliance(code: str, language: str, context: str | None = None) -> ReviewResult:
    findings = []
    for pattern, sev, cat, title, desc, rec in _COMPLIANCE_PATTERNS:
        if re.search(pattern, code):
            findings.append(dict(severity=sev, category=cat, title=title, description=desc, recommendation=rec))
    score = 7 if len(findings) <= 1 else 5
    return ReviewResult(
        score=score,
        summary=f"静态合规审查完成，发现 {len(findings)} 个潜在问题（降级规则）。",
        findings=findings,
    )


# -- Synthesis (Coordinator, final step) -------------------------------------

def synthesize_report(
    code: str,
    language: str,
    coordinator_analysis: str,
    all_findings: dict[str, list[dict]],
) -> SynthesisResult:
    arch = len(all_findings.get("architecture", []))
    sec = len(all_findings.get("security", []))
    perf = len(all_findings.get("performance", []))
    comp = len(all_findings.get("compliance", []))

    arch_score = max(1, 8 - arch)
    sec_score = max(1, 9 - sec * 2)
    perf_score = max(1, 9 - perf)
    comp_score = max(1, 8 - comp)

    overall = round((arch_score + sec_score + perf_score + comp_score) / 4)

    risks = []
    for domain, findings in all_findings.items():
        for f in findings:
            if f.get("severity") in ("critical", "high"):
                risks.append(dict(
                    severity=f["severity"], category=f.get("category", domain),
                    title=f.get("title", ""), impact=f.get("description", ""),
                    mitigation=f.get("recommendation", ""),
                ))

    risks.sort(key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r["severity"], 4))
    for i, r in enumerate(risks, 1):
        r["rank"] = i

    summary = (
        f"静态综合审查完成（LLM 不可用，降级规则）。"
        f"综合评分 {overall}/10。架构 {arch_score}/10，安全 {sec_score}/10，"
        f"性能 {perf_score}/10，合规 {comp_score}/10。共发现 "
        f"{arch + sec + perf + comp} 个潜在问题。"
    )

    return SynthesisResult(
        overall_score=overall, summary=summary,
        architecture_score=arch_score, security_score=sec_score,
        performance_score=perf_score, compliance_score=comp_score,
        risk_items=risks,
        recommendations=["请确保 LLM 服务可用以获得更准确的审查结果。"],
    )
